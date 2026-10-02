mod common;

use std::time::Duration;

use endpoint_cache::identity;
use endpoint_cache::run::{self, Cache, EnrollArgs};
use endpoint_server::branch::caches;
use sha2::Digest;
use sqlx::PgPool;
use tokio::sync::watch;

async fn enrolled(e: &common::Env) -> (tempfile::TempDir, i64) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root-in.pem");
    std::fs::write(&root, &e.root_pem).unwrap();
    let id = run::enroll(
        dir.path(),
        &EnrollArgs {
            server: e.url.clone(),
            root_pem_path: root,
            token: common::token(e, endpoint_server::tokens::TokenKind::Cache).await,
            name: format!("台北快取 {}", uuid::Uuid::new_v4()),
            url: "https://127.0.0.1:8443".into(),
            dns: vec!["127.0.0.1".into()],
        },
    )
    .await
    .unwrap();
    (dir, id)
}

/// 註冊、核准、啟動（輪詢間隔縮短）
async fn started(e: &common::Env) -> (tempfile::TempDir, i64, Cache) {
    let (dir, id) = enrolled(e).await;
    let site = common::site(e, "127.0.0.0/8").await;
    caches::approve(&e.pool, &e.state.ca, id, site, "admin")
        .await
        .unwrap();
    let (_tx, rx) = watch::channel(false);
    let c = Cache::start_with(dir.path(), rx, Duration::from_millis(100))
        .await
        .unwrap()
        .unwrap();
    (dir, id, c)
}

#[sqlx::test(migrations = false)]
async fn start_waits_for_approval(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, id) = enrolled(&e).await;
    assert!(dir.path().join("pending.key").exists());
    assert!(
        run::enroll(
            dir.path(),
            &EnrollArgs {
                server: e.url.clone(),
                root_pem_path: dir.path().join("root.pem"),
                token: "x".into(),
                name: "n".into(),
                url: "https://127.0.0.1".into(),
                dns: vec!["127.0.0.1".into()],
            }
        )
        .await
        .is_err(),
        "已註冊過不能再註冊"
    );

    let (_tx, rx) = watch::channel(false);
    let path = dir.path().to_path_buf();
    let task =
        tokio::spawn(async move { Cache::start_with(&path, rx, Duration::from_millis(100)).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "核准前一直輪詢");
    let site = common::site(&e, "127.0.0.0/8").await;
    caches::approve(&e.pool, &e.state.ca, id, site, "admin")
        .await
        .unwrap();
    let c = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(c.is_some());
    assert!(dir.path().join("key.pem").exists());
    assert!(dir.path().join("cert.pem").exists());
    assert!(!dir.path().join("pending.key").exists());

    // 停止訊號會結束輪詢
    let (dir2, _) = enrolled(&e).await;
    let (tx, rx) = watch::channel(false);
    tx.send(true).unwrap();
    assert!(
        Cache::start_with(dir2.path(), rx, Duration::from_millis(100))
            .await
            .unwrap()
            .is_none()
    );
}

#[sqlx::test(migrations = false)]
async fn checkin_prefetches_once(pool: PgPool) {
    let e = common::central(pool).await;
    let (_dir, id, c) = started(&e).await;
    let data = b"prefetch me".repeat(1000);
    let (pkg, sha) = common::package(&e, &data).await;
    c.checkin_once().await.unwrap();
    assert_eq!(c.prefetch().await, 1);
    assert_eq!(c.state.central.downloads_started(), 1);
    assert!(c.state.store.has(&sha, data.len() as u64));
    c.checkin_once().await.unwrap();
    assert_eq!(c.prefetch().await, 0);
    assert_eq!(c.state.central.downloads_started(), 1);
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT package_id FROM cache_packages WHERE cache_id = $1")
            .bind(id)
            .fetch_all(&e.pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![(pkg,)]);
}

#[sqlx::test(migrations = false)]
async fn prefetch_with_bandwidth_limit(pool: PgPool) {
    let e = common::central(pool).await;
    let (_dir, _, c) = started(&e).await;
    sqlx::query("UPDATE sites SET bandwidth_limit_mbps = 1")
        .execute(&e.pool)
        .await
        .unwrap();
    let data = vec![7u8; 10_000];
    common::package(&e, &data).await;
    c.checkin_once().await.unwrap();
    let t = std::time::Instant::now();
    assert_eq!(c.prefetch().await, 1);
    // 1 Mbps：10 KB 約 80 ms
    assert!(
        t.elapsed() >= Duration::from_millis(70),
        "{:?}",
        t.elapsed()
    );
}

async fn served_cert(e: &common::Env, c: &Cache, dev: &identity::Identity) -> Vec<u8> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(endpoint_cache::server::serve(
        listener,
        c.tls().unwrap(),
        c.router(),
        10,
    ));
    let pem = format!("{}{}", dev.chain_pem, dev.key_pem);
    let client = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(e.root_pem.as_bytes()).unwrap()])
        .identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap())
        .tls_info(true)
        .build()
        .unwrap();
    let r = client
        .get(format!("https://127.0.0.1:{}/healthz", addr.port()))
        .send()
        .await
        .unwrap();
    r.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .unwrap()
        .peer_certificate()
        .unwrap()
        .to_vec()
}

#[sqlx::test(migrations = false)]
async fn renews_and_hot_swaps_certificate(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, id, c) = started(&e).await;
    let dev = common::device(&e).await;
    let before = served_cert(&e, &c, &dev).await;
    let old_pem = std::fs::read_to_string(dir.path().join("cert.pem")).unwrap();
    sqlx::query(
        "UPDATE cache_certs SET not_after = now() + interval '10 days' WHERE cache_id = $1",
    )
    .bind(id)
    .execute(&e.pool)
    .await
    .unwrap();
    c.checkin_once().await.unwrap();
    let new_pem = std::fs::read_to_string(dir.path().join("cert.pem")).unwrap();
    assert_ne!(old_pem, new_pem);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM cache_certs WHERE cache_id = $1")
        .bind(id)
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let after = served_cert(&e, &c, &dev).await;
    assert_ne!(
        hex::encode(sha2::Sha256::digest(&before)),
        hex::encode(sha2::Sha256::digest(&after)),
        "不重新啟動就換上新憑證"
    );
    // 新身分可以報到
    c.checkin_once().await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn disabled_cache_recovers_after_enable(pool: PgPool) {
    let e = common::central(pool).await;
    let (_dir, id, c) = started(&e).await;
    caches::set_disabled(&e.pool, &e.state.ca, id, true, "admin")
        .await
        .unwrap();
    assert!(c.checkin_once().await.is_err());
    assert!(!c.recover().await.unwrap(), "停用中沒有憑證");
    caches::set_disabled(&e.pool, &e.state.ca, id, false, "admin")
        .await
        .unwrap();
    assert!(c.recover().await.unwrap());
    c.checkin_once().await.unwrap();
}

fn serve_cache(c: &Cache) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(endpoint_cache::server::serve(
        listener,
        c.tls().unwrap(),
        c.router(),
        10,
    ));
    port
}

/// 中央斷線時重新啟動快取：清單是空的，不能回 404（Agent 會當成不再指派），要回 503
#[sqlx::test(migrations = false)]
async fn restart_while_central_down_returns_503(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _, c) = started(&e).await;
    let (pkg, _) = common::package(&e, b"stored before outage").await;
    c.checkin_once().await.unwrap();
    assert_eq!(c.prefetch().await, 1);
    drop(c);

    let mut cfg = endpoint_cache::config::Config::load(dir.path()).unwrap();
    cfg.server_url = common::dead_url();
    cfg.save(dir.path()).unwrap();
    let (_tx, rx) = watch::channel(false);
    let c = Cache::start_with(dir.path(), rx, Duration::from_millis(100))
        .await
        .unwrap()
        .unwrap();
    let port = serve_cache(&c);
    let dev = common::device(&e).await;
    let r = common::client(&e, Some(&dev))
        .get(format!(
            "https://127.0.0.1:{port}/v1/packages/{pkg}/content"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    assert_eq!(r.headers()["retry-after"], "60");
}

/// 限速的預先下載進行中也能立即停止（服務停止、關機），不必等下載完成
#[sqlx::test(migrations = false)]
async fn stop_during_paced_prefetch(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _, c) = started(&e).await;
    drop(c);
    let mut cfg = endpoint_cache::config::Config::load(dir.path()).unwrap();
    cfg.listen = "127.0.0.1:0".into();
    cfg.save(dir.path()).unwrap();
    sqlx::query("UPDATE sites SET bandwidth_limit_mbps = 1")
        .execute(&e.pool)
        .await
        .unwrap();
    // 1 Mbps 下 2 MB 約需 16 秒
    common::package(&e, &vec![5u8; 2 * 1024 * 1024]).await;
    let (tx, rx) = watch::channel(false);
    let path = dir.path().to_path_buf();
    let task = tokio::spawn(async move { run::run(&path, rx).await });
    tokio::time::sleep(Duration::from_secs(2)).await;
    tx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("停止訊號後很快結束")
        .unwrap()
        .unwrap();
}
