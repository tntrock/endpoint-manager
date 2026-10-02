//! loadsim ↔ 真伺服器（小規模），確認三個情境端對端可用。需要 DATABASE_URL。

use std::time::Duration;

use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use loadsim::Target;
use sqlx::PgPool;
use tokio::net::TcpListener;

#[sqlx::test(migrations = false)]
async fn enroll_heartbeat_upload(pool: PgPool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["127.0.0.1".into()]).unwrap();
    db::migrate(&pool).await.unwrap();
    partitions::maintain_partitions(&pool, chrono::Utc::now())
        .await
        .unwrap();
    let state_dir = pki.path().join("packages");
    let state = AppState::new(pool.clone(), ca::Ca::load(pki.path()).unwrap())
        .with_packages(state_dir.clone(), 4);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(tls::serve_mtls(
        listener,
        tls::server_config(pki.path()).unwrap(),
        agent_router(state),
        tls::ConnLimits::default(),
    ));
    let (_, token) = tokens::create_token(
        &pool,
        &tokens::NewToken {
            name: "loadsim".into(),
            group_id: None,
            expires_at: None,
            max_uses: 5,
            created_by: "test".into(),
            kind: tokens::TokenKind::Device,
        },
    )
    .await
    .unwrap();
    let t = Target {
        server: format!("https://127.0.0.1:{port}"),
        root_pem: std::fs::read_to_string(pki.path().join("root.pem")).unwrap(),
        ip: "10.0.0.1".into(),
    };

    let devices = loadsim::enroll(&t, &token, 5, 5).await.unwrap();
    assert_eq!(devices.len(), 5);

    let hb = loadsim::heartbeat(&t, &devices, 20, Duration::from_secs(1)).await;
    assert_eq!(hb.errors, 0);
    assert!(hb.ok >= 15, "{} ok", hb.ok);

    let (up, unverified) = loadsim::upload(&t, &devices, 50, 5).await;
    assert_eq!((up.ok, up.errors, unverified), (5, 0, 0));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM device_software")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 250);

    // 組態：套用 config_rules.sql 後，每台上傳 1,000 個登錄檔值與 security
    sqlx::raw_sql(include_str!("../config_rules.sql"))
        .execute(&pool)
        .await
        .unwrap();
    // 報到用的規則快取最多每 5 秒確認一次 generation
    tokio::time::sleep(Duration::from_millis(5500)).await;
    let (cfg, unverified) = loadsim::config(&t, &devices, 5).await;
    assert_eq!((cfg.ok, cfg.errors, unverified), (5, 0, 0));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM device_registry")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 5 * 1000);

    // 派送：一個套件、兩個派送；每台驗證下載並回報
    use endpoint_server::deploy::{admin, store};
    let data = loadsim::package_bytes(200_000);
    let chunk: Result<bytes::Bytes, std::io::Error> = Ok(bytes::Bytes::from(data));
    let st = store::save(&state_dir, futures_util::stream::iter(vec![chunk]))
        .await
        .unwrap();
    let pkg = admin::create_package(
        &pool,
        &state_dir,
        &st,
        "loadsim.exe",
        None,
        &admin::PackageInput {
            name: "Loadsim Package".into(),
            version: "1.0".into(),
            kind: "exe".into(),
            install_args: "/S".into(),
            uninstall_args: String::new(),
            success_codes: vec![],
            detect_name: "Loadsim Package*".into(),
            detect_publisher: String::new(),
            detect_min_version: String::new(),
        },
        "test",
    )
    .await
    .unwrap();
    for i in 0..2 {
        admin::create_deployment(
            &pool,
            &admin::DeploymentInput {
                name: format!("load {i}"),
                package_id: pkg,
                action: "install".into(),
                include: vec![],
                exclude: vec![],
                pilot_group_id: None,
                max_failure_pct: 100,
                min_samples: 10_000,
            },
            "test",
        )
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(5500)).await;
    let (dep, retries, unassigned) = loadsim::deploy(&t, &devices, 5).await;
    assert_eq!(
        (dep.ok, dep.errors, unassigned),
        (5, 0, 0),
        "retries {retries}"
    );
    let reported: i64 = sqlx::query_scalar("SELECT count(*) FROM deployment_status")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reported, 5 * 2);

    // 更新原則：5 個群組各一個原則，所有裝置都受管；每台報到後回報一次狀態
    sqlx::raw_sql(include_str!("../updates_setup.sql"))
        .execute(&pool)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5500)).await;
    let (up, unmanaged) = loadsim::updates(&t, &devices, 5).await;
    assert_eq!((up.ok, up.errors, unmanaged), (5, 0, 0));
    let applied: i64 =
        sqlx::query_scalar("SELECT count(*) FROM update_policy_status WHERE state = 'applied'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(applied, 5);

    // 遠端指令：對每台下一個「重新收集」，每台報到後回報結果
    use endpoint_server::commands::Actor;
    use endpoint_server::commands::runs::{self, RunInput};
    let admin = Actor {
        username: "loadsim".into(),
        platform: true,
        groups: vec![],
    };
    for d in &devices {
        runs::create_run(
            &pool,
            &RunInput {
                action: "collect".into(),
                target: runs::Target::Device(d.device_id),
                delay_minutes: None,
                script_id: None,
                expires_hours: 24,
            },
            &admin,
        )
        .await
        .unwrap();
    }
    let (cmd, without) = loadsim::commands(&t, &devices, 5).await;
    assert_eq!((cmd.ok, cmd.errors, without), (5, 0, 0));
    let done: i64 =
        sqlx::query_scalar("SELECT count(*) FROM command_targets WHERE status = 'succeeded'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(done, 5);
}

/// 透過真實快取下載：中央 + endpoint-cache + 3 台模擬裝置
#[sqlx::test(migrations = false)]
async fn cache_deploy_through_real_cache(pool: PgPool) {
    use endpoint_server::branch::{caches, sites};
    use endpoint_server::deploy::{admin, store};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["127.0.0.1".into()]).unwrap();
    db::migrate(&pool).await.unwrap();
    partitions::maintain_partitions(&pool, chrono::Utc::now())
        .await
        .unwrap();
    let state_dir = pki.path().join("packages");
    let state = AppState::new(pool.clone(), ca::Ca::load(pki.path()).unwrap())
        .with_packages(state_dir.clone(), 4);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(tls::serve_mtls(
        listener,
        tls::server_config(pki.path()).unwrap(),
        agent_router(state.clone()),
        tls::ConnLimits::default(),
    ));
    let server = format!("https://127.0.0.1:{port}");
    let token = |kind| {
        let pool = pool.clone();
        async move {
            tokens::create_token(
                &pool,
                &tokens::NewToken {
                    name: "loadsim".into(),
                    group_id: None,
                    expires_at: None,
                    max_uses: 5,
                    created_by: "test".into(),
                    kind,
                },
            )
            .await
            .unwrap()
            .1
        }
    };

    // 快取：註冊、核准到 10.0.0.0/8 的據點、啟動
    let cache_dir = tempfile::tempdir().unwrap();
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_listener.set_nonblocking(true).unwrap();
    let cache_url = format!(
        "https://127.0.0.1:{}",
        std_listener.local_addr().unwrap().port()
    );
    let id = endpoint_cache::run::enroll(
        cache_dir.path(),
        &endpoint_cache::run::EnrollArgs {
            server: server.clone(),
            root_pem_path: pki.path().join("root.pem"),
            token: token(tokens::TokenKind::Cache).await,
            name: "loadsim cache".into(),
            url: cache_url,
            dns: vec!["127.0.0.1".into()],
        },
    )
    .await
    .unwrap();
    let site = sites::create_site(
        &pool,
        &sites::SiteInput {
            name: "loadsim".into(),
            cidrs: vec!["10.0.0.0/8".into()],
            fallback_to_central: true,
            bandwidth_limit_mbps: None,
            disk_limit_gb: 100,
        },
        "test",
    )
    .await
    .unwrap();
    caches::approve(&pool, &state.ca, id, site, "test")
        .await
        .unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let cache =
        endpoint_cache::run::Cache::start_with(cache_dir.path(), rx, Duration::from_millis(100))
            .await
            .unwrap()
            .unwrap();
    tokio::spawn(endpoint_cache::server::serve(
        TcpListener::from_std(std_listener).unwrap(),
        cache.tls().unwrap(),
        cache.router(),
        100,
    ));

    // 套件與派送
    let data = loadsim::package_bytes(200_000);
    let chunk: Result<bytes::Bytes, std::io::Error> = Ok(bytes::Bytes::from(data));
    let st = store::save(&state_dir, futures_util::stream::iter(vec![chunk]))
        .await
        .unwrap();
    let pkg = admin::create_package(
        &pool,
        &state_dir,
        &st,
        "loadsim.exe",
        None,
        &admin::PackageInput {
            name: "Loadsim Package".into(),
            version: "1.0".into(),
            kind: "exe".into(),
            install_args: "/S".into(),
            uninstall_args: String::new(),
            success_codes: vec![],
            detect_name: "Loadsim Package*".into(),
            detect_publisher: String::new(),
            detect_min_version: String::new(),
        },
        "test",
    )
    .await
    .unwrap();
    admin::create_deployment(
        &pool,
        &admin::DeploymentInput {
            name: "load".into(),
            package_id: pkg,
            action: "install".into(),
            include: vec![],
            exclude: vec![],
            pilot_group_id: None,
            max_failure_pct: 100,
            min_samples: 10_000,
        },
        "test",
    )
    .await
    .unwrap();
    state.deploy.invalidate();
    state.branch.invalidate();

    let t = Target {
        server,
        root_pem: std::fs::read_to_string(pki.path().join("root.pem")).unwrap(),
        ip: "10.0.0.1".into(),
    };
    let devices = loadsim::enroll(&t, &token(tokens::TokenKind::Device).await, 3, 3)
        .await
        .unwrap();
    let r = loadsim::cache_deploy(&t, &devices, 3).await;
    assert_eq!(
        (r.report.ok, r.report.errors, r.no_source, r.fallback),
        (3, 0, 0, 0),
        "{r:?}"
    );
    assert_eq!(cache.state.central.downloads_started(), 1);
    let cached: i64 =
        sqlx::query_scalar("SELECT count(*) FROM deployment_status WHERE source = 'cache'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cached, 3);
}
