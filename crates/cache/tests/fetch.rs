mod common;

use std::sync::Arc;

use endpoint_cache::central::Central;
use endpoint_cache::fetch::{FetchError, Fetcher};
use endpoint_cache::identity;
use endpoint_cache::store::Store;
use protocol::branch::{CacheCheckin, CachePackage};
use sqlx::PgPool;

async fn setup(
    e: &common::Env,
    data: &[u8],
) -> (tempfile::TempDir, Arc<Central>, Arc<Store>, CachePackage) {
    let (dir, _) = common::approved_cache(e).await;
    let id = identity::load_identity(dir.path()).unwrap().unwrap();
    let central = Arc::new(Central::new(&e.url, &e.root_pem, Some(&id)).unwrap());
    let (pkg, _) = common::package(e, data).await;
    let r = central
        .checkin(&CacheCheckin {
            version: "t".into(),
            disk_used_bytes: 0,
            stored: vec![],
        })
        .await
        .unwrap();
    let p = r.packages.into_iter().find(|p| p.id == pkg).unwrap();
    let store = Arc::new(Store::open(&dir.path().join("packages"), dir.path()).unwrap());
    (dir, central, store, p)
}

async fn ensure_many(
    f: &Arc<Fetcher>,
    p: &CachePackage,
    n: usize,
) -> Vec<Result<std::path::PathBuf, FetchError>> {
    let tasks: Vec<_> = (0..n)
        .map(|_| {
            let f = f.clone();
            let p = p.clone();
            tokio::spawn(async move { f.ensure(&p, None, None).await })
        })
        .collect();
    let mut out = vec![];
    for t in tasks {
        out.push(t.await.unwrap());
    }
    out
}

#[sqlx::test(migrations = false)]
async fn concurrent_requests_download_once(pool: PgPool) {
    let e = common::central(pool).await;
    let data = b"single flight".repeat(50_000);
    let (_dir, central, store, p) = setup(&e, &data).await;
    let f = Arc::new(Fetcher::new(central.clone(), store.clone()));
    for r in ensure_many(&f, &p, 10).await {
        let path = r.unwrap();
        assert_eq!(std::fs::read(path).unwrap(), data);
    }
    assert_eq!(central.downloads_started(), 1);
}

#[sqlx::test(migrations = false)]
async fn mismatch_is_remembered_and_nothing_is_kept(pool: PgPool) {
    let e = common::central(pool).await;
    let (_dir, central, store, p) = setup(&e, b"good bytes").await;
    common::corrupt(&e, &p.sha256);
    let f = Arc::new(Fetcher::new(central.clone(), store.clone()));
    for r in ensure_many(&f, &p, 10).await {
        assert_eq!(r.unwrap_err(), FetchError::Mismatch);
    }
    assert_eq!(central.downloads_started(), 1, "失敗結果被記住");
    let path = store.path(&p.sha256);
    assert!(!path.exists());
    let mut part = path.into_os_string();
    part.push(".part");
    assert!(!std::path::PathBuf::from(part).exists());
}

#[sqlx::test(migrations = false)]
async fn unreachable_central_fails_fast_on_retry(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _, store, p) = setup(&e, b"bytes").await;
    let id = identity::load_identity(dir.path()).unwrap().unwrap();
    // 已關閉的埠
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("https://127.0.0.1:{}", l.local_addr().unwrap().port());
    drop(l);
    let central = Arc::new(Central::new(&dead, &e.root_pem, Some(&id)).unwrap());
    let f = Arc::new(Fetcher::new(central.clone(), store));
    assert_eq!(
        f.ensure(&p, None, None).await.unwrap_err(),
        FetchError::Unavailable
    );
    assert_eq!(
        f.ensure(&p, None, None).await.unwrap_err(),
        FetchError::Unavailable
    );
    assert_eq!(central.downloads_started(), 1, "30 秒內不再送出請求");
}

/// 請求的一方取消（端點逾時斷線）時，下載仍繼續完成，不會從頭再下載一次
#[sqlx::test(migrations = false)]
async fn cancelled_request_does_not_restart_download(pool: PgPool) {
    let e = common::central(pool).await;
    let data = vec![3u8; 8 * 1024 * 1024];
    let (_dir, central, store, p) = setup(&e, &data).await;
    let f = Arc::new(Fetcher::new(central.clone(), store.clone()));
    let first = tokio::time::timeout(
        std::time::Duration::from_millis(5),
        f.ensure(&p, None, None),
    )
    .await;
    assert!(first.is_err(), "第一個請求在下載完成前就放棄");
    let path = f.ensure(&p, None, None).await.unwrap();
    assert_eq!(std::fs::metadata(path).unwrap().len(), data.len() as u64);
    assert_eq!(central.downloads_started(), 1, "沒有因為取消而重新下載");
}

/// 等待上限：下載還沒完成就先回 Unavailable（端點稍後重試），下載在背景繼續
#[sqlx::test(migrations = false)]
async fn wait_limit_returns_unavailable_while_download_continues(pool: PgPool) {
    let e = common::central(pool).await;
    let data = vec![4u8; 8 * 1024 * 1024];
    let (_dir, central, store, p) = setup(&e, &data).await;
    let f = Arc::new(Fetcher::new(central.clone(), store.clone()));
    assert_eq!(
        f.ensure(&p, None, Some(std::time::Duration::from_millis(1)))
            .await
            .unwrap_err(),
        FetchError::Unavailable
    );
    f.ensure(&p, None, None).await.unwrap();
    assert_eq!(central.downloads_started(), 1);
}
