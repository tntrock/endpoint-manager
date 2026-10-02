mod common;

use std::time::Duration;

use common::{Opts, get, start_cache};
use sha2::Digest;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn serves_assigned_devices_only(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _) = common::approved_cache(&e).await;
    let data = b"cached installer".repeat(10_000);
    let (pkg, sha) = common::package(&e, &data).await;
    let (not_deployed, _) = common::package_only(&e, b"not deployed").await;
    let (other_group, _) = common::package_only(&e, b"other group").await;
    let g = {
        let mut c = e.pool.acquire().await.unwrap();
        endpoint_server::groups::find_or_create(&mut c, "高雄")
            .await
            .unwrap()
    };
    common::deploy(&e, other_group, vec![g]).await;
    let r = start_cache(&e, dir.path(), Opts::default()).await;
    let dev = common::device(&e).await;

    let resp = get(&e, &r, Some(&dev), pkg).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()["content-length"].to_str().unwrap(),
        data.len().to_string()
    );
    let body = resp.bytes().await.unwrap();
    assert_eq!(hex::encode(sha2::Sha256::digest(&body)), sha);
    assert_eq!(get(&e, &r, Some(&dev), pkg).await.unwrap().status(), 200);
    assert_eq!(r.st.central.downloads_started(), 1, "第二次從本機提供");

    assert_eq!(
        get(&e, &r, Some(&dev), not_deployed)
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        get(&e, &r, Some(&dev), other_group).await.unwrap().status(),
        403
    );

    // 快取自己的憑證不是裝置
    let cache_id = endpoint_cache::identity::load_identity(dir.path())
        .unwrap()
        .unwrap();
    assert_eq!(
        get(&e, &r, Some(&cache_id), pkg).await.unwrap().status(),
        403
    );
    // 不帶用戶端憑證：握手失敗
    assert!(get(&e, &r, None, pkg).await.is_err());
}

#[sqlx::test(migrations = false)]
async fn revoked_device_loses_access_after_ttl(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _) = common::approved_cache(&e).await;
    let (pkg, _) = common::package(&e, b"bytes").await;
    let r = start_cache(
        &e,
        dir.path(),
        Opts {
            auth_ttl: Duration::from_secs(1),
            ..Opts::default()
        },
    )
    .await;
    let dev = common::device(&e).await;
    assert_eq!(get(&e, &r, Some(&dev), pkg).await.unwrap().status(), 200);
    sqlx::query("UPDATE device_certs SET revoked_at = now() WHERE fingerprint = $1")
        .bind(common::fingerprint(&dev))
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        get(&e, &r, Some(&dev), pkg).await.unwrap().status(),
        200,
        "授權結果還在快取期內"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(get(&e, &r, Some(&dev), pkg).await.unwrap().status(), 403);
}

#[sqlx::test(migrations = false)]
async fn central_down_serves_previously_allowed_only(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _) = common::approved_cache(&e).await;
    let (pkg, _) = common::package(&e, b"bytes").await;
    let dev = common::device(&e).await;
    let other = common::device(&e).await;
    {
        // 先在本機存好檔案
        let live = start_cache(&e, dir.path(), Opts::default()).await;
        assert_eq!(get(&e, &live, Some(&dev), pkg).await.unwrap().status(), 200);
    }
    let r = start_cache(
        &e,
        dir.path(),
        Opts {
            central_url: Some(common::dead_url()),
            ..Opts::default()
        },
    )
    .await;
    r.st.auth.put(&common::fingerprint(&dev), pkg, true);
    assert_eq!(get(&e, &r, Some(&dev), pkg).await.unwrap().status(), 200);
    let resp = get(&e, &r, Some(&other), pkg).await.unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "60");
}

#[sqlx::test(migrations = false)]
async fn mismatch_returns_502_and_keeps_nothing(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _) = common::approved_cache(&e).await;
    let (pkg, sha) = common::package(&e, b"good bytes").await;
    common::corrupt(&e, &sha);
    let r = start_cache(&e, dir.path(), Opts::default()).await;
    let dev = common::device(&e).await;
    assert_eq!(get(&e, &r, Some(&dev), pkg).await.unwrap().status(), 502);
    assert!(!dir.path().join("packages").join(&sha).exists());
}

#[sqlx::test(migrations = false)]
async fn stale_catalog_is_refreshed(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _) = common::approved_cache(&e).await;
    let r = start_cache(&e, dir.path(), Opts::default()).await;
    // 快取報到之後才派送
    let (pkg, _) = common::package(&e, b"new deployment").await;
    let dev = common::device(&e).await;
    assert_eq!(get(&e, &r, Some(&dev), pkg).await.unwrap().status(), 200);
}

#[sqlx::test(migrations = false)]
async fn full_returns_503(pool: PgPool) {
    let e = common::central(pool).await;
    let (dir, _) = common::approved_cache(&e).await;
    let (pkg, _) = common::package(&e, b"bytes").await;
    let r = start_cache(
        &e,
        dir.path(),
        Opts {
            max_downloads: 0,
            ..Opts::default()
        },
    )
    .await;
    let dev = common::device(&e).await;
    let resp = get(&e, &r, Some(&dev), pkg).await.unwrap();
    assert_eq!(resp.status(), 503);
    assert_eq!(resp.headers()["retry-after"], "60");
}
