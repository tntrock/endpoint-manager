mod common;

use endpoint_cache::central::{Central, CentralError};
use endpoint_cache::identity;
use protocol::branch::{CacheAuthorize, CacheCheckin, CacheEnrollPoll, CacheEnrollState};
use sha2::Digest;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn enroll_poll_checkin_authorize_download(pool: PgPool) {
    let e = common::central(pool).await;

    // 註冊後在核准前是 Pending
    let anon = Central::new(&e.url, &e.root_pem, None).unwrap();
    let (_, csr) = identity::new_key_and_csr().unwrap();
    let tok = common::token(&e, endpoint_server::tokens::TokenKind::Cache).await;
    let r = anon
        .enroll(&common::enroll_request(&tok, &csr))
        .await
        .unwrap();
    let p = anon
        .poll(&CacheEnrollPoll {
            cache_id: r.cache_id,
            poll_secret: r.poll_secret,
        })
        .await
        .unwrap();
    assert_eq!(p.state, CacheEnrollState::Pending);
    let checkin = CacheCheckin {
        version: "t".into(),
        disk_used_bytes: 0,
        stored: vec![],
    };
    assert!(matches!(
        anon.checkin(&checkin).await,
        Err(CentralError::Unauthorized)
    ));

    let (dir, _) = common::approved_cache(&e).await;
    let id = identity::load_identity(dir.path()).unwrap().unwrap();
    let c = Central::new(&e.url, &e.root_pem, Some(&id)).unwrap();
    let data = b"package bytes".repeat(1000);
    let (pkg, sha) = common::package(&e, &data).await;
    let resp = c.checkin(&checkin).await.unwrap();
    let listed = resp.packages.iter().find(|p| p.id == pkg).unwrap().clone();
    assert_eq!(
        (listed.sha256.as_str(), listed.size),
        (sha.as_str(), data.len() as u64)
    );

    let dev = common::device(&e).await;
    let fp = common::fingerprint(&dev);
    let ask = |fp: String| CacheAuthorize {
        device_cert_fingerprint: fp,
        package_id: pkg,
    };
    assert!(c.authorize(&ask(fp)).await.unwrap());
    assert!(!c.authorize(&ask("0".repeat(64))).await.unwrap());

    let out = tempfile::tempdir().unwrap();
    let dest = out.path().join(&sha);
    c.download(&listed, &dest, None).await.unwrap();
    let got = std::fs::read(&dest).unwrap();
    assert_eq!(hex::encode(sha2::Sha256::digest(&got)), sha);
    assert_eq!(c.downloads_started(), 1);

    // 中央的檔案損毀：不留下任何檔案
    common::corrupt(&e, &sha);
    let dest2 = out.path().join("again");
    assert!(matches!(
        c.download(&listed, &dest2, None).await,
        Err(CentralError::Mismatch)
    ));
    assert!(!dest2.exists());
    assert!(!dest2.with_extension("part").exists());
    assert_eq!(c.downloads_started(), 2);
}
