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
    let state = AppState::new(pool.clone(), ca::Ca::load(pki.path()).unwrap());
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
        },
    )
    .await
    .unwrap();
    let t = Target {
        server: format!("https://127.0.0.1:{port}"),
        root_pem: std::fs::read_to_string(pki.path().join("root.pem")).unwrap(),
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
}
