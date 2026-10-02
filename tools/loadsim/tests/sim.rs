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
