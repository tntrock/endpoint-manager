mod common;

use std::collections::BTreeMap;

use common::TestServer;
use protocol::{CheckinRequest, CheckinResponse, OsFamily, SCHEMA_VERSION, Section};
use sqlx::PgPool;

fn body(hashes: BTreeMap<Section, String>) -> CheckinRequest {
    CheckinRequest {
        os_family: None,
        schema_version: SCHEMA_VERSION,
        agent_version: "0.1.0".into(),
        boot_time: chrono::Utc::now(),
        logged_on_user: Some("CORP\\alice".into()),
        ip_addresses: vec!["10.0.0.5".into()],
        section_hashes: hashes,
        section_errors: BTreeMap::from([(Section::Patches, "WMI timeout".to_string())]),
    }
}

#[sqlx::test(migrations = false)]
async fn healthz_ok_without_client_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let r = s.client(None).get(s.url("/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
}

#[sqlx::test(migrations = false)]
async fn checkin_without_client_cert_is_401(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let r = s
        .client(None)
        .post(s.url("/v1/checkin"))
        .json(&body(BTreeMap::new()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn checkin_requests_unknown_sections(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let hashes = BTreeMap::from([
        (Section::Software, "h1".into()),
        (Section::Basic, "h2".into()),
    ]);
    let r: CheckinResponse = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&body(hashes))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(r.request_sections, vec![Section::Basic, Section::Software]);
    assert_eq!(r.next_checkin_seconds, 60);
    assert!(!r.renew_certificate);
}

#[sqlx::test(migrations = false)]
async fn heartbeat_flush_updates_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    s.client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&body(BTreeMap::new()))
        .send()
        .await
        .unwrap();

    assert_eq!(s.state.heartbeat.flush(&s.pool).await.unwrap(), 1);
    let (ip, user, errors): (Option<String>, Option<String>, String) = sqlx::query_as(
        "SELECT last_ip, logged_on_user, section_errors::text FROM devices WHERE id = $1",
    )
    .bind(a.device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(user.as_deref(), Some("CORP\\alice"));
    assert!(errors.contains("WMI timeout"));
    assert_eq!(s.state.heartbeat.flush(&s.pool).await.unwrap(), 0);
}

#[sqlx::test(migrations = false)]
async fn renew_flag_when_cert_expiring(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query(
        "UPDATE device_certs SET not_after = now() + interval '10 days' WHERE device_id = $1",
    )
    .bind(a.device_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let r: CheckinResponse = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&body(BTreeMap::new()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(r.renew_certificate);
}

#[sqlx::test(migrations = false)]
async fn revoked_cert_is_401(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE device_certs SET revoked_at = now() WHERE device_id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let r = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&body(BTreeMap::new()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn nul_in_checkin_is_400(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let mut b = body(BTreeMap::new());
    b.section_errors = BTreeMap::from([(Section::Patches, "bad\0error".to_string())]);
    let r = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[sqlx::test(migrations = false)]
async fn future_boot_time_is_clamped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let mut b = body(BTreeMap::new());
    b.boot_time = "+200000-01-01T00:00:00Z".parse().unwrap();
    let r = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    s.state.heartbeat.flush(&s.pool).await.unwrap();
    let boot: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT boot_time FROM devices WHERE id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(boot <= chrono::Utc::now());
}

#[sqlx::test(migrations = false)]
async fn poisoned_row_does_not_block_other_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let bad = s.enroll_ok(&tok, None, None).await;
    let good = s.enroll_ok(&tok, None, None).await;
    let hot = |user: &str| endpoint_server::heartbeat::HotFields {
        seen_at: chrono::Utc::now(),
        ip: None,
        logged_on_user: Some(user.into()),
        boot_time: chrono::Utc::now(),
        agent_version: "0.1.0".into(),
        section_errors: serde_json::json!({}),
    };
    // 繞過 API 驗證，直接塞入資料庫無法接受的值
    s.state.heartbeat.record(bad.device_id, hot("x\0y"));
    s.state.heartbeat.record(good.device_id, hot("alice"));
    let _ = s.state.heartbeat.flush(&s.pool).await;
    let _ = s.state.heartbeat.flush(&s.pool).await;

    let seen: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT last_seen_at FROM devices WHERE id = $1")
            .bind(good.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(
        seen.is_some(),
        "good device must be updated despite a bad row"
    );
    assert_eq!(
        s.state.heartbeat.flush(&s.pool).await.unwrap(),
        0,
        "bad row dropped, not requeued forever"
    );
}

#[sqlx::test(migrations = false)]
async fn checkin_announces_config_support(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let r: CheckinResponse = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&body(BTreeMap::new()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        r.registry_queries_hash.as_deref(),
        Some(protocol::regpath::queries_hash(&[]).as_str())
    );
    assert!(r.registry_queries.is_empty());
    assert_eq!(r.collection_intervals.security_secs, 3600);
}

async fn os_of(s: &TestServer, a: &common::TestAgent) -> String {
    sqlx::query_scalar("SELECT os_family FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn checkin_as(
    s: &TestServer,
    a: &common::TestAgent,
    os_family: Option<OsFamily>,
) -> CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family,
            ..body(BTreeMap::new())
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn checkin_updates_os_family_when_changed(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    assert_eq!(os_of(&s, &a).await, "windows");
    checkin_as(&s, &a, Some(OsFamily::Linux)).await;
    assert_eq!(os_of(&s, &a).await, "linux");
    checkin_as(&s, &a, None).await;
    assert_eq!(os_of(&s, &a).await, "linux", "None 不覆寫");
}

#[sqlx::test(migrations = false)]
async fn linux_checkin_gets_empty_assignments(pool: PgPool) {
    use endpoint_server::compliance::admin as rules;
    use endpoint_server::deploy::{admin as dep, store};
    use endpoint_server::updates::{admin as upd, policy::PolicySettings};
    let s = TestServer::start(pool).await;
    // 全公司的登錄檔規則、更新原則、派送；兩台裝置同群組
    let tok = s.create_group_token("台北", 2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    let g = s.group_id("台北").await;
    rules::create_rule(
        &s.pool,
        &rules::RuleInput {
            name: "r".into(),
            description: String::new(),
            kind: "registry_value".into(),
            severity: "high".into(),
            enabled: true,
            params: serde_json::json!({"path": r"HKLM\SOFTWARE\X", "name": "Y", "op": "equals", "expected": "1"}),
            include: vec![],
            exclude: vec![],
            template_key: None,
        },
        "admin",
    )
    .await
    .unwrap();
    upd::create_policy(
        &s.pool,
        &upd::PolicyInput {
            name: "p".into(),
            settings: PolicySettings {
                quality_defer_days: Some(7),
                ..Default::default()
            },
            groups: vec![g],
        },
        "admin",
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let data = futures_util::stream::iter([Ok::<_, std::io::Error>(
        axum::body::Bytes::from_static(b"payload"),
    )]);
    let st = store::save(dir.path(), data).await.unwrap();
    let pkg = dep::create_package(
        &s.pool,
        dir.path(),
        &st,
        "7z.exe",
        None,
        &dep::PackageInput {
            name: "7-Zip".into(),
            version: "23.01".into(),
            kind: "exe".into(),
            install_args: "/S".into(),
            uninstall_args: String::new(),
            success_codes: vec![],
            detect_name: "7-Zip*".into(),
            detect_publisher: String::new(),
            detect_min_version: "23.01".into(),
        },
        "admin",
    )
    .await
    .unwrap();
    dep::create_deployment(
        &s.pool,
        &dep::DeploymentInput {
            name: "d".into(),
            package_id: pkg,
            action: "install".into(),
            include: vec![],
            exclude: vec![],
            pilot_group_id: None,
            max_failure_pct: 10,
            min_samples: 20,
        },
        "admin",
    )
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET os_family = 'linux' WHERE id = $1")
        .bind(lin.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    s.state.deploy.invalidate();
    s.state.updates.invalidate();

    let r = checkin_as(&s, &lin, None).await;
    assert!(r.deployments.is_empty() && r.update_policy.is_none());
    assert!(r.registry_queries.is_empty() && r.package_source.is_none());
    assert_eq!(
        r.deployments_hash.as_deref(),
        Some(protocol::deploy::assignments_hash(&[]).as_str())
    );
    assert_eq!(
        r.update_policy_hash.as_deref(),
        Some(protocol::update::update_policy_hash(None).as_str())
    );
    assert_eq!(
        r.registry_queries_hash.as_deref(),
        Some(protocol::regpath::queries_hash(&[]).as_str())
    );
    let r = checkin_as(&s, &win, None).await;
    assert_eq!(r.deployments.len(), 1);
    assert!(r.update_policy.is_some());
    assert_eq!(r.registry_queries.len(), 1);
}

#[sqlx::test(migrations = false)]
async fn linux_checkin_still_gets_commands(pool: PgPool) {
    use endpoint_server::commands::Actor;
    use endpoint_server::commands::runs::{RunInput, Target, create_run};
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE devices SET os_family = 'linux' WHERE id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let actor = Actor {
        username: "admin".into(),
        platform: true,
        groups: vec![],
    };
    create_run(
        &s.pool,
        &RunInput {
            action: "collect".into(),
            target: Target::Device(a.device_id),
            delay_minutes: None,
            script_id: None,
            expires_hours: 24,
        },
        &actor,
    )
    .await
    .unwrap();
    assert_eq!(checkin_as(&s, &a, None).await.commands.len(), 1);
}
