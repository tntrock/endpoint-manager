mod common;

use std::collections::BTreeMap;

use common::TestServer;
use protocol::{CheckinRequest, CheckinResponse, SCHEMA_VERSION, Section};
use sqlx::PgPool;

fn body(hashes: BTreeMap<Section, String>) -> CheckinRequest {
    CheckinRequest {
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
async fn absurd_boot_time_is_400(pool: PgPool) {
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
    assert_eq!(r.status(), 400);
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
