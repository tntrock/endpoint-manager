mod common;

use common::TestServer;
use protocol::{CheckinRequest, SCHEMA_VERSION};
use sqlx::PgPool;

fn checkin_body() -> CheckinRequest {
    CheckinRequest {
        schema_version: SCHEMA_VERSION,
        agent_version: "0.1.0".into(),
        boot_time: chrono::Utc::now(),
        logged_on_user: None,
        ip_addresses: vec![],
        section_hashes: Default::default(),
        section_errors: Default::default(),
    }
}

#[sqlx::test(migrations = false)]
async fn enroll_with_valid_token_creates_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let (host, status): (String, String) =
        sqlx::query_as("SELECT hostname, status FROM devices WHERE id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((host.as_str(), status.as_str()), ("PC-001", "active"));
    assert_eq!(a.chain_pem.matches("BEGIN CERTIFICATE").count(), 3);
}

#[sqlx::test(migrations = false)]
async fn enroll_with_bad_token_is_401(pool: PgPool) {
    let s = TestServer::start(pool).await;
    assert_eq!(s.enroll("wrong", None, None).await.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn concurrent_enroll_does_not_exceed_max_uses(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let futs = (0..10).map(|i| {
        let serial = format!("SN-{i}");
        let uuid = format!("UUID-{i}");
        let (s, tok) = (&s, &tok);
        async move {
            s.enroll(tok, Some(&uuid), Some(&serial))
                .await
                .status()
                .as_u16()
        }
    });
    let statuses = futures_util::future::join_all(futs).await;
    assert_eq!(statuses.iter().filter(|&&c| c == 200).count(), 3);
    assert_eq!(statuses.iter().filter(|&&c| c == 401).count(), 7);
}

#[sqlx::test(migrations = false)]
async fn same_smbios_different_serial_marked_duplicate_suspect(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, Some("UUID-VM"), Some("SN-1")).await;
    let b = s.enroll_ok(&tok, Some("UUID-VM"), Some("SN-2")).await;
    assert_ne!(a.device_id, b.device_id);
    let status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(b.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(status, "duplicate_suspect");
}

#[sqlx::test(migrations = false)]
async fn invalid_csr_is_400_and_token_not_consumed(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let r = s.enroll_with_csr(&tok, "garbage", None, None).await;
    assert_eq!(r.status(), 400);
    s.enroll_ok(&tok, None, None).await; // 金鑰仍可使用一次
}

#[sqlx::test(migrations = false)]
async fn future_schema_version_rejected(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let (csr, _) = common::make_csr();
    let r = s
        .client(None)
        .post(s.url("/v1/enroll"))
        .json(&serde_json::json!({
            "schema_version": 99, "enroll_token": tok, "csr_pem": csr, "hostname": "X",
            "smbios_uuid": null, "bios_serial": null, "mac_addresses": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[sqlx::test(migrations = false)]
async fn nul_in_hostname_is_400(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let (csr, _) = common::make_csr();
    let r = s
        .client(None)
        .post(s.url("/v1/enroll"))
        .json(&serde_json::json!({
            "schema_version": 1, "enroll_token": tok, "csr_pem": csr, "hostname": "PC\u{0}1",
            "smbios_uuid": null, "bios_serial": null, "mac_addresses": []
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[sqlx::test(migrations = false)]
async fn device_joins_token_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let name: String = sqlx::query_scalar(
        "SELECT g.name FROM devices d JOIN device_groups g ON g.id = d.group_id WHERE d.id = $1",
    )
    .bind(a.device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(name, "台北總部");
}

async fn status_of(s: &TestServer, id: uuid::Uuid) -> (String, Option<uuid::Uuid>) {
    sqlx::query_as("SELECT status, reenroll_of FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn checkin_status(s: &TestServer, a: &common::TestAgent) -> u16 {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&checkin_body())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[sqlx::test(migrations = false)]
async fn same_hardware_reenroll_waits_for_approval(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("uuid-a"), Some("SN-A")).await;
    assert_ne!(old.device_id, new.device_id);
    assert_eq!(
        status_of(&s, new.device_id).await,
        ("pending_approval".into(), Some(old.device_id))
    );
    assert_eq!(checkin_status(&s, &old).await, 200, "舊裝置不受影響");
    assert_eq!(checkin_status(&s, &new).await, 200, "待核准裝置可報到");
}

#[sqlx::test(migrations = false)]
async fn approve_moves_new_cert_to_old_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let merged = endpoint_server::devices::approve(&s.pool, new.device_id, "tester")
        .await
        .unwrap();
    assert_eq!(merged, old.device_id);
    assert_eq!(checkin_status(&s, &old).await, 401, "舊憑證失效");
    assert_eq!(checkin_status(&s, &new).await, 200, "新憑證可用");
    let owner: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM device_certs WHERE revoked_at IS NULL")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(owner, old.device_id, "資料歸到舊裝置");
    let (n, grouped): (i64, i64) = sqlx::query_as("SELECT count(*), count(group_id) FROM devices")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!((n, grouped), (1, 1), "待核准記錄已刪除，舊裝置保留群組");
    assert_eq!(status_of(&s, old.device_id).await.0, "active");
}

#[sqlx::test(migrations = false)]
async fn reject_revokes_pending_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    endpoint_server::devices::reject(&s.pool, new.device_id, "tester")
        .await
        .unwrap();
    assert_eq!(checkin_status(&s, &new).await, 401);
    assert_eq!(checkin_status(&s, &old).await, 200);
    assert_eq!(status_of(&s, new.device_id).await.0, "retired");
}

#[sqlx::test(migrations = false)]
async fn retire_revokes_all_certs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    endpoint_server::devices::retire(&s.pool, a.device_id, "tester")
        .await
        .unwrap();
    assert_eq!(checkin_status(&s, &a).await, 401);
    let action: String =
        sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(action, "device_retire");
}

#[sqlx::test(migrations = false)]
async fn approve_rejects_non_pending_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    assert!(
        endpoint_server::devices::approve(&s.pool, a.device_id, "tester")
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = false)]
async fn move_device_changes_group_and_audits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let kh = s.group_id("高雄廠").await;
    endpoint_server::groups::move_device(&s.pool, a.device_id, Some(kh), "tester")
        .await
        .unwrap();
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, Some(kh));
}
