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
async fn reenroll_same_hardware_reuses_device_and_revokes_old_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let first = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let second = s.enroll_ok(&tok, Some("uuid-a"), Some("SN-A")).await;
    assert_eq!(first.device_id, second.device_id);

    let old = s
        .client(Some(&first))
        .post(s.url("/v1/checkin"))
        .json(&checkin_body())
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), 401);
    let new = s
        .client(Some(&second))
        .post(s.url("/v1/checkin"))
        .json(&checkin_body())
        .send()
        .await
        .unwrap();
    assert_eq!(new.status(), 200);
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
