mod common;

use common::{TestAgent, TestServer, make_csr};
use protocol::{CheckinRequest, RenewRequest, RenewResponse, SCHEMA_VERSION};
use sqlx::PgPool;

fn checkin() -> CheckinRequest {
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
async fn renew_not_due_is_400(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (csr, _) = make_csr();
    let r = s
        .client(Some(&a))
        .post(s.url("/v1/renew"))
        .json(&RenewRequest { csr_pem: csr })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[sqlx::test(migrations = false)]
async fn renew_when_due_returns_working_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query(
        "UPDATE device_certs SET not_after = now() + interval '5 days' WHERE device_id = $1",
    )
    .bind(a.device_id)
    .execute(&s.pool)
    .await
    .unwrap();

    let (csr, key_pem) = make_csr();
    let r: RenewResponse = s
        .client(Some(&a))
        .post(s.url("/v1/renew"))
        .json(&RenewRequest { csr_pem: csr })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let renewed = TestAgent {
        device_id: a.device_id,
        key_pem,
        chain_pem: r.certificate_chain_pem,
    };

    let status = s
        .client(Some(&renewed))
        .post(s.url("/v1/checkin"))
        .json(&checkin())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(status, 200);
    let old_status = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&checkin())
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(old_status, 200, "舊憑證在原到期日前仍有效");
}
