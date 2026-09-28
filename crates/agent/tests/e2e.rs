//! 假 Collector ↔ 真伺服器。需要 DATABASE_URL（PostgreSQL）。

use endpoint_agent::client::{ClientError, ServerClient};
use endpoint_agent::config::AgentConfig;
use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use protocol::{CheckinRequest, EnrollRequest, SCHEMA_VERSION};
use sqlx::PgPool;
use tempfile::TempDir;
use tokio::net::TcpListener;

struct Env {
    pool: PgPool,
    state: AppState,
    dir: TempDir,
    _pki: TempDir,
    port: u16,
}

impl Env {
    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn root_pem(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("root.pem")).unwrap()
    }
}

async fn env(pool: PgPool, token_uses: i32) -> Env {
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
        agent_router(state.clone()),
        tls::ConnLimits::default(),
    ));

    let (_, token) = tokens::create_token(
        &pool,
        &tokens::NewToken {
            name: "e2e".into(),
            group_label: None,
            expires_at: None,
            max_uses: token_uses,
            created_by: "test".into(),
        },
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(pki.path().join("root.pem"), dir.path().join("root.pem")).unwrap();
    AgentConfig {
        server_url: format!("https://127.0.0.1:{port}"),
        enroll_token: Some(token),
    }
    .save(dir.path())
    .unwrap();
    Env {
        pool,
        state,
        dir,
        _pki: pki,
        port,
    }
}

fn csr() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn client_maps_status_codes(pool: PgPool) {
    let e = env(pool, 1).await;
    let c = ServerClient::new(&e.url(), &e.root_pem(), None).unwrap();

    let checkin = CheckinRequest {
        schema_version: SCHEMA_VERSION,
        agent_version: "t".into(),
        boot_time: chrono::Utc::now(),
        logged_on_user: None,
        ip_addresses: vec![],
        section_hashes: Default::default(),
        section_errors: Default::default(),
    };
    assert!(matches!(
        c.checkin(&checkin).await,
        Err(ClientError::Unauthorized)
    ));

    let enroll = |token: &str, csr: String| EnrollRequest {
        schema_version: SCHEMA_VERSION,
        enroll_token: token.into(),
        csr_pem: csr,
        hostname: "PC".into(),
        smbios_uuid: None,
        bios_serial: None,
        mac_addresses: vec![],
    };
    assert!(matches!(
        c.enroll(&enroll("bad", csr())).await,
        Err(ClientError::Unauthorized)
    ));
    let token = AgentConfig::load(e.dir.path())
        .unwrap()
        .enroll_token
        .unwrap();
    assert!(matches!(
        c.enroll(&enroll(&token, "garbage".into())).await,
        Err(ClientError::Rejected(400, _))
    ));
    assert!(c.enroll(&enroll(&token, csr())).await.is_ok());
}

#[tokio::test]
async fn unreachable_server_is_retry() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["127.0.0.1".into()]).unwrap();
    let root = std::fs::read_to_string(pki.path().join("root.pem")).unwrap();
    let c = ServerClient::new("https://127.0.0.1:1", &root, None).unwrap();
    let r = c.renew(&protocol::RenewRequest { csr_pem: csr() }).await;
    assert!(matches!(r, Err(ClientError::Retry(None))), "{r:?}");
}
