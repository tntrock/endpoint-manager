#![allow(dead_code)]

use std::net::SocketAddr;

use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use protocol::{EnrollRequest, EnrollResponse, SCHEMA_VERSION};
use rcgen::{CertificateParams, KeyPair};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

pub struct TestServer {
    pub addr: SocketAddr,
    pub pool: PgPool,
    pub state: AppState,
    pub root_pem: String,
    _dir: tempfile::TempDir,
}

pub struct TestAgent {
    pub device_id: Uuid,
    pub key_pem: String,
    pub chain_pem: String,
}

pub fn make_csr() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    (csr, key.serialize_pem())
}

impl TestServer {
    pub async fn start(pool: PgPool) -> TestServer {
        Self::start_with(pool, tls::ConnLimits::default()).await
    }

    pub async fn start_with(pool: PgPool, limits: tls::ConnLimits) -> TestServer {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        ca::init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        db::migrate(&pool).await.unwrap();
        partitions::maintain_partitions(&pool, chrono::Utc::now())
            .await
            .unwrap();

        let state = AppState::new(pool.clone(), ca::Ca::load(dir.path()).unwrap());
        let cfg = tls::server_config(dir.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(tls::serve_mtls(
            listener,
            cfg,
            agent_router(state.clone()),
            limits,
        ));

        let root_pem = std::fs::read_to_string(dir.path().join("root.pem")).unwrap();
        TestServer {
            addr,
            pool,
            state,
            root_pem,
            _dir: dir,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.addr.port(), path)
    }

    pub fn client(&self, agent: Option<&TestAgent>) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(self.root_pem.as_bytes()).unwrap()])
            .resolve("localhost", self.addr);
        if let Some(a) = agent {
            let pem = format!("{}{}", a.chain_pem, a.key_pem);
            b = b.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        b.build().unwrap()
    }

    pub async fn create_token(&self, max_uses: i32) -> String {
        tokens::create_token(
            &self.pool,
            &tokens::NewToken {
                name: "test".into(),
                group_label: None,
                expires_at: None,
                max_uses,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap()
        .1
    }

    pub async fn enroll_with_csr(
        &self,
        token: &str,
        csr: &str,
        smbios: Option<&str>,
        serial: Option<&str>,
    ) -> reqwest::Response {
        self.client(None)
            .post(self.url("/v1/enroll"))
            .json(&EnrollRequest {
                schema_version: SCHEMA_VERSION,
                enroll_token: token.into(),
                csr_pem: csr.into(),
                hostname: "PC-001".into(),
                smbios_uuid: smbios.map(Into::into),
                bios_serial: serial.map(Into::into),
                mac_addresses: vec!["00:11:22:33:44:55".into()],
            })
            .send()
            .await
            .unwrap()
    }

    pub async fn enroll(
        &self,
        token: &str,
        smbios: Option<&str>,
        serial: Option<&str>,
    ) -> reqwest::Response {
        let (csr, _) = make_csr();
        self.enroll_with_csr(token, &csr, smbios, serial).await
    }

    pub async fn enroll_ok(
        &self,
        token: &str,
        smbios: Option<&str>,
        serial: Option<&str>,
    ) -> TestAgent {
        let (csr, key_pem) = make_csr();
        let resp = self.enroll_with_csr(token, &csr, smbios, serial).await;
        assert_eq!(
            resp.status(),
            200,
            "{}",
            resp.text().await.unwrap_or_default()
        );
        let body: EnrollResponse = resp.json().await.unwrap();
        TestAgent {
            device_id: body.device_id,
            key_pem,
            chain_pem: body.certificate_chain_pem,
        }
    }
}
