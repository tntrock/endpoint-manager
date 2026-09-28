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
    pub web_addr: SocketAddr,
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

        let msi_path = dir.path().join("template.msi");
        std::fs::write(&msi_path, endpoint_server::installer::sample_template()).unwrap();
        let state = AppState::new(pool.clone(), ca::Ca::load(dir.path()).unwrap()).with_installer(
            Some(msi_path),
            "https://localhost:8443".into(),
            vec!["localhost".into()],
        );
        let cfg = tls::server_config(dir.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(tls::serve_mtls(
            listener,
            cfg,
            agent_router(state.clone()),
            limits,
        ));
        let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_listener.local_addr().unwrap();
        tokio::spawn(tls::serve_mtls(
            web_listener,
            tls::web_server_config(dir.path()).unwrap(),
            endpoint_server::web::web_router(state.clone()),
            limits,
        ));

        let root_pem = std::fs::read_to_string(dir.path().join("root.pem")).unwrap();
        TestServer {
            addr,
            web_addr,
            pool,
            state,
            root_pem,
            _dir: dir,
        }
    }

    pub fn web_url(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.web_addr.port(), path)
    }

    pub fn web_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(self.root_pem.as_bytes()).unwrap()])
            .resolve("localhost", self.web_addr)
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    pub async fn page(&self, c: &reqwest::Client, path: &str) -> (u16, String) {
        let r = c.get(self.web_url(path)).send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    pub async fn group_id(&self, name: &str) -> i64 {
        let mut c = self.pool.acquire().await.unwrap();
        endpoint_server::groups::find_or_create(&mut c, name)
            .await
            .unwrap()
    }

    /// 建立帳號（密碼 = 帳號 + "-long-password"）並登入。
    pub async fn login_as(
        &self,
        username: &str,
        role: endpoint_server::web::auth::Role,
        groups: &[&str],
    ) -> reqwest::Client {
        let mut ids = vec![];
        for g in groups {
            ids.push(self.group_id(g).await);
        }
        let password = format!("{username}-long-password");
        let _ = endpoint_server::accounts::create(
            &self.pool,
            &endpoint_server::accounts::NewAdmin {
                username: username.into(),
                password: password.clone(),
                role,
                groups: ids,
            },
            "test",
        )
        .await;
        let c = self.web_client();
        let r = c
            .post(self.web_url("/login"))
            .form(&[("username", username), ("password", password.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303, "login should redirect");
        c
    }

    pub async fn admin_client(&self) -> reqwest::Client {
        self.login_as("admin", endpoint_server::web::auth::Role::Platform, &[])
            .await
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
                group_id: None,
                expires_at: None,
                max_uses,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap()
        .1
    }

    pub async fn create_group_token(&self, group: &str, max_uses: i32) -> String {
        // 先歸還連線再建立金鑰，避免同時佔用兩條連線導致連線池逾時
        let gid = self.group_id(group).await;
        tokens::create_token(
            &self.pool,
            &tokens::NewToken {
                name: format!("{group} token"),
                group_id: Some(gid),
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

/// 從頁面 HTML 取出第一個 csrf 隱藏欄位的值。
pub fn csrf_from(html: &str) -> String {
    let marker = r#"name="csrf" value=""#;
    let start = html.find(marker).expect("csrf field") + marker.len();
    html[start..].split('"').next().unwrap().to_string()
}
