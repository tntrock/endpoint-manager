//! 在同一個行程啟動真實中央。需要 DATABASE_URL（PostgreSQL）。
#![allow(dead_code)]

use endpoint_cache::central::Central;
use endpoint_cache::config::Config;
use endpoint_cache::identity::{self, Enrollment, Identity};
use endpoint_server::branch::{caches, sites};
use endpoint_server::deploy::admin::{self, DeploymentInput, PackageInput};
use endpoint_server::deploy::store;
use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use protocol::branch::{CacheEnrollPoll, CacheEnrollRequest, CacheEnrollState};
use protocol::{EnrollRequest, EnrollResponse, SCHEMA_VERSION};
use sqlx::PgPool;
use tempfile::TempDir;
use tokio::net::TcpListener;

pub struct Env {
    pub pool: PgPool,
    pub state: AppState,
    pub url: String,
    pub root_pem: String,
    _pki: TempDir,
}

/// 中央憑證含 127.0.0.1；不呼叫 with_installer，所以 server_names 是空的，
/// 快取用 127.0.0.1 當名稱不會被拒絕
pub async fn central(pool: PgPool) -> Env {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    db::migrate(&pool).await.unwrap();
    partitions::maintain_partitions(&pool, chrono::Utc::now())
        .await
        .unwrap();
    let state = AppState::new(pool.clone(), ca::Ca::load(pki.path()).unwrap())
        .with_packages(pki.path().join("packages"), 8);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(tls::serve_mtls(
        listener,
        tls::server_config(pki.path()).unwrap(),
        agent_router(state.clone()),
        tls::ConnLimits::default(),
    ));
    let root_pem = std::fs::read_to_string(pki.path().join("root.pem")).unwrap();
    Env {
        pool,
        state,
        url: format!("https://127.0.0.1:{port}"),
        root_pem,
        _pki: pki,
    }
}

pub async fn token(e: &Env, kind: tokens::TokenKind) -> String {
    tokens::create_token(
        &e.pool,
        &tokens::NewToken {
            name: "test".into(),
            group_id: None,
            expires_at: None,
            max_uses: 100,
            created_by: "test".into(),
            kind,
        },
    )
    .await
    .unwrap()
    .1
}

pub async fn site(e: &Env, cidr: &str) -> i64 {
    sites::create_site(
        &e.pool,
        &sites::SiteInput {
            name: format!("據點 {cidr}"),
            cidrs: vec![cidr.into()],
            fallback_to_central: true,
            bandwidth_limit_mbps: None,
            disk_limit_gb: 100,
        },
        "admin",
    )
    .await
    .unwrap()
}

pub fn enroll_request(token: &str, csr_pem: &str) -> CacheEnrollRequest {
    CacheEnrollRequest {
        token: token.into(),
        name: format!("快取 {}", uuid::Uuid::new_v4()),
        url: "https://127.0.0.1:8443".into(),
        dns_names: vec!["127.0.0.1".into()],
        csr_pem: csr_pem.into(),
    }
}

/// 註冊並核准一台快取：資料目錄有 config.json、root.pem、enroll.json、key.pem、cert.pem
pub async fn approved_cache(e: &Env) -> (TempDir, Enrollment) {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    Config {
        server_url: e.url.clone(),
        listen: "127.0.0.1:0".into(),
        storage_dir: None,
        max_downloads: 200,
    }
    .save(d)
    .unwrap();
    std::fs::write(d.join("root.pem"), &e.root_pem).unwrap();
    let central = Central::new(&e.url, &e.root_pem, None).unwrap();
    let (key_pem, csr) = identity::new_key_and_csr().unwrap();
    let tok = token(e, tokens::TokenKind::Cache).await;
    let r = central.enroll(&enroll_request(&tok, &csr)).await.unwrap();
    let enrollment = Enrollment {
        cache_id: r.cache_id,
        poll_secret: r.poll_secret,
    };
    identity::save_enrollment(d, &enrollment).unwrap();
    let site = site(e, "127.0.0.0/8").await;
    caches::approve(&e.pool, &e.state.ca, r.cache_id, site, "admin")
        .await
        .unwrap();
    let p = central
        .poll(&CacheEnrollPoll {
            cache_id: enrollment.cache_id,
            poll_secret: enrollment.poll_secret.clone(),
        })
        .await
        .unwrap();
    assert_eq!(p.state, CacheEnrollState::Approved);
    identity::save_identity(
        d,
        &Identity {
            key_pem,
            chain_pem: p.certificate_chain_pem.unwrap(),
        },
    )
    .unwrap();
    (dir, enrollment)
}

/// 註冊一台裝置（沒有群組，會被「全公司」派送指派）
pub async fn device(e: &Env) -> Identity {
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let http = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(e.root_pem.as_bytes()).unwrap()])
        .build()
        .unwrap();
    let r: EnrollResponse = http
        .post(format!("{}/v1/enroll", e.url))
        .json(&EnrollRequest {
            schema_version: SCHEMA_VERSION,
            enroll_token: token(e, tokens::TokenKind::Device).await,
            csr_pem: csr,
            hostname: "PC".into(),
            smbios_uuid: None,
            bios_serial: None,
            mac_addresses: vec![],
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    Identity {
        key_pem: key.serialize_pem(),
        chain_pem: r.certificate_chain_pem,
    }
}

pub fn fingerprint(id: &Identity) -> String {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(id.chain_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    ca::fingerprint(&der)
}

/// 存一個套件（不派送）
pub async fn package_only(e: &Env, data: &[u8]) -> (i64, String) {
    let v: Vec<Result<axum::body::Bytes, std::io::Error>> =
        vec![Ok(axum::body::Bytes::copy_from_slice(data))];
    let st = store::save(&e.state.package_dir, futures_util::stream::iter(v))
        .await
        .unwrap();
    let id = admin::create_package(
        &e.pool,
        &e.state.package_dir,
        &st,
        "app.exe",
        None,
        &PackageInput {
            name: format!("App {}", uuid::Uuid::new_v4()),
            version: "1.0".into(),
            kind: "exe".into(),
            install_args: "/S".into(),
            uninstall_args: String::new(),
            success_codes: vec![],
            detect_name: "App*".into(),
            detect_publisher: String::new(),
            detect_min_version: "1.0".into(),
        },
        "admin",
    )
    .await
    .unwrap();
    (id, st.sha256)
}

/// 派送給群組（include）；None 表示全公司
pub async fn deploy(e: &Env, package_id: i64, include: Vec<i64>) -> i64 {
    let d = admin::create_deployment(
        &e.pool,
        &DeploymentInput {
            name: format!("派送 {}", uuid::Uuid::new_v4()),
            package_id,
            action: "install".into(),
            include,
            exclude: vec![],
            pilot_group_id: None,
            max_failure_pct: 10,
            min_samples: 20,
        },
        "admin",
    )
    .await
    .unwrap();
    e.state.deploy.invalidate();
    d
}

/// 存一個套件並派送到全公司
pub async fn package(e: &Env, data: &[u8]) -> (i64, String) {
    let (id, sha) = package_only(e, data).await;
    deploy(e, id, vec![]).await;
    (id, sha)
}

/// 把中央的套件檔換成等長的不同內容（模擬中央檔案損毀）
pub fn corrupt(e: &Env, sha: &str) {
    let p = store::file_path(&e.state.package_dir, sha);
    let mut b = std::fs::read(&p).unwrap();
    for x in &mut b {
        *x ^= 0xff;
    }
    std::fs::write(&p, b).unwrap();
}

pub struct Opts {
    /// 快取向中央連線用的網址（None = 真實中央；可指向已關閉的埠模擬中央斷線）
    pub central_url: Option<String>,
    pub auth_ttl: std::time::Duration,
    pub max_downloads: usize,
    /// 清單過時時是否立即報到
    pub refresh: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            central_url: None,
            auth_ttl: endpoint_cache::auth::AUTH_TTL,
            max_downloads: 200,
            refresh: true,
        }
    }
}

pub struct Running {
    pub addr: std::net::SocketAddr,
    pub st: endpoint_cache::server::CacheState,
    pub slot: std::sync::Arc<endpoint_cache::server::CertSlot>,
}

/// 啟動快取：先用真實中央報到一次填好清單，再以 opts 建立狀態並監聽
pub async fn start_cache(e: &Env, dir: &std::path::Path, opts: Opts) -> Running {
    use endpoint_cache::{auth, fetch, server, store};
    use std::sync::Arc;
    let id = identity::load_identity(dir).unwrap().unwrap();
    let live = Central::new(&e.url, &e.root_pem, Some(&id)).unwrap();
    let catalog = Arc::new(fetch::Catalog::default());
    catalog.replace(
        &live
            .checkin(&protocol::branch::CacheCheckin {
                version: "t".into(),
                disk_used_bytes: 0,
                stored: vec![],
            })
            .await
            .unwrap(),
    );
    let url = opts.central_url.clone().unwrap_or_else(|| e.url.clone());
    let central = Arc::new(Central::new(&url, &e.root_pem, Some(&id)).unwrap());
    let store = Arc::new(store::Store::open(&dir.join("packages"), dir).unwrap());
    let refresh: server::Refresh = if opts.refresh {
        let (c, cat) = (central.clone(), catalog.clone());
        Arc::new(move || {
            let (c, cat) = (c.clone(), cat.clone());
            Box::pin(async move {
                if let Ok(r) = c
                    .checkin(&protocol::branch::CacheCheckin {
                        version: "t".into(),
                        disk_used_bytes: 0,
                        stored: vec![],
                    })
                    .await
                {
                    cat.replace(&r);
                }
            })
        })
    } else {
        Arc::new(|| Box::pin(async {}))
    };
    let st = server::CacheState {
        fetcher: Arc::new(fetch::Fetcher::new(central.clone(), store.clone())),
        central,
        store,
        catalog,
        auth: Arc::new(auth::AuthCache::new(opts.auth_ttl)),
        downloads: Arc::new(tokio::sync::Semaphore::new(opts.max_downloads)),
        refresh,
    };
    let slot = server::CertSlot::new(&id).unwrap();
    let cfg = server::tls_config(&e.root_pem, slot.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server::serve(
        listener,
        cfg,
        server::router(st.clone()),
        100,
    ));
    Running { addr, st, slot }
}

/// 以某個身分（裝置或快取憑證）連快取的 client；None 表示不帶用戶端憑證
pub fn client(e: &Env, id: Option<&Identity>) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(e.root_pem.as_bytes()).unwrap()]);
    if let Some(id) = id {
        let pem = format!("{}{}", id.chain_pem, id.key_pem);
        b = b.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
    }
    b.build().unwrap()
}

pub async fn get(
    e: &Env,
    r: &Running,
    id: Option<&Identity>,
    package_id: i64,
) -> reqwest::Result<reqwest::Response> {
    client(e, id)
        .get(format!(
            "https://127.0.0.1:{}/v1/packages/{package_id}/content",
            r.addr.port()
        ))
        .send()
        .await
}

pub fn dead_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("https://127.0.0.1:{}", l.local_addr().unwrap().port())
}
