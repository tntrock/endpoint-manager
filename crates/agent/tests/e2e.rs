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
            group_id: None,
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

use std::sync::{Arc, Mutex};
use std::time::Duration;

use endpoint_agent::agent::{Agent, Cycle};
use endpoint_agent::collector::{Collector, Heartbeat, Identity};
use protocol::{
    Arch, BasicInfo, HardwareInfo, InventoryPayload, PatchItem, Section, ServiceItem, SoftwareItem,
};

#[derive(Clone)]
struct Fake {
    software: Arc<Mutex<Vec<SoftwareItem>>>,
    fail_patches: bool,
    /// 模擬 WMI 卡住：heartbeat() 睡這麼久
    hang: Option<Duration>,
}

fn app(name: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some("1.0".into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

impl Fake {
    fn new() -> Self {
        Fake {
            software: Arc::new(Mutex::new(vec![app("7-Zip")])),
            fail_patches: false,
            hang: None,
        }
    }
}

impl Collector for Fake {
    fn identity(&self) -> anyhow::Result<Identity> {
        Ok(Identity {
            hostname: "FAKE-PC".into(),
            smbios_uuid: Some("4C4C4544-0000-1111-2222-333344445555".into()),
            bios_serial: Some("SN-FAKE".into()),
            mac_addresses: vec!["00:11:22:33:44:55".into()],
        })
    }

    fn heartbeat(&self) -> anyhow::Result<Heartbeat> {
        if let Some(d) = self.hang {
            std::thread::sleep(d);
        }
        Ok(Heartbeat {
            boot_time: chrono::Utc::now() - chrono::Duration::hours(1),
            logged_on_user: Some("CORP\\bob".into()),
            ip_addresses: vec!["10.1.1.1".into()],
        })
    }

    fn collect(&self, s: Section) -> anyhow::Result<InventoryPayload> {
        Ok(match s {
            Section::Basic => InventoryPayload::Basic(BasicInfo {
                hostname: "FAKE-PC".into(),
                domain: Some("corp.local".into()),
                is_domain_joined: true,
                os_caption: "Windows 11 Pro".into(),
                os_build: "26100".into(),
            }),
            Section::Hardware => InventoryPayload::Hardware(HardwareInfo {
                manufacturer: Some("Dell".into()),
                model: Some("OptiPlex".into()),
                cpu: Some("Intel".into()),
                ram_mb: 16_384,
                disks: vec![],
            }),
            Section::Software => InventoryPayload::Software(self.software.lock().unwrap().clone()),
            Section::Patches if self.fail_patches => anyhow::bail!("WMI timeout"),
            Section::Patches => InventoryPayload::Patches(vec![PatchItem {
                kb: "KB5000001".into(),
                installed_on: None,
            }]),
            Section::Services => InventoryPayload::Services(vec![ServiceItem {
                name: "Spooler".into(),
                display_name: None,
                start_mode: "Auto".into(),
                state: "Running".into(),
                binary_path: None,
            }]),
        })
    }
}

async fn count(e: &Env, sql: &'static str, id: uuid::Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&e.pool)
        .await
        .unwrap()
}

fn next(c: Cycle) -> Duration {
    match c {
        Cycle::Next(d) => d,
        Cycle::Stop => panic!("agent stopped unexpectedly"),
    }
}

#[sqlx::test(migrations = false)]
async fn first_cycle_enrolls_and_uploads_all_sections(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    let wait = next(a.run_cycle().await);
    assert!(
        wait >= Duration::from_secs(48) && wait <= Duration::from_secs(72),
        "{wait:?}"
    );

    let id = a.state().device_id.expect("enrolled");
    assert!(
        AgentConfig::load(e.dir.path())
            .unwrap()
            .enroll_token
            .is_none(),
        "token removed"
    );
    assert_eq!(
        count(
            &e,
            "SELECT count(*) FROM inventory_sections WHERE device_id = $1",
            id
        )
        .await,
        5
    );
    assert_eq!(
        count(
            &e,
            "SELECT count(*) FROM device_software WHERE device_id = $1",
            id
        )
        .await,
        1
    );
}

#[sqlx::test(migrations = false)]
async fn unchanged_inventory_is_not_reuploaded(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let id = a.state().device_id.unwrap();
    let stamp = || async {
        sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT max(updated_at) FROM inventory_sections WHERE device_id = $1",
        )
        .bind(id)
        .fetch_one(&e.pool)
        .await
        .unwrap()
    };
    let before = stamp().await;
    next(a.run_cycle().await);
    assert_eq!(stamp().await, before);
}

#[sqlx::test(migrations = false)]
async fn software_change_is_uploaded_and_recorded(pool: PgPool) {
    let e = env(pool, 1).await;
    let fake = Fake::new();
    let mut a = Agent::new(e.dir.path(), fake.clone()).unwrap();
    next(a.run_cycle().await);
    fake.software.lock().unwrap().push(app("Unapproved Tool"));
    a.trigger(Section::Software);
    next(a.run_cycle().await);
    let id = a.state().device_id.unwrap();
    assert_eq!(
        count(
            &e,
            "SELECT count(*) FROM inventory_changes WHERE device_id = $1 AND change = 'added'",
            id
        )
        .await,
        1
    );
}

#[sqlx::test(migrations = false)]
async fn collector_error_reaches_server(pool: PgPool) {
    let e = env(pool, 1).await;
    let fake = Fake {
        fail_patches: true,
        ..Fake::new()
    };
    let mut a = Agent::new(e.dir.path(), fake).unwrap();
    next(a.run_cycle().await);
    e.state.heartbeat.flush(&e.pool).await.unwrap();
    let id = a.state().device_id.unwrap();
    let errors: String =
        sqlx::query_scalar("SELECT section_errors::text FROM devices WHERE id = $1")
            .bind(id)
            .fetch_one(&e.pool)
            .await
            .unwrap();
    assert!(errors.contains("WMI timeout"), "{errors}");
    assert_eq!(
        count(
            &e,
            "SELECT count(*) FROM inventory_sections WHERE device_id = $1",
            id
        )
        .await,
        4
    );
}

#[sqlx::test(migrations = false)]
async fn revoked_certificate_stops_agent(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    sqlx::query("UPDATE device_certs SET revoked_at = now()")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(a.run_cycle().await, Cycle::Stop);
}

#[sqlx::test(migrations = false)]
async fn unreachable_server_backs_off(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut cfg = AgentConfig::load(e.dir.path()).unwrap();
    cfg.server_url = "https://127.0.0.1:1".into();
    cfg.save(e.dir.path()).unwrap();
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    let first = next(a.run_cycle().await);
    let second = next(a.run_cycle().await);
    assert!(first >= Duration::from_secs(48), "{first:?}");
    assert!(second > first, "{first:?} then {second:?}");
    assert!(a.state().device_id.is_none());
}

#[sqlx::test(migrations = false)]
async fn expiring_certificate_is_renewed(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let old_chain = a.state().chain_pem.clone();
    sqlx::query("UPDATE device_certs SET not_after = now() + interval '5 days'")
        .execute(&e.pool)
        .await
        .unwrap();
    next(a.run_cycle().await);
    assert_ne!(a.state().chain_pem, old_chain);
    next(a.run_cycle().await); // 新憑證可用
}

#[sqlx::test(migrations = false)]
async fn restart_keeps_identity(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let id = a.state().device_id;
    drop(a);
    let mut b = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(b.run_cycle().await);
    assert_eq!(b.state().device_id, id);
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(devices, 1);
}

#[test]
fn missing_config_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = Agent::new(dir.path(), Fake::new())
        .err()
        .expect("must fail");
    assert!(format!("{err:#}").contains("config.json"), "{err:#}");
}

#[sqlx::test(migrations = false)]
async fn state_is_not_rewritten_when_unchanged(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let path = e.dir.path().join("state.json");
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    next(a.run_cycle().await);
    let after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(before, after, "私鑰檔不應每個週期重寫");
}

#[sqlx::test(migrations = false)]
async fn hung_collector_call_is_not_waited_on_again(pool: PgPool) {
    let e = env(pool, 1).await;
    let fake = Fake {
        hang: Some(Duration::from_secs(3)),
        ..Fake::new()
    };
    let mut a = Agent::new(e.dir.path(), fake)
        .unwrap()
        .with_collect_timeout(Duration::from_millis(500));
    next(a.run_cycle().await); // heartbeat 逾時，改用預設值
    let t = std::time::Instant::now();
    next(a.run_cycle().await); // 上一次的 heartbeat 仍卡著 → 直接跳過
    assert!(
        t.elapsed() < Duration::from_millis(400),
        "{:?}",
        t.elapsed()
    );
}

#[sqlx::test(migrations = false)]
async fn shutdown_interrupts_a_running_cycle(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await); // 先完成註冊
    let a = Agent::new(
        e.dir.path(),
        Fake {
            hang: Some(Duration::from_secs(3)),
            ..Fake::new()
        },
    )
    .unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let (_ttx, trx) = tokio::sync::mpsc::channel(16);
    let task = tokio::spawn(endpoint_agent::agent::run_agent(a, rx, trx));
    tokio::time::sleep(Duration::from_millis(300)).await;
    tx.send(true).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .is_ok(),
        "run_agent must return promptly on shutdown"
    );
}

#[sqlx::test(migrations = false)]
async fn expired_certificate_stops_agent(pool: PgPool) {
    let e = env(pool, 1).await;
    let (csr_pem, key_pem) = {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        (csr, key.serialize_pem())
    };
    // 400 天前簽發、效期 365 天 → 已過期
    let issued = ca::Ca::load(e._pki.path())
        .unwrap()
        .sign_device_csr(
            &csr_pem,
            uuid::Uuid::new_v4(),
            chrono::Utc::now() - chrono::Duration::days(400),
        )
        .unwrap();
    endpoint_agent::state::AgentState {
        device_id: Some(uuid::Uuid::new_v4()),
        chain_pem: Some(issued.pem),
        key_pem: Some(key_pem),
        ..Default::default()
    }
    .save(e.dir.path())
    .unwrap();

    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    assert_eq!(a.run_cycle().await, Cycle::Stop);
}
