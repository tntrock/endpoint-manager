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
    let state = AppState::new(pool.clone(), ca::Ca::load(pki.path()).unwrap())
        .with_packages(pki.path().join("packages"), 4);
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
            kind: tokens::TokenKind::Device,
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

/// 封包被丟棄的位址：沒有連線逾時時要等到整個請求逾時（60 秒）
#[tokio::test]
async fn connect_timeout_is_short() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["127.0.0.1".into()]).unwrap();
    let root = std::fs::read_to_string(pki.path().join("root.pem")).unwrap();
    let c = ServerClient::new("https://10.255.255.1:443", &root, None).unwrap();
    let start = std::time::Instant::now();
    let r = c.renew(&protocol::RenewRequest { csr_pem: csr() }).await;
    assert!(r.is_err());
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "{:?}",
        start.elapsed()
    );
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
    /// 模擬 WMI 卡住：收集 patches 睡這麼多毫秒（0 = 不卡）
    hang_patches_ms: Arc<std::sync::atomic::AtomicU64>,
    /// patches 的 InstalledOn
    installed_on: Arc<Mutex<Option<String>>>,
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
            hang_patches_ms: Default::default(),
            installed_on: Default::default(),
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

    fn collect_registry(
        &self,
        queries: &[protocol::RegistryQuery],
    ) -> anyhow::Result<InventoryPayload> {
        Ok(InventoryPayload::Registry(
            queries
                .iter()
                .map(|q| protocol::RegistryValue {
                    path: q.path.clone(),
                    name: q.name.clone(),
                    state: protocol::RegState::Present,
                    kind: protocol::RegKind::Dword,
                    data: "1".into(),
                })
                .collect(),
        ))
    }

    fn collect(&self, s: Section) -> anyhow::Result<InventoryPayload> {
        Ok(match s {
            Section::Basic => InventoryPayload::Basic(BasicInfo {
                hostname: "FAKE-PC".into(),
                domain: Some("corp.local".into()),
                is_domain_joined: true,
                os_caption: "Windows 11 Pro".into(),
                os_build: "26100".into(),
                os_ubr: None,
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
            Section::Patches => {
                let ms = self
                    .hang_patches_ms
                    .load(std::sync::atomic::Ordering::SeqCst);
                if ms > 0 {
                    std::thread::sleep(Duration::from_millis(ms));
                }
                InventoryPayload::Patches(vec![PatchItem {
                    kb: "KB5000001".into(),
                    installed_on: self.installed_on.lock().unwrap().clone(),
                }])
            }
            Section::Services => InventoryPayload::Services(vec![ServiceItem {
                name: "Spooler".into(),
                display_name: None,
                start_mode: "Auto".into(),
                state: "Running".into(),
                binary_path: None,
            }]),
            Section::Security => InventoryPayload::Security(protocol::SecurityInfo {
                firewall: protocol::Probe::Ok(protocol::FirewallInfo {
                    domain: true,
                    private: true,
                    public: false,
                }),
                bitlocker: protocol::Probe::Error("no BitLocker".into()),
                defender: protocol::Probe::Ok(protocol::DefenderInfo {
                    active: true,
                    realtime: true,
                    tamper: false,
                    signature_updated: None,
                }),
                password: protocol::Probe::Ok(protocol::PasswordPolicy {
                    min_length: 8,
                    max_age_days: 42,
                    lockout_threshold: 0,
                }),
                admins: protocol::Probe::Ok(vec![protocol::AccountInfo {
                    name: r"FAKE-PC\Administrator".into(),
                    sid: "S-1-5-21-1-500".into(),
                }]),
            }),
            Section::Registry => anyhow::bail!("registry is collected via collect_registry"),
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
    // 第二輪伺服器已表明支援，會上傳 security／registry；之後內容不變就不再上傳
    next(a.run_cycle().await);
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

#[sqlx::test(migrations = false)]
async fn config_sections_start_after_server_confirms_support(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let id = a.state().device_id.unwrap();
    let sections = || {
        let pool = e.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT section FROM inventory_sections WHERE device_id = $1 ORDER BY section",
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    assert!(
        !sections().await.contains(&"security".to_string()),
        "第一輪還不知道伺服器是否支援"
    );
    next(a.run_cycle().await);
    let s = sections().await;
    assert!(
        s.contains(&"security".to_string()) && s.contains(&"registry".to_string()),
        "{s:?}"
    );
}

mod deploy {
    use super::*;
    use endpoint_agent::client::DownloadError;
    use endpoint_server::deploy::{admin, store};
    use protocol::deploy::{DeployResult, DeployStatus, PackageSpec};

    pub async fn enrolled(e: &Env, fake: Fake) -> (Agent<Fake>, ServerClient) {
        let mut a = Agent::new(e.dir.path(), fake).unwrap();
        a.run_cycle().await;
        assert!(a.state().is_enrolled());
        let c = ServerClient::new(&e.url(), &e.root_pem(), a.state().identity_pem()).unwrap();
        (a, c)
    }

    /// 建立 EXE 套件與派送（全部裝置），回傳派送 id
    pub async fn deployment(e: &Env, data: &[u8], args: &str) -> i64 {
        deployment_with(e, data, args, "install", "").await
    }

    pub async fn deployment_with(
        e: &Env,
        data: &[u8],
        args: &str,
        action: &str,
        uninstall_args: &str,
    ) -> i64 {
        let chunk: Result<bytes::Bytes, std::io::Error> = Ok(bytes::Bytes::copy_from_slice(data));
        let st = store::save(
            &e.state.package_dir,
            futures_util::stream::iter(vec![chunk]),
        )
        .await
        .unwrap();
        let pkg = admin::create_package(
            &e.pool,
            &e.state.package_dir,
            &st,
            "setup.exe",
            None,
            &admin::PackageInput {
                name: "Fake App".into(),
                version: "1.0".into(),
                kind: "exe".into(),
                install_args: args.into(),
                uninstall_args: uninstall_args.into(),
                success_codes: vec![],
                detect_name: "Fake App*".into(),
                detect_publisher: String::new(),
                detect_min_version: String::new(),
            },
            "admin",
        )
        .await
        .unwrap();
        let d = admin::create_deployment(
            &e.pool,
            &admin::DeploymentInput {
                name: "Fake".into(),
                package_id: pkg,
                action: action.into(),
                include: vec![],
                exclude: vec![],
                pilot_group_id: None,
                max_failure_pct: 50,
                min_samples: 100,
            },
            "admin",
        )
        .await
        .unwrap();
        e.state.deploy.invalidate();
        d
    }

    async fn spec(c: &ServerClient) -> PackageSpec {
        let r = c
            .checkin(&CheckinRequest {
                schema_version: SCHEMA_VERSION,
                agent_version: "t".into(),
                boot_time: chrono::Utc::now(),
                logged_on_user: None,
                ip_addresses: vec![],
                section_hashes: Default::default(),
                section_errors: Default::default(),
            })
            .await
            .unwrap();
        r.deployments[0].package.clone()
    }

    #[sqlx::test(migrations = false)]
    async fn download_verifies_hash_and_report_is_stored(pool: PgPool) {
        let e = env(pool, 1).await;
        let (a, c) = enrolled(&e, Fake::new()).await;
        let data = b"MZ fake installer ".repeat(10_000);
        let d = deployment(&e, &data, "/S").await;
        let spec = spec(&c).await;
        let out = tempfile::tempdir().unwrap();
        let dest = out.path().join("pkg.exe");
        c.download(&spec, &dest).await.unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), data);

        let wrong = PackageSpec {
            sha256: "00".repeat(32),
            ..spec.clone()
        };
        let bad = out.path().join("bad.exe");
        assert!(matches!(
            c.download(&wrong, &bad).await,
            Err(DownloadError::Mismatch)
        ));
        let short = PackageSpec {
            size: 10,
            ..spec.clone()
        };
        assert!(matches!(
            c.download(&short, &bad).await,
            Err(DownloadError::Mismatch)
        ));
        assert_eq!(
            std::fs::read_dir(out.path()).unwrap().count(),
            1,
            "不符時不留檔"
        );
        let gone = PackageSpec {
            id: 9999,
            ..spec.clone()
        };
        assert!(matches!(
            c.download(&gone, &bad).await,
            Err(DownloadError::NotFound)
        ));

        c.report(
            d,
            &DeployResult {
                revision: 1,
                status: DeployStatus::Succeeded,
                exit_code: Some(0),
                message: String::new(),
                attempts: 1,
                source: None,
            },
        )
        .await
        .unwrap();
        let status: String = sqlx::query_scalar(
            "SELECT status FROM deployment_status WHERE deployment_id = $1 AND device_id = $2",
        )
        .bind(d)
        .bind(a.state().device_id.unwrap())
        .fetch_one(&e.pool)
        .await
        .unwrap();
        assert_eq!(status, "succeeded");
    }

    use endpoint_agent::deploy::logic::Cmd;
    use endpoint_agent::deploy::worker::{RunResult, Runner, Work, Worker};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 假的執行器：記錄呼叫次數，回傳固定結束碼；install=true 時把軟體加進假清單（模擬安裝成功）
    #[derive(Clone)]
    struct FakeRunner {
        code: i32,
        install: bool,
        software: Arc<Mutex<Vec<SoftwareItem>>>,
        runs: Arc<AtomicUsize>,
    }

    impl Runner for FakeRunner {
        async fn run(&self, cmd: &Cmd, _timeout: Duration) -> std::io::Result<RunResult> {
            assert!(
                cmd.program.exists(),
                "執行前檔案已下載並驗證：{:?}",
                cmd.program
            );
            self.runs.fetch_add(1, Ordering::SeqCst);
            if cmd.args.contains("/uninstall") {
                self.software
                    .lock()
                    .unwrap()
                    .retain(|i| !i.name.starts_with("Fake App"));
            } else if self.install {
                self.software.lock().unwrap().push(app("Fake App"));
            }
            Ok(RunResult::Exited(self.code))
        }
    }

    fn work(a: &Agent<Fake>, e: &Env, assignments: Vec<protocol::deploy::Assignment>) -> Work {
        Work {
            assignments,
            server_url: e.url(),
            root_pem: e.root_pem(),
            identity_pem: a.state().identity_pem(),
            package_source: None,
        }
    }

    async fn assignments(c: &ServerClient) -> Vec<protocol::deploy::Assignment> {
        c.checkin(&CheckinRequest {
            schema_version: SCHEMA_VERSION,
            agent_version: "t".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .await
        .unwrap()
        .deployments
    }

    async fn status(e: &Env, d: i64) -> Option<(String, String, i32)> {
        sqlx::query_as(
            "SELECT status, message, attempts FROM deployment_status WHERE deployment_id = $1",
        )
        .bind(d)
        .fetch_optional(&e.pool)
        .await
        .unwrap()
    }

    async fn setup(
        e: &Env,
        code: i32,
        install: bool,
    ) -> (Agent<Fake>, Worker<Fake, FakeRunner>, FakeRunner, Work, i64) {
        let fake = Fake::new();
        let (a, c) = enrolled(e, fake.clone()).await;
        let d = deployment(e, b"MZ installer", "/S").await;
        let runner = FakeRunner {
            code,
            install,
            software: fake.software.clone(),
            runs: Arc::new(AtomicUsize::new(0)),
        };
        let w = work(&a, e, assignments(&c).await);
        let worker = Worker::new(e.dir.path(), Arc::new(fake), runner.clone());
        (a, worker, runner, w, d)
    }

    #[sqlx::test(migrations = false)]
    async fn worker_installs_and_reports(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        worker.pass(&w).await;
        assert_eq!(status(&e, d).await.unwrap().0, "succeeded");
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
        let left: Vec<_> = std::fs::read_dir(e.dir.path().join("packages"))
            .unwrap()
            .filter_map(|x| x.ok())
            .filter(|x| x.path().extension().is_some_and(|ext| ext == "exe"))
            .collect();
        assert!(left.is_empty(), "安裝後刪除安裝檔");
        // 已安裝且已回報：不再執行、不再回報
        worker.pass(&w).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
    }

    #[sqlx::test(migrations = false)]
    async fn success_without_detection_is_failure(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, d) = setup(&e, 0, false).await;
        worker.pass(&w).await;
        let (st, msg, attempts) = status(&e, d).await.unwrap();
        assert_eq!((st.as_str(), attempts), ("failed", 1));
        assert!(msg.contains("偵測不到"), "{msg}");
    }

    #[sqlx::test(migrations = false)]
    async fn installer_busy_is_not_an_attempt(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 1618, false).await;
        worker.pass(&w).await;
        assert!(status(&e, d).await.is_none(), "1618 不回報");
        worker.pass(&w).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 2, "下次再試");
    }

    #[sqlx::test(migrations = false)]
    async fn failures_retry_daily_at_most_three_times(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 1603, false).await;
        let t0 = chrono::Utc::now();
        worker.pass_at(&w, t0).await;
        worker.pass_at(&w, t0 + chrono::Duration::hours(1)).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1, "24 小時內不重試");
        worker.pass_at(&w, t0 + chrono::Duration::hours(25)).await;
        worker.pass_at(&w, t0 + chrono::Duration::hours(50)).await;
        worker.pass_at(&w, t0 + chrono::Duration::hours(75)).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 3, "最多 3 次");
        let (st, msg, attempts) = status(&e, d).await.unwrap();
        assert_eq!((st.as_str(), attempts), ("failed", 3));
        assert!(msg.contains("1603"), "{msg}");
    }

    #[sqlx::test(migrations = false)]
    async fn already_installed_reports_compliant_once(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        runner.software.lock().unwrap().push(app("Fake App"));
        worker.pass(&w).await;
        assert_eq!(status(&e, d).await.unwrap().0, "compliant");
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
    }

    #[sqlx::test(migrations = false)]
    async fn reinstalls_stop_after_three_removals(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        for _ in 0..3 {
            worker.pass(&w).await;
            // 其他工具把軟體移除
            runner.software.lock().unwrap().clear();
        }
        worker.pass(&w).await;
        worker.pass(&w).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 3);
        let (st, msg, _) = status(&e, d).await.unwrap();
        assert_eq!(st, "failed");
        assert!(msg.contains("一再被移除"), "{msg}");
    }

    #[sqlx::test(migrations = false)]
    async fn result_for_deleted_deployment_is_done(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, c) = enrolled(&e, Fake::new()).await;
        let r = DeployResult {
            revision: 1,
            status: DeployStatus::Failed,
            exit_code: None,
            message: String::new(),
            attempts: 1,
            source: None,
        };
        assert!(c.report(999_999, &r).await.is_ok(), "404：伺服器已沒有這筆");
    }

    #[sqlx::test(migrations = false)]
    async fn each_assignment_uses_its_own_time(pool: PgPool) {
        let e = env(pool, 1).await;
        let (a, mut worker, _runner, _w, d1) = setup(&e, 1603, false).await;
        let d2 = deployment(&e, b"MZ second installer", "/S").await;
        let c = ServerClient::new(&e.url(), &e.root_pem(), a.state().identity_pem()).unwrap();
        let w = work(&a, &e, assignments(&c).await);
        assert_eq!(w.assignments.len(), 2);
        worker
            .pass_at(&w, chrono::Utc::now() - chrono::Duration::hours(1))
            .await;
        let at = |d: i64| worker.state().entries[&d].last_attempt.unwrap();
        assert!(at(d2) > at(d1), "{} vs {}", at(d1), at(d2));
    }

    #[sqlx::test(migrations = false)]
    async fn old_install_logs_are_removed(pool: PgPool) {
        let e = env(pool, 1).await;
        let dir = e.dir.path().join("packages");
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["old.log", "new.log"] {
            std::fs::write(dir.join(name), b"log").unwrap();
        }
        std::fs::File::options()
            .write(true)
            .open(dir.join("old.log"))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(31 * 86_400))
            .unwrap();
        let fake = Fake::new();
        let runner = FakeRunner {
            code: 0,
            install: false,
            software: fake.software.clone(),
            runs: Arc::new(AtomicUsize::new(0)),
        };
        let _w = Worker::new(e.dir.path(), Arc::new(fake), runner);
        assert!(!dir.join("old.log").exists());
        assert!(dir.join("new.log").exists());
    }

    #[sqlx::test(migrations = false)]
    async fn worker_uninstalls_and_reports(pool: PgPool) {
        let e = env(pool, 1).await;
        let fake = Fake::new();
        fake.software.lock().unwrap().push(app("Fake App"));
        let (a, c) = enrolled(&e, fake.clone()).await;
        let d = deployment_with(&e, b"MZ uninstaller", "/S", "uninstall", "/uninstall /S").await;
        let runner = FakeRunner {
            code: 0,
            install: false,
            software: fake.software.clone(),
            runs: Arc::new(AtomicUsize::new(0)),
        };
        let w = work(&a, &e, assignments(&c).await);
        let mut worker = Worker::new(e.dir.path(), Arc::new(fake.clone()), runner.clone());
        worker.pass(&w).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1);
        assert_eq!(status(&e, d).await.unwrap().0, "succeeded");
        assert!(
            !fake
                .software
                .lock()
                .unwrap()
                .iter()
                .any(|i| i.name.starts_with("Fake App"))
        );
        worker.pass(&w).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 1, "已移除不再執行");
    }

    #[sqlx::test(migrations = false)]
    async fn agent_hands_assignments_to_worker(pool: PgPool) {
        let e = env(pool, 1).await;
        let (tx, rx) = tokio::sync::watch::channel(None);
        let mut a = Agent::new(e.dir.path(), Fake::new())
            .unwrap()
            .with_deploy(tx);
        a.run_cycle().await;
        assert!(
            rx.borrow()
                .as_ref()
                .is_some_and(|w| w.assignments.is_empty())
        );
        deployment(&e, b"x", "").await;
        a.run_cycle().await;
        assert_eq!(rx.borrow().as_ref().unwrap().assignments.len(), 1);
    }

    /// 永遠不結束的執行器：模擬安裝中 Agent 被停止或電腦重新開機
    struct Hang;

    impl Runner for Hang {
        async fn run(&self, _cmd: &Cmd, _timeout: Duration) -> std::io::Result<RunResult> {
            std::future::pending().await
        }
    }

    #[sqlx::test(migrations = false)]
    async fn interrupted_install_counts_as_attempt(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, _worker, runner, w, d) = setup(&e, 0, true).await;
        let fake = Fake {
            software: runner.software.clone(),
            ..Fake::new()
        };
        let mut hang = Worker::new(e.dir.path(), Arc::new(fake.clone()), Hang);
        // 等「執行中」寫進狀態檔再中斷（不用固定時間：全套件負載下下載可能較慢）
        let state_file = e.dir.path().join("deploy.json");
        let started = async {
            loop {
                let s = std::fs::read_to_string(&state_file).unwrap_or_default();
                if s.contains(r#""in_progress":true"#) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::select! {
            _ = hang.pass(&w) => panic!("安裝卡住時 pass 不會結束"),
            _ = tokio::time::timeout(Duration::from_secs(60), started) => {}
        }
        drop(hang);
        // 重新啟動：上次中斷算一次失敗，24 小時內不再執行
        let mut worker = Worker::new(e.dir.path(), Arc::new(fake), runner.clone());
        worker.pass(&w).await;
        assert_eq!(
            runner.runs.load(Ordering::SeqCst),
            0,
            "不立刻重試（避免重開機迴圈）"
        );
        let (st, msg, attempts) = status(&e, d).await.unwrap();
        assert_eq!((st.as_str(), attempts), ("failed", 1));
        assert!(msg.contains("中斷"), "{msg}");
    }

    #[sqlx::test(migrations = false)]
    async fn paused_assignment_keeps_attempt_history(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, _d) = setup(&e, 1603, false).await;
        let t0 = chrono::Utc::now();
        worker.pass_at(&w, t0).await;
        // 暫停期間指派消失，繼續後同一 revision 仍在 24 小時等待中
        let empty = Work {
            assignments: vec![],
            ..w.clone()
        };
        worker
            .pass_at(&empty, t0 + chrono::Duration::hours(1))
            .await;
        worker.pass_at(&w, t0 + chrono::Duration::hours(2)).await;
        assert_eq!(
            runner.runs.load(Ordering::SeqCst),
            1,
            "暫停不能重設嘗試次數"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn busy_installer_keeps_verified_file(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, _d) = setup(&e, 1618, false).await;
        worker.pass(&w).await;
        let exes = || {
            std::fs::read_dir(e.dir.path().join("packages"))
                .unwrap()
                .filter_map(|x| x.ok())
                .filter(|x| x.path().extension().is_some_and(|ext| ext == "exe"))
                .count()
        };
        assert_eq!(exes(), 1, "1618 時保留已驗證的安裝檔");
        // 伺服器下載名額用完：仍能用本機已驗證的檔案執行
        let _held = e
            .state
            .downloads
            .clone()
            .acquire_many_owned(4)
            .await
            .unwrap();
        worker.pass(&w).await;
        assert_eq!(runner.runs.load(Ordering::SeqCst), 2);
    }

    #[sqlx::test(migrations = false)]
    async fn download_busy_waits_for_retry_after(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        let _held = e
            .state
            .downloads
            .clone()
            .acquire_many_owned(4)
            .await
            .unwrap();
        let now = chrono::Utc::now();
        let next = worker
            .pass_at(&w, now)
            .await
            .expect("依 Retry-After 排下次");
        assert!(
            next > now && next <= now + chrono::Duration::seconds(60 + 120),
            "{next} vs {now}"
        );
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert!(status(&e, d).await.is_none(), "忙碌不算嘗試、不回報");
    }

    // ── 分點快取：依來源下載 ─────────────────────────────────────────────

    use protocol::branch::PackageSource;

    #[derive(Clone)]
    enum Stub {
        Bytes(Vec<u8>),
        Status(u16, Option<u64>),
    }

    /// 假的快取：用中央的伺服器憑證（含 127.0.0.1）提供 HTTPS，回傳固定內容或狀態碼；計算請求數
    async fn stub(e: &Env, kind: Stub) -> (String, Arc<AtomicUsize>) {
        use axum::http::{HeaderValue, StatusCode, header};
        use axum::response::IntoResponse;
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let app = axum::Router::new().route(
            "/v1/packages/{id}/content",
            axum::routing::get(move || {
                let (kind, h) = (kind.clone(), h.clone());
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    match kind {
                        Stub::Bytes(b) => b.into_response(),
                        Stub::Status(code, after) => {
                            let mut r = StatusCode::from_u16(code).unwrap().into_response();
                            if let Some(a) = after {
                                r.headers_mut().insert(
                                    header::RETRY_AFTER,
                                    HeaderValue::from_str(&a.to_string()).unwrap(),
                                );
                            }
                            r
                        }
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(tls::serve_mtls(
            listener,
            tls::server_config(e._pki.path()).unwrap(),
            app,
            tls::ConnLimits::default(),
        ));
        (format!("https://127.0.0.1:{port}"), hits)
    }

    fn dead_url() -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        format!("https://127.0.0.1:{}", l.local_addr().unwrap().port())
    }

    fn via(w: &Work, url: &str, fallback: bool) -> Work {
        Work {
            package_source: Some(PackageSource {
                cache_id: 1,
                url: url.into(),
                fallback_to_central: fallback,
            }),
            ..w.clone()
        }
    }

    async fn source_of(e: &Env, d: i64) -> Option<String> {
        sqlx::query_scalar("SELECT source FROM deployment_status WHERE deployment_id = $1")
            .bind(d)
            .fetch_one(&e.pool)
            .await
            .unwrap()
    }

    /// 讓中央的下載失敗：確認沒有向中央下載
    fn break_central(e: &Env) {
        for f in std::fs::read_dir(&e.state.package_dir).unwrap().flatten() {
            std::fs::remove_file(f.path()).unwrap();
        }
    }

    const INSTALLER: &[u8] = b"MZ installer";

    #[sqlx::test(migrations = false)]
    async fn downloads_from_cache(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, d) = setup(&e, 0, true).await;
        let (url, hits) = stub(&e, Stub::Bytes(INSTALLER.to_vec())).await;
        break_central(&e);
        worker.pass(&via(&w, &url, true)).await;
        assert_eq!(status(&e, d).await.unwrap().0, "succeeded");
        assert_eq!(source_of(&e, d).await.as_deref(), Some("cache"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[sqlx::test(migrations = false)]
    async fn without_source_downloads_from_central(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, d) = setup(&e, 0, true).await;
        worker.pass(&w).await;
        assert_eq!(source_of(&e, d).await.as_deref(), Some("central"));
    }

    #[sqlx::test(migrations = false)]
    async fn cache_busy_waits_without_fallback(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        let (url, _) = stub(&e, Stub::Status(503, Some(60))).await;
        let before = chrono::Utc::now();
        let next = worker.pass(&via(&w, &url, true)).await.expect("稍後再試");
        // Retry-After 60 秒，加上 0.8～1.2 倍的隨機延遲（不是沒有 Retry-After 時的 5 分鐘）
        assert!(next >= before + chrono::Duration::seconds(47), "{next}");
        assert!(
            next <= chrono::Utc::now() + chrono::Duration::seconds(73),
            "{next}"
        );
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert!(status(&e, d).await.is_none(), "沒有回報、沒有向中央下載");
    }

    #[sqlx::test(migrations = false)]
    async fn cache_pause_uses_current_time(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, _d) = setup(&e, 0, false).await;
        // 一輪的起始時間在 2 小時前（例如前面的安裝跑了很久）：暫停仍要從現在算 5 分鐘
        worker
            .pass_at(
                &via(&w, &dead_url(), true),
                chrono::Utc::now() - chrono::Duration::hours(2),
            )
            .await;
        let until = worker.cache_paused_until().expect("快取連不上時暫停");
        assert!(until > chrono::Utc::now(), "{until}");
    }

    #[sqlx::test(migrations = false)]
    async fn package_source_change_wakes_worker(pool: PgPool) {
        let e = env(pool, 1).await;
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let mut a = Agent::new(e.dir.path(), Fake::new())
            .unwrap()
            .with_deploy(tx);
        a.run_cycle().await;
        deployment(&e, b"x", "/S").await;
        a.run_cycle().await;
        rx.borrow_and_update();
        let site = endpoint_server::branch::sites::create_site(
            &e.pool,
            &endpoint_server::branch::sites::SiteInput {
                name: "總部".into(),
                cidrs: vec!["10.0.0.0/8".into()],
                fallback_to_central: false,
                bandwidth_limit_mbps: None,
                disk_limit_gb: 100,
            },
            "admin",
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, poll_secret_hash, status) \
             VALUES ('c', $1, 'https://cache.corp:8443', ARRAY['cache.corp'], 'x', 'x', 'active')",
        )
        .bind(site)
        .execute(&e.pool)
        .await
        .unwrap();
        e.state.branch.invalidate();
        a.run_cycle().await;
        assert!(
            rx.has_changed().unwrap(),
            "據點的快取改變：喚醒等待重試的派送"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn unreachable_cache_falls_back_and_pauses(pool: PgPool) {
        let e = env(pool, 1).await;
        // install=false：兩個派送都會下載（偵測不到安裝結果）
        let (_a, mut worker, _runner, _w, d1) = setup(&e, 0, false).await;
        let d2 = deployment(&e, b"MZ second installer", "/S").await;
        let c = ServerClient::new(&e.url(), &e.root_pem(), _a.state().identity_pem()).unwrap();
        let w = work(&_a, &e, assignments(&c).await);
        let (url, hits) = stub(&e, Stub::Status(500, None)).await;
        worker.pass(&via(&w, &url, true)).await;
        assert_eq!(hits.load(Ordering::SeqCst), 1, "暫停期內不再連快取");
        assert_eq!(source_of(&e, d1).await.as_deref(), Some("central"));
        assert_eq!(source_of(&e, d2).await.as_deref(), Some("central"));
    }

    #[sqlx::test(migrations = false)]
    async fn unreachable_cache_without_fallback_retries_cache(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        assert!(worker.pass(&via(&w, &dead_url(), false)).await.is_some());
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert!(status(&e, d).await.is_none(), "不算失敗、不向中央下載");
        let (url, _) = stub(&e, Stub::Bytes(INSTALLER.to_vec())).await;
        worker.pass(&via(&w, &url, false)).await;
        assert_eq!(status(&e, d).await.unwrap().0, "succeeded");
        assert_eq!(source_of(&e, d).await.as_deref(), Some("cache"));
    }

    async fn refused(pool: PgPool, code: u16) {
        let e = env(pool, 1).await;
        let (_a, mut worker, runner, w, d) = setup(&e, 0, true).await;
        let (url, _) = stub(&e, Stub::Status(code, None)).await;
        worker.pass(&via(&w, &url, true)).await;
        let (st, _, attempts) = status(&e, d).await.unwrap();
        assert_eq!((st.as_str(), attempts), ("failed", 1), "{code}");
        assert_eq!(runner.runs.load(Ordering::SeqCst), 0);
        assert_eq!(source_of(&e, d).await, None, "沒有向中央下載");
    }

    #[sqlx::test(migrations = false)]
    async fn cache_forbidden_is_a_failure(pool: PgPool) {
        refused(pool, 403).await;
    }

    #[sqlx::test(migrations = false)]
    async fn cache_not_found_is_a_failure(pool: PgPool) {
        refused(pool, 404).await;
    }

    #[sqlx::test(migrations = false)]
    async fn corrupt_cache_file_falls_back(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, d) = setup(&e, 0, true).await;
        let (url, _) = stub(&e, Stub::Bytes(vec![b'X'; INSTALLER.len()])).await;
        worker.pass(&via(&w, &url, true)).await;
        assert_eq!(status(&e, d).await.unwrap().0, "succeeded");
        assert_eq!(source_of(&e, d).await.as_deref(), Some("central"));
    }

    #[sqlx::test(migrations = false)]
    async fn corrupt_cache_file_without_fallback_fails(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, d) = setup(&e, 0, true).await;
        let (url, _) = stub(&e, Stub::Bytes(vec![b'X'; INSTALLER.len()])).await;
        worker.pass(&via(&w, &url, false)).await;
        assert_eq!(status(&e, d).await.unwrap().0, "failed");
    }

    #[sqlx::test(migrations = false)]
    async fn cache_server_error_falls_back(pool: PgPool) {
        let e = env(pool, 1).await;
        let (_a, mut worker, _runner, w, d) = setup(&e, 0, true).await;
        let (url, _) = stub(&e, Stub::Status(500, None)).await;
        worker.pass(&via(&w, &url, true)).await;
        assert_eq!(status(&e, d).await.unwrap().0, "succeeded");
        assert_eq!(source_of(&e, d).await.as_deref(), Some("central"));
    }

    #[sqlx::test(migrations = false)]
    async fn checkin_passes_package_source_to_worker(pool: PgPool) {
        let e = env(pool, 1).await;
        let (tx, rx) = tokio::sync::watch::channel(None);
        let mut a = Agent::new(e.dir.path(), Fake::new())
            .unwrap()
            .with_deploy(tx);
        a.run_cycle().await;
        let site = endpoint_server::branch::sites::create_site(
            &e.pool,
            &endpoint_server::branch::sites::SiteInput {
                name: "總部".into(),
                cidrs: vec!["10.0.0.0/8".into()],
                fallback_to_central: false,
                bandwidth_limit_mbps: None,
                disk_limit_gb: 100,
            },
            "admin",
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, poll_secret_hash, status) \
             VALUES ('c', $1, 'https://cache.corp:8443', ARRAY['cache.corp'], 'x', 'x', 'active')",
        )
        .bind(site)
        .execute(&e.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE branch_state SET generation = generation + 1")
            .execute(&e.pool)
            .await
            .unwrap();
        e.state.branch.invalidate();
        deployment(&e, b"x", "/S").await;
        a.run_cycle().await;
        let src = rx
            .borrow()
            .as_ref()
            .unwrap()
            .package_source
            .clone()
            .unwrap();
        assert_eq!(src.url, "https://cache.corp:8443");
        assert!(!src.fallback_to_central);
    }

    // ── 分點快取：真實中央 + 真實 endpoint-cache ──────────────────────────

    struct RealCache {
        url: String,
        cache: Arc<endpoint_cache::run::Cache>,
        serve: tokio::task::JoinHandle<anyhow::Result<()>>,
        _dir: tempfile::TempDir,
    }

    /// 註冊、核准（據點 10.0.0.0/8，Fake 的 IP 是 10.1.1.1）、啟動快取並開始監聽
    async fn real_cache(e: &Env) -> RealCache {
        use endpoint_server::branch::{caches, sites};
        let dir = tempfile::tempdir().unwrap();
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std_listener.set_nonblocking(true).unwrap();
        let url = format!(
            "https://127.0.0.1:{}",
            std_listener.local_addr().unwrap().port()
        );
        let token = tokens::create_token(
            &e.pool,
            &tokens::NewToken {
                name: "cache".into(),
                group_id: None,
                expires_at: None,
                max_uses: 1,
                created_by: "test".into(),
                kind: tokens::TokenKind::Cache,
            },
        )
        .await
        .unwrap()
        .1;
        let id = endpoint_cache::run::enroll(
            dir.path(),
            &endpoint_cache::run::EnrollArgs {
                server: e.url(),
                root_pem_path: e.dir.path().join("root.pem"),
                token,
                name: "台北快取".into(),
                url: url.clone(),
                dns: vec!["127.0.0.1".into()],
            },
        )
        .await
        .unwrap();
        let site = sites::create_site(
            &e.pool,
            &sites::SiteInput {
                name: "台北".into(),
                cidrs: vec!["10.0.0.0/8".into()],
                fallback_to_central: true,
                bandwidth_limit_mbps: None,
                disk_limit_gb: 100,
            },
            "admin",
        )
        .await
        .unwrap();
        caches::approve(&e.pool, &e.state.ca, id, site, "admin")
            .await
            .unwrap();
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let cache = Arc::new(
            endpoint_cache::run::Cache::start_with(dir.path(), rx, Duration::from_millis(100))
                .await
                .unwrap()
                .unwrap(),
        );
        cache.checkin_once().await.unwrap();
        let serve = tokio::spawn(endpoint_cache::server::serve(
            TcpListener::from_std(std_listener).unwrap(),
            cache.tls().unwrap(),
            cache.router(),
            100,
        ));
        RealCache {
            url,
            cache,
            serve,
            _dir: dir,
        }
    }

    /// 另一台裝置（沒有 SMBIOS，不會被當成重灌）：回傳連快取用的身分 PEM
    async fn other_device(e: &Env) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr = rcgen::CertificateParams::default()
            .serialize_request(&key)
            .unwrap()
            .pem()
            .unwrap();
        let token = tokens::create_token(
            &e.pool,
            &tokens::NewToken {
                name: "dev".into(),
                group_id: None,
                expires_at: None,
                max_uses: 1,
                created_by: "test".into(),
                kind: tokens::TokenKind::Device,
            },
        )
        .await
        .unwrap()
        .1;
        let c = ServerClient::new(&e.url(), &e.root_pem(), None).unwrap();
        let r = c
            .enroll(&EnrollRequest {
                schema_version: SCHEMA_VERSION,
                enroll_token: token,
                csr_pem: csr,
                hostname: "PC-2".into(),
                smbios_uuid: None,
                bios_serial: None,
                mac_addresses: vec![],
            })
            .await
            .unwrap();
        format!("{}{}", r.certificate_chain_pem, key.serialize_pem())
    }

    #[sqlx::test(migrations = false)]
    async fn real_cache_serves_and_falls_back(pool: PgPool) {
        let e = env(pool, 1).await;
        // install=false：每個派送都會下載（偵測不到安裝結果，回報 failed 但會帶來源）
        let (a, mut worker, _runner, _w, d1) = setup(&e, 0, false).await;
        let rc = real_cache(&e).await;
        let c = ServerClient::new(&e.url(), &e.root_pem(), a.state().identity_pem()).unwrap();
        let w = work(&a, &e, assignments(&c).await);
        worker.pass(&via(&w, &rc.url, true)).await;
        assert_eq!(source_of(&e, d1).await.as_deref(), Some("cache"));
        assert_eq!(rc.cache.state.central.downloads_started(), 1);

        // 第二台從快取下載：快取不再向中央下載
        let spec = w.assignments[0].package.clone();
        let other = other_device(&e).await;
        let oc = ServerClient::new(&rc.url, &e.root_pem(), Some(other.clone())).unwrap();
        oc.verify_package(&spec).await.unwrap();
        assert_eq!(rc.cache.state.central.downloads_started(), 1);

        // 只派送給「高雄」群組的套件：沒有群組的裝置向快取要 → 403
        let g = {
            let mut conn = e.pool.acquire().await.unwrap();
            endpoint_server::groups::find_or_create(&mut conn, "高雄")
                .await
                .unwrap()
        };
        let chunk: Result<bytes::Bytes, std::io::Error> =
            Ok(bytes::Bytes::from_static(b"MZ kaohsiung only"));
        let st = store::save(
            &e.state.package_dir,
            futures_util::stream::iter(vec![chunk]),
        )
        .await
        .unwrap();
        let pkg = admin::create_package(
            &e.pool,
            &e.state.package_dir,
            &st,
            "ks.exe",
            None,
            &admin::PackageInput {
                name: "KS App".into(),
                version: "1.0".into(),
                kind: "exe".into(),
                install_args: "/S".into(),
                uninstall_args: String::new(),
                success_codes: vec![],
                detect_name: "KS App*".into(),
                detect_publisher: String::new(),
                detect_min_version: String::new(),
            },
            "admin",
        )
        .await
        .unwrap();
        admin::create_deployment(
            &e.pool,
            &admin::DeploymentInput {
                name: "KS".into(),
                package_id: pkg,
                action: "install".into(),
                include: vec![g],
                exclude: vec![],
                pilot_group_id: None,
                max_failure_pct: 50,
                min_samples: 100,
            },
            "admin",
        )
        .await
        .unwrap();
        e.state.deploy.invalidate();
        let ks = PackageSpec {
            id: pkg,
            sha256: st.sha256.clone(),
            size: st.size,
            ..spec.clone()
        };
        assert!(matches!(
            oc.verify_package(&ks).await,
            Err(DownloadError::Forbidden)
        ));

        // 快取停機：第二個派送改向中央
        rc.serve.abort();
        let d2 = deployment(&e, b"MZ second installer", "/S").await;
        let w = work(&a, &e, assignments(&c).await);
        worker.pass(&via(&w, &rc.url, true)).await;
        assert_eq!(source_of(&e, d2).await.as_deref(), Some("central"));
    }
}

mod updates {
    use super::*;
    use endpoint_agent::updates::host::MemoryHost;
    use endpoint_agent::updates::worker::{UpdateWork, UpdateWorker};
    use endpoint_server::updates::admin::{self, PolicyInput};
    use endpoint_server::updates::policy::PolicySettings;
    use protocol::update::PolicyData;
    use std::sync::atomic::Ordering;
    use tokio::sync::watch;

    struct Setup {
        a: Agent<Fake>,
        rx: watch::Receiver<Option<UpdateWork>>,
        host: Arc<MemoryHost>,
        worker: UpdateWorker<Fake, MemoryHost>,
        policy: i64,
        device: uuid::Uuid,
        fake: Arc<Fake>,
    }

    fn input(days: u32, group: i64) -> PolicyInput {
        PolicyInput {
            name: "一般".into(),
            settings: PolicySettings {
                quality_defer_days: Some(days),
                ..Default::default()
            },
            groups: vec![group],
        }
    }

    /// 註冊後把裝置放進「台北」，建立套用台北的原則（品質更新延後 7 天）
    async fn setup(e: &Env) -> Setup {
        let (tx, rx) = watch::channel(None);
        let mut a = Agent::new(e.dir.path(), Fake::new())
            .unwrap()
            .with_updates(tx);
        a.run_cycle().await;
        let device = a.state().device_id.unwrap();
        let g = {
            let mut c = e.pool.acquire().await.unwrap();
            endpoint_server::groups::find_or_create(&mut c, "台北")
                .await
                .unwrap()
        };
        sqlx::query("UPDATE devices SET group_id = $1 WHERE id = $2")
            .bind(g)
            .bind(device)
            .execute(&e.pool)
            .await
            .unwrap();
        let policy = admin::create_policy(&e.pool, &input(7, g), "admin")
            .await
            .unwrap();
        e.state.updates.invalidate();
        a.run_cycle().await;
        let host = Arc::new(MemoryHost::default());
        let fake = Arc::new(Fake::new());
        let worker = UpdateWorker::new(e.dir.path(), fake.clone(), host.clone());
        Setup {
            a,
            rx,
            host,
            worker,
            policy,
            device,
            fake,
        }
    }

    fn work(s: &Setup) -> UpdateWork {
        s.rx.borrow().clone().expect("伺服器支援更新原則")
    }

    async fn row(e: &Env, device: uuid::Uuid) -> (String, String, Option<i32>) {
        sqlx::query_as(
            "SELECT state, detail, revision FROM update_policy_status WHERE device_id = $1",
        )
        .bind(device)
        .fetch_one(&e.pool)
        .await
        .unwrap()
    }

    fn value(s: &Setup, name: &str) -> Option<PolicyData> {
        s.host.values.lock().unwrap().get(name).cloned()
    }

    #[sqlx::test(migrations = false)]
    async fn policy_applied_conflict_and_released(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        assert_eq!(w.policy.as_ref().unwrap().id, s.policy);
        s.worker.pass(&w).await;
        assert_eq!(
            value(&s, "DeferQualityUpdatesPeriodInDays"),
            Some(PolicyData::Dword(7))
        );
        assert_eq!(value(&s, "DeferQualityUpdates"), Some(PolicyData::Dword(1)));
        assert_eq!(
            row(&e, s.device).await,
            ("applied".into(), "".into(), Some(1))
        );

        // 別人（例如 GPO）改了值：回報衝突，不寫回
        s.host.values.lock().unwrap().insert(
            "DeferQualityUpdatesPeriodInDays".into(),
            PolicyData::Dword(30),
        );
        s.worker.pass(&w).await;
        let (state, detail, _) = row(&e, s.device).await;
        assert_eq!(state, "conflict");
        assert!(
            detail.contains("DeferQualityUpdatesPeriodInDays"),
            "{detail}"
        );
        assert_eq!(
            value(&s, "DeferQualityUpdatesPeriodInDays"),
            Some(PolicyData::Dword(30))
        );

        // 原則改版：重新寫入
        let g = e.state.updates.get(&e.pool).await.unwrap();
        let group = *g.by_group.keys().next().unwrap();
        admin::update_policy(&e.pool, s.policy, &input(14, group), None, "admin")
            .await
            .unwrap();
        e.state.updates.invalidate();
        s.a.run_cycle().await;
        s.worker.pass(&work(&s)).await;
        assert_eq!(
            value(&s, "DeferQualityUpdatesPeriodInDays"),
            Some(PolicyData::Dword(14))
        );
        assert_eq!(
            row(&e, s.device).await,
            ("applied".into(), "".into(), Some(2))
        );

        // 刪除原則：清除自己寫的值
        admin::delete_policy(&e.pool, s.policy, "admin")
            .await
            .unwrap();
        e.state.updates.invalidate();
        s.a.run_cycle().await;
        let w = work(&s);
        assert!(w.policy.is_none());
        s.worker.pass(&w).await;
        assert!(s.host.values.lock().unwrap().is_empty());
        assert_eq!(
            row(&e, s.device).await,
            ("unmanaged".into(), "".into(), None)
        );
    }

    #[sqlx::test(migrations = false)]
    async fn write_failure_is_error_and_retried(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        s.host.fail_writes.store(true, Ordering::SeqCst);
        s.worker.pass(&w).await;
        let (state, detail, _) = row(&e, s.device).await;
        assert_eq!(state, "error");
        assert!(!detail.is_empty());
        s.host.fail_writes.store(false, Ordering::SeqCst);
        s.worker.pass(&w).await;
        assert_eq!(row(&e, s.device).await.0, "applied");
    }

    #[sqlx::test(migrations = false)]
    async fn status_not_resent_when_unchanged(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        let now = chrono::Utc::now();
        s.worker.pass_at(&w, now).await;
        let first = s.worker.state().sent_at;
        assert_eq!(first, Some(now));
        s.worker.pass_at(&w, now + chrono::Duration::hours(1)).await;
        assert_eq!(s.worker.state().sent_at, first, "內容沒變不重送");
        let later = now + chrono::Duration::hours(25);
        s.worker.pass_at(&w, later).await;
        assert_eq!(s.worker.state().sent_at, Some(later), "滿 24 小時重送");
    }

    #[sqlx::test(migrations = false)]
    async fn reboot_pending_since_is_tracked(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        let since = |e: &Env, d| {
            let pool = e.pool.clone();
            async move {
                let r: (bool, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
                    "SELECT reboot_pending, reboot_pending_since FROM update_policy_status \
                     WHERE device_id = $1",
                )
                .bind(d)
                .fetch_one(&pool)
                .await
                .unwrap();
                r
            }
        };
        let t0 = chrono::DateTime::from_timestamp(chrono::Utc::now().timestamp(), 0).unwrap();
        s.host.reboot.store(true, Ordering::SeqCst);
        s.worker.pass_at(&w, t0).await;
        assert_eq!(since(&e, s.device).await, (true, Some(t0)));
        s.worker.pass_at(&w, t0 + chrono::Duration::hours(2)).await;
        assert_eq!(since(&e, s.device).await, (true, Some(t0)), "起始時間不變");
        s.host.reboot.store(false, Ordering::SeqCst);
        s.worker.pass_at(&w, t0 + chrono::Duration::hours(3)).await;
        assert_eq!(since(&e, s.device).await, (false, None));
    }

    async fn patch_date(e: &Env, device: uuid::Uuid) -> Option<chrono::NaiveDate> {
        sqlx::query_scalar("SELECT last_patch_date FROM update_policy_status WHERE device_id = $1")
            .bind(device)
            .fetch_one(&e.pool)
            .await
            .unwrap()
    }

    /// 寫完登錄檔就先存檔：之後的 WMI、回報途中被中斷（服務停止、重開機）也記得自己寫過的值
    #[sqlx::test(migrations = false)]
    async fn written_is_saved_before_reporting(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        s.fake.hang_patches_ms.store(3000, Ordering::SeqCst);
        assert!(
            tokio::time::timeout(Duration::from_millis(1000), s.worker.pass(&w))
                .await
                .is_err(),
            "pass 卡在 WMI"
        );
        let saved = endpoint_agent::updates::state::UpdateState::load(e.dir.path());
        assert!(
            saved.applied.written.contains_key("DeferQualityUpdates"),
            "{saved:?}"
        );
    }

    /// WMI 卡住不能讓 worker 停擺；失敗時沿用上次的日期，不在「未知」與正常之間跳動
    #[sqlx::test(migrations = false)]
    async fn hung_wmi_keeps_last_patch_date(pool: PgPool) {
        let e = env(pool, 1).await;
        let s = setup(&e).await;
        *s.fake.installed_on.lock().unwrap() = Some("9/10/2026".into());
        let mut worker = UpdateWorker::new(e.dir.path(), s.fake.clone(), s.host.clone())
            .with_patch_timeout(Duration::from_millis(200));
        let w = work(&s);
        let now = chrono::Utc::now();
        worker.pass_at(&w, now).await;
        let d = chrono::NaiveDate::from_ymd_opt(2026, 9, 10);
        assert_eq!(patch_date(&e, s.device).await, d);
        s.fake.hang_patches_ms.store(3000, Ordering::SeqCst);
        let start = std::time::Instant::now();
        // 25 小時後：一定會重送
        worker.pass_at(&w, now + chrono::Duration::hours(25)).await;
        assert!(start.elapsed() < Duration::from_secs(2), "沒有等 WMI");
        assert_eq!(patch_date(&e, s.device).await, d);
        assert_eq!(
            worker.state().sent_at,
            Some(now + chrono::Duration::hours(25))
        );
    }

    /// 端點上的未來日期（時鐘或 WMI 垃圾資料）不送：否則伺服器永遠回 400、狀態永遠進不去
    #[sqlx::test(migrations = false)]
    async fn future_patch_date_is_dropped(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        *s.fake.installed_on.lock().unwrap() = Some("1/1/2099".into());
        s.worker.pass(&work(&s)).await;
        assert_eq!(patch_date(&e, s.device).await, None);
        assert_eq!(row(&e, s.device).await.0, "applied");
    }

    /// 移出範圍時刪除失敗：記為 error、保留 written，下次再刪
    #[sqlx::test(migrations = false)]
    async fn read_failure_does_not_overwrite_next_round(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        s.worker.pass(&w).await;
        // 別人（例如 GPO）改了值：衝突，不寫回
        let name = "DeferQualityUpdatesPeriodInDays";
        s.host
            .values
            .lock()
            .unwrap()
            .insert(name.into(), PolicyData::Dword(30));
        s.worker.pass(&w).await;
        assert_eq!(row(&e, s.device).await.0, "conflict");
        // 一輪讀取失敗：回報錯誤
        s.host.fail_reads.store(true, Ordering::SeqCst);
        s.worker.pass(&w).await;
        assert_eq!(row(&e, s.device).await.0, "error");
        // 恢復後仍是衝突，別人的值不被覆寫
        s.host.fail_reads.store(false, Ordering::SeqCst);
        s.worker.pass(&w).await;
        assert_eq!(row(&e, s.device).await.0, "conflict");
        assert_eq!(value(&s, name), Some(PolicyData::Dword(30)));
    }

    #[sqlx::test(migrations = false)]
    async fn read_failure_on_release_keeps_written(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        s.worker.pass(&work(&s)).await;
        admin::delete_policy(&e.pool, s.policy, "admin")
            .await
            .unwrap();
        e.state.updates.invalidate();
        s.a.run_cycle().await;
        let w = work(&s);
        s.host.fail_reads.store(true, Ordering::SeqCst);
        s.worker.pass(&w).await;
        assert_eq!(row(&e, s.device).await.0, "error");
        assert!(!s.worker.state().applied.written.is_empty(), "還要清");
        s.host.fail_reads.store(false, Ordering::SeqCst);
        s.worker.pass(&w).await;
        assert!(s.host.values.lock().unwrap().is_empty());
        assert_eq!(row(&e, s.device).await.0, "unmanaged");
    }

    #[sqlx::test(migrations = false)]
    async fn read_failure_is_error_not_conflict(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let w = work(&s);
        s.worker.pass(&w).await;
        assert_eq!(row(&e, s.device).await.0, "applied");
        let before = s.host.values.lock().unwrap().clone();
        s.host.fail_reads.store(true, Ordering::SeqCst);
        s.worker.pass(&w).await;
        let (state, detail, _) = row(&e, s.device).await;
        assert_eq!(state, "error", "{detail}");
        assert!(detail.contains("讀取"), "{detail}");
        assert_eq!(*s.host.values.lock().unwrap(), before, "不刪也不覆寫");
    }

    #[sqlx::test(migrations = false)]
    async fn release_failure_keeps_written_and_retries(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        s.worker.pass(&work(&s)).await;
        admin::delete_policy(&e.pool, s.policy, "admin")
            .await
            .unwrap();
        e.state.updates.invalidate();
        s.a.run_cycle().await;
        let w = work(&s);
        s.host.fail_writes.store(true, Ordering::SeqCst);
        s.worker.pass(&w).await;
        let (state, _, revision) = row(&e, s.device).await;
        assert_eq!(
            (state.as_str(), revision),
            ("error", None),
            "已移出原則：不再回報舊原則"
        );
        assert!(!s.worker.state().applied.written.is_empty());
        assert!(!s.host.values.lock().unwrap().is_empty());
        s.host.fail_writes.store(false, Ordering::SeqCst);
        s.worker.pass(&w).await;
        assert!(s.host.values.lock().unwrap().is_empty());
        assert_eq!(row(&e, s.device).await.0, "unmanaged");
    }
}

mod commands {
    use super::*;
    use endpoint_agent::commands::state::{CommandsState, Entry};
    use endpoint_agent::commands::worker::{CommandHost, CommandWork, CommandWorker};
    use endpoint_agent::deploy::worker::{RunOutput, RunResult};
    use endpoint_server::commands::runs::{self, RunInput, Target};
    use endpoint_server::commands::{Actor, scripts};
    use tokio::sync::watch;

    /// 記錄所有呼叫；shutdown 時記下伺服器上的指令狀態（確認先回報再關機）
    struct FakeHost {
        calls: Mutex<Vec<String>>,
        pool: PgPool,
        status_at_shutdown: Mutex<Option<String>>,
    }

    impl CommandHost for FakeHost {
        async fn collect_all(&self) {
            self.calls.lock().unwrap().push("collect".into());
        }
        fn apply_now(&self) {
            self.calls.lock().unwrap().push("apply".into());
        }
        async fn shutdown(&self, args: &str) -> std::io::Result<()> {
            self.calls.lock().unwrap().push(format!("shutdown {args}"));
            let s: Option<String> =
                sqlx::query_scalar("SELECT string_agg(status, ',') FROM command_targets")
                    .fetch_one(&self.pool)
                    .await
                    .unwrap();
            *self.status_at_shutdown.lock().unwrap() = s;
            Ok(())
        }
        async fn run_script(
            &self,
            path: &std::path::Path,
            _timeout: Duration,
        ) -> std::io::Result<RunOutput> {
            let content = std::fs::read_to_string(path)?;
            self.calls.lock().unwrap().push(format!("script {content}"));
            Ok(RunOutput {
                result: RunResult::Exited(3),
                output: "hi".into(),
            })
        }
    }

    struct Setup {
        a: Agent<Fake>,
        rx: watch::Receiver<Option<CommandWork>>,
        host: Arc<FakeHost>,
        device: uuid::Uuid,
    }

    fn admin(name: &str) -> Actor {
        Actor {
            username: name.into(),
            platform: true,
            groups: vec![],
        }
    }

    async fn setup(e: &Env) -> Setup {
        let (tx, rx) = watch::channel(None);
        let mut a = Agent::new(e.dir.path(), Fake::new())
            .unwrap()
            .with_commands(tx);
        a.run_cycle().await;
        let device = a.state().device_id.unwrap();
        let host = Arc::new(FakeHost {
            calls: Mutex::new(vec![]),
            pool: e.pool.clone(),
            status_at_shutdown: Mutex::new(None),
        });
        Setup {
            a,
            rx,
            host,
            device,
        }
    }

    async fn command(e: &Env, device: uuid::Uuid, action: &str, script_id: Option<i64>) {
        runs::create_run(
            &e.pool,
            &RunInput {
                action: action.into(),
                target: Target::Device(device),
                delay_minutes: None,
                script_id,
                expires_hours: 24,
            },
            &admin("admin"),
        )
        .await
        .unwrap();
    }

    async fn work(s: &mut Setup) -> CommandWork {
        s.a.run_cycle().await;
        s.rx.borrow().clone().expect("伺服器有下發指令清單")
    }

    async fn results(e: &Env) -> Vec<(String, Option<i32>, String)> {
        sqlx::query_as("SELECT status, exit_code, output FROM command_targets ORDER BY id")
            .fetch_all(&e.pool)
            .await
            .unwrap()
    }

    fn calls(s: &Setup) -> Vec<String> {
        s.host.calls.lock().unwrap().clone()
    }

    #[sqlx::test(migrations = false)]
    async fn collect_and_apply_reach_the_host_and_server(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        command(&e, s.device, "collect", None).await;
        command(&e, s.device, "apply", None).await;
        let w = work(&mut s).await;
        assert_eq!(w.commands.len(), 2);
        let mut worker = CommandWorker::new(e.dir.path(), s.host.clone());
        worker.pass(&w).await;
        assert_eq!(calls(&s), vec!["collect", "apply"]);
        let r = results(&e).await;
        assert!(r.iter().all(|x| x.0 == "succeeded"), "{r:?}");
        // 已回報：伺服器不再下發，再跑一輪也不會再呼叫
        let w = work(&mut s).await;
        assert!(w.commands.is_empty());
        worker.pass(&w).await;
        assert_eq!(calls(&s).len(), 2);
    }

    #[sqlx::test(migrations = false)]
    async fn reboot_reports_before_shutdown(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        command(&e, s.device, "reboot", None).await;
        let w = work(&mut s).await;
        CommandWorker::new(e.dir.path(), s.host.clone())
            .pass(&w)
            .await;
        let c = calls(&s);
        assert_eq!(c.len(), 1);
        assert!(c[0].starts_with("shutdown /r /t 600 "), "{c:?}");
        assert_eq!(
            s.host.status_at_shutdown.lock().unwrap().as_deref(),
            Some("succeeded"),
            "關機前結果已送到伺服器"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn reboot_runs_even_if_report_fails(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        command(&e, s.device, "reboot", None).await;
        let good = work(&mut s).await;
        let offline = CommandWork {
            server_url: "https://127.0.0.1:1".into(),
            ..good.clone()
        };
        let mut worker = CommandWorker::new(e.dir.path(), s.host.clone());
        worker.pass(&offline).await;
        assert_eq!(calls(&s).len(), 1, "網路斷也要重開機");
        let id = good.commands[0].id;
        assert!(!worker.state().entries[&id].reported);
        // 開機後（新的 worker 讀狀態檔）補送，不再重開
        let mut after = CommandWorker::new(e.dir.path(), s.host.clone());
        after.pass(&good).await;
        assert_eq!(calls(&s).len(), 1);
        assert_eq!(results(&e).await[0].0, "succeeded");
    }

    async fn approved_script(e: &Env, content: &str) -> i64 {
        let id = scripts::create_script(
            &e.pool,
            &scripts::ScriptInput {
                name: "測試".into(),
                description: String::new(),
                content: content.into(),
                timeout_minutes: 5,
            },
            &admin("alice"),
        )
        .await
        .unwrap();
        let sha: String = sqlx::query_scalar("SELECT sha256 FROM scripts WHERE id = $1")
            .bind(id)
            .fetch_one(&e.pool)
            .await
            .unwrap();
        scripts::approve_script(&e.pool, id, &sha, &admin("bob"))
            .await
            .unwrap();
        id
    }

    #[sqlx::test(migrations = false)]
    async fn immediate_reboot_runs_after_scripts_in_the_same_batch(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        runs::create_run(
            &e.pool,
            &RunInput {
                action: "reboot".into(),
                target: Target::Device(s.device),
                delay_minutes: Some(0),
                script_id: None,
                expires_hours: 24,
            },
            &admin("admin"),
        )
        .await
        .unwrap();
        let sid = approved_script(&e, "Write-Output before reboot").await;
        command(&e, s.device, "script", Some(sid)).await;
        let w = work(&mut s).await;
        assert_eq!(w.commands.len(), 2);
        CommandWorker::new(e.dir.path(), s.host.clone())
            .pass(&w)
            .await;
        let c = calls(&s);
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(c[0].starts_with("script "), "腳本先執行：{c:?}");
        assert!(c[1].starts_with("shutdown /r /t 0 "), "{c:?}");
    }

    #[sqlx::test(migrations = false)]
    async fn leftover_scripts_are_removed_on_start(pool: PgPool) {
        let e = env(pool, 1).await;
        let s = setup(&e).await;
        let dir = e.dir.path().join("scripts");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("42.ps1"), "Remove-Item C:\\").unwrap();
        let _worker = CommandWorker::new(e.dir.path(), s.host.clone());
        assert!(!dir.join("42.ps1").exists());
    }

    #[sqlx::test(migrations = false)]
    async fn script_hash_mismatch_is_not_run(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let sid = approved_script(&e, "Write-Output ok").await;
        command(&e, s.device, "script", Some(sid)).await;
        let mut w = work(&mut s).await;
        w.commands[0].script.as_mut().unwrap().content = r"Remove-Item C:\".into();
        CommandWorker::new(e.dir.path(), s.host.clone())
            .pass(&w)
            .await;
        assert!(calls(&s).is_empty());
        let r = &results(&e).await[0];
        assert_eq!(r.0, "failed");
        assert!(r.2.contains("雜湊不符"), "{r:?}");
    }

    #[sqlx::test(migrations = false)]
    async fn script_runs_and_file_is_removed(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        let sid = approved_script(&e, "Write-Output hi; exit 3").await;
        command(&e, s.device, "script", Some(sid)).await;
        let w = work(&mut s).await;
        CommandWorker::new(e.dir.path(), s.host.clone())
            .pass(&w)
            .await;
        assert_eq!(calls(&s), vec!["script \u{feff}Write-Output hi; exit 3"]);
        assert_eq!(
            results(&e).await[0],
            ("failed".into(), Some(3), "hi".into())
        );
        let id = w.commands[0].id;
        assert!(
            !e.dir
                .path()
                .join("scripts")
                .join(format!("{id}.ps1"))
                .exists()
        );
    }

    #[sqlx::test(migrations = false)]
    async fn interrupted_command_is_reported_not_rerun(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        command(&e, s.device, "reboot", None).await;
        let w = work(&mut s).await;
        let mut st = CommandsState::default();
        st.entries.insert(
            w.commands[0].id,
            Entry {
                started_at: Some(chrono::Utc::now()),
                result: None,
                reported: false,
            },
        );
        st.save(e.dir.path()).unwrap();
        CommandWorker::new(e.dir.path(), s.host.clone())
            .pass(&w)
            .await;
        assert!(calls(&s).is_empty());
        let r = &results(&e).await[0];
        assert_eq!(
            (r.0.as_str(), r.2.as_str()),
            ("failed", endpoint_agent::commands::logic::INTERRUPTED)
        );
    }

    /// 狀態檔寫不進去（磁碟滿、被鎖住）：不能執行，否則中斷後會重跑或重複關機
    #[sqlx::test(migrations = false)]
    async fn unsaved_start_is_not_run(pool: PgPool) {
        let e = env(pool, 1).await;
        let mut s = setup(&e).await;
        command(&e, s.device, "reboot", None).await;
        let w = work(&mut s).await;
        // 讓 commands.json 無法寫入：同名的資料夾
        std::fs::create_dir(e.dir.path().join("commands.json")).unwrap();
        CommandWorker::new(e.dir.path(), s.host.clone())
            .pass(&w)
            .await;
        assert!(calls(&s).is_empty(), "{:?}", calls(&s));
        let r = &results(&e).await[0];
        assert_eq!(r.0, "failed");
        assert!(r.2.contains("狀態檔"), "{r:?}");
    }
}
