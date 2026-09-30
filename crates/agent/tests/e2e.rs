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
                uninstall_args: String::new(),
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
                action: "install".into(),
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
            if self.install {
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
        let r = tokio::time::timeout(Duration::from_millis(500), hang.pass(&w)).await;
        assert!(r.is_err(), "安裝卡住時 pass 被中斷");
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
        let worker = UpdateWorker::new(e.dir.path(), Arc::new(Fake::new()), host.clone());
        Setup {
            a,
            rx,
            host,
            worker,
            policy,
            device,
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
        admin::update_policy(&e.pool, s.policy, &input(14, group), "admin")
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
}
