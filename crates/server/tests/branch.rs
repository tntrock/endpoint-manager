mod common;

use common::TestServer;
use endpoint_server::branch::caches;
use endpoint_server::branch::sites::{self, SiteInput};
use endpoint_server::deploy::admin::{self, DeploymentInput, PackageInput, Transition};
use endpoint_server::deploy::store;
use endpoint_server::tokens::{self, TokenKind};
use protocol::branch::{
    CacheAuthorize, CacheAuthorizeResponse, CacheCheckin, CacheCheckinResponse, CacheEnrollPoll,
    CacheEnrollPollResponse, CacheEnrollRequest, CacheEnrollResponse, CacheEnrollState,
    CachePackage, DownloadSource, StoredPackage,
};
use protocol::deploy::{DeployResult, DeployStatus};
use sqlx::PgPool;

fn input(name: &str, cidrs: &[&str]) -> SiteInput {
    SiteInput {
        name: name.into(),
        cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
        fallback_to_central: false,
        bandwidth_limit_mbps: Some(50),
        disk_limit_gb: 100,
    }
}

async fn generation(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT generation FROM branch_state")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn insert_cache(pool: &PgPool, site_id: i64, status: &str) -> i64 {
    let id = sqlx::query_scalar(
        "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, poll_secret_hash, status) \
         VALUES ('快取', $1, 'https://cache-tp.corp:8443', ARRAY['cache-tp.corp'], 'csr', 'x', $2) \
         RETURNING id",
    )
    .bind(site_id)
    .bind(status)
    .fetch_one(pool)
    .await
    .unwrap();
    bump(pool).await;
    id
}

/// 快取狀態不經過 sites 模組：直接改資料庫時要自己推進 generation
async fn bump(pool: &PgPool) {
    sqlx::query("UPDATE branch_state SET generation = generation + 1")
        .execute(pool)
        .await
        .unwrap();
}

async fn checkin(s: &TestServer, a: &common::TestAgent) -> protocol::CheckinResponse {
    s.state.branch.invalidate();
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.7.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec!["127.0.0.5".into()],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn checkin_delivers_package_source(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let g0 = generation(&s.pool).await;
    let site = sites::create_site(&s.pool, &input("台北", &["127.0.0.0/8"]), "admin")
        .await
        .unwrap();
    assert_eq!(generation(&s.pool).await, g0 + 1);
    assert!(
        checkin(&s, &a).await.package_source.is_none(),
        "據點沒有快取"
    );

    let cache = insert_cache(&s.pool, site, "active").await;
    let src = checkin(&s, &a)
        .await
        .package_source
        .expect("有使用中的快取");
    assert_eq!(src.cache_id, cache);
    assert_eq!(src.url, "https://cache-tp.corp:8443");
    assert!(!src.fallback_to_central);

    sqlx::query("UPDATE caches SET status = 'disabled' WHERE id = $1")
        .bind(cache)
        .execute(&s.pool)
        .await
        .unwrap();
    bump(&s.pool).await;
    assert!(checkin(&s, &a).await.package_source.is_none(), "快取已停用");

    sqlx::query("UPDATE caches SET status = 'active' WHERE id = $1")
        .bind(cache)
        .execute(&s.pool)
        .await
        .unwrap();
    bump(&s.pool).await;
    assert!(checkin(&s, &a).await.package_source.is_some());
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(checkin(&s, &a).await.package_source.is_none(), "停用的裝置");
}

#[sqlx::test(migrations = false)]
async fn site_validation_and_delete(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = sites::create_site(
        &s.pool,
        &input("台北", &["10.1.2.3/16", "10.1.0.0/16"]),
        "admin",
    )
    .await
    .unwrap();
    let stored: Vec<String> = sqlx::query_scalar("SELECT cidrs::text[] FROM sites WHERE id = $1")
        .bind(tp)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(stored, vec!["10.1.0.0/16"], "正規化並去重");

    let e = sites::create_site(&s.pool, &input("高雄", &["10.1.0.0/16"]), "admin")
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("台北"), "{e:#}");
    let e = sites::create_site(&s.pool, &input("台北", &["10.2.0.0/16"]), "admin")
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("名稱"), "{e:#}");
    for bad in [
        input(" ", &["10.3.0.0/16"]),
        input("a\tb", &["10.3.0.0/16"]),
        input("空網段", &[]),
        input("壞網段", &["10.3.0.0"]),
        SiteInput {
            disk_limit_gb: 0,
            ..input("磁碟", &["10.3.0.0/16"])
        },
        SiteInput {
            bandwidth_limit_mbps: Some(100_001),
            ..input("頻寬", &["10.3.0.0/16"])
        },
    ] {
        assert!(
            sites::create_site(&s.pool, &bad, "admin").await.is_err(),
            "{}",
            bad.name
        );
    }
    // 更新自己的網段不算重複
    sites::update_site(&s.pool, tp, &input("台北總部", &["10.1.0.0/16"]), "admin")
        .await
        .unwrap();

    let cache = insert_cache(&s.pool, tp, "active").await;
    sites::delete_site(&s.pool, tp, "admin").await.unwrap();
    let site_id: Option<i64> = sqlx::query_scalar("SELECT site_id FROM caches WHERE id = $1")
        .bind(cache)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(site_id, None);
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action IN ('site_create', 'site_update', 'site_delete')",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(n, 3);
    assert!(
        sites::delete_site(&s.pool, tp, "admin").await.is_err(),
        "已刪除"
    );
}

async fn token(s: &TestServer, kind: TokenKind) -> String {
    tokens::create_token(
        &s.pool,
        &tokens::NewToken {
            name: "cache token".into(),
            group_id: None,
            expires_at: None,
            max_uses: 5,
            created_by: "test".into(),
            kind,
        },
    )
    .await
    .unwrap()
    .1
}

fn enroll_req(token: &str, name: &str, csr: &str) -> CacheEnrollRequest {
    CacheEnrollRequest {
        token: token.into(),
        name: name.into(),
        url: "https://cache-tp.test:8443".into(),
        dns_names: vec!["cache-tp.test".into(), "127.0.0.1".into()],
        csr_pem: csr.into(),
    }
}

async fn cache_enroll(s: &TestServer, req: &CacheEnrollRequest) -> reqwest::Response {
    s.client(None)
        .post(s.url("/v1/cache/enroll"))
        .json(req)
        .send()
        .await
        .unwrap()
}

async fn poll(s: &TestServer, cache_id: i64, secret: &str) -> reqwest::Response {
    s.client(None)
        .post(s.url("/v1/cache/enroll/poll"))
        .json(&CacheEnrollPoll {
            cache_id,
            poll_secret: secret.into(),
        })
        .send()
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn cache_enroll_approve_and_certificate(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let device_tok = token(&s, TokenKind::Device).await;
    let cache_tok = token(&s, TokenKind::Cache).await;
    let (csr, key_pem) = common::make_csr();

    let r = cache_enroll(&s, &enroll_req(&device_tok, "台北快取", &csr)).await;
    assert_eq!(r.status(), 401, "裝置金鑰不能註冊快取");
    let r = s.enroll_with_csr(&cache_tok, &csr, None, None).await;
    assert_eq!(r.status(), 401, "快取金鑰不能註冊裝置");
    let r = cache_enroll(&s, &enroll_req(&cache_tok, "壞 CSR", "not a csr")).await;
    assert_eq!(r.status(), 400);

    let r = cache_enroll(&s, &enroll_req(&cache_tok, "台北快取", &csr)).await;
    assert_eq!(r.status(), 200);
    let e: CacheEnrollResponse = r.json().await.unwrap();
    let r = cache_enroll(&s, &enroll_req(&cache_tok, "台北快取", &csr)).await;
    assert_eq!(r.status(), 409, "名稱重複");

    let p: CacheEnrollPollResponse = poll(&s, e.cache_id, &e.poll_secret)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(p.state, CacheEnrollState::Pending);
    assert!(p.certificate_chain_pem.is_none());
    assert_eq!(poll(&s, e.cache_id, "wrong").await.status(), 401);

    let site = sites::create_site(&s.pool, &input("台北", &["127.0.0.0/8"]), "admin")
        .await
        .unwrap();
    caches::approve(&s.pool, &s.state.ca, e.cache_id, site, "admin")
        .await
        .unwrap();
    assert!(
        caches::reject(&s.pool, e.cache_id, "admin").await.is_err(),
        "只能拒絕待核准的快取"
    );
    let p: CacheEnrollPollResponse = poll(&s, e.cache_id, &e.poll_secret)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(p.state, CacheEnrollState::Approved);
    assert_eq!(p.root_pem.as_deref(), Some(s.root_pem.as_str()));
    let chain = p.certificate_chain_pem.unwrap();

    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(chain.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let san = format!(
        "{:?}",
        cert.subject_alternative_name().unwrap().unwrap().value
    );
    assert!(
        san.contains("cache-tp.test") && san.contains("IPAddress([127, 0, 0, 1])"),
        "{san}"
    );
    let eku = cert.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.server_auth && eku.client_auth);

    // 快取憑證不能當裝置用
    let cache_identity = common::TestAgent {
        device_id: uuid::Uuid::nil(),
        key_pem,
        chain_pem: chain,
    };
    let r = s
        .client(Some(&cache_identity))
        .post(s.url("/v1/checkin"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // 第二台快取不能核准到已有快取的據點；拒絕待核准的可以
    let (csr2, _) = common::make_csr();
    let e2: CacheEnrollResponse = cache_enroll(&s, &enroll_req(&cache_tok, "第二台", &csr2))
        .await
        .json()
        .await
        .unwrap();
    assert!(
        caches::approve(&s.pool, &s.state.ca, e2.cache_id, site, "admin")
            .await
            .is_err()
    );
    caches::reject(&s.pool, e2.cache_id, "admin").await.unwrap();
    let p: CacheEnrollPollResponse = poll(&s, e2.cache_id, &e2.poll_secret)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(p.state, CacheEnrollState::Rejected);

    for action in ["cache_enroll", "cache_approve", "cache_reject"] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1")
            .bind(action)
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert!(n >= 1, "{action}");
    }
}

/// 註冊並核准一台快取（指定據點），回傳 (cache_id, 快取憑證身分)
async fn approved_cache(s: &TestServer, site: i64) -> (i64, common::TestAgent) {
    let tok = token(s, TokenKind::Cache).await;
    let (csr, key_pem) = common::make_csr();
    let e: CacheEnrollResponse = cache_enroll(s, &enroll_req(&tok, "台北快取", &csr))
        .await
        .json()
        .await
        .unwrap();
    caches::approve(&s.pool, &s.state.ca, e.cache_id, site, "admin")
        .await
        .unwrap();
    let p: CacheEnrollPollResponse = poll(s, e.cache_id, &e.poll_secret)
        .await
        .json()
        .await
        .unwrap();
    let identity = common::TestAgent {
        device_id: uuid::Uuid::nil(),
        key_pem,
        chain_pem: p.certificate_chain_pem.unwrap(),
    };
    (e.cache_id, identity)
}

async fn server_package(s: &TestServer, data: &[u8]) -> i64 {
    let v: Vec<Result<axum::body::Bytes, std::io::Error>> =
        vec![Ok(axum::body::Bytes::copy_from_slice(data))];
    let st = store::save(&s.state.package_dir, futures_util::stream::iter(v))
        .await
        .unwrap();
    admin::create_package(
        &s.pool,
        &s.state.package_dir,
        &st,
        "7z.exe",
        None,
        &PackageInput {
            name: "7-Zip".into(),
            version: "23.01".into(),
            kind: "exe".into(),
            install_args: "/S".into(),
            uninstall_args: String::new(),
            success_codes: vec![],
            detect_name: "7-Zip*".into(),
            detect_publisher: String::new(),
            detect_min_version: "23.01".into(),
        },
        "admin",
    )
    .await
    .unwrap()
}

async fn deployment(s: &TestServer, package_id: i64, name: &str) -> i64 {
    let d = admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            name: name.into(),
            package_id,
            action: "install".into(),
            include: vec![],
            exclude: vec![],
            pilot_group_id: None,
            max_failure_pct: 10,
            min_samples: 20,
        },
        "admin",
    )
    .await
    .unwrap();
    s.state.deploy.invalidate();
    d
}

async fn cache_checkin(
    s: &TestServer,
    c: &common::TestAgent,
    stored: Vec<StoredPackage>,
) -> reqwest::Response {
    s.client(Some(c))
        .post(s.url("/v1/cache/checkin"))
        .json(&CacheCheckin {
            version: "0.7.0".into(),
            disk_used_bytes: 1234,
            stored,
        })
        .send()
        .await
        .unwrap()
}

async fn authorize(s: &TestServer, c: &common::TestAgent, fp: &str, pkg: i64) -> reqwest::Response {
    s.client(Some(c))
        .post(s.url("/v1/cache/authorize"))
        .json(&CacheAuthorize {
            device_cert_fingerprint: fp.into(),
            package_id: pkg,
        })
        .send()
        .await
        .unwrap()
}

async fn allowed(s: &TestServer, c: &common::TestAgent, fp: &str, pkg: i64) -> bool {
    let r = authorize(s, c, fp, pkg).await;
    assert_eq!(r.status(), 200);
    r.json::<CacheAuthorizeResponse>().await.unwrap().allowed
}

fn fingerprint_of(a: &common::TestAgent) -> String {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::pem_slice_iter(a.chain_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    endpoint_server::ca::fingerprint(&der)
}

#[sqlx::test(migrations = false)]
async fn cache_api_checkin_content_authorize(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let site = sites::create_site(&s.pool, &input("台北", &["127.0.0.0/8"]), "admin")
        .await
        .unwrap();
    let (cache_id, c) = approved_cache(&s, site).await;
    let data = b"MZ fake installer".repeat(100);
    let pkg = server_package(&s, &data).await;
    let other = server_package(&s, b"not deployed").await;
    let dep = deployment(&s, pkg, "7-Zip 全公司").await;
    let dev = s.enroll_ok(&s.create_token(1).await, None, None).await;

    // checkin：應預先下載的套件、據點上限，並記錄已存套件（不存在的 id 略過）
    let r = cache_checkin(
        &s,
        &c,
        vec![
            StoredPackage {
                package_id: pkg,
                size: data.len() as u64,
            },
            StoredPackage {
                package_id: 99_999,
                size: 1,
            },
        ],
    )
    .await;
    assert_eq!(r.status(), 200);
    let resp: CacheCheckinResponse = r.json().await.unwrap();
    let sha: String = sqlx::query_scalar("SELECT sha256 FROM packages WHERE id = $1")
        .bind(pkg)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(
        resp.packages,
        vec![CachePackage {
            id: pkg,
            sha256: sha,
            size: data.len() as u64
        }]
    );
    assert_eq!(
        (resp.bandwidth_limit_mbps, resp.disk_limit_gb),
        (Some(50), 100)
    );
    assert!(!resp.renew_certificate);
    let rows: Vec<(i64, i64)> =
        sqlx::query_as("SELECT package_id, size FROM cache_packages WHERE cache_id = $1")
            .bind(cache_id)
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(rows, vec![(pkg, data.len() as i64)]);
    let (version, used): (Option<String>, Option<i64>) =
        sqlx::query_as("SELECT version, disk_used_bytes FROM caches WHERE id = $1")
            .bind(cache_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((version.as_deref(), used), (Some("0.7.0"), Some(1234)));
    // 下次回報清單變了：差異寫入
    cache_checkin(&s, &c, vec![]).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM cache_packages")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let too_many = (0..=protocol::branch::MAX_STORED as i64)
        .map(|i| StoredPackage {
            package_id: i,
            size: 1,
        })
        .collect();
    assert_eq!(cache_checkin(&s, &c, too_many).await.status(), 400);

    // 套件內容：清單內的才給
    let get = |id: i64| {
        let cl = s.client(Some(&c));
        let url = s.url(&format!("/v1/cache/packages/{id}/content"));
        async move { cl.get(url).send().await.unwrap() }
    };
    let r = get(pkg).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), data.as_slice());
    assert_eq!(get(other).await.status(), 404);

    // authorize
    let fp = fingerprint_of(&dev);
    assert!(allowed(&s, &c, &fp, pkg).await);
    assert!(!allowed(&s, &c, &fp, other).await, "沒被指派的套件");
    assert!(!allowed(&s, &c, &"0".repeat(64), pkg).await, "不存在的指紋");
    assert_eq!(authorize(&s, &c, "xyz", pkg).await.status(), 400);
    admin::set_stage(&s.pool, dep, Transition::Pause, "admin")
        .await
        .unwrap();
    s.state.deploy.invalidate();
    assert!(allowed(&s, &c, &fp, pkg).await, "暫停中的派送仍允許");
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(dev.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(!allowed(&s, &c, &fp, pkg).await, "非使用中的裝置");
    sqlx::query("UPDATE devices SET status = 'active' WHERE id = $1")
        .bind(dev.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE device_certs SET revoked_at = now() WHERE fingerprint = $1")
        .bind(&fp)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(!allowed(&s, &c, &fp, pkg).await, "已撤銷的裝置憑證");

    // 停止派送後清單是空的
    admin::set_stage(&s.pool, dep, Transition::Stop, "admin")
        .await
        .unwrap();
    s.state.deploy.invalidate();
    let resp: CacheCheckinResponse = cache_checkin(&s, &c, vec![]).await.json().await.unwrap();
    assert!(resp.packages.is_empty());

    // 裝置憑證不能呼叫快取 API
    let dev2 = s.enroll_ok(&s.create_token(1).await, None, None).await;
    assert_eq!(cache_checkin(&s, &dev2, vec![]).await.status(), 401);

    // 停用後三個 API 都拒絕
    caches::set_disabled(&s.pool, &s.state.ca, cache_id, true, "admin")
        .await
        .unwrap();
    assert_eq!(cache_checkin(&s, &c, vec![]).await.status(), 401);
    assert_eq!(get(pkg).await.status(), 401);
    assert_eq!(authorize(&s, &c, &fp, pkg).await.status(), 401);
    // 重新啟用：輪詢可拿到新憑證（舊憑證已撤銷）
    caches::set_disabled(&s.pool, &s.state.ca, cache_id, false, "admin")
        .await
        .unwrap();
    assert_eq!(
        cache_checkin(&s, &c, vec![]).await.status(),
        401,
        "舊憑證已撤銷"
    );
}

#[sqlx::test(migrations = false)]
async fn cache_renew_and_result_source(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let site = sites::create_site(&s.pool, &input("台北", &["127.0.0.0/8"]), "admin")
        .await
        .unwrap();
    let (cache_id, c) = approved_cache(&s, site).await;
    let renew = |a: &common::TestAgent| {
        let cl = s.client(Some(a));
        let url = s.url("/v1/cache/renew");
        let (csr, key) = common::make_csr();
        async move {
            let r = cl
                .post(url)
                .json(&protocol::RenewRequest { csr_pem: csr })
                .send()
                .await
                .unwrap();
            (r, key)
        }
    };
    assert_eq!(renew(&c).await.0.status(), 400, "還不需要換發");
    sqlx::query(
        "UPDATE cache_certs SET not_after = now() + interval '10 days' WHERE cache_id = $1",
    )
    .bind(cache_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let resp: CacheCheckinResponse = cache_checkin(&s, &c, vec![]).await.json().await.unwrap();
    assert!(resp.renew_certificate);
    let (r, key_pem) = renew(&c).await;
    assert_eq!(r.status(), 200);
    let renewed = common::TestAgent {
        device_id: uuid::Uuid::nil(),
        key_pem,
        chain_pem: r
            .json::<protocol::RenewResponse>()
            .await
            .unwrap()
            .certificate_chain_pem,
    };
    assert_eq!(cache_checkin(&s, &renewed, vec![]).await.status(), 200);
    assert_eq!(
        cache_checkin(&s, &c, vec![]).await.status(),
        200,
        "舊憑證保留到期"
    );

    // 派送結果記錄下載來源
    let pkg = server_package(&s, b"x").await;
    let dep = deployment(&s, pkg, "來源").await;
    let dev = s.enroll_ok(&s.create_token(1).await, None, None).await;
    let post = |source: Option<DownloadSource>| {
        let cl = s.client(Some(&dev));
        let url = s.url(&format!("/v1/deployments/{dep}/result"));
        async move {
            cl.post(url)
                .json(&DeployResult {
                    revision: 1,
                    status: DeployStatus::Succeeded,
                    exit_code: Some(0),
                    message: String::new(),
                    attempts: 1,
                    source,
                })
                .send()
                .await
                .unwrap()
                .status()
        }
    };
    let src = || async {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT source FROM deployment_status WHERE deployment_id = $1",
        )
        .bind(dep)
        .fetch_one(&s.pool)
        .await
        .unwrap()
    };
    assert_eq!(post(Some(DownloadSource::Cache)).await, 204);
    assert_eq!(src().await.as_deref(), Some("cache"));
    assert_eq!(post(None).await, 204);
    assert_eq!(src().await, None, "舊版 Agent 沒帶來源");
    assert_eq!(post(Some(DownloadSource::Unknown)).await, 204);
    assert_eq!(src().await, None);
}
