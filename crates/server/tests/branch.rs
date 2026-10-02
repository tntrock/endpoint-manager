mod common;

use common::TestServer;
use endpoint_server::branch::caches;
use endpoint_server::branch::sites::{self, SiteInput};
use endpoint_server::tokens::{self, TokenKind};
use protocol::branch::{
    CacheEnrollPoll, CacheEnrollPollResponse, CacheEnrollRequest, CacheEnrollResponse,
    CacheEnrollState,
};
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
