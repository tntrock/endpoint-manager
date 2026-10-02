mod common;

use common::TestServer;
use endpoint_server::branch::sites::{self, SiteInput};
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
