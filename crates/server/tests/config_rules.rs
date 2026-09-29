mod common;

use common::{TestAgent, TestServer};
use endpoint_server::compliance::admin::{self, RuleInput};
use protocol::{InventoryPayload, InventoryUpload, SCHEMA_VERSION};
use sqlx::PgPool;

async fn put(s: &TestServer, a: &TestAgent, p: InventoryPayload) {
    let section = p.section().as_str();
    let r = s
        .client(Some(a))
        .put(s.url(&format!("/v1/inventory/{section}")))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: p,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

async fn setup(pool: PgPool) -> (TestServer, TestAgent) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    (s, a)
}

async fn violations(s: &TestServer, a: &TestAgent) -> Vec<(i64, String)> {
    sqlx::query_as(
        "SELECT rule_id, status FROM device_violations WHERE device_id = $1 ORDER BY rule_id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

fn reg_rule(path: &str, name: &str) -> RuleInput {
    RuleInput {
        name: format!("{path}\\{name}"),
        description: String::new(),
        kind: "registry_value".into(),
        severity: "high".into(),
        enabled: true,
        params: serde_json::json!({"path": path, "name": name, "op": "equals", "expected": "1"}),
        include: vec![],
        exclude: vec![],
    }
}

async fn checkin(s: &TestServer, a: &TestAgent) -> protocol::CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: SCHEMA_VERSION,
            agent_version: "0.3.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec![],
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
async fn registry_rule_drives_queries_evaluation_and_filtering(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let id = admin::create_rule(
        &s.pool,
        &reg_rule(r"hklm\SOFTWARE\Policies\X", "Y"),
        "admin",
    )
    .await
    .unwrap();
    // 同一個值、不同寫法：只算一個查詢
    admin::create_rule(
        &s.pool,
        &reg_rule(r"HKLM\software\policies\x", "y"),
        "admin",
    )
    .await
    .unwrap();
    let r = checkin(&s, &a).await;
    assert_eq!(r.registry_queries.len(), 1, "{:?}", r.registry_queries);
    assert_eq!(
        r.registry_queries_hash.as_deref(),
        Some(protocol::regpath::queries_hash(&r.registry_queries).as_str())
    );

    let v = |name: &str, data: &str| protocol::RegistryValue {
        path: r"HKLM\SOFTWARE\Policies\X".into(),
        name: name.into(),
        state: protocol::RegState::Present,
        kind: protocol::RegKind::Dword,
        data: data.into(),
    };
    put(
        &s,
        &a,
        InventoryPayload::Registry(vec![v("Y", "0"), v("NotAsked", "1")]),
    )
    .await;
    let stored: i64 =
        sqlx::query_scalar("SELECT count(*) FROM device_registry WHERE device_id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(stored, 1, "清單外的值被丟棄");
    assert!(
        violations(&s, &a)
            .await
            .contains(&(id, "violating".to_string()))
    );
}

#[sqlx::test(migrations = false)]
async fn registry_value_cap_is_enforced(pool: PgPool) {
    let s = TestServer::start(pool).await;
    sqlx::query("UPDATE settings SET value = '2' WHERE key = 'registry_max_values'")
        .execute(&s.pool)
        .await
        .unwrap();
    admin::create_rule(&s.pool, &reg_rule(r"HKLM\A", "1"), "admin")
        .await
        .unwrap();
    let second = admin::create_rule(&s.pool, &reg_rule(r"HKLM\A", "2"), "admin")
        .await
        .unwrap();
    let err = admin::create_rule(&s.pool, &reg_rule(r"HKLM\A", "3"), "admin")
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("registry_max_values"),
        "{err:#}"
    );
    // 停用的規則不佔上限
    let mut off = reg_rule(r"HKLM\A", "3");
    off.enabled = false;
    let third = admin::create_rule(&s.pool, &off, "admin").await.unwrap();
    // 修改規則時不把自己算兩次；啟用第三條會超過
    admin::update_rule(&s.pool, second, &reg_rule(r"HKLM\A", "2"), "admin")
        .await
        .unwrap();
    assert!(
        admin::update_rule(&s.pool, third, &reg_rule(r"HKLM\A", "3"), "admin")
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = false)]
async fn security_and_services_uploads_trigger_evaluation(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let fw = admin::create_rule(
        &s.pool,
        &RuleInput {
            kind: "firewall".into(),
            params: serde_json::json!({"profiles": ["public"]}),
            ..reg_rule(r"HKLM\A", "B")
        },
        "admin",
    )
    .await
    .unwrap();
    let svc = admin::create_rule(
        &s.pool,
        &RuleInput {
            kind: "service_state".into(),
            params: serde_json::json!({"name": "RemoteRegistry", "require": "disabled"}),
            ..reg_rule(r"HKLM\A", "B")
        },
        "admin",
    )
    .await
    .unwrap();
    put(
        &s,
        &a,
        InventoryPayload::Security(protocol::SecurityInfo {
            firewall: protocol::Probe::Ok(protocol::FirewallInfo {
                domain: true,
                private: true,
                public: false,
            }),
            bitlocker: protocol::Probe::Error("x".into()),
            defender: protocol::Probe::Error("x".into()),
            password: protocol::Probe::Error("x".into()),
            admins: protocol::Probe::Error("x".into()),
        }),
    )
    .await;
    put(
        &s,
        &a,
        InventoryPayload::Services(vec![protocol::ServiceItem {
            name: "RemoteRegistry".into(),
            display_name: None,
            start_mode: "Manual".into(),
            state: "Stopped".into(),
            binary_path: None,
        }]),
    )
    .await;
    let v = violations(&s, &a).await;
    assert!(
        v.contains(&(fw, "violating".into())) && v.contains(&(svc, "violating".into())),
        "{v:?}"
    );
}

/// 舊版 Agent（沒有 security／registry）：結果是未知，細節註明版本過舊
#[sqlx::test(migrations = false)]
async fn old_agent_is_unknown_not_violating(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let fw = admin::create_rule(
        &s.pool,
        &RuleInput {
            kind: "firewall".into(),
            params: serde_json::json!({"profiles": ["public"]}),
            ..reg_rule(r"HKLM\A", "B")
        },
        "admin",
    )
    .await
    .unwrap();
    sqlx::query("UPDATE devices SET agent_version = '0.2.1' WHERE id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    // 觸發評估：上傳一個舊區段
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    let detail: String = sqlx::query_scalar(
        "SELECT detail::text FROM device_violations WHERE device_id = $1 AND rule_id = $2 \
         AND status = 'unknown'",
    )
    .bind(a.device_id)
    .bind(fw)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert!(detail.contains("agent_outdated"), "{detail}");
}
