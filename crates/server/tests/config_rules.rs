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
        template_key: None,
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

/// 上傳時濾掉了值（查詢清單剛變）：存過濾後內容的雜湊，下次報到會要求重傳，
/// 否則規則重新啟用後該值可能永遠不再收集
#[sqlx::test(migrations = false)]
async fn filtered_upload_is_requested_again(pool: PgPool) {
    let (s, a) = setup(pool).await;
    admin::create_rule(&s.pool, &reg_rule(r"HKLM\X", "V1"), "admin")
        .await
        .unwrap();
    let r2 = admin::create_rule(&s.pool, &reg_rule(r"HKLM\X", "V2"), "admin")
        .await
        .unwrap();
    let mut off = reg_rule(r"HKLM\X", "V2");
    off.enabled = false;
    admin::update_rule(&s.pool, r2, &off, "admin")
        .await
        .unwrap();
    let v = |name: &str| protocol::RegistryValue {
        path: r"HKLM\X".into(),
        name: name.into(),
        state: protocol::RegState::Present,
        kind: protocol::RegKind::Dword,
        data: "1".into(),
    };
    let payload = InventoryPayload::Registry(vec![v("V1"), v("V2")]);
    let full_hash = payload.canonical_hash();
    put(&s, &a, payload).await;
    let r: protocol::CheckinResponse = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: SCHEMA_VERSION,
            agent_version: "0.3.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: [(protocol::Section::Registry, full_hash)]
                .into_iter()
                .collect(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        r.request_sections.contains(&protocol::Section::Registry),
        "{:?}",
        r.request_sections
    );
}

#[sqlx::test(migrations = false)]
async fn overlong_registry_path_is_rejected(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let long = format!(r"HKLM\{}", "x".repeat(1100));
    assert!(
        admin::create_rule(&s.pool, &reg_rule(&long, "V"), "admin")
            .await
            .is_err()
    );
}

async fn rule_events(s: &TestServer, a: &TestAgent) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT from_status, to_status FROM violation_events WHERE device_id = $1 ORDER BY id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

fn sec(public: protocol::Probe<protocol::FirewallInfo>) -> InventoryPayload {
    InventoryPayload::Security(protocol::SecurityInfo {
        firewall: public,
        bitlocker: protocol::Probe::Error("x".into()),
        defender: protocol::Probe::Error("x".into()),
        password: protocol::Probe::Error("x".into()),
        admins: protocol::Probe::Error("x".into()),
    })
}

fn fw(public: bool) -> protocol::Probe<protocol::FirewallInfo> {
    protocol::Probe::Ok(protocol::FirewallInfo {
        domain: true,
        private: true,
        public,
    })
}

/// 「未知」的進出不寫歷程（規則上線時三萬台 × 每條規則都會是未知）；
/// 但未知 ↔ 違規照常記錄，刪除規則時也不為未知寫事件
#[sqlx::test(migrations = false)]
async fn unknown_transitions_are_not_recorded(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let id = admin::create_rule(
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
    // 還沒有 security 資料 → 未知，不寫事件
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await, vec![(id, "unknown".into())]);
    assert!(rule_events(&s, &a).await.is_empty());
    // 未知 → 違規：記錄
    put(&s, &a, sec(fw(false))).await;
    assert_eq!(
        rule_events(&s, &a).await,
        vec![("unknown".into(), "violating".into())]
    );
    // 違規 → 未知（收集失敗）：記錄
    put(&s, &a, sec(protocol::Probe::Error("boom".into()))).await;
    // 未知 → 符合：不記錄
    put(&s, &a, sec(fw(true))).await;
    // 符合 → 未知：不記錄
    put(&s, &a, sec(protocol::Probe::Error("boom2".into()))).await;
    assert_eq!(violations(&s, &a).await, vec![(id, "unknown".into())]);
    // 刪除規則：未知的列不寫「→ none」
    admin::delete_rule(&s.pool, id, "admin").await.unwrap();
    assert_eq!(
        rule_events(&s, &a).await,
        vec![
            ("unknown".into(), "violating".into()),
            ("violating".into(), "unknown".into()),
        ]
    );
}

/// 登錄檔只寫入有變動的值：資料不變時不重寫（xmin 不變），少掉的值刪除，重複鍵不失敗
#[sqlx::test(migrations = false)]
async fn registry_writes_only_changes(pool: PgPool) {
    let (s, a) = setup(pool).await;
    for n in ["V1", "V2", "V3"] {
        admin::create_rule(&s.pool, &reg_rule(r"HKLM\X", n), "admin")
            .await
            .unwrap();
    }
    let v = |name: &str, data: &str| protocol::RegistryValue {
        path: r"HKLM\X".into(),
        name: name.into(),
        state: protocol::RegState::Present,
        kind: protocol::RegKind::Dword,
        data: data.into(),
    };
    let rows = || async {
        let r: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT name, data, xmin::text FROM device_registry WHERE device_id = $1 ORDER BY name",
        )
        .bind(a.device_id)
        .fetch_all(&s.pool)
        .await
        .unwrap();
        r
    };
    put(
        &s,
        &a,
        InventoryPayload::Registry(vec![v("V1", "1"), v("V2", "1"), v("V3", "1")]),
    )
    .await;
    let first = rows().await;
    assert_eq!(first.len(), 3);
    put(
        &s,
        &a,
        InventoryPayload::Registry(vec![v("V1", "1"), v("V2", "1"), v("V3", "1")]),
    )
    .await;
    assert_eq!(rows().await, first, "資料不變時不重寫");
    // V2 改值、V3 消失；V1 重複兩次
    put(
        &s,
        &a,
        InventoryPayload::Registry(vec![v("V1", "1"), v("V2", "2"), v("V1", "1")]),
    )
    .await;
    let now = rows().await;
    assert_eq!(now.len(), 2, "{now:?}");
    assert_eq!(now[0], first[0], "V1 未變");
    assert_eq!((now[1].0.as_str(), now[1].1.as_str()), ("V2", "2"));
    assert_ne!(now[1].2, first[1].2, "V2 已更新");
}
