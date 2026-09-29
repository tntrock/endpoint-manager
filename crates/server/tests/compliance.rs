mod common;

use common::{TestAgent, TestServer};
use protocol::{Arch, InventoryPayload, InventoryUpload, PatchItem, SCHEMA_VERSION, SoftwareItem};
use sqlx::PgPool;

fn sw(name: &str, ver: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some(ver.into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

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

/// 直接寫入規則並 bump generation（不經 admin API）。
async fn add_rule(s: &TestServer, kind: &str, params: serde_json::Value) -> i64 {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
         VALUES ($1, $2, 'high', $3::jsonb, 'test') RETURNING id",
    )
    .bind(format!("{kind} rule"))
    .bind(kind)
    .bind(params.to_string())
    .fetch_one(&s.pool)
    .await
    .unwrap();
    bump(s).await;
    id
}

async fn bump(s: &TestServer) {
    sqlx::query("UPDATE compliance_state SET generation = generation + 1")
        .execute(&s.pool)
        .await
        .unwrap();
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

async fn events(s: &TestServer, a: &TestAgent) -> Vec<(String, String)> {
    sqlx::query_as(
        "SELECT from_status, to_status FROM violation_events WHERE device_id = $1 ORDER BY id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

async fn setup(pool: PgPool) -> (TestServer, TestAgent) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    (s, a)
}

#[sqlx::test(migrations = false)]
async fn upload_triggers_evaluation_and_history(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = add_rule(
        &s,
        "forbidden_software",
        serde_json::json!({"name": "*TeamViewer*"}),
    )
    .await;

    put(
        &s,
        &a,
        InventoryPayload::Software(vec![sw("TeamViewer 15", "15.1")]),
    )
    .await;
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    assert_eq!(
        events(&s, &a).await,
        vec![("none".into(), "violating".into())]
    );

    // 版本變了但仍違規：只更新細節，不寫歷程
    put(
        &s,
        &a,
        InventoryPayload::Software(vec![sw("TeamViewer 15", "15.2")]),
    )
    .await;
    let detail: String =
        sqlx::query_scalar("SELECT detail::text FROM device_violations WHERE device_id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(detail.contains("15.2"), "{detail}");
    assert_eq!(events(&s, &a).await.len(), 1);

    put(
        &s,
        &a,
        InventoryPayload::Software(vec![sw("7-Zip", "23.01")]),
    )
    .await;
    assert!(violations(&s, &a).await.is_empty());
    assert_eq!(events(&s, &a).await[1], ("violating".into(), "none".into()));
}

#[sqlx::test(migrations = false)]
async fn broken_rule_does_not_fail_upload(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let broken = add_rule(&s, "required_kb", serde_json::json!({"oops": true})).await;
    let good = add_rule(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    put(
        &s,
        &a,
        InventoryPayload::Patches(vec![PatchItem {
            kb: "KB1".into(),
            installed_on: None,
        }]),
    )
    .await;
    assert_eq!(
        violations(&s, &a).await,
        vec![(broken, "unknown".into()), (good, "violating".into())]
    );
}

#[sqlx::test(migrations = false)]
async fn retire_clears_and_group_move_reevaluates(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let g = s.group_id("資訊亭").await;
    let rule = add_rule(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    sqlx::query(
        "INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, 'exclude')",
    )
    .bind(rule)
    .bind(g)
    .execute(&s.pool)
    .await
    .unwrap();
    bump(&s).await;
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await.len(), 1);

    endpoint_server::groups::move_device(&s.pool, a.device_id, Some(g), "t")
        .await
        .unwrap();
    assert!(
        violations(&s, &a).await.is_empty(),
        "移到排除群組後違規消失"
    );
    endpoint_server::groups::move_device(&s.pool, a.device_id, None, "t")
        .await
        .unwrap();
    assert_eq!(violations(&s, &a).await.len(), 1);

    endpoint_server::devices::retire(&s.pool, a.device_id, "t")
        .await
        .unwrap();
    assert!(violations(&s, &a).await.is_empty(), "除役後清除");
    assert_eq!(events(&s, &a).await.last().unwrap().1, "none");
}

use endpoint_server::compliance::admin::{self, RuleInput};

fn input(kind: &str, params: serde_json::Value) -> RuleInput {
    RuleInput {
        name: "禁止遠端桌面軟體".into(),
        description: String::new(),
        kind: kind.into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
    }
}

async fn generation(s: &TestServer) -> i64 {
    sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn rule_crud_validates_and_audits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let g = s.group_id("資訊亭").await;
    let kb = || serde_json::json!({"kb": "KB5034439"});
    let bad = RuleInput {
        include: vec![g],
        exclude: vec![g],
        ..input("required_kb", kb())
    };
    assert!(
        admin::create_rule(&s.pool, &bad, "admin").await.is_err(),
        "同一群組不能同時只套用又排除"
    );
    assert!(
        admin::create_rule(
            &s.pool,
            &input("required_kb", serde_json::json!({"kb": "x"})),
            "admin"
        )
        .await
        .is_err()
    );
    let blank = RuleInput {
        name: "  ".into(),
        ..input("required_kb", kb())
    };
    assert!(admin::create_rule(&s.pool, &blank, "admin").await.is_err());

    let before = generation(&s).await;
    let id = admin::create_rule(
        &s.pool,
        &input("required_kb", serde_json::json!({"kb": " kb5034439"})),
        "admin",
    )
    .await
    .unwrap();
    let params: String =
        sqlx::query_scalar("SELECT params::text FROM compliance_rules WHERE id = $1")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(params, r#"{"kb": "KB5034439"}"#, "存正規化後的參數");
    let mut upd = input("required_kb", kb());
    upd.include = vec![g];
    admin::update_rule(&s.pool, id, &upd, "admin")
        .await
        .unwrap();
    let groups: Vec<(i64, String)> =
        sqlx::query_as("SELECT group_id, mode FROM compliance_rule_groups WHERE rule_id = $1")
            .bind(id)
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(groups, vec![(g, "include".into())]);
    admin::delete_rule(&s.pool, id, "admin").await.unwrap();
    assert_eq!(generation(&s).await, before + 3);
    let actions: Vec<String> =
        sqlx::query_scalar("SELECT action FROM audit_log WHERE action LIKE 'rule_%' ORDER BY id")
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(actions, ["rule_create", "rule_update", "rule_delete"]);
    assert!(
        admin::update_rule(&s.pool, id, &upd, "admin")
            .await
            .is_err(),
        "已刪除"
    );
}

#[sqlx::test(migrations = false)]
async fn exemption_marks_exempt_and_revoke_restores(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(
        &s.pool,
        &input("required_kb", serde_json::json!({"kb": "KB5031455"})),
        "admin",
    )
    .await
    .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);

    let now = chrono::Utc::now();
    let soon = now + chrono::Duration::days(30);
    for (reason, until) in [
        (" ", soon),
        ("ok", now + chrono::Duration::days(400)),
        ("ok", now - chrono::Duration::minutes(1)),
    ] {
        assert!(
            admin::create_exemption(&s.pool, a.device_id, rule, reason, until, "admin")
                .await
                .is_err(),
            "{reason:?} {until}"
        );
    }

    let ex = admin::create_exemption(&s.pool, a.device_id, rule, "舊系統相容性", soon, "admin")
        .await
        .unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "exempt".into())]);
    admin::revoke_exemption(&s.pool, ex, "admin").await.unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'exemption_%'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 2);
}
