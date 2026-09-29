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
