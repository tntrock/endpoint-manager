mod common;

use common::{TestAgent, TestServer, csrf_from};
use endpoint_server::compliance::rules::{Params, Rule, Severity};
use endpoint_server::web::auth::Role;
use protocol::{Arch, InventoryPayload, InventoryUpload, PatchItem, SCHEMA_VERSION, SoftwareItem};
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

fn sw(name: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some("1".into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

/// 在指定群組註冊一台裝置並上傳軟體與修補。
async fn device_in(s: &TestServer, group: &str, software: &[&str]) -> TestAgent {
    let tok = s.create_group_token(group, 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    put(
        s,
        &a,
        InventoryPayload::Software(software.iter().map(|n| sw(n)).collect()),
    )
    .await;
    put(
        s,
        &a,
        InventoryPayload::Patches(vec![PatchItem {
            kb: "KB1".into(),
            installed_on: None,
        }]),
    )
    .await;
    a
}

#[sqlx::test(migrations = false)]
async fn preview_counts_matching_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    device_in(&s, "台北", &["TeamViewer 15"]).await;
    device_in(&s, "高雄", &["TeamViewer 15"]).await;
    device_in(&s, "高雄", &["7-Zip"]).await;
    let rule = |include: Vec<i64>| Rule {
        id: 0,
        name: "p".into(),
        severity: Severity::High,
        include,
        exclude: vec![],
        check: Ok(Params::parse(
            "forbidden_software",
            &serde_json::json!({"name": "*TeamViewer*"}),
        )
        .unwrap()
        .compile()),
    };
    let c = endpoint_server::compliance::preview::preview(&s.pool, rule(vec![]))
        .await
        .unwrap();
    assert_eq!((c.violating, c.unknown, c.devices), (2, 0, 3));
    let g = s.group_id("高雄").await;
    let c = endpoint_server::compliance::preview::preview(&s.pool, rule(vec![g]))
        .await
        .unwrap();
    assert_eq!(c.violating, 1);
}

#[sqlx::test(migrations = false)]
async fn rule_pages_and_permissions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s
        .page(&admin, "/compliance/rules/new?kind=forbidden_software")
        .await;
    assert_eq!(st, 200);
    let csrf = csrf_from(&html);
    let r = admin
        .post(s.web_url("/compliance/rules"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("kind", "forbidden_software"),
            ("name", "禁止 TeamViewer"),
            ("severity", "high"),
            ("enabled", "1"),
            ("p_name", "*TeamViewer*"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let (_, html) = s.page(&admin, "/compliance/rules").await;
    assert!(html.contains("禁止 TeamViewer") && html.contains("禁止軟體"));

    // 壞參數 → 409 與中文訊息
    let r = admin
        .post(s.web_url("/compliance/rules"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("kind", "required_kb"),
            ("name", "x"),
            ("severity", "high"),
            ("p_kb", "123"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("KB 格式"));

    // 預覽
    let r = admin
        .post(s.web_url("/compliance/rules/preview"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("kind", "required_kb"),
            ("name", "x"),
            ("severity", "high"),
            ("p_kb", "KB5034439"),
        ])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("共評估 0 台"));

    // 群組管理員可看清單，不能新增或編輯
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (st, html) = s.page(&g, "/compliance/rules").await;
    assert_eq!(st, 200);
    assert!(html.contains("禁止 TeamViewer") && !html.contains("/compliance/rules/new"));
    let (st, _) = s.page(&g, "/compliance/rules/new?kind=required_kb").await;
    assert_eq!(st, 403);
    let gcsrf = csrf_from(&html);
    let r = g
        .post(s.web_url("/compliance/rules"))
        .form(&[
            ("csrf", gcsrf.as_str()),
            ("kind", "required_kb"),
            ("name", "x"),
            ("severity", "high"),
            ("p_kb", "KB5034439"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

async fn add_rule_via_admin(s: &TestServer, kind: &str, params: serde_json::Value) -> i64 {
    endpoint_server::compliance::admin::create_rule(
        &s.pool,
        &endpoint_server::compliance::admin::RuleInput {
            name: format!("{kind} rule"),
            description: String::new(),
            kind: kind.into(),
            severity: "high".into(),
            enabled: true,
            params,
            include: vec![],
            exclude: vec![],
        },
        "admin",
    )
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn violations_are_scoped_by_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    add_rule_via_admin(
        &s,
        "forbidden_software",
        serde_json::json!({"name": "*TeamViewer*"}),
    )
    .await;
    let taipei = device_in(&s, "台北", &["TeamViewer 15"]).await;
    let kaohsiung = device_in(&s, "高雄", &["TeamViewer 15"]).await;
    let id = |a: &TestAgent| a.device_id.to_string();

    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/compliance/violations").await;
    assert!(html.contains(&id(&taipei)) && html.contains(&id(&kaohsiung)));
    let (st, html) = s.page(&admin, "/compliance").await;
    assert_eq!(st, 200);
    assert!(html.contains("forbidden_software rule"), "總覽列出規則");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&g, "/compliance/violations").await;
    assert!(html.contains(&id(&taipei)) && !html.contains(&id(&kaohsiung)));
    let (_, html) = s.page(&g, "/compliance").await;
    assert!(!html.contains("近 30 天"), "趨勢只給平台管理員");
    let (_, html) = s.page(&g, "/compliance/violations?q=nomatch").await;
    assert!(!html.contains(&id(&taipei)));
}
