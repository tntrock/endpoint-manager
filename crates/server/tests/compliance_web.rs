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

    // 壞參數 → 重新顯示表單：中文錯誤訊息，且保留已輸入的內容
    let r = admin
        .post(s.web_url("/compliance/rules"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("kind", "required_kb"),
            ("name", "保留我的名稱"),
            ("severity", "high"),
            ("p_kb", "123"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    let html = r.text().await.unwrap();
    assert!(html.contains("KB 格式") && html.contains("<form"), "{html}");
    assert!(
        html.contains(r#"value="保留我的名稱""#) && html.contains(r#"value="123""#),
        "{html}"
    );

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
            template_key: None,
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

#[sqlx::test(migrations = false)]
async fn csv_export_is_scoped_bom_and_safe(pool: PgPool) {
    let s = TestServer::start(pool).await;
    add_rule_via_admin(&s, "forbidden_software", serde_json::json!({"name": "=*"})).await;
    let taipei = device_in(&s, "台北", &["=cmd|' /C calc'!A0"]).await;
    let kaohsiung = device_in(&s, "高雄", &["=evil"]).await;
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let r = g
        .get(s.web_url("/compliance/violations.csv"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/csv")
    );
    let body = r.text().await.unwrap();
    assert!(body.starts_with('\u{feff}'), "BOM");
    assert!(body.contains(&taipei.device_id.to_string()));
    assert!(!body.contains(&kaohsiung.device_id.to_string()), "範圍外");
    assert!(body.contains("\"'=cmd"), "公式開頭加 '：{body}");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'compliance_export'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = false)]
async fn device_tab_and_exemptions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let rule = add_rule_via_admin(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    let a = device_in(&s, "台北", &[]).await;
    let tab = format!("/devices/{}/tab/compliance", a.device_id);
    let rule_id = rule.to_string();

    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, &tab).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("缺少 KB5031455") && html.contains("新增豁免"),
        "{html}"
    );
    let (_, page) = s.page(&admin, &format!("/devices/{}", a.device_id)).await;
    assert!(page.contains("/tab/compliance"), "裝置頁有合規分頁");
    let csrf = csrf_from(&page);
    let r = admin
        .post(s.web_url(&format!("/devices/{}/exemptions", a.device_id)))
        .form(&[
            ("csrf", csrf.as_str()),
            ("rule_id", rule_id.as_str()),
            ("reason", "舊系統"),
            ("days", "30"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let (_, html) = s.page(&admin, &tab).await;
    assert!(html.contains("豁免") && html.contains("舊系統") && html.contains("撤銷"));

    // 群組管理員看得到分頁，但沒有豁免按鈕，POST 也被拒
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (st, html) = s.page(&g, &tab).await;
    assert_eq!(st, 200);
    assert!(!html.contains("新增豁免") && !html.contains("撤銷"));
    let gcsrf = csrf_from(&s.page(&g, "/").await.1);
    let r = g
        .post(s.web_url(&format!("/devices/{}/exemptions", a.device_id)))
        .form(&[
            ("csrf", gcsrf.as_str()),
            ("rule_id", rule_id.as_str()),
            ("reason", "x"),
            ("days", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // 範圍外的群組管理員：分頁 404
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &tab).await.0, 404);

    // 撤銷
    let ex: i64 = sqlx::query_scalar("SELECT id FROM compliance_exemptions")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let r = admin
        .post(s.web_url(&format!("/exemptions/{ex}/revoke")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM compliance_exemptions")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn device_tab_without_rules_or_data(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let admin = s.admin_client().await;
    let (st, html) = s
        .page(&admin, &format!("/devices/{}/tab/compliance", a.device_id))
        .await;
    assert_eq!(st, 200);
    assert!(html.contains("尚未建立任何合規規則"), "{html}");
}

/// 群組管理員在規則清單只看得到自己範圍內的群組名稱
#[sqlx::test(migrations = false)]
async fn rule_list_hides_out_of_scope_group_names(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let taipei = s.group_id("台北").await;
    let secret = s.group_id("機密研發部").await;
    endpoint_server::compliance::admin::create_rule(
        &s.pool,
        &endpoint_server::compliance::admin::RuleInput {
            name: "限定群組規則".into(),
            description: String::new(),
            kind: "required_kb".into(),
            severity: "high".into(),
            enabled: true,
            params: serde_json::json!({"kb": "KB5031455"}),
            include: vec![taipei, secret],
            exclude: vec![],
            template_key: None,
        },
        "admin",
    )
    .await
    .unwrap();
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&g, "/compliance/rules").await;
    assert!(
        html.contains("台北") && !html.contains("機密研發部"),
        "{html}"
    );
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/compliance/rules").await;
    assert!(html.contains("機密研發部"));
}

/// 格式錯誤的輸入回中文訊息，不是 axum 的英文錯誤
#[sqlx::test(migrations = false)]
async fn bad_input_gets_chinese_errors(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let rule = add_rule_via_admin(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    let a = device_in(&s, "台北", &[]).await;
    let admin = s.admin_client().await;
    let (_, page) = s.page(&admin, &format!("/devices/{}", a.device_id)).await;
    let csrf = csrf_from(&page);
    let rule_id = rule.to_string();
    let r = admin
        .post(s.web_url(&format!("/devices/{}/exemptions", a.device_id)))
        .form(&[
            ("csrf", csrf.as_str()),
            ("rule_id", rule_id.as_str()),
            ("reason", "x"),
            ("days", "abc"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("天數"));
    let (st, _) = s.page(&admin, "/compliance/violations?page=abc").await;
    assert_eq!(st, 200);
}
