mod common;

use common::{TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

async fn post_templates(
    s: &TestServer,
    c: &reqwest::Client,
    csrf: &str,
    keys: &[&str],
) -> (u16, String) {
    let mut form: Vec<(&str, &str)> = vec![("csrf", csrf)];
    form.extend(keys.iter().map(|k| ("key", *k)));
    let r = c
        .post(s.web_url("/compliance/rules/templates"))
        .form(&form)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[sqlx::test(migrations = false)]
async fn templates_create_rules_once(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/compliance/rules/templates").await;
    assert_eq!(st, 200);
    assert!(html.contains("防火牆") && html.contains("BitLocker"));
    let csrf = csrf_from(&html);

    let (st, html) = post_templates(
        &s,
        &admin,
        &csrf,
        &["firewall_all_profiles", "bitlocker_system"],
    )
    .await;
    assert_eq!(st, 200);
    assert!(html.contains("已建立 2 條"), "{html}");
    let (_, html) = post_templates(&s, &admin, &csrf, &["firewall_all_profiles"]).await;
    assert!(html.contains("略過 1 條"), "重複的範本不再建立：{html}");
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM compliance_rules WHERE template_key IS NOT NULL")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 2);
    let audit: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'rule_create' \
         AND detail->>'template_key' = 'bitlocker_system'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(audit, 1, "稽核記錄附上 template_key");
    let (_, html) = s.page(&admin, "/compliance/rules/templates").await;
    assert!(html.contains("已建立"), "已建立的範本有標示");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    assert_eq!(s.page(&g, "/compliance/rules/templates").await.0, 403);
}

async fn device_with(s: &TestServer, group: &str, data: &str) -> common::TestAgent {
    let tok = s.create_group_token(group, 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let payload = protocol::InventoryPayload::Registry(vec![protocol::RegistryValue {
        path: r"HKLM\SOFTWARE\Policies\X".into(),
        name: "Y".into(),
        state: protocol::RegState::Present,
        kind: protocol::RegKind::Dword,
        data: data.into(),
    }]);
    let r = s
        .client(Some(&a))
        .put(s.url("/v1/inventory/registry"))
        .json(&protocol::InventoryUpload {
            schema_version: protocol::SCHEMA_VERSION,
            payload,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    a
}

#[sqlx::test(migrations = false)]
async fn registry_query_is_scoped_and_case_insensitive(pool: PgPool) {
    let s = TestServer::start(pool).await;
    // 先建立會收集這個值的規則，上傳才不會被過濾掉
    endpoint_server::compliance::admin::create_rule(
        &s.pool,
        &endpoint_server::compliance::admin::RuleInput {
            name: "x".into(),
            description: String::new(),
            kind: "registry_value".into(),
            severity: "low".into(),
            enabled: true,
            params: serde_json::json!({"path": r"HKLM\SOFTWARE\Policies\X", "name": "Y", "op": "exists"}),
            include: vec![],
            exclude: vec![],
            template_key: None,
        },
        "admin",
    )
    .await
    .unwrap();
    let taipei = device_with(&s, "台北", "1").await;
    let kaohsiung = device_with(&s, "高雄", "0").await;
    let admin = s.admin_client().await;
    let (st, html) = s
        .page(
            &admin,
            "/registry?path=hklm%2Fsoftware%2Fpolicies%2Fx&name=y",
        )
        .await;
    assert_eq!(st, 200);
    assert!(
        html.contains("<td>1</td>") && html.contains("<td>0</td>"),
        "{html}"
    );
    assert!(html.contains("共 2 台"), "{html}");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s
        .page(&g, "/registry?path=HKLM%5CSOFTWARE%5CPolicies%5CX&name=Y")
        .await;
    assert!(
        !html.contains("<td>0</td>") && html.contains("共 1 台"),
        "{html}"
    );
    // 裝置清單：只列範圍內的裝置
    let (st, html) = s
        .page(
            &g,
            "/registry/devices?path=HKLM%5CSOFTWARE%5CPolicies%5CX&name=Y&state=present&data=0",
        )
        .await;
    assert_eq!(st, 200);
    assert!(!html.contains(&kaohsiung.device_id.to_string()), "{html}");
    let (_, html) = s
        .page(
            &g,
            "/registry/devices?path=HKLM%5CSOFTWARE%5CPolicies%5CX&name=Y&state=present&data=1",
        )
        .await;
    assert!(html.contains(&taipei.device_id.to_string()), "{html}");
    // 不合法的路徑顯示錯誤，不查詢
    let (st, html) = s.page(&admin, "/registry?path=HKCU%5CX&name=Y").await;
    assert_eq!(st, 200);
    assert!(html.contains("HKLM"), "{html}");
}

#[sqlx::test(migrations = false)]
async fn security_tab_shows_probes_and_errors(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let admin = s.admin_client().await;
    let tab = format!("/devices/{}/tab/security", a.device_id);
    let (st, html) = s.page(&admin, &tab).await;
    assert_eq!(st, 200);
    assert!(html.contains("尚未收到安全設定"), "{html}");
    let payload = protocol::InventoryPayload::Security(protocol::SecurityInfo {
        firewall: protocol::Probe::Ok(protocol::FirewallInfo {
            domain: true,
            private: true,
            public: false,
        }),
        bitlocker: protocol::Probe::Error("找不到 BitLocker".into()),
        defender: protocol::Probe::Ok(protocol::DefenderInfo {
            active: true,
            realtime: true,
            tamper: true,
            signature_updated: None,
        }),
        password: protocol::Probe::Ok(protocol::PasswordPolicy {
            min_length: 12,
            max_age_days: 0,
            lockout_threshold: 5,
        }),
        admins: protocol::Probe::Ok(vec![protocol::AccountInfo {
            name: r"PC\Administrator".into(),
            sid: "S-1-5-21-1-500".into(),
        }]),
    });
    let r = s
        .client(Some(&a))
        .put(s.url("/v1/inventory/security"))
        .json(&protocol::InventoryUpload {
            schema_version: protocol::SCHEMA_VERSION,
            payload,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let (_, html) = s.page(&admin, &tab).await;
    assert!(
        html.contains("公用")
            && html.contains("找不到 BitLocker")
            && html.contains(r"PC\Administrator")
            && html.contains("永不過期"),
        "{html}"
    );
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &tab).await.0, 404);
}

#[sqlx::test(migrations = false)]
async fn template_exists_is_typed(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let input = endpoint_server::compliance::admin::RuleInput {
        name: "a".into(),
        description: String::new(),
        kind: "firewall".into(),
        severity: "high".into(),
        enabled: true,
        params: serde_json::json!({"profiles": ["public"]}),
        include: vec![],
        exclude: vec![],
        template_key: Some("t1".into()),
    };
    endpoint_server::compliance::admin::create_rule(&s.pool, &input, "admin")
        .await
        .unwrap();
    let e = endpoint_server::compliance::admin::create_rule(
        &s.pool,
        &endpoint_server::compliance::admin::RuleInput {
            name: "b".into(),
            ..input
        },
        "admin",
    )
    .await
    .unwrap_err();
    assert!(
        e.downcast_ref::<endpoint_server::compliance::admin::TemplateExists>()
            .is_some(),
        "{e:#}"
    );
}
