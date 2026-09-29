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
