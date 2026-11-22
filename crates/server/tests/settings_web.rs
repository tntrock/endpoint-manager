mod common;

use common::{TestServer, csrf_from};
use endpoint_server::db::load_settings;
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

fn form(csrf: &str, values: [&str; 7]) -> Vec<(String, String)> {
    let mut f = vec![("csrf".to_string(), csrf.to_string())];
    for ((key, ..), v) in endpoint_server::db::INTERVALS.iter().zip(values) {
        f.push((key.to_string(), v.to_string()));
    }
    f
}

#[sqlx::test(migrations = false)]
async fn platform_admin_changes_intervals(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    s.enroll_ok(&tok, None, None).await;
    s.enroll_ok(&tok, None, None).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/settings").await;
    assert_eq!(st, 200);
    for want in [
        r#"href="/settings""#,
        r#"name="checkin_interval_secs" value="60""#,
        // 收集以分鐘填
        r#"name="software_interval_secs" value="60""#,
        r#"name="hardware_interval_secs" value="1440""#,
        "目前 2 台",
        "每台每天約收集 24 次",
    ] {
        assert!(html.contains(want), "{want}: {html}");
    }
    let csrf = csrf_from(&html);
    let post = |f: Vec<(String, String)>| {
        let c = admin.clone();
        let url = s.web_url("/settings");
        async move { c.post(url).form(&f).send().await.unwrap() }
    };

    // 超出範圍：保留原值、顯示錯誤
    let r = post(form(&csrf, ["10", "60", "60", "60", "1440", "60", "60"])).await;
    assert_eq!(r.status(), 422);
    let body = r.text().await.unwrap();
    assert!(body.contains("報到的間隔必須介於 30 秒"), "{body}");
    assert!(
        body.contains(r#"name="checkin_interval_secs" value="10""#),
        "{body}"
    );

    let r = post(form(&csrf, ["120", "30", "60", "15", "1440", "60", "60"])).await;
    assert_eq!(r.status(), 303);
    let st = load_settings(&s.pool).await.unwrap();
    assert_eq!(st.checkin_interval_secs, 120);
    assert_eq!(st.intervals.software_secs, 1800);
    assert_eq!(st.intervals.services_secs, 900);
    let (_, html) = s.page(&admin, "/settings?saved=true").await;
    assert!(html.contains("已儲存"), "{html}");
    let (_, html) = s.page(&admin, "/audit").await;
    assert!(html.contains("修改報到與收集間隔"), "{html}");

    // 群組管理員看不到也改不了
    s.create_group_token("台北", 1).await;
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    assert_eq!(s.page(&g, "/settings").await.0, 403);
    let (_, ghtml) = s.page(&g, "/devices").await;
    assert!(!ghtml.contains(r#"href="/settings""#));
    let r = g
        .post(s.web_url("/settings"))
        .form(&form(
            &csrf_from(&ghtml),
            ["60", "60", "60", "60", "1440", "60", "60"],
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
