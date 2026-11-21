mod common;

use common::{METRICS_TOKEN, TestServer, csrf_from};
use endpoint_server::retention::{self, Retention};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

async fn scrape(s: &TestServer, token: Option<&str>) -> (u16, String) {
    let mut req = s.web_client().get(s.web_url("/metrics"));
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    let r = req.send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

fn has(body: &str, line: &str) {
    assert!(
        body.lines().any(|l| l == line),
        "missing `{line}` in\n{body}"
    );
}

#[sqlx::test(migrations = false)]
async fn metrics_requires_token_and_reports_counts(pool: PgPool) {
    let s = TestServer::start(pool).await;
    assert_eq!(scrape(&s, None).await.0, 401);
    assert_eq!(scrape(&s, Some("wrong-token")).await.0, 401);

    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let r = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            os_family: None,
            signing_keys: vec![],
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.9.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    s.state.heartbeat.flush(&s.pool).await.unwrap();

    let (st, body) = scrape(&s, Some(METRICS_TOKEN)).await;
    assert_eq!(st, 200);
    has(&body, "em_metrics_db_up 1");
    has(
        &body,
        r#"em_devices{os_family="windows",status="active"} 1"#,
    );
    has(&body, r#"em_devices_online{os_family="windows"} 1"#);
    has(&body, r#"em_devices_online{os_family="linux"} 0"#);
    has(&body, "em_devices_violating 0");
    has(&body, r#"em_command_targets_open{status="pending"} 0"#);
    has(
        &body,
        r#"em_http_requests_total{listener="agent",route="/v1/checkin",code="2xx"} 1"#,
    );
    has(
        &body,
        r#"em_http_requests_total{listener="web",route="/metrics",code="4xx"} 2"#,
    );
    assert!(
        body.contains("em_table_rows_estimate{table=\"audit_log\"}"),
        "{body}"
    );
    assert!(body.contains("\nem_database_size_bytes "), "{body}");
    // 只有統計數字，沒有個別裝置的資料
    assert!(!body.contains(&a.device_id.to_string()));
}

#[sqlx::test(migrations = false)]
async fn retention_settings_on_audit_page(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/audit").await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"action="/audit/retention""#), "{html}");
    assert!(
        html.contains(r#"name="command_days" value="180""#),
        "{html}"
    );
    let csrf = csrf_from(&html);

    let post = |form: Vec<(&'static str, String)>| {
        let c = admin.clone();
        let url = s.web_url("/audit/retention");
        async move { c.post(url).form(&form).send().await.unwrap() }
    };
    let r = post(vec![
        ("csrf", csrf.clone()),
        ("command_days", "10".into()),
        ("audit_days", "0".into()),
    ])
    .await;
    assert_eq!(r.status(), 422);
    let body = r.text().await.unwrap();
    assert!(body.contains("遠端指令的保留天數須為 0"), "{body}");
    assert!(
        body.contains(r#"name="command_days" value="10""#),
        "原值保留"
    );

    let r = post(vec![
        ("csrf", csrf.clone()),
        ("command_days", "90".into()),
        ("audit_days", "400".into()),
    ])
    .await;
    assert_eq!(r.status(), 303);
    assert_eq!(
        retention::load(&s.pool).await.unwrap(),
        Retention {
            command_days: 90,
            audit_days: 400
        }
    );
    let (_, html) = s.page(&admin, "/audit?saved=true").await;
    assert!(html.contains("資料保留設定已儲存"));
    assert!(html.contains("修改資料保留"), "稽核記錄有這次修改");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    assert_eq!(s.page(&g, "/audit").await.0, 403);
    let (_, ghtml) = s.page(&g, "/devices").await;
    let r = g
        .post(s.web_url("/audit/retention"))
        .form(&[
            ("csrf", csrf_from(&ghtml).as_str()),
            ("command_days", "30"),
            ("audit_days", "0"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
