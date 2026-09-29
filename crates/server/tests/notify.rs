mod common;

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use chrono::{Duration as CDuration, Utc};
use common::TestServer;
use endpoint_server::notify::{self, send, worker};
use sqlx::PgPool;

type Seen = Arc<Mutex<Vec<(HeaderMap, String)>>>;

/// 本機 HTTP 接收端（送出函式本身不檢查 https；https 在存檔時驗證）。
async fn receiver(status: StatusCode) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let s2 = seen.clone();
    let app = Router::new().route(
        "/hook",
        post(move |h: HeaderMap, body: String| {
            let s2 = s2.clone();
            async move {
                s2.lock().unwrap().push((h, body));
                status
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

#[tokio::test]
async fn webhook_signs_and_reports_status() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = send::webhook_client(&[]).unwrap();
    let (url, seen) = receiver(StatusCode::NO_CONTENT).await;
    let body = serde_json::json!({"a": 1});
    send::send_webhook(&client, &url, Some("s3cret"), &body)
        .await
        .unwrap();
    let (h, got) = seen.lock().unwrap()[0].clone();
    assert_eq!(got, r#"{"a":1}"#);
    let ts: i64 = h["x-em-timestamp"].to_str().unwrap().parse().unwrap();
    assert_eq!(
        h["x-em-signature"].to_str().unwrap(),
        endpoint_server::notify::digest::signature("s3cret", ts, got.as_bytes())
    );
    assert_eq!(h["content-type"], "application/json");

    let (url, _) = receiver(StatusCode::INTERNAL_SERVER_ERROR).await;
    let err = send::send_webhook(&client, &url, Some("s3cret"), &body)
        .await
        .unwrap_err();
    assert!(err.contains("500") && !err.contains("s3cret"), "{err}");

    // 不跟隨重新導向
    let (url, seen) = receiver(StatusCode::FOUND).await;
    assert!(
        send::send_webhook(&client, &url, None, &body)
            .await
            .is_err()
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(
        seen.lock().unwrap()[0].0.get("x-em-signature").is_none(),
        "沒有密鑰就不簽"
    );
}

async fn event(s: &TestServer, device: uuid::Uuid, sev: &str, from: &str, to: &str) {
    sqlx::query(
        "INSERT INTO violation_events          (device_id, rule_name, severity, from_status, to_status, detail, at)          VALUES ($1, '禁止 TeamViewer', $2, $3, $4, '{\"software\": []}',                  now() - interval '5 minutes')",
    )
    .bind(device)
    .bind(sev)
    .bind(from)
    .bind(to)
    .execute(&s.pool)
    .await
    .unwrap();
}

/// 直接寫設定（測試用 http 接收端；網頁存檔時才驗證 https）
async fn enable_webhook(s: &TestServer, url: &str) {
    sqlx::query("UPDATE settings SET value = $1::jsonb WHERE key = 'notify_webhook_url'")
        .bind(serde_json::json!(url).to_string())
        .execute(&s.pool)
        .await
        .unwrap();
}

async fn channel_row(s: &TestServer) -> (i64, i32, Option<String>) {
    sqlx::query_as(
        "SELECT last_event_id, failures, last_error FROM notify_channels          WHERE channel = 'webhook'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

fn senders() -> worker::Senders {
    worker::Senders {
        webhook: send::webhook_client(&[]).unwrap(),
    }
}

#[sqlx::test(migrations = false)]
async fn worker_sends_digest_filters_and_backs_off(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (url, seen) = receiver(StatusCode::OK).await;
    enable_webhook(&s, &url).await;
    let senders = senders();
    let secrets = notify::NotifySecrets::default();

    event(&s, a.device_id, "high", "none", "violating").await;
    event(&s, a.device_id, "low", "none", "violating").await; // 低於門檻（預設 medium）
    event(&s, a.device_id, "high", "none", "unknown").await; // 不是違規
    event(&s, a.device_id, "high", "violating", "none").await; // 解除
    let settings = notify::load_settings(&s.pool).await.unwrap();
    let now = Utc::now();
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, now)
        .await
        .unwrap();
    {
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&got[0].1).unwrap();
        assert_eq!(
            (v["total_new"].as_i64(), v["total_resolved"].as_i64()),
            (Some(1), Some(1))
        );
    }
    let max: i64 = sqlx::query_scalar("SELECT max(id) FROM violation_events")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(channel_row(&s).await.0, max, "游標推進到最新");

    // 間隔未到：不送
    event(&s, a.device_id, "high", "none", "violating").await;
    let later = now + CDuration::minutes(1);
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, later)
        .await
        .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    // 間隔到了但接收端故障：失敗、游標不動、倍增重試
    let (bad, _) = receiver(StatusCode::SERVICE_UNAVAILABLE).await;
    enable_webhook(&s, &bad).await;
    let settings = notify::load_settings(&s.pool).await.unwrap();
    let t = now + CDuration::minutes(11);
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, t)
        .await
        .unwrap();
    let (cursor, failures, err) = channel_row(&s).await;
    assert_eq!((cursor, failures), (max, 1));
    assert!(err.unwrap().contains("503"));
    let next: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT next_attempt_at FROM notify_channels WHERE channel = 'webhook'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(next >= t + CDuration::minutes(1) - CDuration::seconds(1));
    // 重試時間未到：不嘗試
    let soon = t + CDuration::seconds(30);
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, soon)
        .await
        .unwrap();
    assert_eq!(channel_row(&s).await.1, 1);
}

#[sqlx::test(migrations = false)]
async fn backlog_is_capped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (url, seen) = receiver(StatusCode::OK).await;
    enable_webhook(&s, &url).await;
    sqlx::query(
        "INSERT INTO violation_events          (device_id, rule_name, severity, from_status, to_status, detail, at)          SELECT $1, 'r', 'high', 'none', 'violating', '{}', now() - interval '5 minutes'          FROM generate_series(1, $2)",
    )
    .bind(a.device_id)
    .bind((worker::MAX_BACKLOG + 5) as i32)
    .execute(&s.pool)
    .await
    .unwrap();
    let settings = notify::load_settings(&s.pool).await.unwrap();
    let secrets = notify::NotifySecrets::default();
    worker::run_channel(
        &s.pool,
        "webhook",
        &settings,
        &secrets,
        &senders(),
        Utc::now(),
    )
    .await
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&seen.lock().unwrap()[0].1).unwrap();
    assert_eq!(v["dropped"], 5);
    assert_eq!(v["total_new"], worker::MAX_BACKLOG);
    assert_eq!(v["new"].as_array().unwrap().len(), 500);
}

#[test]
fn backoff_doubles_to_an_hour() {
    let m = |f| worker::backoff(f).num_minutes();
    assert_eq!((m(1), m(2), m(3), m(7), m(30)), (1, 2, 4, 60, 60));
}

#[sqlx::test(migrations = false)]
async fn notify_settings_page(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/compliance/notify").await;
    assert_eq!(st, 200);
    assert!(
        html.contains("EM_WEBHOOK_SECRET") && html.contains("未設定"),
        "只顯示機密是否已設定"
    );
    let csrf = common::csrf_from(&html);
    let post = |pairs: Vec<(&'static str, String)>| {
        let c = admin.clone();
        let url = s.web_url("/compliance/notify");
        async move { c.post(url).form(&pairs).send().await.unwrap() }
    };
    let r = post(vec![
        ("csrf", csrf.clone()),
        ("min_severity", "high".into()),
        ("interval_minutes", "5".into()),
        ("webhook_url", "http://insecure.example.com".into()),
    ])
    .await;
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("https://"));
    let r = post(vec![
        ("csrf", csrf.clone()),
        ("min_severity", "high".into()),
        ("interval_minutes", "5".into()),
        ("webhook_url", "https://hooks.example.com/x".into()),
    ])
    .await;
    assert_eq!(r.status(), 303);
    let n = notify::load_settings(&s.pool).await.unwrap();
    assert_eq!(
        n.min_severity,
        endpoint_server::compliance::rules::Severity::High
    );
    assert_eq!(
        n.webhook_url.as_deref(),
        Some("https://hooks.example.com/x")
    );
    let (_, html) = s.page(&admin, "/compliance").await;
    assert!(
        html.contains("Webhook") && html.contains("通知"),
        "總覽顯示通知狀態"
    );

    let g = s
        .login_as(
            "gary",
            endpoint_server::web::auth::Role::GroupAdmin,
            &["台北"],
        )
        .await;
    assert_eq!(s.page(&g, "/compliance/notify").await.0, 403);
    let (_, html) = s.page(&g, "/compliance").await;
    assert!(!html.contains("Webhook"), "通知狀態只給平台管理員");
}

/// 剛寫入的事件可能屬於尚未提交的交易（id 較小的晚提交）：游標只推進到確定已提交的事件，
/// 否則晚提交的事件會被永遠跳過
#[sqlx::test(migrations = false)]
async fn cursor_does_not_pass_recent_events(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (url, seen) = receiver(StatusCode::OK).await;
    enable_webhook(&s, &url).await;
    sqlx::query(
        "INSERT INTO violation_events          (device_id, rule_name, severity, from_status, to_status, detail)          VALUES ($1, 'r', 'high', 'none', 'violating', '{}')",
    )
    .bind(a.device_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let settings = notify::load_settings(&s.pool).await.unwrap();
    let secrets = notify::NotifySecrets::default();
    worker::run_channel(
        &s.pool,
        "webhook",
        &settings,
        &secrets,
        &senders(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert!(seen.lock().unwrap().is_empty(), "剛寫入的事件先不送");
    assert_eq!(channel_row(&s).await.0, 0, "游標不越過它");
    sqlx::query("UPDATE violation_events SET at = now() - interval '5 minutes'")
        .execute(&s.pool)
        .await
        .unwrap();
    worker::run_channel(
        &s.pool,
        "webhook",
        &settings,
        &secrets,
        &senders(),
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);
}

/// 積壓上限只算會通知的事件：大量「未知」事件不能讓正常的管道跳過真正的違規
#[sqlx::test(migrations = false)]
async fn backlog_cap_ignores_irrelevant_events(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (url, seen) = receiver(StatusCode::OK).await;
    enable_webhook(&s, &url).await;
    event(&s, a.device_id, "high", "none", "violating").await;
    sqlx::query(
        "INSERT INTO violation_events          (device_id, rule_name, severity, from_status, to_status, detail, at)          SELECT $1, 'r', 'high', 'none', 'unknown', '{}', now() - interval '5 minutes'          FROM generate_series(1, $2)",
    )
    .bind(a.device_id)
    .bind((worker::MAX_BACKLOG + 5) as i32)
    .execute(&s.pool)
    .await
    .unwrap();
    let settings = notify::load_settings(&s.pool).await.unwrap();
    let secrets = notify::NotifySecrets::default();
    worker::run_channel(
        &s.pool,
        "webhook",
        &settings,
        &secrets,
        &senders(),
        Utc::now(),
    )
    .await
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&seen.lock().unwrap()[0].1).unwrap();
    assert_eq!(
        (v["total_new"].as_i64(), v["dropped"].as_i64()),
        (Some(1), Some(0))
    );
}
