use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use endpoint_server::notify::send;

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
