//! 通知設定（平台管理員）。機密只顯示是否已設定。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf};
use super::devices::{SelectOption, db_error};
use super::{forbidden, render};
use crate::AppState;
use crate::compliance::rules::Severity;
use crate::notify::{self, NotifySettings, digest, send};

#[derive(Template)]
#[template(path = "notify.html")]
struct NotifyPage {
    nav: Nav,
    severities: Vec<SelectOption>,
    interval_minutes: u32,
    webhook_url: String,
    webhook_secret_set: bool,
}

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    if !s.all_devices() {
        return Err(forbidden());
    }
    let n = notify::load_settings(&st.pool).await.map_err(db_error)?;
    Ok(render(&NotifyPage {
        nav: Nav::from(&s),
        severities: Severity::ALL
            .into_iter()
            .map(|x| SelectOption {
                value: x.as_str().into(),
                label: x.label().into(),
                selected: x == n.min_severity,
            })
            .collect(),
        interval_minutes: n.interval_minutes,
        webhook_url: n.webhook_url.unwrap_or_default(),
        webhook_secret_set: st.notify.webhook_secret.is_some(),
    }))
}

#[derive(Deserialize)]
pub struct SaveForm {
    csrf: String,
    min_severity: String,
    interval_minutes: String,
    #[serde(default)]
    webhook_url: String,
}

fn conflict(msg: impl std::fmt::Display) -> Response {
    (StatusCode::CONFLICT, msg.to_string()).into_response()
}

/// 表單轉設定；Webhook 網址留空＝停用。
fn to_settings(f: &SaveForm) -> Result<NotifySettings, String> {
    let min_severity = Severity::parse(&f.min_severity).ok_or("嚴重度無效")?;
    let interval_minutes = f
        .interval_minutes
        .trim()
        .parse::<u32>()
        .map_err(|_| "彙整間隔必須是數字")?;
    let webhook_url = Some(f.webhook_url.trim().to_string()).filter(|u| !u.is_empty());
    Ok(NotifySettings {
        min_severity,
        interval_minutes,
        webhook_url,
    })
}

pub async fn save(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<SaveForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let n = to_settings(&f).map_err(conflict)?;
    notify::save_settings(&st.pool, &n, &s.username)
        .await
        .map_err(|e| match e.downcast::<sqlx::Error>() {
            Ok(db) => db_error(db),
            Err(e) => conflict(format!("{e:#}")),
        })?;
    Ok(Redirect::to("/compliance/notify").into_response())
}

#[derive(Deserialize)]
pub struct TestForm {
    csrf: String,
}

/// 立即送一則示範通知，回報成功或錯誤（htmx 片段）。
pub async fn test(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<TestForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let n = notify::load_settings(&st.pool).await.map_err(db_error)?;
    let result = match &n.webhook_url {
        None => Err("尚未設定 Webhook".to_string()),
        Some(url) => match send::webhook_client(&[]) {
            Ok(c) => {
                let body = digest::webhook_body(&digest::test_digest(), chrono::Utc::now());
                send::send_webhook(&c, url, st.notify.webhook_secret.as_deref(), &body).await
            }
            Err(err) => Err(err.to_string()),
        },
    };
    let msg = match result {
        Ok(()) => "測試通知已送出".to_string(),
        Err(e) => format!("送出失敗：{e}"),
    };
    // 一律回 200，htmx 才會把訊息放進頁面；askama 以外的輸出要自己跳脫
    Ok(axum::response::Html(format!(
        "<p class=\"notice\">{}</p>",
        msg.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    ))
    .into_response())
}
