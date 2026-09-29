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
use crate::notify::{self, EmailSettings, NotifySettings, TlsMode, digest, send};

#[derive(Template)]
#[template(path = "notify.html")]
struct NotifyPage {
    nav: Nav,
    severities: Vec<SelectOption>,
    interval_minutes: u32,
    webhook_url: String,
    smtp_host: String,
    smtp_port: String,
    starttls: bool,
    smtp_username: String,
    smtp_from: String,
    smtp_to: String,
    smtp_password_set: bool,
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
    let e = n.email.as_ref();
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
        smtp_host: e.map(|e| e.host.clone()).unwrap_or_default(),
        smtp_port: e
            .map(|e| e.port.to_string())
            .unwrap_or_else(|| "587".into()),
        starttls: e.is_none_or(|e| e.tls == TlsMode::StartTls),
        smtp_username: e.map(|e| e.username.clone()).unwrap_or_default(),
        smtp_from: e.map(|e| e.from.clone()).unwrap_or_default(),
        smtp_to: e.map(|e| e.to.join(", ")).unwrap_or_default(),
        webhook_url: n.webhook_url.clone().unwrap_or_default(),
        smtp_password_set: st.notify.smtp_password.is_some(),
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
    #[serde(default)]
    smtp_host: String,
    #[serde(default)]
    smtp_port: String,
    #[serde(default)]
    smtp_tls: String,
    #[serde(default)]
    smtp_username: String,
    #[serde(default)]
    smtp_from: String,
    #[serde(default)]
    smtp_to: String,
}

fn conflict(msg: impl std::fmt::Display) -> Response {
    (StatusCode::CONFLICT, msg.to_string()).into_response()
}

/// 表單轉設定；SMTP 主機留空＝停用 Email，Webhook 網址留空＝停用 Webhook。
fn to_settings(f: &SaveForm) -> Result<NotifySettings, String> {
    let min_severity = Severity::parse(&f.min_severity).ok_or("嚴重度無效")?;
    let interval_minutes = f
        .interval_minutes
        .trim()
        .parse::<u32>()
        .map_err(|_| "彙整間隔必須是數字")?;
    let email = if f.smtp_host.trim().is_empty() {
        None
    } else {
        Some(EmailSettings {
            host: f.smtp_host.trim().into(),
            port: f
                .smtp_port
                .trim()
                .parse()
                .map_err(|_| "SMTP 埠號必須是數字")?,
            tls: if f.smtp_tls == "tls" {
                TlsMode::Tls
            } else {
                TlsMode::StartTls
            },
            username: f.smtp_username.trim().into(),
            from: f.smtp_from.trim().into(),
            to: f
                .smtp_to
                .split([',', ';', '\n'])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        })
    };
    let webhook_url = Some(f.webhook_url.trim().to_string()).filter(|u| !u.is_empty());
    Ok(NotifySettings {
        min_severity,
        interval_minutes,
        email,
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
    channel: String,
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
    let d = digest::test_digest();
    let result = match (f.channel.as_str(), &n.email, &n.webhook_url) {
        ("email", None, _) => Err("尚未設定 Email".to_string()),
        ("email", Some(e), _) => {
            let (subject, body) = digest::email_text(&d, &st.notify.web_public_url);
            match send::email_message(e, &subject, &body) {
                Ok(msg) => send::send_email(e, st.notify.smtp_password.as_deref(), msg).await,
                Err(err) => Err(err.to_string()),
            }
        }
        ("webhook", _, None) => Err("尚未設定 Webhook".to_string()),
        ("webhook", _, Some(url)) => match send::webhook_client(&[]) {
            Ok(c) => {
                let body = digest::webhook_body(&d, chrono::Utc::now());
                send::send_webhook(&c, url, st.notify.webhook_secret.as_deref(), &body).await
            }
            Err(err) => Err(err.to_string()),
        },
        _ => Err("未知的管道".to_string()),
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
