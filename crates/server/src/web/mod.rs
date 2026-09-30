//! 管理網頁：路由、安全標頭、樣板輸出與共用格式化。
//!
//! handler 以 `Result<Response, Response>` 回傳錯誤頁（axum 慣用寫法），允許較大的 Err。
#![allow(clippy::result_large_err)]

pub mod accounts;
pub mod audit;
pub mod auth;
pub mod compliance;
pub mod dashboard;
pub mod deployments;
pub mod devices;
pub mod groups;
pub mod login;
pub mod notify;
pub mod packages;
pub mod password;
pub mod registry;
pub mod rules;
pub mod software;
pub mod tokens;
pub mod updates;

use askama::Template;
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};

use crate::AppState;

const CSP: &str = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    h.entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    res
}

pub fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "權限不足").into_response()
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "找不到").into_response()
}

pub fn fmt_time(state: &AppState, t: Option<DateTime<Utc>>) -> String {
    t.map(|t| {
        t.with_timezone(&state.display_offset)
            .format("%Y-%m-%d %H:%M")
            .to_string()
    })
    .unwrap_or_else(|| "—".into())
}

/// LIKE 搜尋時把使用者輸入的 % _ \ 當一般字元。
pub fn escape_like(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

/// URL query 參數編碼。
pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn asset(body: &'static str, content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        body,
    )
        .into_response()
}

pub fn web_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::page))
        .route("/login", get(login::form).post(login::submit))
        .route("/logout", post(login::logout))
        .route("/devices", get(devices::list))
        .route("/software", get(software::search))
        .route("/registry", get(registry::query))
        .route(
            "/deployments",
            get(deployments::list).post(deployments::create),
        )
        .route("/deployments/new", get(deployments::new_form))
        .route("/deployments/{id}", get(deployments::detail))
        .route("/deployments/{id}/{action}", post(deployments::act))
        .route("/updates", get(updates::list).post(updates::create))
        .route("/updates/new", get(updates::new_form))
        .route("/updates/{id}", get(updates::detail))
        .route(
            "/updates/{id}/edit",
            get(updates::edit_form).post(updates::update),
        )
        .route("/updates/{id}/{action}", post(updates::act))
        .route("/packages", get(packages::list))
        .route(
            "/packages/upload",
            get(packages::upload_page).put(packages::upload),
        )
        .route(
            "/packages/{id}",
            get(packages::edit_form).post(packages::update),
        )
        .route("/packages/{id}/delete", post(packages::delete))
        .route("/registry/devices", get(registry::devices))
        .route("/compliance", get(compliance::overview))
        .route("/compliance/violations", get(compliance::violations))
        .route("/compliance/violations.csv", get(compliance::export_csv))
        .route("/compliance/notify", get(notify::page).post(notify::save))
        .route("/compliance/notify/test", post(notify::test))
        .route("/compliance/rules", get(rules::list).post(rules::create))
        .route("/compliance/rules/new", get(rules::new_form))
        .route(
            "/compliance/rules/templates",
            get(rules::templates_page).post(rules::create_from_templates),
        )
        .route("/compliance/rules/preview", post(rules::preview))
        .route(
            "/compliance/rules/{id}",
            get(rules::edit_form).post(rules::update),
        )
        .route("/compliance/rules/{id}/delete", post(rules::delete))
        .route("/tokens", get(tokens::list).post(tokens::create))
        .route("/tokens/{id}/revoke", post(tokens::revoke))
        .route("/groups", get(groups::list).post(groups::create))
        .route("/groups/{id}/delete", post(groups::delete))
        .route("/accounts", get(accounts::list).post(accounts::create))
        .route(
            "/accounts/{id}",
            get(accounts::detail).post(accounts::update),
        )
        .route("/accounts/{id}/disable", post(accounts::disable))
        .route("/accounts/{id}/enable", post(accounts::enable))
        .route("/accounts/{id}/unlock", post(accounts::unlock))
        .route("/accounts/{id}/password", post(accounts::reset_password))
        .route("/password", get(password::form).post(password::submit))
        .route("/audit", get(audit::page))
        .route("/devices/approve-all", post(devices::approve_all))
        .route("/devices/{id}/approve", post(devices::approve))
        .route("/devices/{id}/reject", post(devices::reject))
        .route("/devices/{id}", get(devices::detail))
        .route("/devices/{id}/tab/{tab}", get(devices::tab))
        .route("/devices/{id}/retire", post(devices::retire))
        .route("/devices/{id}/group", post(devices::move_group))
        .route(
            "/devices/{id}/exemptions",
            post(compliance::create_exemption),
        )
        .route(
            "/exemptions/{id}/revoke",
            post(compliance::revoke_exemption),
        )
        .route(
            "/static/htmx.min.js",
            get(|| async {
                asset(
                    include_str!("../../static/htmx.min.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/static/upload.js",
            get(|| async {
                asset(
                    include_str!("../../static/upload.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/static/app.css",
            get(|| async {
                asset(
                    include_str!("../../static/app.css"),
                    "text/css; charset=utf-8",
                )
            }),
        )
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_helpers() {
        assert_eq!(escape_like("50%_off\\"), "%50\\%\\_off\\\\%");
        assert_eq!(enc("Google Chrome&x"), "Google%20Chrome%26x");
    }
}
