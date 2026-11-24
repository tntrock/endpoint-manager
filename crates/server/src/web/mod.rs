//! 管理網頁：路由、安全標頭、樣板輸出與共用格式化。
//!
//! handler 以 `Result<Response, Response>` 回傳錯誤頁（axum 慣用寫法），允許較大的 Err。
#![allow(clippy::result_large_err)]

pub mod accounts;
pub mod audit;
pub mod auth;
pub mod caches;
pub mod chart;
pub mod commands;
pub mod compliance;
pub mod containers;
pub mod dashboard;
pub mod deployments;
pub mod device_status;
pub mod devices;
pub mod exposure;
pub mod groups;
pub mod images;
pub mod integrity;
pub mod local_users;
pub mod login;
pub mod mfa;
pub mod netdevices;
pub mod network;
pub mod notify;
pub mod packages;
pub mod password;
pub mod registry;
pub mod report;
pub mod rules;
pub mod scripts;
pub mod settings;
pub mod shares;
pub mod signing;
pub mod sites;
pub mod software;
pub mod sort;
pub mod timeline;
pub mod tokens;
pub mod unmanaged;
pub mod updates;
pub mod vms;

use askama::Template;
use axum::Router;
use axum::extract::{RawQuery, Request};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};

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

pub fn fmt_time(state: &AppState, t: Option<time::OffsetDateTime>) -> String {
    t.and_then(|t| {
        t.to_offset(state.display_offset)
            .format(time::macros::format_description!(
                "[year]-[month]-[day] [hour]:[minute]"
            ))
            .ok()
    })
    .unwrap_or_else(|| "—".into())
}

/// UTC 的「年-月-日 時:分:秒」（CSV 匯出）
pub fn fmt_utc_seconds(t: time::OffsetDateTime) -> String {
    t.to_offset(time::UtcOffset::UTC)
        .format(time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second]"
        ))
        .unwrap_or_default()
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

/// 內嵌的靜態檔：(網址, 內容, Content-Type)
const STATIC_FILES: &[(&str, &str, &str)] = &[
    (
        "/static/htmx.min.js",
        include_str!("../../static/htmx.min.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/static/upload.js",
        include_str!("../../static/upload.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/static/app.css",
        include_str!("../../static/app.css"),
        "text/css; charset=utf-8",
    ),
    (
        "/static/app.js",
        include_str!("../../static/app.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/static/theme.js",
        include_str!("../../static/theme.js"),
        "text/javascript; charset=utf-8",
    ),
    (
        "/static/favicon.svg",
        include_str!("../../static/favicon.svg"),
        "image/svg+xml",
    ),
    (
        "/static/icons.svg",
        include_str!("../../static/icons.svg"),
        "image/svg+xml",
    ),
];

/// 靜態檔內容的雜湊（前 12 個十六進位字元）：頁面用 `?v=` 帶上它，
/// 內容一改網址就變，瀏覽器不會沿用舊的 CSS、圖示（同一個版本號重新建置也一樣）。
pub fn asset_version() -> &'static str {
    static V: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        for (path, body, _) in STATIC_FILES {
            ctx.update(path.as_bytes());
            ctx.update(&[0]);
            ctx.update(body.as_bytes());
            ctx.update(&[0]);
        }
        ctx.finish().as_ref()[..6]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    });
    &V
}

fn static_routes() -> Router<AppState> {
    STATIC_FILES
        .iter()
        .fold(Router::new(), |r, &(path, body, content_type)| {
            r.route(
                path,
                get(move |h: HeaderMap, q: RawQuery| async move {
                    asset(body, content_type, &h, q.0.as_deref())
                }),
            )
        })
}

/// 網址帶著目前的 `?v=` 就長期快取；其他（例如 `<use href="/static/icons.svg#…">`
/// 與舊版頁面）每次都要向伺服器確認，沒變就回 304。
fn asset(
    body: &'static str,
    content_type: &'static str,
    req: &HeaderMap,
    query: Option<&str>,
) -> Response {
    let etag = format!("\"{}\"", asset_version());
    let versioned = query.is_some_and(|q| {
        q.split('&')
            .any(|kv| kv.strip_prefix("v=") == Some(asset_version()))
    });
    let cache = if versioned {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let fresh = req
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
    let headers = [
        (header::CONTENT_TYPE, content_type.to_string()),
        (header::CACHE_CONTROL, cache.to_string()),
        (header::ETAG, etag),
    ];
    if fresh {
        (StatusCode::NOT_MODIFIED, headers).into_response()
    } else {
        (headers, body).into_response()
    }
}

pub fn web_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::page))
        .route("/report", get(report::page))
        .route("/ui/status", get(dashboard::status))
        .route("/login", get(login::form).post(login::submit))
        .route("/login/mfa", get(login::mfa_form).post(login::mfa_submit))
        .route("/login/oidc", get(login::oidc_start))
        .route("/login/oidc/callback", get(login::oidc_callback))
        .route("/mfa", get(mfa::form))
        .route("/mfa/enable", post(mfa::enable))
        .route("/mfa/disable", post(mfa::disable))
        .route("/mfa/recovery", post(mfa::recovery))
        .route("/logout", post(login::logout))
        .route("/devices", get(devices::list))
        .route("/software", get(software::search))
        .route("/vms", get(vms::list))
        .route("/containers", get(images::list))
        .route("/containers/image", get(images::detail))
        .route("/exposure", get(exposure::list))
        .route("/exposure/port", get(exposure::detail))
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
        .route("/updates/overview", get(updates::overview))
        .route("/updates/{id}", get(updates::detail))
        .route(
            "/updates/{id}/edit",
            get(updates::edit_form).post(updates::update),
        )
        .route("/updates/{id}/{action}", post(updates::act))
        .route("/commands", get(commands::list).post(commands::create))
        .route("/commands/{id}", get(commands::detail))
        .route("/commands/{id}/cancel", post(commands::cancel))
        .route("/devices/{id}/commands", post(commands::create_for_device))
        .route("/scripts", get(scripts::list).post(scripts::create))
        .route("/scripts/new", get(scripts::new_form))
        .route("/scripts/settings", post(scripts::settings))
        .route("/scripts/{id}", get(scripts::detail))
        .route(
            "/scripts/{id}/edit",
            get(scripts::edit_form).post(scripts::update),
        )
        .route(
            "/scripts/{id}/signing-request.json",
            get(signing::script_request),
        )
        .route("/scripts/{id}/signature", post(signing::sign_script))
        .route("/scripts/{id}/{action}", post(scripts::act))
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
        .route(
            "/packages/{id}/signing-request.json",
            get(signing::package_request),
        )
        .route("/packages/{id}/signature", post(signing::sign_package))
        .route("/registry/devices", get(registry::devices))
        .route("/compliance", get(compliance::overview))
        .route("/compliance/violations", get(compliance::violations))
        .route("/compliance/violations.csv", get(compliance::export_csv))
        .route(
            "/compliance/violations/exempt",
            post(compliance::bulk_exempt),
        )
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
        .route("/caches", get(caches::list))
        .route("/caches/tokens", post(caches::create_token))
        .route(
            "/caches/tokens/{id}/revoke",
            post(caches::revoke_cache_token),
        )
        .route("/caches/{id}/{action}", post(caches::act))
        .route(
            "/netdevices",
            get(netdevices::list).post(netdevices::create_device),
        )
        .route("/netdevices/new", get(netdevices::new_device))
        .route("/netdevices/settings", post(netdevices::save_intervals))
        .route(
            "/netdevices/credentials",
            post(netdevices::create_credential),
        )
        .route(
            "/netdevices/credentials/new",
            get(netdevices::new_credential),
        )
        .route(
            "/netdevices/credentials/{id}",
            post(netdevices::update_credential),
        )
        .route(
            "/netdevices/credentials/{id}/edit",
            get(netdevices::edit_credential),
        )
        .route(
            "/netdevices/credentials/{id}/delete",
            post(netdevices::delete_credential),
        )
        .route(
            "/netdevices/{id}",
            get(netdevices::detail).post(netdevices::update_device),
        )
        .route("/netdevices/{id}/edit", get(netdevices::edit_device))
        .route("/netdevices/{id}/delete", post(netdevices::delete_device))
        .route("/netdevices/{id}/poll", post(netdevices::poll_device))
        .route(
            "/netdevices/{id}/ports/{if_index}/role",
            post(netdevices::set_port_role),
        )
        .route("/netdevices/unmanaged", get(unmanaged::list))
        .route("/netdevices/unmanaged/known", post(unmanaged::add_known))
        .route("/netdevices/known", get(unmanaged::known))
        .route(
            "/netdevices/known/{id}/delete",
            post(unmanaged::delete_known),
        )
        .route("/sites", get(sites::list).post(sites::create))
        .route("/sites/new", get(sites::new_form))
        .route("/sites/{id}", post(sites::update))
        .route("/sites/{id}/edit", get(sites::edit_form))
        .route("/sites/{id}/delete", post(sites::delete))
        .route("/tokens", get(tokens::list).post(tokens::create))
        .route("/tokens/{id}/revoke", post(tokens::revoke))
        .route("/tokens/agent.deb", get(tokens::linux_deb))
        .route("/tokens/agent.rpm", get(tokens::linux_rpm))
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
        .route("/accounts/{id}/mfa-reset", post(accounts::reset_mfa))
        .route("/accounts/mfa-required", post(accounts::set_mfa_required))
        .route(
            "/accounts/password-login",
            post(accounts::set_password_login),
        )
        .route("/accounts/{id}/oidc-unlink", post(accounts::unlink_oidc))
        .route("/password", get(password::form).post(password::submit))
        .route("/settings", get(settings::page).post(settings::save))
        .route("/audit", get(audit::page))
        .route("/audit/retention", post(audit::retention))
        .route("/metrics", get(crate::metrics::handler))
        .route("/devices/approve-all", post(devices::approve_all))
        .route("/devices/bulk", post(devices::bulk))
        .route("/devices/{id}/approve", post(devices::approve))
        .route("/devices/{id}/reject", post(devices::reject))
        .route("/devices/{id}", get(devices::detail))
        .route("/devices/{id}/tab/{tab}", get(devices::tab))
        .route("/devices/{id}/timeline", get(timeline::more))
        .route("/devices/{id}/retire", post(devices::retire))
        .route("/devices/{id}/group", post(devices::move_group))
        .route(
            "/devices/{id}/findings/{finding}/ack",
            post(integrity::acknowledge),
        )
        .route(
            "/devices/{id}/exemptions",
            post(compliance::create_exemption),
        )
        .route(
            "/exemptions/{id}/revoke",
            post(compliance::revoke_exemption),
        )
        .merge(static_routes())
        .route_layer(middleware::from_fn_with_state(
            (state.metrics.clone(), "web"),
            crate::metrics::track,
        ))
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

    /// CSP 不允許 inline style、inline script 與事件屬性：寫了也不會生效
    #[test]
    fn templates_have_no_inline_code() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let html = std::fs::read_to_string(&path).unwrap().to_lowercase();
            let name = path.display();
            assert!(
                !html.contains("style=") && !html.contains("<style"),
                "{name}: inline style"
            );
            for (i, _) in html.match_indices("<script") {
                let tag = html[i..].split('>').next().unwrap();
                assert!(tag.contains(" src="), "{name}: inline script");
            }
            for (i, _) in html.match_indices(" on") {
                let rest = &html[i + 1..];
                let attr: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphabetic())
                    .collect();
                assert!(
                    !(attr.len() > 2 && rest[attr.len()..].starts_with('=')),
                    "{name}: 事件屬性 {attr}"
                );
            }
        }
    }
}
