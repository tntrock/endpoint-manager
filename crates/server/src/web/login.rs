//! 登入（帳號密碼，再視需要輸入驗證碼）與登出。登入表單沒有工作階段可綁 CSRF；
//! cookie 為 SameSite=Strict，跨站送出的登入只會讓攻擊者登入自己的帳號，影響有限。

use askama::Template;
use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{AppendHeaders, IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{self, AdminSession, LoginOutcome, MfaOutcome, Nav, check_csrf};
use super::render;
use crate::AppState;
use crate::error::AppError;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    nav: Nav,
    error: Option<&'static str>,
    /// 單一登入按鈕的文字；None 表示沒設定單一登入
    sso_label: Option<String>,
}

/// 單一登入成功後的中繼頁：工作階段 cookie 是 SameSite=Strict，
/// 從跨站回呼直接重新導向時第一個請求不會帶 cookie
#[derive(Template)]
#[template(path = "login_done.html")]
struct DonePage {
    nav: Nav,
}

#[derive(Template)]
#[template(path = "login_mfa.html")]
struct MfaPage {
    nav: Nav,
    error: Option<&'static str>,
}

fn sso_label(st: &AppState) -> Option<String> {
    st.oidc.as_ref().map(|p| p.cfg.label.clone())
}

pub async fn form(State(st): State<AppState>) -> Response {
    render(&LoginPage {
        nav: Nav::anonymous(),
        error: None,
        sso_label: sso_label(&st),
    })
}

fn login_error(st: &AppState, error: &'static str) -> Response {
    let page = LoginPage {
        nav: Nav::anonymous(),
        error: Some(error),
        sso_label: sso_label(st),
    };
    (StatusCode::UNAUTHORIZED, render(&page)).into_response()
}

fn signed_in(session_token: &str) -> Response {
    (
        AppendHeaders([
            (header::SET_COOKIE, auth::session_cookie(session_token)),
            (header::SET_COOKIE, auth::clear_mfa_cookie()),
        ]),
        Redirect::to("/"),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn submit(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Form(f): Form<LoginForm>,
) -> Result<Response, AppError> {
    if !st.login_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    let sso_only = st.oidc.is_some() && auth::password_login_platform_only(&st.pool).await?;
    match auth::login_checked(&st.pool, f.username.trim(), &f.password, sso_only).await? {
        LoginOutcome::Ok { session_token } => Ok(signed_in(&session_token)),
        LoginOutcome::MfaRequired { challenge_token } => Ok((
            [(header::SET_COOKIE, auth::mfa_cookie(&challenge_token))],
            Redirect::to("/login/mfa"),
        )
            .into_response()),
        LoginOutcome::Failed => Ok(login_error(&st, "帳號或密碼錯誤")),
        LoginOutcome::SsoOnly => Ok(login_error(
            &st,
            "這個帳號只能用單一登入，請按下方的按鈕登入",
        )),
    }
}

pub async fn mfa_form(headers: HeaderMap) -> Response {
    if auth::cookie_from(&headers, auth::MFA_COOKIE).is_none_or(|c| c.is_empty()) {
        return Redirect::to("/login").into_response();
    }
    render(&MfaPage {
        nav: Nav::anonymous(),
        error: None,
    })
}

#[derive(Deserialize)]
pub struct MfaForm {
    code: String,
}

pub async fn mfa_submit(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(f): Form<MfaForm>,
) -> Result<Response, AppError> {
    if !st.login_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    let restart = || {
        (
            [(header::SET_COOKIE, auth::clear_mfa_cookie())],
            login_error(&st, "驗證逾時或錯誤次數過多，請重新登入"),
        )
            .into_response()
    };
    let Some(challenge) = auth::cookie_from(&headers, auth::MFA_COOKIE).filter(|c| !c.is_empty())
    else {
        return Ok(restart());
    };
    Ok(
        match auth::login_mfa(&st.pool, &challenge, &f.code).await? {
            MfaOutcome::Ok { session_token } => signed_in(&session_token),
            MfaOutcome::Retry => {
                let page = MfaPage {
                    nav: Nav::anonymous(),
                    error: Some("驗證碼不正確"),
                };
                (StatusCode::UNAUTHORIZED, render(&page)).into_response()
            }
            MfaOutcome::Restart => restart(),
        },
    )
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf: String,
}

pub async fn logout(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    auth::logout(&st.pool, &s)
        .await
        .map_err(|e| AppError::from(e).into_response())?;
    Ok((
        [(header::SET_COOKIE, auth::clear_cookie())],
        Redirect::to("/login"),
    )
        .into_response())
}

/// `em_oidc`：回呼是從身分提供者網站來的頂層 GET，必須是 SameSite=Lax 才會送出
fn oidc_cookie(value: &str, max_age: i32) -> String {
    format!(
        "{}={value}; Path=/login/oidc; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}",
        crate::oidc::COOKIE
    )
}

/// 開始單一登入：導向身分提供者
pub async fn oidc_start(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
) -> Result<Response, AppError> {
    let Some(p) = st.oidc.clone() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !st.login_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    match crate::oidc::start(&st.pool, &p).await {
        Ok((id, url)) => Ok((
            [(
                header::SET_COOKIE,
                oidc_cookie(&id, crate::oidc::LOGIN_MINUTES * 60),
            )],
            Redirect::to(&url),
        )
            .into_response()),
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "oidc start failed");
            Ok((
                StatusCode::BAD_GATEWAY,
                login_error(&st, "無法連線到身分提供者，請稍後再試"),
            )
                .into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    state: String,
    code: Option<String>,
}

/// 身分提供者導回：確認流程、換得身分、對應帳號
pub async fn oidc_callback(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<CallbackQuery>,
) -> Result<Response, AppError> {
    let Some(p) = st.oidc.clone() else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !st.login_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    let cookie = auth::cookie_from(&headers, crate::oidc::COOKIE);
    let clear = (header::SET_COOKIE, oidc_cookie("", 0));
    let id = match crate::oidc::finish(&st.pool, &p, cookie.as_deref(), &q.state, q.code.as_deref())
        .await
    {
        Ok(id) => id,
        Err(f) => {
            let mut c = st.pool.acquire().await?;
            crate::audit::record(
                &mut c,
                "-",
                "login_failed",
                None,
                serde_json::json!({ "reason": f.reason() }),
            )
            .await?;
            return Ok(([clear], login_error(&st, f.message())).into_response());
        }
    };
    let error = match auth::login_oidc(&st.pool, &p.cfg.issuer, &id).await? {
        auth::OidcOutcome::Ok { session_token } => {
            return Ok((
                AppendHeaders([
                    clear,
                    (header::SET_COOKIE, auth::session_cookie(&session_token)),
                ]),
                render(&DonePage {
                    nav: Nav::anonymous(),
                }),
            )
                .into_response());
        }
        auth::OidcOutcome::NoAccount => "這個公司帳號沒有對應的管理帳號，請聯絡平台管理員",
        auth::OidcOutcome::Conflict => {
            "同名的管理帳號已綁定另一個公司帳號，請聯絡平台管理員解除綁定"
        }
    };
    Ok(([clear], login_error(&st, error)).into_response())
}
