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
}

#[derive(Template)]
#[template(path = "login_mfa.html")]
struct MfaPage {
    nav: Nav,
    error: Option<&'static str>,
}

pub async fn form() -> Response {
    render(&LoginPage {
        nav: Nav::anonymous(),
        error: None,
    })
}

fn login_error(error: &'static str) -> Response {
    let page = LoginPage {
        nav: Nav::anonymous(),
        error: Some(error),
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
    match auth::login(&st.pool, f.username.trim(), &f.password).await? {
        LoginOutcome::Ok { session_token } => Ok(signed_in(&session_token)),
        LoginOutcome::MfaRequired { challenge_token } => Ok((
            [(header::SET_COOKIE, auth::mfa_cookie(&challenge_token))],
            Redirect::to("/login/mfa"),
        )
            .into_response()),
        LoginOutcome::Failed => Ok(login_error("帳號或密碼錯誤")),
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
            login_error("驗證逾時或錯誤次數過多，請重新登入"),
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
