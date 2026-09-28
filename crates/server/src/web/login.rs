//! 登入與登出。登入表單沒有工作階段可綁 CSRF；cookie 為 SameSite=Strict，
//! 跨站送出的登入只會讓攻擊者登入自己的帳號，影響有限。

use askama::Template;
use std::net::SocketAddr;
use std::time::Instant;

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{self, AdminSession, LoginOutcome, Nav, check_csrf};
use super::render;
use crate::AppState;
use crate::error::AppError;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    nav: Nav,
    error: Option<&'static str>,
}

pub async fn form() -> Response {
    render(&LoginPage {
        nav: Nav::anonymous(),
        error: None,
    })
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
        LoginOutcome::Ok { session_token } => Ok((
            [(header::SET_COOKIE, auth::session_cookie(&session_token))],
            Redirect::to("/"),
        )
            .into_response()),
        LoginOutcome::Failed => {
            let page = LoginPage {
                nav: Nav::anonymous(),
                error: Some("帳號或密碼錯誤"),
            };
            Ok((StatusCode::UNAUTHORIZED, render(&page)).into_response())
        }
    }
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
