//! 自己的兩步驟驗證：設定、停用、重新產生復原碼（所有角色）。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;
use crate::mfa::{self, MfaError};
use crate::totp;

#[derive(Template)]
#[template(path = "mfa.html")]
struct MfaPage {
    nav: Nav,
    setup_only: bool,
    /// 剛從「只能設定」的工作階段完成設定，顯示前往管理網頁的按鈕
    setup_only_done: bool,
    required: bool,
    enabled_at: Option<String>,
    recovery_left: i64,
    secret: String,
    qr: String,
    codes: Vec<String>,
    message: Option<&'static str>,
    error: Option<String>,
}

#[derive(Default)]
struct Extra {
    codes: Vec<String>,
    message: Option<&'static str>,
    error: Option<String>,
    setup_only_done: bool,
}

async fn page(st: &AppState, s: &Session, extra: Extra) -> Result<Response, AppError> {
    let status = mfa::status(&st.pool, s.admin_id).await?;
    let (secret, qr) = if status.enabled_at.is_none() {
        let secret = mfa::pending_secret(&st.pool, s.admin_id).await?;
        let qr = totp::qr_svg(&totp::otpauth_uri(mfa::ISSUER, &s.username, &secret));
        (secret, qr)
    } else {
        Default::default()
    };
    let status_code = if extra.error.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let page = MfaPage {
        nav: Nav::new(s, "mfa"),
        // 剛完成設定時，同一個請求裡的 Session 還是舊值
        setup_only: s.setup_only && status.enabled_at.is_none(),
        setup_only_done: extra.setup_only_done,
        required: mfa::required(&st.pool).await?,
        enabled_at: status.enabled_at.map(|t| fmt_time(st, Some(t))),
        recovery_left: status.recovery_left,
        secret,
        qr,
        codes: extra.codes,
        message: extra.message,
        error: extra.error,
    };
    Ok((status_code, render(&page)).into_response())
}

pub async fn form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    page(&st, &s, Extra::default()).await
}

#[derive(Deserialize)]
pub struct CodeForm {
    csrf: String,
    code: String,
}

/// 使用者輸入問題重新顯示頁面；資料庫錯誤照一般錯誤處理
async fn result(
    st: &AppState,
    s: &Session,
    r: Result<Extra, MfaError>,
) -> Result<Response, AppError> {
    match r {
        Ok(extra) => page(st, s, extra).await,
        Err(MfaError::Db(e)) => Err(e.into()),
        Err(e) => {
            page(
                st,
                s,
                Extra {
                    error: Some(e.to_string()),
                    ..Default::default()
                },
            )
            .await
        }
    }
}

pub async fn enable(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CodeForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let r = mfa::enable(&st.pool, s.admin_id, &f.code, &s.token_hash)
        .await
        .map(|codes| Extra {
            codes,
            message: Some("已啟用兩步驟驗證"),
            setup_only_done: s.setup_only,
            ..Default::default()
        });
    result(&st, &s, r)
        .await
        .map_err(IntoResponse::into_response)
}

pub async fn disable(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CodeForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let r = mfa::disable(&st.pool, s.admin_id, &f.code, &s.token_hash)
        .await
        .map(|()| Extra {
            message: Some("已停用兩步驟驗證"),
            ..Default::default()
        });
    result(&st, &s, r)
        .await
        .map_err(IntoResponse::into_response)
}

pub async fn recovery(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CodeForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let r = mfa::regenerate_recovery(&st.pool, s.admin_id, &f.code)
        .await
        .map(|codes| Extra {
            codes,
            message: Some("已重新產生復原碼，舊的已作廢"),
            ..Default::default()
        });
    result(&st, &s, r)
        .await
        .map_err(IntoResponse::into_response)
}
