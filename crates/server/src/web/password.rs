//! 修改自己的密碼（所有角色）。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf};
use super::render;
use crate::AppState;

#[derive(Template)]
#[template(path = "password.html")]
struct PasswordPage {
    nav: Nav,
    message: Option<&'static str>,
    error: Option<String>,
}

pub async fn form(AdminSession(s): AdminSession) -> Response {
    render(&PasswordPage {
        nav: Nav::from(&s),
        message: None,
        error: None,
    })
}

#[derive(Deserialize)]
pub struct ChangeForm {
    csrf: String,
    current: String,
    new: String,
    confirm: String,
}

pub async fn submit(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<ChangeForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let fail = |e: String| {
        let page = PasswordPage {
            nav: Nav::from(&s),
            message: None,
            error: Some(e),
        };
        (StatusCode::BAD_REQUEST, render(&page)).into_response()
    };
    if f.new != f.confirm {
        return Err(fail("兩次輸入的新密碼不一致".into()));
    }
    crate::accounts::change_own_password(&st.pool, s.admin_id, &f.current, &f.new, &s.token_hash)
        .await
        .map_err(|e| fail(format!("{e:#}")))?;
    Ok(render(&PasswordPage {
        nav: Nav::from(&s),
        message: Some("密碼已更新"),
        error: None,
    }))
}
