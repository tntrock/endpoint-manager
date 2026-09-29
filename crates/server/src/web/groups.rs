//! 群組管理（平台管理員）。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf};
use super::login::CsrfForm;
use super::{forbidden, render};
use crate::AppState;
use crate::error::AppError;

pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub devices: i64,
    pub tokens: i64,
    pub admins: i64,
    pub rules: i64,
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsPage {
    nav: Nav,
    rows: Vec<GroupRow>,
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    if !s.all_devices() {
        return Ok(forbidden());
    }
    let groups: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM device_groups ORDER BY name")
            .fetch_all(&st.pool)
            .await?;
    // 與刪除檢查同一個定義（groups::usage），群組不多，逐一查即可
    let mut conn = st.pool.acquire().await?;
    let mut rows = Vec::with_capacity(groups.len());
    for (id, name) in groups {
        let (devices, tokens, admins, rules) = crate::groups::usage(&mut conn, id).await?;
        rows.push((id, name, devices, tokens, admins, rules));
    }
    Ok(render(&GroupsPage {
        nav: Nav::from(&s),
        rows: rows
            .into_iter()
            .map(|(id, name, devices, tokens, admins, rules)| GroupRow {
                id,
                name,
                devices,
                tokens,
                admins,
                rules,
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
}

fn conflict(e: anyhow::Error) -> Response {
    (StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CreateForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    crate::groups::create(&st.pool, &f.name, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to("/groups").into_response())
}

pub async fn delete(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    crate::groups::delete(&st.pool, id, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to("/groups").into_response())
}
