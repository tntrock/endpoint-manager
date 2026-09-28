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
    let rows: Vec<(i64, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, \
                (SELECT count(*) FROM devices d WHERE d.group_id = g.id AND d.status <> 'retired'), \
                (SELECT count(*) FROM enroll_tokens t WHERE t.group_id = g.id), \
                (SELECT count(*) FROM admin_groups a WHERE a.group_id = g.id) \
         FROM device_groups g ORDER BY g.name",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(render(&GroupsPage {
        nav: Nav::from(&s),
        rows: rows
            .into_iter()
            .map(|(id, name, devices, tokens, admins)| GroupRow {
                id,
                name,
                devices,
                tokens,
                admins,
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
