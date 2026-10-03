//! 帳號管理（平台管理員）。

use askama::Template;
use axum::extract::{Form, Path, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Role, check_csrf, platform};
use super::devices::{SelectOption, db_error};
use super::login::CsrfForm;
use super::{fmt_time, not_found, render};
use crate::AppState;
use crate::accounts::{self, NewAdmin};

pub struct AccountRow {
    pub id: i64,
    pub username: String,
    pub role: &'static str,
    pub groups: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub created_at: String,
    pub locked: bool,
    pub disabled: bool,
}

#[derive(Template)]
#[template(path = "accounts.html")]
struct AccountsPage {
    nav: Nav,
    roles: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<AccountRow>,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    nav: Nav,
    a: AccountRow,
    roles: Vec<SelectOption>,
    groups: Vec<SelectOption>,
}

type Row = (
    i64,
    String,
    String,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Vec<i64>,
);

const SELECT: &str = "SELECT a.id, a.username, a.role, \
       (SELECT string_agg(g.name, '、' ORDER BY g.name) FROM admin_groups ag \
          JOIN device_groups g ON g.id = ag.group_id WHERE ag.admin_id = a.id), \
       a.locked_until, a.disabled_at, a.created_at, \
       ARRAY(SELECT group_id FROM admin_groups WHERE admin_id = a.id) \
     FROM admins a";

fn to_row(st: &AppState, r: Row) -> (AccountRow, Vec<i64>) {
    let (id, username, role, groups, locked_until, disabled_at, created_at, group_ids) = r;
    let locked = locked_until.is_some_and(|t| t > Utc::now());
    let (state, state_class) = if disabled_at.is_some() {
        ("已停用", "bad")
    } else if locked {
        ("已鎖定", "warn")
    } else {
        ("啟用中", "ok")
    };
    (
        AccountRow {
            id,
            username,
            role: Role::parse(&role).map(Role::label).unwrap_or("?"),
            groups: groups.unwrap_or_default(),
            state,
            state_class,
            created_at: fmt_time(st, Some(created_at)),
            locked,
            disabled: disabled_at.is_some(),
        },
        group_ids,
    )
}

async fn all_groups(st: &AppState, selected: &[i64]) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM device_groups ORDER BY name")
            .fetch_all(&st.pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| SelectOption {
            selected: selected.contains(&id),
            value: id.to_string(),
            label: name,
        })
        .collect())
}

fn roles(current: &str) -> Vec<SelectOption> {
    Role::ALL
        .into_iter()
        .map(|r| SelectOption {
            value: r.as_str().into(),
            label: r.label().into(),
            selected: r.as_str() == current,
        })
        .collect()
}

fn conflict(e: anyhow::Error) -> Response {
    (StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    let rows: Vec<Row> =
        sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} ORDER BY a.username")))
            .fetch_all(&st.pool)
            .await
            .map_err(db_error)?;
    Ok(render(&AccountsPage {
        nav: Nav::new(&s, "accounts"),
        roles: roles("group_admin"),
        groups: all_groups(&st, &[]).await.map_err(db_error)?,
        rows: rows.into_iter().map(|r| to_row(&st, r).0).collect(),
    }))
}

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<Row> = sqlx::query_as(sqlx::AssertSqlSafe(format!("{SELECT} WHERE a.id = $1")))
        .bind(id)
        .fetch_optional(&st.pool)
        .await
        .map_err(db_error)?;
    let Some(row) = row else {
        return Err(not_found());
    };
    let role = row.2.clone();
    let (a, group_ids) = to_row(&st, row);
    Ok(render(&AccountPage {
        nav: Nav::new(&s, "accounts"),
        roles: roles(&role),
        groups: all_groups(&st, &group_ids).await.map_err(db_error)?,
        a,
    }))
}

/// 含重複 `groups` 欄位的表單（多選核取方塊）。
struct AccountForm {
    csrf: String,
    username: String,
    password: String,
    role: Option<Role>,
    groups: Vec<i64>,
}

fn parse_form(raw: &[u8]) -> AccountForm {
    let mut f = AccountForm {
        csrf: String::new(),
        username: String::new(),
        password: String::new(),
        role: None,
        groups: vec![],
    };
    for (k, v) in form_urlencoded::parse(raw) {
        match k.as_ref() {
            "csrf" => f.csrf = v.into_owned(),
            "username" => f.username = v.into_owned(),
            "password" => f.password = v.into_owned(),
            "role" => f.role = Role::parse(&v),
            "groups" => f.groups.extend(v.parse::<i64>().ok()),
            _ => {}
        }
    }
    f
}

fn bad_role() -> Response {
    (StatusCode::BAD_REQUEST, "角色不正確").into_response()
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let role = f.role.ok_or_else(bad_role)?;
    accounts::create(
        &st.pool,
        &NewAdmin {
            username: f.username,
            password: f.password,
            role,
            groups: f.groups,
        },
        &s.username,
    )
    .await
    .map_err(conflict)?;
    Ok(Redirect::to("/accounts").into_response())
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let role = f.role.ok_or_else(bad_role)?;
    accounts::update(&st.pool, id, role, &f.groups, s.admin_id, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

pub async fn disable(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::set_disabled(&st.pool, id, true, s.admin_id, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

pub async fn enable(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::set_disabled(&st.pool, id, false, s.admin_id, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

pub async fn unlock(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::unlock(&st.pool, id, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

#[derive(Deserialize)]
pub struct ResetForm {
    csrf: String,
    password: String,
}

pub async fn reset_password(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<ResetForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::reset_password(&st.pool, id, &f.password, &s.username)
        .await
        .map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}
