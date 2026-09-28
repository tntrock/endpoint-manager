//! 註冊金鑰：建立（明碼只顯示一次）、列表、作廢；群組管理員限自己的群組。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, db_error, group_options};
use super::login::CsrfForm;
use super::{fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::tokens::{NewToken, create_token, revoke_token};

pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub group: String,
    pub used: i32,
    pub max: i32,
    pub expires: String,
    pub created_by: String,
    pub created_at: String,
    pub active: bool,
    pub state: &'static str,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensPage {
    nav: Nav,
    new_token: Option<String>,
    groups: Vec<SelectOption>,
    rows: Vec<TokenRow>,
}

type Row = (
    i64,
    String,
    Option<String>,
    i32,
    i32,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    String,
    DateTime<Utc>,
);

async fn page_for(
    st: &AppState,
    s: &Session,
    new_token: Option<String>,
) -> Result<Response, Response> {
    if !s.can_manage() {
        return Err(forbidden());
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT t.id, t.name, g.name, t.used_count, t.max_uses, t.expires_at, t.revoked_at, \
                t.created_by, t.created_at \
         FROM enroll_tokens t LEFT JOIN device_groups g ON g.id = t.group_id \
         WHERE ($1::bool OR t.group_id = ANY($2::bigint[])) ORDER BY t.id DESC",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let now = Utc::now();
    let rows = rows
        .into_iter()
        .map(
            |(id, name, group, used, max, expires, revoked, created_by, created_at)| {
                let state = if revoked.is_some() {
                    "已作廢"
                } else if expires.is_some_and(|e| e <= now) {
                    "已過期"
                } else if used >= max {
                    "已用完"
                } else {
                    ""
                };
                TokenRow {
                    id,
                    name,
                    group: group.unwrap_or_else(|| "未分組".into()),
                    used,
                    max,
                    expires: expires
                        .map(|e| fmt_time(st, Some(e)))
                        .unwrap_or_else(|| "不限".into()),
                    created_by,
                    created_at: fmt_time(st, Some(created_at)),
                    active: state.is_empty(),
                    state,
                }
            },
        )
        .collect();
    Ok(render(&TokensPage {
        nav: Nav::from(s),
        new_token,
        groups: group_options(st, s, "", false).await.map_err(db_error)?,
        rows,
    }))
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    page_for(&st, &s, None).await
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
    max_uses: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    valid_days: String,
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CreateForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string()).into_response();
    let group: Option<i64> = match f.group.as_str() {
        "" | "none" => None,
        g => Some(g.parse().map_err(|_| bad("群組不正確"))?),
    };
    if !s.in_scope(group) {
        return Err(forbidden());
    }
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(bad("名稱必填，最多 100 字"));
    }
    let max_uses: i32 = f
        .max_uses
        .trim()
        .parse()
        .ok()
        .filter(|n| *n >= 1)
        .ok_or_else(|| bad("可使用次數需為正整數"))?;
    let valid_days: Option<i64> = match f.valid_days.trim() {
        "" => None,
        d => Some(
            d.parse()
                .ok()
                .filter(|n: &i64| (1..=3650).contains(n))
                .ok_or_else(|| bad("有效天數需為 1～3650"))?,
        ),
    };
    let (id, token) = create_token(
        &st.pool,
        &NewToken {
            name: name.into(),
            group_id: group,
            expires_at: valid_days.map(|d| Utc::now() + Duration::days(d)),
            max_uses,
            created_by: s.username.clone(),
        },
    )
    .await
    .map_err(db_error)?;
    let mut c = st.pool.acquire().await.map_err(db_error)?;
    crate::audit::record(
        &mut c,
        &s.username,
        "token_create",
        Some(&id.to_string()),
        serde_json::json!({
            "name": name, "max_uses": max_uses, "group_id": group, "valid_days": valid_days
        }),
    )
    .await
    .map_err(db_error)?;
    drop(c);
    page_for(&st, &s, Some(token)).await
}

pub async fn revoke(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let group: Option<Option<i64>> =
        sqlx::query_scalar("SELECT group_id FROM enroll_tokens WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await
            .map_err(db_error)?;
    match group {
        Some(g) if s.in_scope(g) => {}
        _ => return Err(not_found()),
    }
    revoke_token(&st.pool, id, &s.username)
        .await
        .map_err(|e| (StatusCode::CONFLICT, format!("{e:#}")).into_response())?;
    Ok(Redirect::to("/tokens").into_response())
}
