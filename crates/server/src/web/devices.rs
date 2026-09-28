//! 裝置列表、詳細資料與動作。所有查詢都以工作階段的群組範圍過濾；範圍外一律 404。

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::login::CsrfForm;
use super::{enc, escape_like, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::db::load_settings;
use crate::error::AppError;

pub const PAGE_SIZE: i64 = 50;

pub async fn online_cutoff(st: &AppState) -> Result<DateTime<Utc>, sqlx::Error> {
    let s = load_settings(&st.pool).await?;
    Ok(Utc::now() - Duration::seconds(3 * i64::from(s.checkin_interval_secs)))
}

pub fn status_label(status: &str, online: bool) -> (&'static str, &'static str) {
    match status {
        "retired" => ("retired", "已除役"),
        "pending_approval" => ("pending_approval", "待核准"),
        "duplicate_suspect" => ("duplicate_suspect", "疑似重複"),
        _ if online => ("online", "在線"),
        _ => ("offline", "離線"),
    }
}

pub struct SelectOption {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

/// 範圍內可選的群組（平台管理員另有「未分組」）。
pub async fn group_options(
    st: &AppState,
    s: &Session,
    current: &str,
    with_all: bool,
) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM device_groups WHERE ($1::bool OR id = ANY($2::bigint[])) ORDER BY name",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let mut out = vec![];
    if with_all {
        out.push(SelectOption {
            value: String::new(),
            label: "所有群組".into(),
            selected: current.is_empty(),
        });
    }
    if s.all_devices() {
        out.push(SelectOption {
            value: "none".into(),
            label: "未分組".into(),
            selected: current == "none",
        });
    }
    out.extend(rows.into_iter().map(|(id, name)| SelectOption {
        selected: current == id.to_string(),
        value: id.to_string(),
        label: name,
    }));
    Ok(out)
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    software: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    page: i64,
}

pub struct DeviceRow {
    pub id: Uuid,
    pub hostname: String,
    pub group: String,
    pub domain: String,
    pub os: String,
    pub user: String,
    pub ip: String,
    pub last_seen: String,
    pub badge: &'static str,
    pub badge_label: &'static str,
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesPage {
    nav: Nav,
    q: String,
    software: String,
    version: String,
    statuses: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<DeviceRow>,
    page: i64,
    has_next: bool,
    prev_url: String,
    next_url: String,
}

type ListRow = (
    Uuid,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    Option<DateTime<Utc>>,
    String,
);

fn page_url(q: &ListQuery, page: i64) -> String {
    format!(
        "/devices?q={}&status={}&group={}&software={}&version={}&page={page}",
        enc(&q.q),
        enc(&q.status),
        enc(&q.group),
        enc(&q.software),
        enc(&q.version)
    )
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let cutoff = online_cutoff(&st).await?;
    let page = q.page.max(0);
    let group_filter: Option<i64> = q.group.parse().ok();
    let mut rows: Vec<ListRow> = sqlx::query_as(
        "SELECT d.id, d.hostname, g.name, coalesce(d.domain, ''), coalesce(d.os_caption, ''), \
                coalesce(d.logged_on_user, ''), coalesce(d.last_ip, ''), d.last_seen_at, d.status \
         FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
           AND ($3 = '' OR d.hostname ILIKE $4 OR d.logged_on_user ILIKE $4 OR d.last_ip ILIKE $4) \
           AND (CASE WHEN $5 = '' THEN d.status <> 'retired' WHEN $5 = 'all' THEN true \
                     ELSE d.status = $5 END) \
           AND (CASE WHEN $6 = '' THEN true WHEN $6 = 'none' THEN d.group_id IS NULL \
                     ELSE d.group_id = $7 END) \
           AND ($8 = '' OR EXISTS (SELECT 1 FROM device_software sw WHERE sw.device_id = d.id \
                                   AND sw.name = $8 AND ($9 = '' OR coalesce(sw.version, '') = $9))) \
         ORDER BY d.hostname, d.id LIMIT $10 OFFSET $11",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(&q.q)
    .bind(escape_like(&q.q))
    .bind(&q.status)
    .bind(&q.group)
    .bind(group_filter)
    .bind(&q.software)
    .bind(&q.version)
    .bind(PAGE_SIZE + 1)
    .bind(page * PAGE_SIZE)
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rows = rows
        .into_iter()
        .map(
            |(id, hostname, group, domain, os, user, ip, last_seen, status)| {
                let (badge, badge_label) =
                    status_label(&status, last_seen.is_some_and(|t| t > cutoff));
                DeviceRow {
                    id,
                    hostname,
                    group: group.unwrap_or_else(|| "未分組".into()),
                    domain,
                    os,
                    user,
                    ip,
                    last_seen: fmt_time(&st, last_seen),
                    badge,
                    badge_label,
                }
            },
        )
        .collect();
    let statuses = [
        ("", "使用中"),
        ("pending_approval", "待核准"),
        ("duplicate_suspect", "疑似重複"),
        ("retired", "已除役"),
        ("all", "全部"),
    ]
    .into_iter()
    .map(|(v, l)| SelectOption {
        value: v.into(),
        label: l.into(),
        selected: q.status == v,
    })
    .collect();
    Ok(render(&DevicesPage {
        groups: group_options(&st, &s, &q.group, true).await?,
        nav: Nav::from(&s),
        prev_url: page_url(&q, page - 1),
        next_url: page_url(&q, page + 1),
        q: q.q,
        software: q.software,
        version: q.version,
        statuses,
        rows,
        page,
        has_next,
    }))
}

/// 取裝置的群組；不存在或不在範圍內回 None。
pub async fn device_group_in_scope(
    st: &AppState,
    s: &Session,
    id: Uuid,
) -> Result<Option<Option<i64>>, sqlx::Error> {
    let g: Option<Option<i64>> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await?;
    Ok(g.filter(|g| s.in_scope(*g)))
}

pub fn action_error(e: anyhow::Error) -> Response {
    (axum::http::StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

pub fn db_error(e: sqlx::Error) -> Response {
    AppError::from(e).into_response()
}

/// 可管理（非檢視者）且新、舊裝置都在範圍內。
async fn check_pending(st: &AppState, s: &Session, id: Uuid) -> Result<(), Response> {
    if !s.can_manage() {
        return Err(forbidden());
    }
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT d.group_id, o.group_id FROM devices d \
         LEFT JOIN devices o ON o.id = d.reenroll_of WHERE d.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(db_error)?;
    match row {
        Some((new_g, old_g)) if s.in_scope(new_g) && s.in_scope(old_g) => Ok(()),
        _ => Err(not_found()),
    }
}

pub async fn approve(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    check_pending(&st, &s, id).await?;
    crate::devices::approve(&st.pool, id, &s.username)
        .await
        .map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}

pub async fn reject(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    check_pending(&st, &s, id).await?;
    crate::devices::reject(&st.pool, id, &s.username)
        .await
        .map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}

pub async fn approve_all(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM devices d JOIN devices o ON o.id = d.reenroll_of \
         WHERE d.status = 'pending_approval' \
           AND ($1::bool OR (d.group_id = ANY($2::bigint[]) AND o.group_id = ANY($2::bigint[]))) \
         ORDER BY d.enrolled_at",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let mut tx = st.pool.begin().await.map_err(db_error)?;
    for id in ids {
        crate::devices::approve_in(&mut tx, id, &s.username)
            .await
            .map_err(action_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(Redirect::to("/").into_response())
}
