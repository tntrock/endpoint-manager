//! 全公司軟體搜尋：範圍內依名稱與版本統計安裝台數。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use super::auth::{AdminSession, Nav};
use super::{enc, escape_like, render};
use crate::AppState;
use crate::error::AppError;

const LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}

pub struct SoftwareRow {
    pub name: String,
    pub version: String,
    pub count: i64,
    pub url: String,
}

#[derive(Template)]
#[template(path = "software.html")]
struct SoftwarePage {
    nav: Nav,
    q: String,
    rows: Vec<SoftwareRow>,
    truncated: bool,
}

pub async fn search(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let mut rows: Vec<(String, String, i64)> = if q.q.trim().is_empty() {
        vec![]
    } else {
        sqlx::query_as(
            "SELECT sw.name, coalesce(sw.version, ''), count(DISTINCT sw.device_id) \
             FROM device_software sw \
             JOIN devices d ON d.id = sw.device_id AND d.status <> 'retired' \
             WHERE sw.name ILIKE $1 AND ($2::bool OR d.group_id = ANY($3::bigint[])) \
             GROUP BY 1, 2 ORDER BY lower(sw.name), 2 LIMIT $4",
        )
        .bind(escape_like(q.q.trim()))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(LIMIT + 1)
        .fetch_all(&st.pool)
        .await?
    };
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    Ok(render(&SoftwarePage {
        nav: Nav::from(&s),
        q: q.q,
        rows: rows
            .into_iter()
            .map(|(name, version, count)| SoftwareRow {
                url: format!("/devices?software={}&version={}", enc(&name), enc(&version)),
                name,
                version,
                count,
            })
            .collect(),
        truncated,
    }))
}
