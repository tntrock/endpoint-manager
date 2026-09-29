//! 全公司登錄檔值查詢：範圍內使用中的裝置，依狀態／類型／值統計台數。
//! 只查得到有規則在收集的值（上傳時只保存規則需要的值）。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use super::auth::{AdminSession, Nav};
use super::{enc, render};
use crate::AppState;
use crate::error::AppError;

const LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct RegistryQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    name: String,
}

pub struct ValueRow {
    pub state: String,
    pub kind: String,
    pub data: String,
    pub count: i64,
    pub url: String,
}

#[derive(Template)]
#[template(path = "registry.html")]
struct RegistryPage {
    nav: Nav,
    path: String,
    name: String,
    error: Option<&'static str>,
    searched: bool,
    rows: Vec<ValueRow>,
    total: i64,
    truncated: bool,
}

/// 正規化路徑；空白查詢回 Ok(None)
fn normalized(q: &RegistryQuery) -> Result<Option<String>, &'static str> {
    if q.path.trim().is_empty() {
        return Ok(None);
    }
    protocol::regpath::normalize(&q.path).map(Some)
}

pub async fn query(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<RegistryQuery>,
) -> Result<Response, AppError> {
    let (path, error) = match normalized(&q) {
        Ok(p) => (p, None),
        Err(e) => (None, Some(e)),
    };
    let name = q.name.trim().to_string();
    let (mut rows, total): (Vec<(String, String, String, i64)>, i64) = match &path {
        None => (vec![], 0),
        Some(p) => {
            let rows = sqlx::query_as(
                "SELECT r.state, r.kind, r.data, count(*) FROM device_registry r \
                 JOIN devices d ON d.id = r.device_id AND d.status = 'active' \
                 WHERE upper(r.path) = upper($1) AND upper(r.name) = upper($2) \
                   AND ($3::bool OR d.group_id = ANY($4::bigint[])) \
                 GROUP BY 1, 2, 3 ORDER BY 4 DESC, 3 LIMIT $5",
            )
            .bind(p)
            .bind(&name)
            .bind(s.all_devices())
            .bind(&s.groups)
            .bind(LIMIT + 1)
            .fetch_all(&st.pool)
            .await?;
            let total: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM device_registry r \
                 JOIN devices d ON d.id = r.device_id AND d.status = 'active' \
                 WHERE upper(r.path) = upper($1) AND upper(r.name) = upper($2) \
                   AND ($3::bool OR d.group_id = ANY($4::bigint[]))",
            )
            .bind(p)
            .bind(&name)
            .bind(s.all_devices())
            .bind(&s.groups)
            .fetch_one(&st.pool)
            .await?;
            (rows, total)
        }
    };
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    let shown_path = path.clone().unwrap_or_else(|| q.path.clone());
    Ok(render(&RegistryPage {
        nav: Nav::from(&s),
        searched: path.is_some(),
        rows: rows
            .into_iter()
            .map(|(state, kind, data, count)| ValueRow {
                url: format!(
                    "/registry/devices?path={}&name={}&state={}&data={}",
                    enc(&shown_path),
                    enc(&name),
                    enc(&state),
                    enc(&data)
                ),
                state,
                kind,
                data,
                count,
            })
            .collect(),
        path: shown_path,
        name,
        error,
        total,
        truncated,
    }))
}

#[derive(Deserialize)]
pub struct DevicesQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    data: String,
}

#[derive(Template)]
#[template(path = "registry_devices.html")]
struct DevicesPage {
    nav: Nav,
    path: String,
    name: String,
    state: String,
    data: String,
    /// (裝置 id, 主機名稱)
    rows: Vec<(String, String)>,
    truncated: bool,
}

pub async fn devices(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<DevicesQuery>,
) -> Result<Response, AppError> {
    let path = protocol::regpath::normalize(&q.path).unwrap_or_default();
    // ponytail: 只列前 500 台，不分頁；要看全部時再加分頁
    let mut rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT d.id::text, d.hostname FROM device_registry r \
         JOIN devices d ON d.id = r.device_id AND d.status = 'active' \
         WHERE upper(r.path) = upper($1) AND upper(r.name) = upper($2) \
           AND r.state = $3 AND r.data = $4 \
           AND ($5::bool OR d.group_id = ANY($6::bigint[])) \
         ORDER BY lower(d.hostname) LIMIT $7",
    )
    .bind(&path)
    .bind(q.name.trim())
    .bind(&q.state)
    .bind(&q.data)
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(LIMIT + 1)
    .fetch_all(&st.pool)
    .await?;
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    Ok(render(&DevicesPage {
        nav: Nav::from(&s),
        path,
        name: q.name,
        state: q.state,
        data: q.data,
        rows,
        truncated,
    }))
}
