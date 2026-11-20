//! 全公司軟體搜尋：範圍內依名稱與版本統計安裝台數。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use super::auth::{AdminSession, Nav};
use super::devices::SelectOption;
use super::{enc, escape_like, render};
use crate::AppState;
use crate::error::AppError;

const LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
    /// 作業系統：預設 windows；linux 或 all
    #[serde(default)]
    os: String,
}

/// 預設 Windows：Linux 套件數量很大，混在一起會改變 Windows 管理者原本的結果
fn os_choice(os: &str) -> &'static str {
    match os {
        "linux" => "linux",
        "all" => "all",
        _ => "windows",
    }
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
    oses: Vec<SelectOption>,
    rows: Vec<SoftwareRow>,
    truncated: bool,
}

pub async fn search(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let os = os_choice(&q.os);
    let mut rows: Vec<(String, String, i64)> = if q.q.trim().is_empty() {
        vec![]
    } else {
        sqlx::query_as(
            "SELECT sw.name, coalesce(sw.version, ''), count(DISTINCT sw.device_id) \
             FROM device_software sw \
             JOIN devices d ON d.id = sw.device_id \
                  AND d.status NOT IN ('retired', 'pending_approval') \
             WHERE sw.name ILIKE $1 AND ($2::bool OR d.group_id = ANY($3::bigint[])) \
               AND ($5 = 'all' OR d.os_family = $5) \
             GROUP BY 1, 2 ORDER BY lower(sw.name), 2 LIMIT $4",
        )
        .bind(escape_like(q.q.trim()))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(LIMIT + 1)
        .bind(os)
        .fetch_all(&st.pool)
        .await?
    };
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    // 裝置列表的 os 參數：空白是全部
    let device_os = if os == "all" { "" } else { os };
    Ok(render(&SoftwarePage {
        nav: Nav::new(&s, "software"),
        q: q.q,
        oses: [
            ("windows", "Windows"),
            ("linux", "Linux"),
            ("all", "所有作業系統"),
        ]
        .into_iter()
        .map(|(v, l)| SelectOption {
            value: v.into(),
            label: l.into(),
            selected: os == v,
        })
        .collect(),
        rows: rows
            .into_iter()
            .map(|(name, version, count)| SoftwareRow {
                url: format!(
                    "/devices?software={}&version={}&os={device_os}",
                    enc(&name),
                    enc(&version)
                ),
                name,
                version,
                count,
            })
            .collect(),
        truncated,
    }))
}
