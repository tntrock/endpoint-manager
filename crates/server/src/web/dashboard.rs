//! 儀表板：範圍內的數量統計與待核准清單。

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session};
use super::devices::online_cutoff;
use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;

type PendingDbRow = (Uuid, String, Uuid, String, Option<String>, DateTime<Utc>);

pub struct PendingRow {
    pub id: Uuid,
    pub hostname: String,
    pub old_id: Uuid,
    pub old_hostname: String,
    pub group: String,
    pub enrolled_at: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: Nav,
    total: i64,
    online: i64,
    duplicate: i64,
    pending: Vec<PendingRow>,
    /// 全部核准的結果：(核准, 略過)
    approve_result: Option<(u32, u32)>,
}

pub async fn page(State(st): State<AppState>, AdminSession(s): AdminSession) -> Response {
    with_result(&st, &s, None).await
}

/// 儀表板；`approve_result` 只由「全部核准」的 POST 帶入（不從網址參數讀，連結無法偽造結果）
pub(super) async fn with_result(
    st: &AppState,
    s: &Session,
    approve_result: Option<(u32, u32)>,
) -> Response {
    match build(st, s).await {
        Ok(mut p) => {
            p.approve_result = approve_result;
            render(&p)
        }
        Err(e) => e.into_response(),
    }
}

async fn build(st: &AppState, s: &Session) -> Result<DashboardPage, AppError> {
    let cutoff = online_cutoff(st).await?;
    let (total, online, duplicate): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status NOT IN ('retired', 'pending_approval')), \
                count(*) FILTER (WHERE status NOT IN ('retired', 'pending_approval') \
                                   AND last_seen_at > $1), \
                count(*) FILTER (WHERE status = 'duplicate_suspect') \
         FROM devices d WHERE ($2::bool OR d.group_id = ANY($3::bigint[]))",
    )
    .bind(cutoff)
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_one(&st.pool)
    .await?;
    let rows: Vec<PendingDbRow> = sqlx::query_as(
        "SELECT d.id, d.hostname, o.id, o.hostname, g.name, d.enrolled_at \
         FROM devices d JOIN devices o ON o.id = d.reenroll_of \
         LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE d.status = 'pending_approval' \
           AND ($1::bool OR (d.group_id = ANY($2::bigint[]) AND o.group_id = ANY($2::bigint[]))) \
         ORDER BY d.enrolled_at",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    Ok(DashboardPage {
        nav: Nav::from(s),
        total,
        online,
        duplicate,
        pending: rows
            .into_iter()
            .map(
                |(id, hostname, old_id, old_hostname, group, at)| PendingRow {
                    id,
                    hostname,
                    old_id,
                    old_hostname,
                    group: group.unwrap_or_else(|| "未分組".into()),
                    enrolled_at: fmt_time(st, Some(at)),
                },
            )
            .collect(),
        approve_result: None,
    })
}
