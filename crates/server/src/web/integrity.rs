//! 裝置頁的「完整性」分頁：竄改偵測的發現與確認（竄改偵測規格 §2.3、§7）。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::auth::{AdminSession, Session, check_csrf};
use super::{fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::error::AppError;
use crate::findings;

/// 分頁最多列幾筆
const LIMIT: i64 = 200;
/// 確認說明的長度上限
const MAX_NOTE: usize = 500;

pub struct Row {
    pub id: i64,
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub hint: &'static str,
    pub started: String,
    /// 持續中的發現
    pub ongoing: bool,
    pub acknowledged: bool,
    pub ack: String,
}

#[derive(Template)]
#[template(path = "integrity_tab.html")]
struct Tab {
    device: Uuid,
    rows: Vec<Row>,
    truncated: bool,
    can_ack: bool,
    csrf: String,
    error: Option<String>,
}

/// 這台有沒有任何發現（才顯示「完整性」分頁）
pub async fn has_findings(st: &AppState, id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM device_findings WHERE device_id = $1)")
        .bind(id)
        .fetch_one(&st.pool)
        .await
}

fn severity(s: &str) -> &'static str {
    if s == "high" { "high" } else { "medium" }
}

type DbRow = (
    i64,
    String,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
    serde_json::Value,
    Option<OffsetDateTime>,
    Option<String>,
    Option<String>,
);

async fn rows(st: &AppState, id: Uuid) -> Result<(Vec<Row>, bool), sqlx::Error> {
    let db: Vec<DbRow> = sqlx::query_as(
        "SELECT id, kind, severity, started_at, ended_at, detail, \
                acknowledged_at, acknowledged_by, ack_note \
         FROM device_findings WHERE device_id = $1 \
         ORDER BY acknowledged_at IS NULL DESC, started_at DESC, id DESC LIMIT $2",
    )
    .bind(id)
    .bind(LIMIT + 1)
    .fetch_all(&st.pool)
    .await?;
    let truncated = db.len() as i64 > LIMIT;
    let rows = db
        .into_iter()
        .take(LIMIT as usize)
        .map(
            |(fid, kind, sev, started, ended, detail, ack_at, ack_by, note)| Row {
                id: fid,
                severity: severity(&sev),
                title: findings::label(&kind).to_string(),
                detail: findings::describe(&kind, &detail),
                hint: findings::hint(&kind),
                started: fmt_time(st, Some(started)),
                ongoing: ended.is_none(),
                acknowledged: ack_at.is_some(),
                ack: match ack_at {
                    Some(at) => {
                        let note = note.filter(|n| !n.is_empty());
                        format!(
                            "{} 由 {} 確認{}",
                            fmt_time(st, Some(at)),
                            ack_by.unwrap_or_default(),
                            note.map(|n| format!("：{n}")).unwrap_or_default()
                        )
                    }
                    None => String::new(),
                },
            },
        )
        .collect();
    Ok((rows, truncated))
}

/// 能確認這台的發現：可以管理裝置、而且這台在範圍內
fn can_ack(s: &Session, group: Option<i64>) -> bool {
    s.can_manage() && s.in_scope(group)
}

async fn group_of(st: &AppState, id: Uuid) -> Result<Option<Option<i64>>, sqlx::Error> {
    sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await
}

async fn render_tab(
    st: &AppState,
    s: &Session,
    id: Uuid,
    group: Option<i64>,
    error: Option<String>,
) -> Result<Response, AppError> {
    let (rows, truncated) = rows(st, id).await?;
    Ok(render(&Tab {
        device: id,
        rows,
        truncated,
        can_ack: can_ack(s, group),
        csrf: s.csrf.clone(),
        error,
    }))
}

/// 分頁內容（呼叫端已檢查範圍）
pub async fn device_tab(st: &AppState, s: &Session, id: Uuid) -> Result<Response, AppError> {
    let group = group_of(st, id).await?.flatten();
    render_tab(st, s, id, group, None).await
}

#[derive(Deserialize, Default)]
pub struct AckForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    note: String,
}

/// 確認一筆發現。htmx 送出時回傳更新後的分頁；沒有 JavaScript 時回到裝置頁
pub async fn acknowledge(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    headers: HeaderMap,
    Path((id, finding)): Path<(Uuid, i64)>,
    Form(f): Form<AckForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let group = match group_of(&st, id).await {
        Ok(Some(g)) if s.in_scope(g) => g,
        Ok(_) => return Err(not_found()),
        Err(e) => return Err(AppError::from(e).into_response()),
    };
    if !can_ack(&s, group) {
        return Err(forbidden());
    }
    let note = f.note.trim();
    let error = if note.chars().count() > MAX_NOTE {
        Some(format!("說明最多 {MAX_NOTE} 個字"))
    } else {
        let done = async {
            let mut tx = st.pool.begin().await?;
            let ok = findings::acknowledge(&mut tx, id, finding, &s.username, note).await?;
            tx.commit().await?;
            Ok::<bool, sqlx::Error>(ok)
        }
        .await
        .map_err(|e| AppError::from(e).into_response())?;
        (!done).then(|| "這筆已經確認過，或已不存在".to_string())
    };
    if headers.contains_key("hx-request") {
        render_tab(&st, &s, id, group, error)
            .await
            .map_err(IntoResponse::into_response)
    } else {
        Ok(Redirect::to(&format!("/devices/{id}")).into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities() {
        assert_eq!(severity("high"), "high");
        assert_eq!(severity("medium"), "medium");
        assert_eq!(severity("x"), "medium");
    }
}
