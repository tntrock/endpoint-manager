//! 裝置頁的時間軸：把違規、清單變更、遠端指令、派送、管理動作與註冊合併成一條。

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::response::Response;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use super::auth::{AdminSession, Session};
use super::{not_found, render};
use crate::AppState;
use crate::error::AppError;

/// 每種來源一次最多取幾筆
const LIMIT: i64 = 50;

pub struct Event {
    pub at: OffsetDateTime,
    /// bad／ok／info／change／admin（圖示與顏色）
    pub kind: &'static str,
    pub title: String,
    pub detail: String,
    /// 可以打開的分頁
    pub tab: Option<&'static str>,
}

pub struct Day {
    pub date: String,
    pub events: Vec<(String, Event)>,
}

#[derive(Template)]
#[template(path = "timeline.html")]
struct TimelineFragment {
    id: Uuid,
    days: Vec<Day>,
    /// 還有更早的事件時，下一頁的網址
    more: Option<String>,
    /// 接在前一頁後面時不重複標題
    first_page: bool,
}

#[derive(Deserialize)]
pub struct MoreQuery {
    #[serde(default)]
    before: String,
}

pub fn section_label(section: &str) -> &str {
    match section {
        "basic" => "基本資料",
        "hardware" => "硬體",
        "software" => "軟體",
        "patches" => "修補",
        "services" => "服務",
        "security" => "安全設定",
        "registry" => "登錄檔",
        "accounts" => "帳號",
        "containers" => "容器",
        other => other,
    }
}

/// 違規事件的標題與類別
fn violation_title(rule: &str, from: &str, to: &str) -> (&'static str, String) {
    match to {
        "violating" => ("bad", format!("違反「{rule}」")),
        "exempt" => ("info", format!("「{rule}」已豁免")),
        "unknown" => ("info", format!("「{rule}」無法判斷")),
        _ if from == "violating" => ("ok", format!("「{rule}」恢復合規")),
        _ => ("ok", format!("「{rule}」不再適用")),
    }
}

/// 一次上傳、一個區段的變更摘要
fn change_title(section: &str, added: i64, removed: i64, updated: i64) -> String {
    let mut parts = vec![];
    for (n, label) in [(added, "新增"), (removed, "移除"), (updated, "更新")] {
        if n > 0 {
            parts.push(format!("{label} {n}"));
        }
    }
    format!("{}：{}", section_label(section), parts.join("、"))
}

/// 項目 key 的顯示名稱（軟體是 `名稱|架構|發行者`，只取名稱）
fn item_names(keys: &[String], total: i64) -> String {
    let names: Vec<&str> = keys
        .iter()
        .map(|k| k.split('|').next().unwrap_or(k))
        .collect();
    let mut s = names.join("、");
    if total > names.len() as i64 {
        s.push_str(&format!(" 等 {total} 項"));
    }
    s
}

type ChangeRow = (OffsetDateTime, String, i64, i64, i64, Vec<String>);
type CommandRow = (OffsetDateTime, String, Option<String>, String, String);

/// `before` 之前的事件，新的在前；第二個值表示是否還有更早的
pub async fn events(
    st: &AppState,
    id: Uuid,
    enrolled: OffsetDateTime,
    before: OffsetDateTime,
) -> Result<(Vec<Event>, bool), sqlx::Error> {
    let mut out: Vec<Event> = vec![];
    // 有來源取滿時，比它最舊一筆更早的事件可能還沒取到：只保留不早於這個時間的事件
    let mut floor: Option<OffsetDateTime> = None;
    let mut full = |rows: usize, last: Option<OffsetDateTime>| {
        if rows as i64 == LIMIT {
            floor = floor.max(last);
        }
    };

    let v: Vec<(OffsetDateTime, String, String, String)> = sqlx::query_as(
        "SELECT at, rule_name, from_status, to_status FROM violation_events \
         WHERE device_id = $1 AND at < $2 ORDER BY at DESC LIMIT $3",
    )
    .bind(id)
    .bind(before)
    .bind(LIMIT)
    .fetch_all(&st.pool)
    .await?;
    full(v.len(), v.last().map(|r| r.0));
    out.extend(v.into_iter().map(|(at, rule, from, to)| {
        let (kind, title) = violation_title(&rule, &from, &to);
        Event {
            at,
            kind,
            title,
            detail: String::new(),
            tab: Some("compliance"),
        }
    }));

    let c: Vec<ChangeRow> = sqlx::query_as(
        "SELECT detected_at, section, \
                count(*) FILTER (WHERE change = 'added'), \
                count(*) FILTER (WHERE change = 'removed'), \
                count(*) FILTER (WHERE change = 'updated'), \
                (array_agg(item_key ORDER BY item_key))[1:3] \
         FROM inventory_changes WHERE device_id = $1 AND detected_at < $2 \
         GROUP BY detected_at, section ORDER BY detected_at DESC, section LIMIT $3",
    )
    .bind(id)
    .bind(before)
    .bind(LIMIT)
    .fetch_all(&st.pool)
    .await?;
    full(c.len(), c.last().map(|r| r.0));
    out.extend(
        c.into_iter()
            .map(|(at, section, added, removed, updated, keys)| Event {
                at,
                kind: "change",
                title: change_title(&section, added, removed, updated),
                detail: item_names(&keys, added + removed + updated),
                tab: Some("changes"),
            }),
    );

    let cmd: Vec<CommandRow> = sqlx::query_as(
        "SELECT coalesce(t.finished_at, t.sent_at, r.created_at), r.action, s.name, t.status, \
                r.created_by \
         FROM command_targets t JOIN command_runs r ON r.id = t.run_id \
         LEFT JOIN scripts s ON s.id = r.script_id \
         WHERE t.device_id = $1 AND coalesce(t.finished_at, t.sent_at, r.created_at) < $2 \
         ORDER BY 1 DESC LIMIT $3",
    )
    .bind(id)
    .bind(before)
    .bind(LIMIT)
    .fetch_all(&st.pool)
    .await?;
    full(cmd.len(), cmd.last().map(|r| r.0));
    out.extend(
        cmd.into_iter()
            .map(|(at, action, script, status, by)| Event {
                at,
                kind: match status.as_str() {
                    "succeeded" => "ok",
                    "failed" | "expired" => "bad",
                    _ => "info",
                },
                title: format!(
                    "指令「{}」{}",
                    script.unwrap_or_else(|| super::commands::action_label(&action).into()),
                    super::commands::status_label(&status)
                ),
                detail: format!("由 {by} 下達"),
                tab: Some("commands"),
            }),
    );

    let dep: Vec<(OffsetDateTime, String, String, String)> = sqlx::query_as(
        "SELECT ds.updated_at, dep.name, ds.status, ds.message FROM deployment_status ds \
         JOIN deployments dep ON dep.id = ds.deployment_id \
         WHERE ds.device_id = $1 AND ds.updated_at < $2 ORDER BY ds.updated_at DESC LIMIT $3",
    )
    .bind(id)
    .bind(before)
    .bind(LIMIT)
    .fetch_all(&st.pool)
    .await?;
    full(dep.len(), dep.last().map(|r| r.0));
    out.extend(dep.into_iter().map(|(at, name, status, message)| Event {
        at,
        kind: if status == "failed" { "bad" } else { "ok" },
        title: format!(
            "派送「{name}」{}",
            super::deployments::status_label(&status)
        ),
        detail: message,
        tab: Some("deployments"),
    }));

    let audit: Vec<(OffsetDateTime, String, String)> = sqlx::query_as(
        "SELECT at, actor, action FROM audit_log WHERE target = $1 AND at < $2 \
         ORDER BY at DESC LIMIT $3",
    )
    .bind(id.to_string())
    .bind(before)
    .bind(LIMIT)
    .fetch_all(&st.pool)
    .await?;
    full(audit.len(), audit.last().map(|r| r.0));
    out.extend(audit.into_iter().map(|(at, actor, action)| Event {
        at,
        kind: "admin",
        title: super::audit::label(&action).to_string(),
        detail: if actor == "system" {
            "系統".into()
        } else {
            format!("由 {actor}")
        },
        tab: None,
    }));

    if enrolled < before {
        out.push(Event {
            at: enrolled,
            kind: "info",
            title: "註冊".into(),
            detail: String::new(),
            tab: None,
        });
    }

    out.sort_by_key(|e| std::cmp::Reverse(e.at));
    if let Some(floor) = floor {
        out.retain(|e| e.at >= floor);
    }
    Ok((out, floor.is_some()))
}

/// 依管理網頁時區的日期分組
fn group_days(st: &AppState, events: Vec<Event>) -> Vec<Day> {
    let mut days: Vec<Day> = vec![];
    for e in events {
        let local = e.at.to_offset(st.display_offset);
        let date = protocol::timefmt::format_date(local.date());
        let time = format!("{:02}:{:02}", local.hour(), local.minute());
        match days.last_mut() {
            Some(d) if d.date == date => d.events.push((time, e)),
            _ => days.push(Day {
                date,
                events: vec![(time, e)],
            }),
        }
    }
    days
}

async fn device(
    st: &AppState,
    s: &Session,
    id: Uuid,
) -> Result<Option<OffsetDateTime>, sqlx::Error> {
    let row: Option<(Option<i64>, OffsetDateTime)> =
        sqlx::query_as("SELECT group_id, enrolled_at FROM devices WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(row.filter(|r| s.in_scope(r.0)).map(|r| r.1))
}

async fn fragment(
    st: &AppState,
    id: Uuid,
    enrolled: OffsetDateTime,
    before: OffsetDateTime,
    first_page: bool,
) -> Result<Response, AppError> {
    let (events, more) = events(st, id, enrolled, before).await?;
    let more = if more {
        events
            .last()
            .and_then(|e| protocol::timefmt::format_rfc3339(e.at).ok())
            .map(|b| format!("/devices/{id}/timeline?before={}", super::enc(&b)))
    } else {
        None
    };
    Ok(render(&TimelineFragment {
        id,
        days: group_days(st, events),
        more,
        first_page,
    }))
}

/// 時間軸分頁（第一頁）；呼叫端已確認範圍
pub async fn tab(st: &AppState, id: Uuid) -> Result<Response, AppError> {
    let enrolled: OffsetDateTime =
        sqlx::query_scalar("SELECT enrolled_at FROM devices WHERE id = $1")
            .bind(id)
            .fetch_one(&st.pool)
            .await?;
    // 加一秒：剛發生的事件時間可能略晚於這裡取的 now
    let before = OffsetDateTime::now_utc() + time::Duration::seconds(1);
    fragment(st, id, enrolled, before, true).await
}

/// `GET /devices/{id}/timeline?before=`：更早的事件
pub async fn more(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Query(q): Query<MoreQuery>,
) -> Result<Response, AppError> {
    let Some(enrolled) = device(&st, &s, id).await? else {
        return Ok(not_found());
    };
    let Ok(before) = protocol::timefmt::parse_rfc3339(&q.before) else {
        return Err(AppError::BadRequest("before 格式不正確".into()));
    };
    fragment(&st, id, enrolled, before, false).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(violation_title("R", "none", "violating").0, "bad");
        assert_eq!(violation_title("R", "violating", "none").1, "「R」恢復合規");
        assert_eq!(violation_title("R", "unknown", "none").1, "「R」不再適用");
        assert_eq!(violation_title("R", "violating", "exempt").1, "「R」已豁免");
        assert_eq!(violation_title("R", "none", "unknown").0, "info");
        assert_eq!(change_title("software", 2, 1, 0), "軟體：新增 2、移除 1");
        assert_eq!(change_title("patches", 0, 0, 3), "修補：更新 3");
        assert_eq!(section_label("x"), "x");
        let keys = vec![
            "7-Zip|x64|Igor".to_string(),
            "Chrome|x64|Google".to_string(),
        ];
        assert_eq!(item_names(&keys, 2), "7-Zip、Chrome");
        assert_eq!(item_names(&keys, 9), "7-Zip、Chrome 等 9 項");
    }
}
