//! 遠端指令：清單、對群組下指令、詳情、取消；裝置頁「遠端指令」分頁。

use askama::Template;
use axum::extract::{Path, Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, db_error};
use super::{enc, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::commands::runs::{self, RunInput, Target};
use crate::commands::{Actor, CmdError, cmd_error_kind};
use crate::error::AppError;

pub(super) fn actor(s: &Session) -> Actor {
    Actor {
        username: s.username.clone(),
        platform: s.all_devices(),
        groups: s.groups.clone(),
    }
}

/// 給使用者看的錯誤依種類回 403／422／404／409 與訊息；其他錯誤（資料庫等）記錄後回 500，
/// 不把內部細節顯示在畫面上
pub(super) fn command_error(e: anyhow::Error) -> Response {
    let status = match cmd_error_kind(&e) {
        Some(CmdError::Forbidden(_)) => StatusCode::FORBIDDEN,
        Some(CmdError::Invalid(_)) => StatusCode::UNPROCESSABLE_ENTITY,
        Some(CmdError::NotFound(_)) => StatusCode::NOT_FOUND,
        Some(CmdError::Conflict(_)) => StatusCode::CONFLICT,
        None => {
            tracing::error!(error = %format!("{e:#}"), "command action failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "伺服器錯誤，請稍後再試").into_response();
        }
    };
    (status, format!("{e:#}")).into_response()
}

/// 表單可以重新顯示的錯誤（輸入或狀態問題）：(狀態碼, 訊息)
fn form_error(e: &anyhow::Error) -> Option<(StatusCode, String)> {
    match cmd_error_kind(e)? {
        CmdError::Invalid(m) => Some((StatusCode::UNPROCESSABLE_ENTITY, m.clone())),
        CmdError::Conflict(m) => Some((StatusCode::CONFLICT, m.clone())),
        // 送出時腳本剛被刪除：重新顯示表單讓使用者改選
        CmdError::NotFound(m) => Some((StatusCode::NOT_FOUND, m.clone())),
        _ => None,
    }
}

pub fn action_label(a: &str) -> &'static str {
    match a {
        "collect" => "重新收集",
        "apply" => "立即套用",
        "reboot" => "重新開機",
        "shutdown" => "關機",
        "script" => "執行腳本",
        _ => "未知",
    }
}

pub fn status_label(s: &str) -> &'static str {
    match s {
        "pending" => "等待中",
        "sent" => "已送出",
        "succeeded" => "成功",
        "failed" => "失敗",
        "expired" => "已過期",
        "canceled" => "已取消",
        _ => "未知",
    }
}

const DELAY_ERROR: &str = "延遲必須是 0–60 分鐘的整數";
const EXPIRES: [(i64, &str); 4] = [(1, "1 小時"), (24, "1 天"), (168, "7 天"), (720, "30 天")];
const RUN_PAGE: i64 = 50;
const DEVICE_PAGE: i64 = 100;

pub struct Counts {
    pub total: i64,
    pub waiting: i64,
    pub succeeded: i64,
    pub failed: i64,
    pub expired: i64,
    pub canceled: i64,
}

pub struct RunRow {
    pub id: i64,
    pub action: &'static str,
    pub target: String,
    pub created_by: String,
    pub created: String,
    pub expires: String,
    pub canceled: bool,
    pub counts: Counts,
}

/// 指令清單的查詢：台數只算範圍內（$1 全部、$2 群組）。群組管理員只看得到至少有一台範圍內
/// 裝置的 run；平台管理員也看得到對象裝置都已刪除的 run（台數 0）
fn runs_sql(filter: &str) -> String {
    format!(
        "SELECT r.id, r.action, r.target_label, r.created_by, r.created_at, r.expires_at, \
           r.canceled_at IS NOT NULL, count(t.id), \
           count(*) FILTER (WHERE t.status IN ('pending', 'sent')), \
           count(*) FILTER (WHERE t.status = 'succeeded'), \
           count(*) FILTER (WHERE t.status = 'failed'), \
           count(*) FILTER (WHERE t.status = 'expired'), \
           count(*) FILTER (WHERE t.status = 'canceled') \
         FROM command_runs r \
         LEFT JOIN (command_targets t JOIN devices v ON v.id = t.device_id) ON t.run_id = r.id \
         WHERE ($1::bool OR v.group_id = ANY($2::bigint[])) {filter} \
         GROUP BY r.id ORDER BY r.id DESC"
    )
}

type RunDbRow = (
    i64,
    String,
    String,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    bool,
    i64,
    i64,
    i64,
    i64,
    i64,
    i64,
);

fn to_run(st: &AppState, r: RunDbRow) -> RunRow {
    RunRow {
        id: r.0,
        action: action_label(&r.1),
        target: r.2,
        created_by: r.3,
        created: fmt_time(st, Some(r.4)),
        expires: fmt_time(st, Some(r.5)),
        canceled: r.6,
        counts: Counts {
            total: r.7,
            waiting: r.8,
            succeeded: r.9,
            failed: r.10,
            expired: r.11,
            canceled: r.12,
        },
    }
}

#[derive(Template)]
#[template(path = "commands.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<RunRow>,
    groups: Vec<SelectOption>,
    scripts: Vec<SelectOption>,
    expires: Vec<(i64, &'static str)>,
    error: Option<String>,
    prev: Option<String>,
    next: Option<String>,
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    page: i64,
    #[serde(default)]
    status: String,
}

/// 範圍內的群組
async fn scoped_groups(st: &AppState, s: &Session) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM device_groups WHERE $1::bool OR id = ANY($2::bigint[]) ORDER BY name",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| SelectOption {
            value: id.to_string(),
            label: name,
            selected: false,
        })
        .collect())
}

/// 已核准的腳本（只有平台管理員能執行）
async fn approved_scripts(st: &AppState, s: &Session) -> Result<Vec<SelectOption>, sqlx::Error> {
    if !s.all_devices() {
        return Ok(vec![]);
    }
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM scripts WHERE status = 'approved' ORDER BY lower(name)",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| SelectOption {
            value: id.to_string(),
            label: name,
            selected: false,
        })
        .collect())
}

async fn list_page(
    st: &AppState,
    s: &Session,
    page: i64,
    error: Option<String>,
) -> Result<ListPage, sqlx::Error> {
    let page = page.clamp(0, super::devices::MAX_PAGE);
    // 先挑出這一頁的指令（範圍內至少有一台），再只對這些指令計數：不必每次彙總整張表
    let rows: Vec<RunDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(runs_sql(
        "AND r.id IN (SELECT p.id FROM command_runs p \
           WHERE $1::bool OR EXISTS (SELECT 1 FROM command_targets pt \
             JOIN devices pv ON pv.id = pt.device_id \
             WHERE pt.run_id = p.id AND pv.group_id = ANY($2::bigint[])) \
           ORDER BY p.id DESC LIMIT $3 OFFSET $4)",
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(RUN_PAGE + 1)
    .bind(page * RUN_PAGE)
    .fetch_all(&st.pool)
    .await?;
    let more = rows.len() as i64 > RUN_PAGE;
    Ok(ListPage {
        nav: Nav::from(s),
        rows: rows
            .into_iter()
            .take(RUN_PAGE as usize)
            .map(|r| to_run(st, r))
            .collect(),
        groups: scoped_groups(st, s).await?,
        scripts: approved_scripts(st, s).await?,
        expires: EXPIRES.to_vec(),
        error,
        prev: (page > 0).then(|| format!("/commands?page={}", page - 1)),
        next: more.then(|| format!("/commands?page={}", page + 1)),
    })
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    Ok(render(&list_page(&st, &s, q.page, None).await?))
}

struct RunForm {
    csrf: String,
    action: String,
    group_id: Option<i64>,
    delay_minutes: Option<i32>,
    /// 延遲有填但不是整數
    bad_delay: bool,
    script_id: Option<i64>,
    expires_hours: i64,
}

fn parse_run_form(raw: &[u8]) -> RunForm {
    let mut f = RunForm {
        csrf: String::new(),
        action: String::new(),
        group_id: None,
        delay_minutes: None,
        bad_delay: false,
        script_id: None,
        expires_hours: crate::commands::runs::DEFAULT_EXPIRES_HOURS,
    };
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.trim().to_string();
        match k.as_ref() {
            "csrf" => f.csrf = v,
            "action" => f.action = v,
            "group_id" => f.group_id = v.parse().ok(),
            "delay_minutes" if !v.is_empty() => match v.parse() {
                Ok(d) => f.delay_minutes = Some(d),
                Err(_) => f.bad_delay = true,
            },
            "script_id" => f.script_id = v.parse().ok(),
            "expires_hours" => f.expires_hours = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    f
}

fn manage(s: &Session) -> Result<(), Response> {
    if s.can_manage() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_run_form(&raw);
    check_csrf(&s, &f.csrf)?;
    manage(&s)?;
    let input_error = if f.bad_delay {
        Some(DELAY_ERROR)
    } else if f.group_id.is_none() {
        Some("請選擇群組")
    } else {
        None
    };
    if let Some(m) = input_error {
        let page = list_page(&st, &s, 0, Some(m.into()))
            .await
            .map_err(db_error)?;
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
    }
    let group = f.group_id.unwrap_or_default();
    let input = RunInput {
        action: f.action,
        target: Target::Group(group),
        delay_minutes: f.delay_minutes,
        script_id: f.script_id,
        expires_hours: f.expires_hours,
    };
    match runs::create_run(&st.pool, &input, &actor(&s)).await {
        Ok((id, _)) => Ok(Redirect::to(&format!("/commands/{id}")).into_response()),
        Err(e) => match form_error(&e) {
            Some((status, m)) => {
                let page = list_page(&st, &s, 0, Some(m)).await.map_err(db_error)?;
                Ok((status, render(&page)).into_response())
            }
            None => Err(command_error(e)),
        },
    }
}

pub struct TargetRow {
    pub device: String,
    pub hostname: String,
    pub status: &'static str,
    pub exit_code: String,
    pub finished: String,
    pub output: String,
}

pub struct FilterLink {
    pub label: String,
    pub url: String,
    pub active: bool,
}

#[derive(Template)]
#[template(path = "command_detail.html")]
struct DetailPage {
    nav: Nav,
    run: RunRow,
    delay: Option<i32>,
    script: Option<(String, String)>,
    canceled: bool,
    can_cancel: bool,
    filters: Vec<FilterLink>,
    targets: Vec<TargetRow>,
    prev: Option<String>,
    next: Option<String>,
}

type TargetDbRow = (
    Uuid,
    String,
    String,
    Option<i32>,
    Option<DateTime<Utc>>,
    String,
);

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    // 範圍內完全沒有裝置的指令視為不存在
    let row: Option<RunDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(runs_sql("AND r.id = $3")))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(id)
        .fetch_optional(&st.pool)
        .await?;
    let Some(row) = row else {
        return Ok(not_found());
    };
    let (delay, script_name, script_sha, canceled): (
        Option<i32>,
        Option<String>,
        Option<String>,
        bool,
    ) = sqlx::query_as(
        "SELECT r.delay_minutes, sc.name, r.script_sha256, r.canceled_at IS NOT NULL \
         FROM command_runs r LEFT JOIN scripts sc ON sc.id = r.script_id WHERE r.id = $1",
    )
    .bind(id)
    .fetch_one(&st.pool)
    .await?;
    let status = match q.status.as_str() {
        s @ ("waiting" | "pending" | "sent" | "succeeded" | "failed" | "expired" | "canceled") => s,
        _ => "",
    };
    let page = q.page.clamp(0, super::devices::MAX_PAGE);
    let rows: Vec<TargetDbRow> = sqlx::query_as(
        "SELECT v.id, v.hostname, t.status, t.exit_code, t.finished_at, t.output \
         FROM command_targets t JOIN devices v ON v.id = t.device_id \
         WHERE t.run_id = $3 AND ($1::bool OR v.group_id = ANY($2::bigint[])) \
           AND ($4 = '' OR t.status = $4 OR ($4 = 'waiting' AND t.status IN ('pending', 'sent'))) \
         ORDER BY lower(v.hostname), v.id LIMIT $5 OFFSET $6",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(id)
    .bind(status)
    .bind(DEVICE_PAGE + 1)
    .bind(page * DEVICE_PAGE)
    .fetch_all(&st.pool)
    .await?;
    let more = rows.len() as i64 > DEVICE_PAGE;
    let url = |status: &str, page: i64| {
        let mut u = format!("/commands/{id}?page={page}");
        if !status.is_empty() {
            u.push_str(&format!("&status={}", enc(status)));
        }
        u
    };
    let run = to_run(&st, row);
    let c = &run.counts;
    let filters = [
        ("", format!("全部：{}", c.total)),
        ("waiting", format!("等待中：{}", c.waiting)),
        ("succeeded", format!("成功：{}", c.succeeded)),
        ("failed", format!("失敗：{}", c.failed)),
        ("expired", format!("已過期：{}", c.expired)),
        ("canceled", format!("已取消：{}", c.canceled)),
    ]
    .into_iter()
    .map(|(k, label)| FilterLink {
        label,
        url: url(k, 0),
        active: k == status,
    })
    .collect();
    // 還有等待中的裝置才能取消
    let can_cancel = !canceled
        && run.counts.waiting > 0
        && (s.all_devices() || run.created_by == s.username)
        && s.can_manage();
    Ok(render(&DetailPage {
        nav: Nav::from(&s),
        delay,
        script: script_sha.map(|sha| (script_name.unwrap_or_else(|| "（已刪除）".into()), sha)),
        canceled,
        can_cancel,
        filters,
        targets: rows
            .into_iter()
            .take(DEVICE_PAGE as usize)
            .map(|(v, hostname, status, code, at, output)| TargetRow {
                device: v.to_string(),
                hostname,
                status: status_label(&status),
                exit_code: code.map(|c| c.to_string()).unwrap_or_default(),
                finished: fmt_time(&st, at),
                output,
            })
            .collect(),
        prev: (page > 0).then(|| url(status, page - 1)),
        next: more.then(|| url(status, page + 1)),
        run,
    }))
}

pub async fn cancel(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_run_form(&raw);
    check_csrf(&s, &f.csrf)?;
    manage(&s)?;
    runs::cancel_run(&st.pool, id, &actor(&s))
        .await
        .map_err(command_error)?;
    Ok(Redirect::to(&format!("/commands/{id}")).into_response())
}

pub async fn create_for_device(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(device): Path<Uuid>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_run_form(&raw);
    check_csrf(&s, &f.csrf)?;
    manage(&s)?;
    if f.bad_delay {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, DELAY_ERROR).into_response());
    }
    let input = RunInput {
        action: f.action,
        target: Target::Device(device),
        delay_minutes: f.delay_minutes,
        script_id: f.script_id,
        expires_hours: crate::commands::runs::DEFAULT_EXPIRES_HOURS,
    };
    runs::create_run(&st.pool, &input, &actor(&s))
        .await
        .map_err(command_error)?;
    Ok(Redirect::to(&format!("/devices/{device}")).into_response())
}

pub struct TabRow {
    pub run: i64,
    pub action: &'static str,
    pub created_by: String,
    pub created: String,
    pub status: &'static str,
    pub exit_code: String,
    pub output: String,
}

#[derive(Template)]
#[template(path = "commands_tab.html")]
struct Tab {
    nav: Nav,
    device: String,
    manage: bool,
    scripts: Vec<SelectOption>,
    rows: Vec<TabRow>,
}

type TabDbRow = (
    i64,
    String,
    String,
    DateTime<Utc>,
    String,
    Option<i32>,
    String,
);

/// 裝置頁的「遠端指令」分頁（htmx 片段）：下指令的按鈕與這台最近 20 筆。範圍外的裝置回 404。
pub async fn device_tab(st: &AppState, s: &Session, device: Uuid) -> Result<Response, AppError> {
    if super::devices::device_group_in_scope(st, s, device)
        .await?
        .is_none()
    {
        return Ok(not_found());
    }
    let rows: Vec<TabDbRow> = sqlx::query_as(
        "SELECT r.id, r.action, r.created_by, r.created_at, t.status, t.exit_code, t.output \
         FROM command_targets t JOIN command_runs r ON r.id = t.run_id \
         WHERE t.device_id = $1 ORDER BY t.id DESC LIMIT 20",
    )
    .bind(device)
    .fetch_all(&st.pool)
    .await?;
    Ok(render(&Tab {
        nav: Nav::from(s),
        device: device.to_string(),
        manage: s.can_manage(),
        scripts: approved_scripts(st, s).await?,
        rows: rows
            .into_iter()
            .map(|(run, action, by, at, status, code, output)| TabRow {
                run,
                action: action_label(&action),
                created_by: by,
                created: fmt_time(st, Some(at)),
                status: status_label(&status),
                exit_code: code.map(|c| c.to_string()).unwrap_or_default(),
                output,
            })
            .collect(),
    }))
}
