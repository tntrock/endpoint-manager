//! 更新原則：清單、新增／編輯、詳情（依狀態列出裝置）、暫停／恢復、刪除。
//! 所有管理員都能看，但群組管理員的台數、裝置與群組名稱只含自己範圍內的；寫入限平台管理員。

use askama::Template;
use axum::extract::{Path, Query, RawForm, State};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, action_error, db_error};
use super::{enc, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::error::AppError;
use crate::updates::admin::{self, PauseKind, PolicyInput};
use crate::updates::policy::{ActiveHours, Deadline, PAUSE_DAYS, PolicySettings};

/// 裝置 v 是否為原則 p 的對象（使用中、群組屬於此原則），並限制在管理員的範圍（$1 全部、$2 群組）
const TARGET: &str = "v.status = 'active' AND ($1::bool OR v.group_id = ANY($2::bigint[])) \
     AND EXISTS (SELECT 1 FROM update_policy_groups g \
                 WHERE g.policy_id = p.id AND g.group_id = v.group_id)";

/// 狀態分類（s = update_policy_status）。第一次套用就失敗時 Agent 回報的 policy_id 是 None，
/// 所以「錯誤」不比對 policy_id；其餘（沒有狀態、舊 revision、不受管）都算尚未回報
const APPLIED: &str = "(s.state = 'applied' AND s.policy_id = p.id AND s.revision = p.revision)";
const CONFLICT: &str = "(s.state = 'conflict' AND s.policy_id = p.id)";
const ERROR: &str = "(s.state = 'error')";

/// Windows Update 寬限期的預設值（期限有填、寬限沒填時使用）
const DEFAULT_GRACE: u32 = 2;

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

fn today(st: &AppState) -> NaiveDate {
    Utc::now().with_timezone(&st.display_offset).date_naive()
}

fn pause_labels(set: &PolicySettings, today: NaiveDate) -> Vec<String> {
    [
        ("品質更新", set.quality_pause_start),
        ("功能更新", set.feature_pause_start),
    ]
    .into_iter()
    .filter_map(|(what, start)| {
        let end = start? + chrono::Duration::days(PAUSE_DAYS);
        Some(if today > end {
            format!("{what}暫停已過期")
        } else {
            format!("{what}暫停中，至 {}", end.format("%-m/%-d"))
        })
    })
    .collect()
}

/// 設定摘要（每項一行）
fn describe(set: &PolicySettings, today: NaiveDate) -> Vec<String> {
    let mut v = vec![];
    if let Some(d) = set.quality_defer_days {
        v.push(format!("品質更新延後 {d} 天"));
    }
    if let Some(d) = set.feature_defer_days {
        v.push(format!("功能更新延後 {d} 天"));
    }
    for (what, d) in [
        ("品質更新", set.quality_deadline),
        ("功能更新", set.feature_deadline),
    ] {
        if let Some(d) = d {
            v.push(format!("{what}期限 {} 天（寬限 {} 天）", d.days, d.grace));
        }
    }
    if set.no_auto_reboot {
        v.push("寬限期結束前不自動重開機".into());
    }
    if let Some(h) = set.active_hours {
        v.push(format!("使用中時段 {}:00–{}:00", h.start, h.end));
    }
    v.extend(pause_labels(set, today));
    if v.is_empty() {
        v.push("沒有設定任何項目".into());
    }
    v
}

fn parse_settings(json: &str) -> PolicySettings {
    serde_json::from_str(json).unwrap_or_default()
}

pub struct Counts {
    pub targeted: i64,
    pub applied: i64,
    pub conflict: i64,
    pub error: i64,
}

impl Counts {
    pub fn pending(&self) -> i64 {
        self.targeted - self.applied - self.conflict - self.error
    }
}

type CountRow = (i64, String, String, i32, i64, i64, i64, i64);

fn counts_sql(filter: &str) -> String {
    format!(
        "SELECT p.id, p.name, p.settings::text, p.revision, count(v.id), \
           count(*) FILTER (WHERE {APPLIED}), count(*) FILTER (WHERE {CONFLICT}), \
           count(*) FILTER (WHERE {ERROR}) \
         FROM update_policies p \
         LEFT JOIN devices v ON {TARGET} \
         LEFT JOIN update_policy_status s ON s.device_id = v.id \
         {filter} GROUP BY p.id ORDER BY lower(p.name), p.id"
    )
}

fn counts(r: &CountRow) -> Counts {
    Counts {
        targeted: r.4,
        applied: r.5,
        conflict: r.6,
        error: r.7,
    }
}

/// 原則 id → 範圍內的群組名稱
async fn group_names(
    st: &AppState,
    s: &Session,
) -> Result<std::collections::HashMap<i64, Vec<String>>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT x.policy_id, g.name FROM update_policy_groups x \
         JOIN device_groups g ON g.id = x.group_id \
         WHERE $1::bool OR x.group_id = ANY($2::bigint[]) ORDER BY g.name",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let mut m: std::collections::HashMap<i64, Vec<String>> = Default::default();
    for (p, g) in rows {
        m.entry(p).or_default().push(g);
    }
    Ok(m)
}

pub struct ListRow {
    pub id: i64,
    pub name: String,
    pub groups: String,
    pub pauses: Vec<String>,
    pub counts: Counts,
}

#[derive(Template)]
#[template(path = "updates.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<ListRow>,
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    let rows: Vec<CountRow> = sqlx::query_as(sqlx::AssertSqlSafe(counts_sql("")))
        .bind(s.all_devices())
        .bind(&s.groups)
        .fetch_all(&st.pool)
        .await?;
    let mut names = group_names(&st, &s).await?;
    let today = today(&st);
    Ok(render(&ListPage {
        nav: Nav::from(&s),
        rows: rows
            .iter()
            .map(|r| ListRow {
                id: r.0,
                name: r.1.clone(),
                groups: names.remove(&r.0).unwrap_or_default().join("、"),
                pauses: pause_labels(&parse_settings(&r.2), today),
                counts: counts(r),
            })
            .collect(),
    }))
}

/// 表單原始值（驗證失敗時原樣顯示）
#[derive(Debug, Clone, Default)]
pub struct FormFields {
    pub name: String,
    pub groups: Vec<i64>,
    pub quality_defer_days: String,
    pub feature_defer_days: String,
    pub quality_deadline: String,
    pub quality_grace: String,
    pub feature_deadline: String,
    pub feature_grace: String,
    pub no_auto_reboot: bool,
    pub active_start: String,
    pub active_end: String,
}

fn parse_form(raw: &[u8]) -> (String, FormFields) {
    let mut csrf = String::new();
    let mut f = FormFields::default();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.into_owned();
        match k.as_ref() {
            "csrf" => csrf = v,
            "name" => f.name = v,
            "groups" => f.groups.extend(v.parse::<i64>().ok()),
            "quality_defer_days" => f.quality_defer_days = v,
            "feature_defer_days" => f.feature_defer_days = v,
            "quality_deadline" => f.quality_deadline = v,
            "quality_grace" => f.quality_grace = v,
            "feature_deadline" => f.feature_deadline = v,
            "feature_grace" => f.feature_grace = v,
            "no_auto_reboot" => f.no_auto_reboot = v == "1",
            "active_start" => f.active_start = v,
            "active_end" => f.active_end = v,
            _ => {}
        }
    }
    (csrf, f)
}

fn num(label: &str, v: &str) -> Result<Option<u32>, String> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    v.parse()
        .map(Some)
        .map_err(|_| format!("{label}必須是 0 以上的整數"))
}

impl FormFields {
    fn to_input(&self) -> Result<PolicyInput, String> {
        let deadline = |label: &str, days: &str, grace: &str| -> Result<Option<Deadline>, String> {
            let Some(days) = num(&format!("{label}期限"), days)? else {
                return Ok(None);
            };
            let grace = num(&format!("{label}寬限期"), grace)?.unwrap_or(DEFAULT_GRACE);
            Ok(Some(Deadline { days, grace }))
        };
        let active_hours = match (
            num("使用中時段開始", &self.active_start)?,
            num("使用中時段結束", &self.active_end)?,
        ) {
            (Some(start), Some(end)) => Some(ActiveHours { start, end }),
            (None, None) => None,
            _ => return Err("使用中時段的開始與結束都要選".into()),
        };
        Ok(PolicyInput {
            name: self.name.clone(),
            settings: PolicySettings {
                quality_defer_days: num("品質更新延後", &self.quality_defer_days)?,
                feature_defer_days: num("功能更新延後", &self.feature_defer_days)?,
                quality_pause_start: None,
                feature_pause_start: None,
                quality_deadline: deadline(
                    "品質更新",
                    &self.quality_deadline,
                    &self.quality_grace,
                )?,
                feature_deadline: deadline(
                    "功能更新",
                    &self.feature_deadline,
                    &self.feature_grace,
                )?,
                no_auto_reboot: self.no_auto_reboot,
                active_hours,
            },
            groups: self.groups.clone(),
        })
    }

    fn from_policy(name: String, set: &PolicySettings, groups: Vec<i64>) -> FormFields {
        let n = |v: Option<u32>| v.map(|v| v.to_string()).unwrap_or_default();
        FormFields {
            name,
            groups,
            quality_defer_days: n(set.quality_defer_days),
            feature_defer_days: n(set.feature_defer_days),
            quality_deadline: n(set.quality_deadline.map(|d| d.days)),
            quality_grace: n(set.quality_deadline.map(|d| d.grace)),
            feature_deadline: n(set.feature_deadline.map(|d| d.days)),
            feature_grace: n(set.feature_deadline.map(|d| d.grace)),
            no_auto_reboot: set.no_auto_reboot,
            active_start: n(set.active_hours.map(|h| h.start)),
            active_end: n(set.active_hours.map(|h| h.end)),
        }
    }
}

#[derive(Template)]
#[template(path = "update_form.html")]
struct FormPage {
    nav: Nav,
    /// None：新增
    id: Option<i64>,
    f: FormFields,
    groups: Vec<SelectOption>,
    hours: Vec<u32>,
    error: Option<String>,
}

async fn form_page(
    st: &AppState,
    s: &Session,
    id: Option<i64>,
    f: FormFields,
    error: Option<String>,
) -> Result<FormPage, sqlx::Error> {
    Ok(FormPage {
        nav: Nav::from(s),
        id,
        groups: super::rules::group_checks(st, &f.groups).await?,
        f,
        hours: (0..24).collect(),
        error,
    })
}

pub async fn new_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    let page = form_page(&st, &s, None, FormFields::default(), None)
        .await
        .map_err(db_error)?;
    Ok(render(&page))
}

async fn invalid(
    st: &AppState,
    s: &Session,
    id: Option<i64>,
    f: FormFields,
    e: String,
) -> Result<Response, Response> {
    let page = form_page(st, s, id, f, Some(e)).await.map_err(db_error)?;
    Ok((axum::http::StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response())
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, f) = parse_form(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let input = match f.to_input() {
        Ok(i) => i,
        Err(e) => return invalid(&st, &s, None, f, e).await,
    };
    match admin::create_policy(&st.pool, &input, &s.username).await {
        Ok(id) => Ok(Redirect::to(&format!("/updates/{id}")).into_response()),
        Err(e) => invalid(&st, &s, None, f, format!("{e:#}")).await,
    }
}

async fn load(
    st: &AppState,
    id: i64,
) -> Result<Option<(String, PolicySettings, i32)>, sqlx::Error> {
    let row: Option<(String, String, i32)> =
        sqlx::query_as("SELECT name, settings::text, revision FROM update_policies WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    Ok(row.map(|(n, set, rev)| (n, parse_settings(&set), rev)))
}

pub async fn edit_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let Some((name, set, _)) = load(&st, id).await.map_err(db_error)? else {
        return Err(not_found());
    };
    let groups: Vec<i64> =
        sqlx::query_scalar("SELECT group_id FROM update_policy_groups WHERE policy_id = $1")
            .bind(id)
            .fetch_all(&st.pool)
            .await
            .map_err(db_error)?;
    let f = FormFields::from_policy(name, &set, groups);
    let page = form_page(&st, &s, Some(id), f, None)
        .await
        .map_err(db_error)?;
    Ok(render(&page))
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, f) = parse_form(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let input = match f.to_input() {
        Ok(i) => i,
        Err(e) => return invalid(&st, &s, Some(id), f, e).await,
    };
    match admin::update_policy(&st.pool, id, &input, &s.username).await {
        Ok(()) => Ok(Redirect::to(&format!("/updates/{id}")).into_response()),
        Err(e) => invalid(&st, &s, Some(id), f, format!("{e:#}")).await,
    }
}

#[derive(Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    state: String,
    #[serde(default)]
    page: i64,
}

pub struct DeviceRow {
    pub id: String,
    pub hostname: String,
    pub state: &'static str,
    pub detail: String,
    pub updated: String,
}

pub struct FilterLink {
    pub label: String,
    pub url: String,
    pub active: bool,
}

#[derive(Template)]
#[template(path = "update_detail.html")]
struct DetailPage {
    nav: Nav,
    id: i64,
    name: String,
    revision: i32,
    groups: String,
    settings: Vec<String>,
    quality_paused: bool,
    feature_paused: bool,
    filters: Vec<FilterLink>,
    devices: Vec<DeviceRow>,
    prev: Option<String>,
    next: Option<String>,
}

const DEVICE_PAGE: i64 = 100;

/// 這台對原則 (id, revision) 的狀態分類
pub fn classify(
    state: Option<&str>,
    policy_id: Option<i64>,
    revision: Option<i32>,
    id: i64,
    rev: i32,
) -> &'static str {
    match state {
        Some("applied") if policy_id == Some(id) && revision == Some(rev) => "已套用",
        Some("conflict") if policy_id == Some(id) => "衝突",
        Some("error") => "錯誤",
        _ => "尚未回報",
    }
}

type DeviceDbRow = (
    Uuid,
    String,
    Option<String>,
    Option<i64>,
    Option<i32>,
    Option<String>,
    Option<DateTime<Utc>>,
);

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Query(q): Query<DetailQuery>,
) -> Result<Response, AppError> {
    let Some((name, set, revision)) = load(&st, id).await? else {
        return Ok(not_found());
    };
    let row: Option<CountRow> = sqlx::query_as(sqlx::AssertSqlSafe(counts_sql("WHERE p.id = $3")))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(id)
        .fetch_optional(&st.pool)
        .await?;
    let c = row.as_ref().map(counts).unwrap_or(Counts {
        targeted: 0,
        applied: 0,
        conflict: 0,
        error: 0,
    });
    let state = match q.state.as_str() {
        s @ ("applied" | "conflict" | "error" | "pending") => s,
        _ => "",
    };
    let page = q.page.clamp(0, super::devices::MAX_PAGE);
    let rows: Vec<DeviceDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT v.id, v.hostname, s.state, s.policy_id, s.revision, s.detail, s.updated_at \
         FROM update_policies p JOIN devices v ON {TARGET} \
         LEFT JOIN update_policy_status s ON s.device_id = v.id \
         WHERE p.id = $3 AND CASE $4::text WHEN '' THEN TRUE \
           WHEN 'applied' THEN COALESCE({APPLIED}, false) \
           WHEN 'conflict' THEN COALESCE({CONFLICT}, false) \
           WHEN 'error' THEN COALESCE({ERROR}, false) \
           ELSE NOT COALESCE({APPLIED} OR {CONFLICT} OR {ERROR}, false) END \
         ORDER BY lower(v.hostname), v.id LIMIT $5 OFFSET $6"
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(id)
    .bind(state)
    .bind(DEVICE_PAGE + 1)
    .bind(page * DEVICE_PAGE)
    .fetch_all(&st.pool)
    .await?;
    let more = rows.len() as i64 > DEVICE_PAGE;
    let url = |state: &str, page: i64| {
        let mut u = format!("/updates/{id}?page={page}");
        if !state.is_empty() {
            u.push_str(&format!("&state={}", enc(state)));
        }
        u
    };
    let filters = [
        ("", format!("全部：{}", c.targeted)),
        ("applied", format!("已套用：{}", c.applied)),
        ("conflict", format!("衝突：{}", c.conflict)),
        ("error", format!("錯誤：{}", c.error)),
        ("pending", format!("尚未回報：{}", c.pending())),
    ]
    .into_iter()
    .map(|(k, label)| FilterLink {
        label,
        url: url(k, 0),
        active: k == state,
    })
    .collect();
    let groups = group_names(&st, &s)
        .await?
        .remove(&id)
        .unwrap_or_default()
        .join("、");
    let today = today(&st);
    Ok(render(&DetailPage {
        nav: Nav::from(&s),
        id,
        name,
        revision,
        groups,
        quality_paused: set.quality_pause_start.is_some(),
        feature_paused: set.feature_pause_start.is_some(),
        settings: describe(&set, today),
        filters,
        devices: rows
            .into_iter()
            .take(DEVICE_PAGE as usize)
            .map(|(vid, hostname, st_, pid, rev, detail, at)| DeviceRow {
                id: vid.to_string(),
                hostname,
                state: classify(st_.as_deref(), pid, rev, id, revision),
                detail: detail.unwrap_or_default(),
                updated: fmt_time(&st, at),
            })
            .collect(),
        prev: (page > 0).then(|| url(state, page - 1)),
        next: more.then(|| url(state, page + 1)),
    }))
}

pub async fn act(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path((id, action)): Path<(i64, String)>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, _) = parse_form(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let pool = &st.pool;
    let user = s.username.as_str();
    let today = today(&st);
    let r = match action.as_str() {
        "pause-quality" => admin::set_pause(pool, id, PauseKind::Quality, Some(today), user).await,
        "resume-quality" => admin::set_pause(pool, id, PauseKind::Quality, None, user).await,
        "pause-feature" => admin::set_pause(pool, id, PauseKind::Feature, Some(today), user).await,
        "resume-feature" => admin::set_pause(pool, id, PauseKind::Feature, None, user).await,
        "delete" => {
            admin::delete_policy(pool, id, user)
                .await
                .map_err(action_error)?;
            return Ok(Redirect::to("/updates").into_response());
        }
        _ => return Err(not_found()),
    };
    r.map_err(action_error)?;
    Ok(Redirect::to(&format!("/updates/{id}")).into_response())
}

pub struct RebootRow {
    pub id: String,
    pub hostname: String,
    pub since: String,
    pub days: i64,
}

#[derive(Template)]
#[template(path = "updates_overview.html")]
struct OverviewPage {
    nav: Nav,
    builds: Vec<(String, String, i64)>,
    reboots: Vec<RebootRow>,
}

pub async fn overview(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    let builds: Vec<(Option<String>, Option<i32>, i64)> = sqlx::query_as(
        "SELECT os_build, os_ubr, count(*) FROM devices \
         WHERE status = 'active' AND ($1::bool OR group_id = ANY($2::bigint[])) \
         GROUP BY 1, 2 ORDER BY 1 DESC NULLS LAST, 2 DESC NULLS LAST",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let reboots: Vec<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT v.id, v.hostname, u.reboot_pending_since FROM update_policy_status u \
         JOIN devices v ON v.id = u.device_id \
         WHERE u.reboot_pending AND u.reboot_pending_since IS NOT NULL \
           AND v.status = 'active' AND ($1::bool OR v.group_id = ANY($2::bigint[])) \
         ORDER BY u.reboot_pending_since, v.id LIMIT 50",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let now = Utc::now();
    let dash = |v: Option<String>| v.unwrap_or_else(|| "—".into());
    Ok(render(&OverviewPage {
        nav: Nav::from(&s),
        builds: builds
            .into_iter()
            .map(|(b, u, n)| (dash(b), dash(u.map(|u| u.to_string())), n))
            .collect(),
        reboots: reboots
            .into_iter()
            .map(|(id, hostname, since)| RebootRow {
                id: id.to_string(),
                hostname,
                since: fmt_time(&st, Some(since)),
                days: (now - since).num_days(),
            })
            .collect(),
    }))
}

fn state_label(state: &str) -> &'static str {
    match state {
        "applied" => "已套用",
        "conflict" => "衝突",
        "error" => "錯誤",
        "unmanaged" => "不受管",
        _ => "未知",
    }
}

pub struct Report {
    pub state: &'static str,
    pub detail: String,
    pub policy: String,
    pub revision: String,
    pub reboot: String,
    pub last_patch: String,
    pub updated: String,
}

#[derive(Template)]
#[template(path = "updates_tab.html")]
struct Tab {
    /// (原則 id, 名稱)；None 為不受管
    policy: Option<(i64, String)>,
    values: Vec<String>,
    report: Option<Report>,
}

type ReportRow = (
    String,
    String,
    Option<i64>,
    Option<i32>,
    bool,
    Option<DateTime<Utc>>,
    Option<NaiveDate>,
    DateTime<Utc>,
    Option<String>,
);

/// 裝置頁的「更新」分頁（htmx 片段）：指派的原則與期望值、Agent 回報。範圍外的裝置回 404。
pub async fn device_tab(st: &AppState, s: &Session, device: Uuid) -> Result<Response, AppError> {
    let Some(group) = super::devices::device_group_in_scope(st, s, device).await? else {
        return Ok(not_found());
    };
    let active: bool = sqlx::query_scalar("SELECT status = 'active' FROM devices WHERE id = $1")
        .bind(device)
        .fetch_one(&st.pool)
        .await?;
    let set = st.updates.get(&st.pool).await?;
    let assigned = if active { set.policy_for(group) } else { None };
    let policy = match &assigned {
        Some(p) => {
            let name: Option<String> =
                sqlx::query_scalar("SELECT name FROM update_policies WHERE id = $1")
                    .bind(p.id)
                    .fetch_optional(&st.pool)
                    .await?;
            name.map(|n| (p.id, n))
        }
        None => None,
    };
    let values = assigned
        .map(|p| {
            p.values
                .iter()
                .map(|v| match &v.data {
                    protocol::update::PolicyData::Dword(d) => format!("{} = {d}", v.name),
                    protocol::update::PolicyData::String(t) => format!("{} = {t}", v.name),
                    protocol::update::PolicyData::Unknown => format!("{} = ?", v.name),
                })
                .collect()
        })
        .unwrap_or_default();
    let row: Option<ReportRow> = sqlx::query_as(
        "SELECT u.state, u.detail, u.policy_id, u.revision, u.reboot_pending, \
                u.reboot_pending_since, u.last_patch_date, u.updated_at, p.name \
         FROM update_policy_status u LEFT JOIN update_policies p ON p.id = u.policy_id \
         WHERE u.device_id = $1",
    )
    .bind(device)
    .fetch_optional(&st.pool)
    .await?;
    let report = row.map(
        |(state, detail, pid, rev, reboot, since, last, at, pname)| Report {
            state: state_label(&state),
            detail,
            policy: match (pid, pname) {
                (None, _) => "—".into(),
                (Some(_), Some(n)) => n,
                (Some(_), None) => "已刪除的原則".into(),
            },
            revision: rev.map(|r| r.to_string()).unwrap_or_else(|| "—".into()),
            reboot: match (reboot, since) {
                (false, _) => "否".into(),
                (true, None) => "是".into(),
                (true, Some(t)) => format!("是（自 {} 起）", fmt_time(st, Some(t))),
            },
            last_patch: last.map(|d| d.to_string()).unwrap_or_else(|| "—".into()),
            updated: fmt_time(st, Some(at)),
        },
    );
    Ok(render(&Tab {
        policy,
        values,
        report,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_labels_expire_after_35_days() {
        let d = |m, day| NaiveDate::from_ymd_opt(2026, m, day).unwrap();
        let set = PolicySettings {
            quality_pause_start: Some(d(9, 1)),
            ..Default::default()
        };
        assert_eq!(
            pause_labels(&set, d(10, 6)),
            vec!["品質更新暫停中，至 10/6"]
        );
        assert_eq!(pause_labels(&set, d(10, 7)), vec!["品質更新暫停已過期"]);
        assert!(pause_labels(&PolicySettings::default(), d(10, 7)).is_empty());
    }

    #[test]
    fn form_defaults_grace_and_requires_both_hours() {
        let f = FormFields {
            name: "x".into(),
            quality_deadline: "3".into(),
            ..Default::default()
        };
        let i = f.to_input().unwrap();
        assert_eq!(
            i.settings.quality_deadline,
            Some(Deadline { days: 3, grace: 2 })
        );
        let f = FormFields {
            active_start: "8".into(),
            ..Default::default()
        };
        assert!(f.to_input().is_err());
        let f = FormFields {
            quality_defer_days: "abc".into(),
            ..Default::default()
        };
        assert!(f.to_input().unwrap_err().contains("品質更新延後"));
    }
}
