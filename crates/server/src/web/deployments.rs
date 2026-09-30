//! 派送：清單、建立、詳情（依狀態列出裝置）、階段切換；裝置頁「派送」分頁。
//! 所有管理員都能看，但群組管理員的台數與裝置只含自己範圍內的裝置；建立與控制限平台管理員。

use askama::Template;
use axum::extract::{Path, Query, RawForm, State};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, action_error, db_error, device_group_in_scope};
use super::{enc, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::deploy::admin::{self, DeploymentInput, Transition};
use crate::error::AppError;

/// 裝置 v 是否為派送 d 的對象（範圍內、使用中），並限制在管理員的範圍（$1 全部、$2 群組）。
/// 規則與報到指派（deploy::assign）相同：排除優先；試點階段只含試點群組；暫停時看暫停前的階段。
const TARGET: &str = "v.status = 'active' \
     AND ($1::bool OR v.group_id = ANY($2::bigint[])) \
     AND NOT EXISTS (SELECT 1 FROM deployment_groups x WHERE x.deployment_id = d.id \
                     AND x.mode = 'exclude' AND x.group_id = v.group_id) \
     AND CASE COALESCE(NULLIF(d.stage, 'paused'), d.paused_from) \
           WHEN 'pilot' THEN v.group_id = d.pilot_group_id \
           ELSE NOT EXISTS (SELECT 1 FROM deployment_groups i WHERE i.deployment_id = d.id \
                            AND i.mode = 'include') \
             OR EXISTS (SELECT 1 FROM deployment_groups i WHERE i.deployment_id = d.id \
                        AND i.mode = 'include' AND i.group_id = v.group_id) \
         END";

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

pub fn stage_label(stage: &str) -> &'static str {
    match stage {
        "pilot" => "試點中",
        "all" => "全部派送中",
        "paused" => "已暫停",
        "stopped" => "已停止",
        _ => "未知",
    }
}

pub fn status_label(status: &str) -> &'static str {
    match status {
        "compliant" => "已符合",
        "succeeded" => "成功",
        "reboot_required" => "成功（待重開機）",
        "failed" => "失敗",
        "pending" => "等待中",
        _ => "未知",
    }
}

fn action_label(a: &str) -> &'static str {
    if a == "uninstall" { "移除" } else { "安裝" }
}

#[derive(Default)]
pub struct Counts {
    pub targeted: i64,
    pub compliant: i64,
    pub succeeded: i64,
    pub reboot: i64,
    pub failed: i64,
}

impl Counts {
    pub fn pending(&self) -> i64 {
        self.targeted - self.compliant - self.succeeded - self.reboot - self.failed
    }
}

pub struct ListRow {
    pub id: i64,
    pub name: String,
    pub package: String,
    pub action: &'static str,
    pub stage: &'static str,
    pub counts: Counts,
}

#[derive(Template)]
#[template(path = "deployments.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<ListRow>,
}

type CountRow = (i64, String, String, String, String, i64, i64, i64, i64, i64);

fn counts_sql(filter: &str) -> String {
    format!(
        "SELECT d.id, d.name, p.name, d.action, d.stage, count(v.id), \
           count(ds.device_id) FILTER (WHERE ds.status = 'compliant'), \
           count(ds.device_id) FILTER (WHERE ds.status = 'succeeded'), \
           count(ds.device_id) FILTER (WHERE ds.status = 'reboot_required'), \
           count(ds.device_id) FILTER (WHERE ds.status = 'failed') \
         FROM deployments d JOIN packages p ON p.id = d.package_id \
         LEFT JOIN devices v ON {TARGET} \
         LEFT JOIN deployment_status ds ON ds.deployment_id = d.id AND ds.device_id = v.id \
         {filter} GROUP BY d.id, p.name ORDER BY d.id DESC"
    )
}

fn to_row(r: CountRow) -> ListRow {
    ListRow {
        id: r.0,
        name: r.1,
        package: r.2,
        action: action_label(&r.3),
        stage: stage_label(&r.4),
        counts: Counts {
            targeted: r.5,
            compliant: r.6,
            succeeded: r.7,
            reboot: r.8,
            failed: r.9,
        },
    }
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
    Ok(render(&ListPage {
        nav: Nav::from(&s),
        rows: rows.into_iter().map(to_row).collect(),
    }))
}

#[derive(Template)]
#[template(path = "deployment_form.html")]
struct FormPage {
    nav: Nav,
    packages: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    include: Vec<SelectOption>,
    exclude: Vec<SelectOption>,
    name: String,
    action: String,
    max_failure_pct: i32,
    min_samples: i32,
    error: Option<String>,
}

async fn form_page(
    st: &AppState,
    s: &Session,
    i: &DeploymentInput,
    error: Option<String>,
) -> Result<FormPage, sqlx::Error> {
    let pkgs: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, name, version, kind FROM packages ORDER BY lower(name), id DESC",
    )
    .fetch_all(&st.pool)
    .await?;
    let groups: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM device_groups ORDER BY name")
            .fetch_all(&st.pool)
            .await?;
    let mut pilot = vec![SelectOption {
        value: String::new(),
        label: "不使用試點（直接派送全部範圍）".into(),
        selected: i.pilot_group_id.is_none(),
    }];
    pilot.extend(groups.iter().map(|(id, name)| SelectOption {
        value: id.to_string(),
        label: name.clone(),
        selected: i.pilot_group_id == Some(*id),
    }));
    Ok(FormPage {
        nav: Nav::from(s),
        packages: pkgs
            .into_iter()
            .map(|(id, name, version, kind)| SelectOption {
                selected: i.package_id == id,
                value: id.to_string(),
                label: format!("{name} {version}（{}）", kind.to_uppercase()),
            })
            .collect(),
        groups: pilot,
        include: super::rules::group_checks(st, &i.include).await?,
        exclude: super::rules::group_checks(st, &i.exclude).await?,
        name: i.name.clone(),
        action: i.action.clone(),
        max_failure_pct: i.max_failure_pct,
        min_samples: i.min_samples,
        error,
    })
}

fn empty_input() -> DeploymentInput {
    DeploymentInput {
        name: String::new(),
        package_id: 0,
        action: "install".into(),
        include: vec![],
        exclude: vec![],
        pilot_group_id: None,
        max_failure_pct: 10,
        min_samples: 20,
    }
}

pub async fn new_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    let page = form_page(&st, &s, &empty_input(), None)
        .await
        .map_err(db_error)?;
    Ok(render(&page))
}

fn parse(raw: &[u8]) -> (String, DeploymentInput) {
    let mut csrf = String::new();
    let mut i = empty_input();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.into_owned();
        match k.as_ref() {
            "csrf" => csrf = v,
            "name" => i.name = v,
            "package_id" => i.package_id = v.parse().unwrap_or(0),
            "action" => i.action = v,
            "include" => i.include.extend(v.parse::<i64>().ok()),
            "exclude" => i.exclude.extend(v.parse::<i64>().ok()),
            "pilot_group_id" => i.pilot_group_id = v.parse().ok(),
            "max_failure_pct" => i.max_failure_pct = v.trim().parse().unwrap_or(0),
            "min_samples" => i.min_samples = v.trim().parse().unwrap_or(0),
            _ => {}
        }
    }
    (csrf, i)
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, input) = parse(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    match admin::create_deployment(&st.pool, &input, &s.username).await {
        Ok(id) => Ok(Redirect::to(&format!("/deployments/{id}")).into_response()),
        Err(e) => {
            let page = form_page(&st, &s, &input, Some(format!("{e:#}")))
                .await
                .map_err(db_error)?;
            Ok((axum::http::StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    status: String,
    #[serde(default)]
    page: i64,
}

pub struct DeviceRow {
    pub id: String,
    pub hostname: String,
    pub status: &'static str,
    pub message: String,
    pub updated: String,
}

pub struct FilterLink {
    pub label: String,
    pub url: String,
    pub active: bool,
}

#[derive(Template)]
#[template(path = "deployment_detail.html")]
struct DetailPage {
    nav: Nav,
    id: i64,
    name: String,
    package: String,
    action: &'static str,
    stage: String,
    stage_label: &'static str,
    pilot: Option<String>,
    revision: i32,
    max_failure_pct: i32,
    min_samples: i32,
    counts: Counts,
    failures: Vec<(String, i64)>,
    filters: Vec<FilterLink>,
    devices: Vec<DeviceRow>,
    prev: Option<String>,
    next: Option<String>,
}

const DEVICE_PAGE: i64 = 100;

type HeaderRow = (
    String,
    String,
    String,
    String,
    Option<String>,
    i32,
    i32,
    i32,
);
type DeviceDbRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
);

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Query(q): Query<DetailQuery>,
) -> Result<Response, AppError> {
    let head: Option<HeaderRow> = sqlx::query_as(
        "SELECT d.name, p.name || ' ' || p.version, d.action, d.stage, g.name, d.revision, \
                d.max_failure_pct, d.min_samples \
         FROM deployments d JOIN packages p ON p.id = d.package_id \
         LEFT JOIN device_groups g ON g.id = d.pilot_group_id WHERE d.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let Some((name, package, action, stage, pilot, revision, max_pct, min_samples)) = head else {
        return Ok(not_found());
    };
    let counts: Option<CountRow> =
        sqlx::query_as(sqlx::AssertSqlSafe(counts_sql("WHERE d.id = $3")))
            .bind(s.all_devices())
            .bind(&s.groups)
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let counts = counts.map(|r| to_row(r).counts).unwrap_or_default();
    let failures: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT ds.message, count(*) FROM deployments d \
         JOIN devices v ON {TARGET} \
         JOIN deployment_status ds ON ds.deployment_id = d.id AND ds.device_id = v.id \
         WHERE d.id = $3 AND ds.status = 'failed' \
         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 5"
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let status = match q.status.as_str() {
        s @ ("pending" | "compliant" | "succeeded" | "reboot_required" | "failed") => s,
        _ => "",
    };
    let page = q.page.clamp(0, super::devices::MAX_PAGE);
    // 等待中＝範圍內但還沒有狀態列
    let rows: Vec<DeviceDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT v.id, v.hostname, ds.status, ds.message, ds.updated_at FROM deployments d \
         JOIN devices v ON {TARGET} \
         LEFT JOIN deployment_status ds ON ds.deployment_id = d.id AND ds.device_id = v.id \
         WHERE d.id = $3 AND CASE $4::text WHEN '' THEN TRUE \
           WHEN 'pending' THEN ds.device_id IS NULL ELSE ds.status = $4 END \
         ORDER BY lower(v.hostname), v.id LIMIT $5 OFFSET $6"
    )))
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
        let mut u = format!("/deployments/{id}?page={page}");
        if !status.is_empty() {
            u.push_str(&format!("&status={}", enc(status)));
        }
        u
    };
    let filters = [
        ("", format!("全部：{}", counts.targeted)),
        ("pending", format!("等待中：{}", counts.pending())),
        ("succeeded", format!("成功：{}", counts.succeeded)),
        ("reboot_required", format!("待重開機：{}", counts.reboot)),
        ("compliant", format!("已符合：{}", counts.compliant)),
        ("failed", format!("失敗：{}", counts.failed)),
    ]
    .into_iter()
    .map(|(k, label)| FilterLink {
        label,
        url: url(k, 0),
        active: k == status,
    })
    .collect();
    Ok(render(&DetailPage {
        nav: Nav::from(&s),
        id,
        name,
        package,
        action: action_label(&action),
        stage_label: stage_label(&stage),
        stage,
        pilot,
        revision,
        max_failure_pct: max_pct,
        min_samples,
        counts,
        failures,
        filters,
        devices: rows
            .into_iter()
            .take(DEVICE_PAGE as usize)
            .map(|(vid, hostname, ds, msg, at)| DeviceRow {
                id: vid.to_string(),
                hostname,
                status: status_label(ds.as_deref().unwrap_or("pending")),
                message: msg.unwrap_or_default(),
                updated: fmt_time(&st, at),
            })
            .collect(),
        prev: (page > 0).then(|| url(status, page - 1)),
        next: more.then(|| url(status, page + 1)),
    }))
}

pub async fn act(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path((id, action)): Path<(i64, String)>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, _) = parse(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let pool = &st.pool;
    let user = s.username.as_str();
    let r = match action.as_str() {
        "expand" => admin::set_stage(pool, id, Transition::Expand, user).await,
        "pause" => admin::set_stage(pool, id, Transition::Pause, user).await,
        "resume" => admin::set_stage(pool, id, Transition::Resume, user).await,
        "stop" => admin::set_stage(pool, id, Transition::Stop, user).await,
        "retry" => admin::retry_failed(pool, id, user).await,
        "delete" => {
            admin::delete_deployment(pool, id, user)
                .await
                .map_err(action_error)?;
            return Ok(Redirect::to("/deployments").into_response());
        }
        _ => return Err(not_found()),
    };
    r.map_err(action_error)?;
    Ok(Redirect::to(&format!("/deployments/{id}")).into_response())
}

pub struct TabRow {
    pub id: i64,
    pub name: String,
    pub package: String,
    pub action: &'static str,
    pub stage: &'static str,
    pub status: &'static str,
    pub message: String,
    pub updated: String,
}

#[derive(Template)]
#[template(path = "deploy_tab.html")]
struct Tab {
    rows: Vec<TabRow>,
}

type TabDbRow = (
    i64,
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
);

/// 裝置頁的「派送」分頁（htmx 片段）：這台是對象的派送與狀態。範圍外的裝置回 404。
pub async fn device_tab(st: &AppState, s: &Session, device: Uuid) -> Result<Response, AppError> {
    if device_group_in_scope(st, s, device).await?.is_none() {
        return Ok(not_found());
    }
    let rows: Vec<TabDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT d.id, d.name, p.name || ' ' || p.version, d.action, d.stage, ds.status, \
                ds.message, ds.updated_at \
         FROM deployments d JOIN packages p ON p.id = d.package_id \
         JOIN devices v ON v.id = $3 AND {TARGET} \
         LEFT JOIN deployment_status ds ON ds.deployment_id = d.id AND ds.device_id = v.id \
         WHERE d.stage <> 'stopped' ORDER BY d.id DESC"
    )))
    .bind(true)
    .bind(Vec::<i64>::new())
    .bind(device)
    .fetch_all(&st.pool)
    .await?;
    Ok(render(&Tab {
        rows: rows
            .into_iter()
            .map(
                |(id, name, package, action, stage, status, msg, at)| TabRow {
                    id,
                    name,
                    package,
                    action: action_label(&action),
                    stage: stage_label(&stage),
                    status: status_label(status.as_deref().unwrap_or("pending")),
                    message: msg.unwrap_or_default(),
                    updated: fmt_time(st, at),
                },
            )
            .collect(),
    }))
}
