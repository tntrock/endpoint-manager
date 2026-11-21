//! 裝置列表、詳細資料與動作。所有查詢都以工作階段的群組範圍過濾；範圍外一律 404。

use askama::Template;
use axum::extract::{Form, Path, Query, RawForm, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::login::CsrfForm;
use super::{enc, escape_like, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::db::load_settings;
use crate::error::AppError;

pub const PAGE_SIZE: i64 = 50;
/// 頁碼上限：避免 page * PAGE_SIZE 溢位
pub const MAX_PAGE: i64 = 100_000;

pub async fn online_cutoff(st: &AppState) -> Result<time::OffsetDateTime, sqlx::Error> {
    let s = load_settings(&st.pool).await?;
    Ok(time::OffsetDateTime::now_utc() - Duration::seconds(3 * i64::from(s.checkin_interval_secs)))
}

/// 作業系統篩選值：只接受 windows、linux，其他（含空白）一律當成全部
pub fn os_filter(os: &str) -> &'static str {
    match os {
        "windows" => "windows",
        "linux" => "linux",
        _ => "",
    }
}

/// Linux 裝置沒有資料的分頁
const WINDOWS_ONLY_TABS: &[&str] = &[
    "compliance",
    "security",
    "deployments",
    "updates",
    "patches",
];

fn tabs_for(os_family: &str) -> Vec<(&'static str, &'static str)> {
    if os_family == "linux" {
        vec![
            ("timeline", "時間軸"),
            ("commands", "遠端指令"),
            ("software", "軟體"),
            ("services", "服務"),
            ("accounts", "帳號與權限"),
            ("changes", "變更歷史"),
        ]
    } else {
        vec![
            ("timeline", "時間軸"),
            ("compliance", "合規"),
            ("security", "安全設定"),
            ("deployments", "派送"),
            ("updates", "更新"),
            ("commands", "遠端指令"),
            ("software", "軟體"),
            ("patches", "修補（KB）"),
            ("services", "服務"),
            ("changes", "變更歷史"),
        ]
    }
}

/// 分頁是否適用於這個作業系統（網址直接打不適用的分頁時回 404）
fn tab_applies(os_family: &str, tab: &str) -> bool {
    match os_family {
        "linux" => !WINDOWS_ONLY_TABS.contains(&tab),
        _ => tab != "accounts",
    }
}

pub fn status_label(status: &str, online: bool) -> (&'static str, &'static str) {
    match status {
        "retired" => ("bad", "已除役"),
        "pending_approval" => ("warn", "待核准"),
        "duplicate_suspect" => ("warn", "疑似重複"),
        _ if online => ("ok", "在線"),
        _ => ("off", "離線"),
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
    /// 作業系統：空白＝全部、windows、linux
    #[serde(default)]
    os: String,
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
    pub linux: bool,
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
    oses: Vec<SelectOption>,
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
    Option<time::OffsetDateTime>,
    String,
    String,
);

fn page_url(q: &ListQuery, page: i64) -> String {
    format!(
        "/devices?q={}&status={}&group={}&os={}&software={}&version={}&page={page}",
        enc(&q.q),
        enc(&q.status),
        enc(&q.group),
        enc(&q.os),
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
    let page = q.page.clamp(0, MAX_PAGE);
    let group_filter: Option<i64> = q.group.parse().ok();
    let mut rows: Vec<ListRow> = sqlx::query_as(
        "SELECT d.id, d.hostname, g.name, coalesce(d.domain, ''), coalesce(d.os_caption, ''), \
                coalesce(d.logged_on_user, ''), coalesce(d.last_ip, ''), d.last_seen_at, d.status, \
                d.os_family \
         FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
           AND ($12 = '' OR d.os_family = $12) \
           AND ($3 = '' OR d.hostname ILIKE $4 OR d.logged_on_user ILIKE $4 OR d.last_ip ILIKE $4) \
           AND (CASE WHEN $5 = '' THEN d.status <> 'retired' WHEN $5 = 'all' THEN true \
                     WHEN $5 = 'stale' THEN d.status NOT IN ('retired', 'pending_approval') \
                          AND (d.last_seen_at IS NULL OR d.last_seen_at < now() - interval '7 days') \
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
    .bind(os_filter(&q.os))
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rows = rows
        .into_iter()
        .map(
            |(id, hostname, group, domain, os, user, ip, last_seen, status, os_family)| {
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
                    linux: os_family == "linux",
                }
            },
        )
        .collect();
    let statuses = [
        ("", "使用中"),
        ("pending_approval", "待核准"),
        ("duplicate_suspect", "疑似重複"),
        ("stale", "離線超過 7 天"),
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
    let oses = [
        ("", "所有作業系統"),
        ("windows", "Windows"),
        ("linux", "Linux"),
    ]
    .into_iter()
    .map(|(v, l)| SelectOption {
        value: v.into(),
        label: l.into(),
        selected: os_filter(&q.os) == v,
    })
    .collect();
    Ok(render(&DevicesPage {
        oses,
        groups: group_options(&st, &s, &q.group, true).await?,
        nav: Nav::new(&s, "devices"),
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
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    // ids 可重複：表單帶著頁面當時列出的裝置，重送或之後才出現的待核准裝置都不會被核准
    let (mut csrf, mut confirm, mut shown) = (String::new(), false, Vec::<Uuid>::new());
    for (k, v) in form_urlencoded::parse(&raw) {
        match k.as_ref() {
            "csrf" => csrf = v.into_owned(),
            "confirm" => confirm = !v.is_empty(),
            "ids" => shown.extend(v.parse::<Uuid>().ok()),
            _ => {}
        }
    }
    check_csrf(&s, &csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    if !confirm {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "請勾選確認後再全部核准",
        )
            .into_response());
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM devices d JOIN devices o ON o.id = d.reenroll_of \
         WHERE d.status = 'pending_approval' AND d.id = ANY($3) \
           AND ($1::bool OR (d.group_id = ANY($2::bigint[]) AND o.group_id = ANY($2::bigint[]))) \
         ORDER BY d.enrolled_at",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(&shown)
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    // 逐台核准：其中一台失敗（例如原裝置已除役）不影響其他台，失敗的留在待核准清單
    let (mut approved, mut skipped) = (0, 0);
    for id in ids {
        match crate::devices::approve(&st.pool, id, &s.username).await {
            Ok(_) => approved += 1,
            Err(e) => {
                skipped += 1;
                tracing::warn!(device_id = %id, error = %format!("{e:#}"), "approve-all skipped a device");
            }
        }
    }
    // 直接顯示儀表板與結果（略過的仍留在待核准清單）
    Ok(super::dashboard::with_result(&st, &s, Some((approved, skipped))).await)
}

pub struct DeviceView {
    pub id: Uuid,
    pub hostname: String,
    pub group: String,
    pub domain: String,
    pub os: String,
    pub build: String,
    pub user: String,
    pub ip: String,
    /// 依最後回報的 IP 對應的據點與快取
    pub site: String,
    pub cache: String,
    pub model: String,
    pub cpu: String,
    pub ram: String,
    pub serial: String,
    pub last_seen: String,
    pub boot: String,
    pub enrolled: String,
    pub agent: String,
    /// 要求簽章時的金鑰 ID（空：不要求）
    pub signing: Vec<String>,
    pub badge: &'static str,
    pub badge_label: &'static str,
    pub can_retire: bool,
    pub linux: bool,
    /// 最後回報的相對時間
    pub seen_ago: String,
}

#[derive(Template)]
#[template(path = "device.html")]
struct DevicePage {
    nav: Nav,
    d: DeviceView,
    cards: Vec<super::device_status::Card>,
    issues: Vec<super::device_status::Issue>,
    groups: Vec<SelectOption>,
    tabs: Vec<(&'static str, &'static str)>,
}

#[derive(Template)]
#[template(path = "table.html")]
struct TableFragment {
    headers: Vec<&'static str>,
    rows: Vec<Vec<String>>,
    truncated: bool,
}

type DetailRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<time::OffsetDateTime>,
    Option<time::OffsetDateTime>,
    time::OffsetDateTime,
    Option<String>,
    String,
    String,
    Option<i64>,
    Option<String>,
    String,
);

type HardwareRow = (Option<String>, Option<String>, Option<String>, i64);

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let row: Option<DetailRow> = sqlx::query_as(
        "SELECT d.hostname, d.domain, d.os_caption, d.os_build, d.logged_on_user, d.last_ip, \
                d.bios_serial, d.last_seen_at, d.boot_time, d.enrolled_at, d.agent_version, \
                d.status, d.section_errors::text, d.group_id, g.name, d.os_family \
         FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE d.id = $1 AND ($2::bool OR d.group_id = ANY($3::bigint[]))",
    )
    .bind(id)
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_optional(&st.pool)
    .await?;
    let Some((
        hostname,
        domain,
        os,
        build,
        user,
        ip,
        serial,
        last_seen,
        boot,
        enrolled,
        agent,
        status,
        errors,
        group_id,
        group,
        os_family,
    )) = row
    else {
        return Ok(not_found());
    };
    let hw: Option<HardwareRow> = sqlx::query_as(
        "SELECT manufacturer, model, cpu, ram_mb FROM device_hardware WHERE device_id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let cutoff = online_cutoff(&st).await?;
    let (badge, badge_label) = status_label(&status, last_seen.is_some_and(|t| t > cutoff));
    let errors: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&errors).unwrap_or_default();
    let o = |v: Option<String>| v.unwrap_or_default();
    let (model, cpu, ram) = match hw {
        Some((mf, model, cpu, ram)) => (
            format!("{} {}", o(mf), o(model)).trim().to_string(),
            o(cpu),
            format!("{:.1} GB", ram as f64 / 1024.0),
        ),
        None => Default::default(),
    };
    let (site, cache) = super::sites::site_of(&st, ip.as_deref()).await?;
    let keys: Vec<String> = sqlx::query_scalar("SELECT signing_keys FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&st.pool)
        .await?;
    let current_group = group_id
        .map(|g| g.to_string())
        .unwrap_or_else(|| "none".into());
    let errors: Vec<(String, String)> = errors
        .into_iter()
        .map(|(k, v)| (super::timeline::section_label(&k).to_string(), v))
        .collect();
    let linux = os_family == "linux";
    let boot = fmt_time(&st, boot);
    let agent = o(agent);
    let (cards, issues) = super::device_status::build(
        &st,
        &super::device_status::Facts {
            id,
            linux,
            status: &status,
            last_seen,
            online: last_seen.is_some_and(|t| t > cutoff),
            boot: boot.clone(),
            agent: agent.clone(),
            errors: &errors,
        },
    )
    .await?;
    Ok(render(&DevicePage {
        cards,
        issues,
        groups: if s.all_devices() {
            group_options(&st, &s, &current_group, false).await?
        } else {
            vec![]
        },
        nav: Nav::new(&s, "devices"),
        d: DeviceView {
            id,
            hostname,
            group: group.unwrap_or_else(|| "未分組".into()),
            domain: o(domain),
            os: o(os),
            build: o(build),
            user: o(user),
            ip: o(ip),
            site,
            cache,
            model,
            cpu,
            ram,
            serial: o(serial),
            last_seen: fmt_time(&st, last_seen),
            seen_ago: super::device_status::ago(time::OffsetDateTime::now_utc(), last_seen),
            boot,
            enrolled: fmt_time(&st, Some(enrolled)),
            agent,
            signing: crate::signing::key_ids(&keys),
            badge,
            badge_label,
            can_retire: status != "retired",
            linux,
        },
        tabs: tabs_for(&os_family),
    }))
}

const TAB_LIMIT: i64 = 5000;

pub async fn tab(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path((id, tab)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    // 範圍外、或分頁不適用這台的作業系統：一律 404
    let dev: Option<(Option<i64>, String)> =
        sqlx::query_as("SELECT group_id, os_family FROM devices WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    match dev {
        Some((g, os)) if s.in_scope(g) && tab_applies(&os, &tab) => {}
        _ => return Ok(not_found()),
    }
    if tab == "timeline" {
        return super::timeline::tab(&st, id).await;
    }
    if tab == "accounts" {
        return accounts_tab(&st, &s, id).await;
    }
    if tab == "compliance" {
        return super::compliance::device_tab(&st, &s, id).await;
    }
    if tab == "deployments" {
        return super::deployments::device_tab(&st, &s, id).await;
    }
    if tab == "commands" {
        return super::commands::device_tab(&st, &s, id).await;
    }
    if tab == "updates" {
        return super::updates::device_tab(&st, &s, id).await;
    }
    if tab == "security" {
        return super::compliance::security_tab(&st, &s, id).await;
    }
    let (headers, sql): (Vec<&'static str>, &'static str) = match tab.as_str() {
        "software" => (
            vec!["名稱", "版本", "發行者", "架構", "安裝日期"],
            "SELECT name, coalesce(version, ''), coalesce(publisher, ''), arch, \
                    coalesce(install_date, '') \
             FROM device_software WHERE device_id = $1 ORDER BY lower(name) LIMIT $2",
        ),
        "patches" => (
            vec!["KB", "安裝日期"],
            "SELECT kb, coalesce(installed_on, '') FROM device_patches \
             WHERE device_id = $1 ORDER BY kb LIMIT $2",
        ),
        "services" => (
            vec!["名稱", "顯示名稱", "啟動類型", "狀態", "執行檔"],
            "SELECT name, coalesce(display_name, ''), start_mode, state, coalesce(binary_path, '') \
             FROM device_services WHERE device_id = $1 ORDER BY lower(name) LIMIT $2",
        ),
        "changes" => (
            vec!["時間（UTC）", "區段", "變更", "項目", "舊值", "新值"],
            "SELECT to_char(detected_at, 'YYYY-MM-DD HH24:MI'), section, change, item_key, \
                    coalesce(old_value, ''), coalesce(new_value, '') \
             FROM inventory_changes WHERE device_id = $1 ORDER BY detected_at DESC LIMIT $2",
        ),
        _ => return Ok(not_found()),
    };
    use sqlx::Row;
    let rows = sqlx::query(sql)
        .bind(id)
        .bind(TAB_LIMIT + 1)
        .fetch_all(&st.pool)
        .await?;
    let truncated = rows.len() as i64 > TAB_LIMIT;
    let rows = rows
        .iter()
        .take(TAB_LIMIT as usize)
        .map(|r| (0..headers.len()).map(|i| r.get::<String, _>(i)).collect())
        .collect();
    Ok(render(&TableFragment {
        headers,
        rows,
        truncated,
    }))
}

pub struct PrivilegeRow {
    pub principal: String,
    pub kind: &'static str,
    pub source: String,
    /// 非 root 的 UID 0 帳號
    pub warn: bool,
}

pub struct UserRow {
    pub name: String,
    pub uid: u32,
    pub shell: String,
    pub locked: &'static str,
    pub password_changed: String,
}

#[derive(Template)]
#[template(path = "accounts_tab.html")]
struct AccountsTab {
    loaded: bool,
    privileged: Vec<PrivilegeRow>,
    users: Vec<UserRow>,
    unparsed: Vec<String>,
    system_user_count: u32,
}

/// 權限來源的顯示文字：uid0、group:<群組>、sudoers:<檔案>
fn source_label(source: &str) -> String {
    if source == "uid0" {
        "UID 0".into()
    } else if let Some(g) = source.strip_prefix("group:") {
        format!("{g} 群組")
    } else {
        source.strip_prefix("sudoers:").unwrap_or(source).into()
    }
}

/// 呼叫端已確認裝置在範圍內且是 Linux
async fn accounts_tab(st: &AppState, _s: &Session, id: Uuid) -> Result<Response, AppError> {
    let data: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT data FROM device_accounts WHERE device_id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    // 還沒上傳，或 jsonb 讀不回來：顯示「尚無資料」
    let Some(a) = data.and_then(|d| serde_json::from_value::<protocol::AccountsInfo>(d).ok())
    else {
        return Ok(render(&AccountsTab {
            loaded: false,
            privileged: vec![],
            users: vec![],
            unparsed: vec![],
            system_user_count: 0,
        }));
    };
    let mut privileged: Vec<PrivilegeRow> = a
        .privileged
        .into_iter()
        .map(|p| PrivilegeRow {
            warn: p.source == "uid0" && p.principal != "root",
            kind: match p.kind {
                protocol::PrincipalKind::User => "使用者",
                protocol::PrincipalKind::Group => "群組",
            },
            source: source_label(&p.source),
            principal: p.principal,
        })
        .collect();
    // 警示的排最前面
    privileged.sort_by_key(|p| !p.warn);
    let users = a
        .users
        .into_iter()
        .map(|u| UserRow {
            locked: match u.locked {
                Some(true) => "已鎖定",
                Some(false) => "否",
                None => "無法讀取",
            },
            password_changed: u
                .password_changed
                .map(|d| d.to_string())
                .unwrap_or_default(),
            name: u.name,
            uid: u.uid,
            shell: u.shell,
        })
        .collect();
    Ok(render(&AccountsTab {
        loaded: true,
        privileged,
        users,
        unparsed: a.sudoers_unparsed,
        system_user_count: a.system_user_count,
    }))
}

pub async fn retire(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    if device_group_in_scope(&st, &s, id)
        .await
        .map_err(db_error)?
        .is_none()
    {
        return Err(not_found());
    }
    crate::devices::retire(&st.pool, id, &s.username)
        .await
        .map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}

#[derive(Deserialize)]
pub struct MoveForm {
    csrf: String,
    #[serde(default)]
    group: String,
}

pub async fn move_group(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<MoveForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let group = match f.group.as_str() {
        "" | "none" => None,
        g => Some(
            g.parse::<i64>()
                .map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "bad group").into_response())?,
        ),
    };
    crate::groups::move_device(&st.pool, id, group, &s.username)
        .await
        .map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}
