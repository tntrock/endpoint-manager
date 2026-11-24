//! 裝置列表、詳細資料與動作。所有查詢都以工作階段的群組範圍過濾；範圍外一律 404。

use askama::Template;
use axum::extract::{Form, Path, Query, RawForm, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use time::Duration;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::login::CsrfForm;
use super::sort::{self, Column, Sort};
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

/// 虛擬化平台的顯示名稱（`systemd-detect-virt` 的名稱）
fn vm_name(v: &str) -> &str {
    match v {
        "kvm" => "KVM",
        "qemu" => "QEMU",
        "vmware" => "VMware",
        "microsoft" => "Hyper-V",
        "oracle" => "VirtualBox",
        "xen" => "Xen",
        "parallels" => "Parallels",
        "amazon" => "AWS",
        "google" => "Google Cloud",
        "bochs" => "Bochs",
        other => other,
    }
}

/// 執行環境的顯示文字；舊版 Agent 沒回報、或不認得的種類回 None
pub fn runs_in_label(kind: Option<&str>, detail: Option<&str>) -> Option<String> {
    let detail = detail.filter(|d| !d.is_empty());
    Some(match (kind?, detail) {
        ("host", Some("none")) => "實體機".into(),
        ("host", Some(v)) => format!("虛擬機（{}）", vm_name(v)),
        ("container", Some(c)) => format!("容器（{c}）"),
        ("container", None) => "容器".into(),
        ("wsl", Some(v)) => format!("WSL {v}"),
        ("wsl", None) => "WSL".into(),
        _ => return None,
    })
}

/// 執行環境的白話說明（滑鼠移上去、裝置頁顯示）；實體機與虛擬機不需要說明
pub fn runs_in_hint(kind: Option<&str>) -> &'static str {
    match kind {
        Some("wsl") => {
            "WSL（Windows Subsystem for Linux）：裝在 Windows 電腦裡的 Linux 環境，不是獨立的電腦；             這裡的資料是那個 Linux 環境的，Windows 本身要另外安裝 Windows 版 Agent"
        }
        Some("container") => "Agent 在容器裡執行：看到的軟體、服務是容器內的，不是主機的",
        _ => "",
    }
}

/// 執行環境篩選值：physical、vm、container、wsl，其他一律當成全部
fn env_filter(env: &str) -> &'static str {
    match env {
        "physical" => "physical",
        "vm" => "vm",
        "container" => "container",
        "wsl" => "wsl",
        _ => "",
    }
}

/// 多重連線篩選值：now（目前）、recent（7 天內），其他一律當成全部
fn net_filter(net: &str) -> &'static str {
    match net {
        "now" => "now",
        "recent" => "recent",
        _ => "",
    }
}

/// Linux 裝置沒有資料的分頁（合規分頁在 Linux 只放容器規則的結果）
const WINDOWS_ONLY_TABS: &[&str] = &["security", "deployments", "updates", "patches"];

/// `containers`：這台有偵測到容器執行環境（才顯示「容器」分頁）；
/// `vms`：這台是虛擬化主機（才顯示「虛擬機」分頁）；
/// `integrity`：這台有竄改偵測的發現（才顯示「完整性」分頁）
fn tabs_for(
    os_family: &str,
    containers: bool,
    vms: bool,
    integrity: bool,
) -> Vec<(&'static str, &'static str)> {
    let mut tabs = tabs_for_os(os_family, containers);
    // 都放在「變更歷史」前面
    if vms {
        let at = tabs.len() - 1;
        tabs.insert(at, ("vms", "虛擬機"));
    }
    if integrity {
        let at = tabs.len() - 1;
        tabs.insert(at, ("integrity", "完整性"));
    }
    tabs
}

fn tabs_for_os(os_family: &str, containers: bool) -> Vec<(&'static str, &'static str)> {
    if os_family == "linux" {
        let mut tabs = vec![
            ("timeline", "時間軸"),
            ("commands", "遠端指令"),
            ("software", "軟體"),
            ("services", "服務"),
            ("network", "網路"),
        ];
        if containers {
            tabs.insert(1, ("compliance", "合規"));
            tabs.push(("containers", "容器"));
        }
        tabs.extend([("accounts", "帳號與權限"), ("changes", "變更歷史")]);
        tabs
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
            ("network", "網路"),
            ("changes", "變更歷史"),
        ]
    }
}

/// 分頁是否適用於這個作業系統（網址直接打不適用的分頁時回 404）
fn tab_applies(os_family: &str, tab: &str) -> bool {
    match os_family {
        "linux" => !WINDOWS_ONLY_TABS.contains(&tab),
        _ => tab != "accounts" && tab != "containers",
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
    /// 執行環境：空白＝全部、physical、vm、container、wsl
    #[serde(default)]
    env: String,
    /// 多重連線：空白＝全部、now、recent
    #[serde(default)]
    net: String,
    #[serde(default)]
    page: i64,
    /// 排序（`web::sort`）
    #[serde(default)]
    sort: String,
}

pub struct DeviceRow {
    pub id: Uuid,
    pub hostname: String,
    pub group: String,
    pub domain: String,
    pub os: String,
    pub user: String,
    pub linux: bool,
    /// 容器或 WSL 的標籤文字與說明
    pub guest: Option<(String, &'static str)>,
    pub ip: String,
    /// 全部位址（滑過 IP 時顯示）
    pub all_ips: String,
    pub last_seen: String,
    pub badge: &'static str,

    pub badge_label: &'static str,
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesPage {
    nav: Nav,
    /// 批次「移到群組」的選項（只有平台管理員）
    move_groups: Vec<SelectOption>,
    scripts: Vec<SelectOption>,
    /// 目前清單的網址（批次操作後回到這裡）
    back: String,
    headers: Vec<sort::Header>,
    sort: String,
    notice: Option<String>,
    q: String,
    software: String,
    version: String,
    statuses: Vec<SelectOption>,
    oses: Vec<SelectOption>,
    envs: Vec<SelectOption>,
    nets: Vec<SelectOption>,
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
    Option<String>,
    Option<String>,
    String,
);

fn page_url(q: &ListQuery, sort: &str, page: i64) -> String {
    format!(
        "/devices?q={}&status={}&group={}&os={}&env={}&net={}&software={}&version={}&sort={}&page={page}",
        enc(&q.q),
        enc(&q.status),
        enc(&q.group),
        enc(&q.os),
        enc(&q.env),
        enc(&q.net),
        enc(&q.software),
        enc(&q.version),
        enc(sort)
    )
}

/// 裝置清單的欄位（排序白名單）
const LIST_COLS: [Column; 8] = [
    Column::new("hostname", "電腦名稱", "d.hostname"),
    Column::new("group", "群組", "g.name"),
    Column::fixed("網域"),
    Column::new("os", "作業系統", "d.os_caption"),
    Column::new("user", "使用者", "d.logged_on_user"),
    Column::new("ip", "IP", "try_inet(d.last_ip)"),
    Column::new("last_seen", "最後報到", "d.last_seen_at").desc_first(),
    Column::new("status", "狀態", "d.status"),
];

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    list_page(&st, &s, q, None).await
}

/// 清單頁；`notice` 是批次操作的結果
async fn list_page(
    st: &AppState,
    s: &Session,
    q: ListQuery,
    notice: Option<String>,
) -> Result<Response, AppError> {
    let cutoff = online_cutoff(st).await?;
    let page = q.page.clamp(0, MAX_PAGE);
    let group_filter: Option<i64> = q.group.parse().ok();
    let sort = Sort::parse(&q.sort, &LIST_COLS, ("hostname", false));
    let sort_param = sort.param(&LIST_COLS);
    let mut rows: Vec<ListRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT d.id, d.hostname, g.name, coalesce(d.domain, ''), coalesce(d.os_caption, ''), \
                coalesce(d.logged_on_user, ''), coalesce(d.last_ip, ''), d.last_seen_at, d.status, \
                d.os_family, d.runs_in, d.runs_in_detail, \
                coalesce((SELECT string_agg(host(x), ', ') FROM unnest(d.ips) x), '') \
         FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
           AND ($12 = '' OR d.os_family = $12) \
           AND (CASE $13 WHEN '' THEN true \
                WHEN 'physical' THEN d.runs_in = 'host' AND d.runs_in_detail = 'none' \
                WHEN 'vm' THEN d.runs_in = 'host' AND d.runs_in_detail <> 'none' \
                ELSE d.runs_in = $13 END) IS TRUE \
           AND ($14 = '' OR EXISTS (SELECT 1 FROM device_dual_homed_periods p \
                WHERE p.device_id = d.id AND (p.ended_at IS NULL \
                      OR ($14 = 'recent' AND p.ended_at > now() - interval '7 days')))) \
           AND ($3 = '' OR d.hostname ILIKE $4 OR d.logged_on_user ILIKE $4 OR d.last_ip ILIKE $4 \
                OR EXISTS (SELECT 1 FROM unnest(d.ips) x WHERE host(x) ILIKE $4)) \
           AND (CASE WHEN $5 = '' THEN d.status <> 'retired' WHEN $5 = 'all' THEN true \
                     WHEN $5 = 'stale' THEN d.status NOT IN ('retired', 'pending_approval') \
                          AND (d.last_seen_at IS NULL OR d.last_seen_at < now() - interval '7 days') \
                     WHEN $5 = 'integrity' THEN d.status <> 'retired' AND EXISTS ( \
                          SELECT 1 FROM device_findings f \
                          WHERE f.device_id = d.id AND f.acknowledged_at IS NULL) \
                     ELSE d.status = $5 END) \
           AND (CASE WHEN $6 = '' THEN true WHEN $6 = 'none' THEN d.group_id IS NULL \
                     ELSE d.group_id = $7 END) \
           AND ($8 = '' OR EXISTS (SELECT 1 FROM device_software sw WHERE sw.device_id = d.id \
                                   AND sw.name = $8 AND ($9 = '' OR coalesce(sw.version, '') = $9))) \
         ORDER BY {}, d.hostname, d.id LIMIT $10 OFFSET $11",
        sort.order_by(&LIST_COLS)
    )))
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
    .bind(env_filter(&q.env))
    .bind(net_filter(&q.net))
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rows = rows
        .into_iter()
        .map(
            |(
                id,
                hostname,
                group,
                domain,
                os,
                user,
                ip,
                last_seen,
                status,
                os_family,
                runs_in,
                runs_in_detail,
                all_ips,
            )| {
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
                    all_ips,
                    last_seen: fmt_time(st, last_seen),
                    badge,
                    badge_label,
                    linux: os_family == "linux",
                    // 清單只標出容器與 WSL：實體機與虛擬機占大多數，全標反而看不出重點
                    guest: runs_in
                        .as_deref()
                        .filter(|k| matches!(*k, "container" | "wsl"))
                        .and_then(|k| {
                            runs_in_label(Some(k), runs_in_detail.as_deref())
                                .map(|l| (l, runs_in_hint(Some(k))))
                        }),
                }
            },
        )
        .collect();
    let statuses = [
        ("", "使用中"),
        ("pending_approval", "待核准"),
        ("duplicate_suspect", "疑似重複"),
        ("stale", "離線超過 7 天"),
        ("integrity", "有完整性警示"),
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
    let envs = [
        ("", "所有執行環境"),
        ("physical", "實體機"),
        ("vm", "虛擬機"),
        ("container", "容器"),
        ("wsl", "WSL（Windows 裡的 Linux）"),
    ]
    .into_iter()
    .map(|(v, l)| SelectOption {
        value: v.into(),
        label: l.into(),
        selected: env_filter(&q.env) == v,
    })
    .collect();
    let nets = [
        ("", "所有網路狀態"),
        ("now", "多重連線（目前）"),
        ("recent", "多重連線（7 天內）"),
    ]
    .into_iter()
    .map(|(v, l)| SelectOption {
        value: v.into(),
        label: l.into(),
        selected: net_filter(&q.net) == v,
    })
    .collect();
    let headers = sort::headers(&LIST_COLS, sort, |p| page_url(&q, p, 0));
    Ok(render(&DevicesPage {
        oses,
        envs,
        nets,
        groups: group_options(st, s, &q.group, true).await?,
        move_groups: if s.all_devices() {
            group_options(st, s, "", false).await?
        } else {
            vec![]
        },
        scripts: super::commands::approved_scripts(st, s, None).await?,
        nav: Nav::new(s, "devices"),
        prev_url: page_url(&q, &sort_param, page - 1),
        next_url: page_url(&q, &sort_param, page + 1),
        back: page_url(&q, &sort_param, page),
        headers,
        sort: sort_param,
        notice,
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
    /// 執行環境（實體機、虛擬機（KVM）、容器、WSL）；不知道時是空字串
    pub runs_in: String,
    /// 執行環境的白話說明（WSL、容器才有）
    pub runs_in_hint: &'static str,
    /// 最後回報的相對時間
    pub seen_ago: String,
    /// 這台是虛擬機：執行於哪台主機（連結（範圍外為空）、主機名稱、虛擬機名稱）
    pub vm_host: Option<(String, String, String)>,
    /// 這台是 WSL：執行於哪台 Windows（連結（範圍外為空）、主機名稱）
    pub wsl_host: Option<(String, String)>,
    /// 這台是 Windows：裡面配對到的 WSL（連結（範圍外為空）、發行版名稱）
    pub wsl_guests: Vec<(String, String)>,
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
    let (keys, runs_in, runs_in_detail): (Vec<String>, Option<String>, Option<String>) =
        sqlx::query_as("SELECT signing_keys, runs_in, runs_in_detail FROM devices WHERE id = $1")
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
    let containers = linux && super::containers::has_runtimes(&st, id).await?;
    let boot = fmt_time(&st, boot);
    let agent = o(agent);
    let (cards, issues) = super::device_status::build(
        &st,
        &super::device_status::Facts {
            id,
            linux,
            containers,
            status: &status,
            last_seen,
            online: last_seen.is_some_and(|t| t > cutoff),
            boot: boot.clone(),
            agent: agent.clone(),
            errors: &errors,
            runs_in: runs_in.as_deref(),
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
            runs_in: runs_in_label(runs_in.as_deref(), runs_in_detail.as_deref())
                .unwrap_or_default(),
            runs_in_hint: runs_in_hint(runs_in.as_deref()),
            vm_host: super::vms::host_of(&st, &s, id).await?,
            wsl_host: if runs_in.as_deref() == Some("wsl") {
                super::vms::wsl_host_of(&st, &s, id).await?
            } else {
                None
            },
            wsl_guests: if linux {
                vec![]
            } else {
                super::vms::wsl_guests_of(&st, &s, id).await?
            },
        },
        tabs: tabs_for(
            &os_family,
            containers,
            super::vms::has_platforms(&st, id).await?,
            super::integrity::has_findings(&st, id).await?,
        ),
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
    if tab == "containers" {
        return super::containers::device_tab(&st, id).await;
    }
    if tab == "vms" {
        return super::vms::device_tab(&st, &s, id).await;
    }
    if tab == "network" {
        return super::network::device_tab(&st, s.all_devices(), id).await;
    }
    if tab == "integrity" {
        return super::integrity::device_tab(&st, &s, id).await;
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
    shares: Option<super::shares::SharesCard>,
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
    let shares = super::shares::load(st, id).await?;
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
            shares,
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
        shares,
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

/// 一次批次操作最多幾台
pub const MAX_BULK: usize = 200;

#[derive(Default)]
struct BulkForm {
    csrf: String,
    ids: Vec<Uuid>,
    /// 有 id 格式不對
    bad_id: bool,
    op: String,
    group: String,
    action: String,
    delay_minutes: Option<i32>,
    bad_delay: bool,
    script_id: Option<i64>,
    confirm: bool,
    /// 回到的清單網址（只取查詢字串）
    back: String,
}

fn parse_bulk(raw: &[u8]) -> BulkForm {
    let mut f = BulkForm::default();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.trim();
        match k.as_ref() {
            "csrf" => f.csrf = v.into(),
            "ids" => match v.parse() {
                Ok(id) => f.ids.push(id),
                Err(_) => f.bad_id = true,
            },
            "op" => f.op = v.into(),
            "group" => f.group = v.into(),
            "action" => f.action = v.into(),
            "delay_minutes" if !v.is_empty() => match v.parse() {
                Ok(d) => f.delay_minutes = Some(d),
                Err(_) => f.bad_delay = true,
            },
            "script_id" => f.script_id = v.parse().ok(),
            "confirm" => f.confirm = v == "1",
            "back" => f.back = v.into(),
            _ => {}
        }
    }
    f.ids.sort();
    f.ids.dedup();
    f
}

/// 批次操作後回到的清單條件；格式不對就用預設
fn back_query(back: &str) -> ListQuery {
    let query = back.split_once('?').map(|(_, q)| q).unwrap_or("");
    let uri: axum::http::Uri = format!("/devices?{query}")
        .parse()
        .unwrap_or_else(|_| axum::http::Uri::from_static("/devices"));
    Query::<ListQuery>::try_from_uri(&uri)
        .map(|q| q.0)
        .unwrap_or_else(|_| {
            Query::<ListQuery>::try_from_uri(&axum::http::Uri::from_static("/devices"))
                .expect("empty query")
                .0
        })
}

fn result_text(verb: &str, ok: usize, skipped: usize) -> String {
    if skipped == 0 {
        format!("已{verb} {ok} 台。")
    } else {
        format!("已{verb} {ok} 台，略過 {skipped} 台（不在管理範圍、不存在或狀態不符）。")
    }
}

/// `POST /devices/bulk`：勾選的裝置移到群組、下遠端指令或除役
pub async fn bulk(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_bulk(&raw);
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let back = back_query(&f.back);
    let show = |notice: String, status: axum::http::StatusCode| {
        let (st, s) = (&st, &s);
        async move {
            match list_page(st, s, back, Some(notice)).await {
                Ok(r) => (status, r).into_response(),
                Err(e) => e.into_response(),
            }
        }
    };
    use axum::http::StatusCode;
    if f.bad_id || f.ids.len() > MAX_BULK {
        return Ok(show(
            format!("選取的裝置格式不正確，或超過 {MAX_BULK} 台。"),
            StatusCode::BAD_REQUEST,
        )
        .await);
    }
    if f.ids.is_empty() {
        return Ok(show("沒有選取任何裝置。".into(), StatusCode::BAD_REQUEST).await);
    }
    match f.op.as_str() {
        "move" => {
            if !s.all_devices() {
                return Err(forbidden());
            }
            let group = match f.group.as_str() {
                "" | "none" => None,
                g => {
                    let id: Option<i64> = g.parse().ok();
                    let exists: bool = sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM device_groups WHERE id = $1)",
                    )
                    .bind(id)
                    .fetch_one(&st.pool)
                    .await
                    .map_err(db_error)?;
                    if !exists {
                        return Ok(show("群組不存在。".into(), StatusCode::BAD_REQUEST).await);
                    }
                    id
                }
            };
            let (mut ok, mut skipped) = (0, 0);
            for id in &f.ids {
                match crate::groups::move_device(&st.pool, *id, group, &s.username).await {
                    Ok(()) => ok += 1,
                    Err(_) => skipped += 1,
                }
            }
            Ok(show(result_text("移動", ok, skipped), StatusCode::OK).await)
        }
        "retire" => {
            if !f.confirm {
                return Ok(show("除役前請勾選確認。".into(), StatusCode::BAD_REQUEST).await);
            }
            let (mut ok, mut skipped) = (0, 0);
            for id in &f.ids {
                let in_scope = device_group_in_scope(&st, &s, *id)
                    .await
                    .map_err(db_error)?
                    .is_some();
                if in_scope
                    && crate::devices::retire(&st.pool, *id, &s.username)
                        .await
                        .is_ok()
                {
                    ok += 1;
                } else {
                    skipped += 1;
                }
            }
            Ok(show(result_text("除役", ok, skipped), StatusCode::OK).await)
        }
        "command" => {
            if f.bad_delay {
                return Ok(show(
                    "延遲必須是 0–60 分鐘的整數。".into(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                )
                .await);
            }
            let input = crate::commands::runs::RunInput {
                action: f.action.clone(),
                target: crate::commands::runs::Target::Devices(f.ids.clone()),
                delay_minutes: f.delay_minutes,
                script_id: f.script_id,
                expires_hours: crate::commands::runs::DEFAULT_EXPIRES_HOURS,
            };
            match crate::commands::runs::create_run(&st.pool, &input, &super::commands::actor(&s))
                .await
            {
                Ok((id, ..)) => Ok(Redirect::to(&format!("/commands/{id}")).into_response()),
                Err(e) => match super::commands::form_error(&e) {
                    Some((status, m)) => Ok(show(m, status).await),
                    None => Err(super::commands::command_error(e)),
                },
            }
        }
        _ => Ok(show("不支援的操作。".into(), StatusCode::BAD_REQUEST).await),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_in_labels() {
        let l = |k: Option<&str>, d: Option<&str>| runs_in_label(k, d);
        assert_eq!(l(Some("host"), Some("none")).as_deref(), Some("實體機"));
        for (v, name) in [
            ("kvm", "KVM"),
            ("qemu", "QEMU"),
            ("vmware", "VMware"),
            ("microsoft", "Hyper-V"),
            ("oracle", "VirtualBox"),
            ("xen", "Xen"),
            ("parallels", "Parallels"),
            ("amazon", "AWS"),
            ("google", "Google Cloud"),
            ("bochs", "Bochs"),
            ("acrn", "acrn"),
        ] {
            assert_eq!(l(Some("host"), Some(v)), Some(format!("虛擬機（{name}）")));
        }
        assert_eq!(l(Some("host"), None), None);
        assert_eq!(l(Some("host"), Some("")), None);
        assert_eq!(
            l(Some("container"), Some("lxc")).as_deref(),
            Some("容器（lxc）")
        );
        assert_eq!(l(Some("container"), None).as_deref(), Some("容器"));
        assert_eq!(l(Some("wsl"), Some("1")).as_deref(), Some("WSL 1"));
        assert_eq!(l(Some("wsl"), None).as_deref(), Some("WSL"));
        assert!(runs_in_hint(Some("wsl")).contains("Windows"));
        assert!(runs_in_hint(Some("container")).contains("容器"));
        assert_eq!(runs_in_hint(Some("host")), "");
        assert_eq!(runs_in_hint(None), "");
        assert_eq!(l(Some("future"), Some("x")), None);
        assert_eq!(l(None, None), None);
        assert_eq!(env_filter("vm"), "vm");
        assert_eq!(env_filter("x'; --"), "");
        assert_eq!(net_filter("now"), "now");
        assert_eq!(net_filter("recent"), "recent");
        assert_eq!(net_filter("x"), "");
    }
}
