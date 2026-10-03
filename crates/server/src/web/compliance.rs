//! 合規：總覽、違規清單、CSV 匯出、裝置頁的合規分頁與豁免。所有裝置資料都以群組範圍過濾。

use askama::Template;
use axum::body::Body;
use axum::extract::{Form, Path, Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{
    MAX_PAGE, PAGE_SIZE, SelectOption, action_error, db_error, device_group_in_scope, group_options,
};
use super::login::CsrfForm;
use super::{enc, escape_like, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::compliance::evaluate::{Status, summarize};
use crate::compliance::rules::Severity;
use crate::error::AppError;

#[derive(Deserialize, Default, Clone)]
pub struct ViolationFilter {
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub q: String,
    /// 文字：格式不對時當第 1 頁，不回 axum 的英文錯誤
    #[serde(default)]
    pub page: String,
}

impl ViolationFilter {
    fn query_string(&self) -> String {
        format!(
            "rule={}&severity={}&status={}&group={}&q={}",
            enc(&self.rule),
            enc(&self.severity),
            enc(&self.status),
            enc(&self.group),
            enc(&self.q)
        )
    }
}

/// 清單與 CSV 共用的條件。參數：$1 all_devices、$2 groups、$3 rule(text)、$4 severity、
/// $5 status、$6 group(text)、$7 q、$8 escape_like(q)
const FILTER: &str = "($1::bool OR d.group_id = ANY($2::bigint[])) \
     AND ($3 = '' OR v.rule_id::text = $3) \
     AND ($4 = '' OR r.severity = $4) \
     AND ($5 = '' OR v.status = $5) \
     AND (CASE WHEN $6 = '' THEN true WHEN $6 = 'none' THEN d.group_id IS NULL \
               ELSE d.group_id::text = $6 END) \
     AND ($7 = '' OR d.hostname ILIKE $8)";

pub struct ViolationRow {
    pub device_id: Uuid,
    pub hostname: String,
    pub group: String,
    pub rule: String,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub since: String,
}

/// (device_id, rule_id, hostname, group, rule, severity, status, detail, since)
pub type RawViolation = (
    Uuid,
    i64,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    DateTime<Utc>,
);

fn violation_select() -> String {
    format!(
        "SELECT v.device_id, v.rule_id, d.hostname, g.name, r.name, r.severity, v.status, \
                v.detail::text, v.since \
         FROM device_violations v \
         JOIN devices d ON d.id = v.device_id \
         JOIN compliance_rules r ON r.id = v.rule_id \
         LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE {FILTER}"
    )
}

fn severity_of(s: &str) -> Severity {
    Severity::parse(s).unwrap_or(Severity::Medium)
}

fn status_label(s: &str) -> &'static str {
    Status::parse(s).map(Status::label).unwrap_or("?")
}

fn to_row(st: &AppState, r: RawViolation) -> ViolationRow {
    let (device_id, _, hostname, group, rule, severity, status, detail, since) = r;
    let sev = severity_of(&severity);
    let detail: serde_json::Value = serde_json::from_str(&detail).unwrap_or_default();
    ViolationRow {
        device_id,
        hostname,
        group: group.unwrap_or_else(|| "未分組".into()),
        rule,
        severity: sev.label(),
        severity_class: sev.as_str(),
        status: status_label(&status),
        summary: summarize(&detail),
        since: fmt_time(st, Some(since)),
    }
}

fn select(options: &[(&str, &str)], current: &str) -> Vec<SelectOption> {
    options
        .iter()
        .map(|(v, l)| SelectOption {
            value: (*v).into(),
            label: (*l).into(),
            selected: *v == current,
        })
        .collect()
}

#[derive(Template)]
#[template(path = "violations.html")]
struct ViolationsPage {
    nav: Nav,
    q: String,
    rules: Vec<SelectOption>,
    severities: Vec<SelectOption>,
    statuses: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<ViolationRow>,
    page: i64,
    has_next: bool,
    prev_url: String,
    next_url: String,
    csv_url: String,
}

pub async fn violations(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(f): Query<ViolationFilter>,
) -> Result<Response, AppError> {
    let page = f.page.trim().parse::<i64>().unwrap_or(0).clamp(0, MAX_PAGE);
    let sql = format!(
        "{} ORDER BY v.since DESC, v.device_id, v.rule_id LIMIT $9 OFFSET $10",
        violation_select()
    );
    let mut rows: Vec<RawViolation> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(&f.rule)
        .bind(&f.severity)
        .bind(&f.status)
        .bind(&f.group)
        .bind(&f.q)
        .bind(escape_like(&f.q))
        .bind(PAGE_SIZE + 1)
        .bind(page * PAGE_SIZE)
        .fetch_all(&st.pool)
        .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rule_names: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM compliance_rules ORDER BY name")
            .fetch_all(&st.pool)
            .await?;
    let mut rules = vec![SelectOption {
        value: String::new(),
        label: "所有規則".into(),
        selected: f.rule.is_empty(),
    }];
    rules.extend(rule_names.into_iter().map(|(id, name)| SelectOption {
        selected: f.rule == id.to_string(),
        value: id.to_string(),
        label: name,
    }));
    let qs = f.query_string();
    Ok(render(&ViolationsPage {
        nav: Nav::new(&s, "compliance"),
        rules,
        severities: select(
            &[
                ("", "所有嚴重度"),
                ("high", "高"),
                ("medium", "中"),
                ("low", "低"),
            ],
            &f.severity,
        ),
        statuses: select(
            &[
                ("", "所有狀態"),
                ("violating", "違規"),
                ("unknown", "未知"),
                ("exempt", "豁免"),
            ],
            &f.status,
        ),
        groups: group_options(&st, &s, &f.group, true).await?,
        rows: rows.into_iter().map(|r| to_row(&st, r)).collect(),
        page,
        has_next,
        prev_url: format!("/compliance/violations?{qs}&page={}", page - 1),
        next_url: format!("/compliance/violations?{qs}&page={}", page + 1),
        csv_url: format!("/compliance/violations.csv?{qs}"),
        q: f.q,
    }))
}

pub struct RuleSummary {
    pub id: i64,
    pub name: String,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub violating: i64,
    pub unknown: i64,
    pub exempt: i64,
}

pub struct TrendRow {
    pub day: String,
    pub violating: i64,
}

#[derive(Template)]
#[template(path = "compliance.html")]
struct OverviewPage {
    nav: Nav,
    devices_violating: i64,
    rules: Vec<RuleSummary>,
    running: bool,
    progress_done: i64,
    progress_total: i64,
    trend: Vec<TrendRow>,
    trend_max: i64,
    channels: Vec<ChannelStatus>,
}

pub struct ChannelStatus {
    pub name: &'static str,
    pub enabled: bool,
    pub last_ok: String,
    pub error: String,
}

type ChannelRow = (String, Option<DateTime<Utc>>, Option<String>);

/// 通知管道狀態（只給平台管理員）
async fn channels(st: &AppState) -> Result<Vec<ChannelStatus>, sqlx::Error> {
    let n = crate::notify::load_settings(&st.pool).await?;
    let rows: Vec<ChannelRow> = sqlx::query_as(
        "SELECT channel, last_ok_at, last_error FROM notify_channels ORDER BY channel",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(_, ok, err)| ChannelStatus {
            name: "Webhook",
            enabled: n.webhook_url.is_some(),
            last_ok: fmt_time(st, ok),
            error: err.unwrap_or_default(),
        })
        .collect())
}

type SummaryRow = (i64, String, String, i64, i64, i64);

pub async fn overview(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    let devices_violating: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT v.device_id) FROM device_violations v \
         JOIN devices d ON d.id = v.device_id \
         WHERE v.status = 'violating' AND ($1::bool OR d.group_id = ANY($2::bigint[]))",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_one(&st.pool)
    .await?;
    // 平台管理員不需要範圍條件（省掉每列違規的 EXISTS 檢查）
    let scope = if s.all_devices() {
        ""
    } else {
        "AND EXISTS (SELECT 1 FROM devices d WHERE d.id = v.device_id \
              AND d.group_id = ANY($1::bigint[]))"
    };
    let sql = format!(
        "SELECT r.id, r.name, r.severity, \
           count(v.rule_id) FILTER (WHERE v.status = 'violating'), \
           count(v.rule_id) FILTER (WHERE v.status = 'unknown'), \
           count(v.rule_id) FILTER (WHERE v.status = 'exempt') \
         FROM compliance_rules r \
         LEFT JOIN device_violations v ON v.rule_id = r.id {scope} \
         WHERE r.enabled GROUP BY r.id \
         ORDER BY CASE r.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, \
                  4 DESC, r.name"
    );
    let q = sqlx::query_as(sqlx::AssertSqlSafe(sql));
    let q = if s.all_devices() {
        q
    } else {
        q.bind(&s.groups)
    };
    let rows: Vec<SummaryRow> = q.fetch_all(&st.pool).await?;
    let p = crate::compliance::worker::progress(&st.pool).await?;
    let trend: Vec<(NaiveDate, i64)> = if s.all_devices() {
        sqlx::query_as(
            "SELECT day, sum(violating)::bigint FROM compliance_daily \
             WHERE day > $1::date - 30 GROUP BY day ORDER BY day",
        )
        // 快照以管理網頁時區的日期記錄：區間也用同一個「今天」
        .bind(crate::compliance::today(chrono::Utc::now()))
        .fetch_all(&st.pool)
        .await?
    } else {
        vec![]
    };
    let trend_max = trend.iter().map(|t| t.1).max().unwrap_or(0).max(1);
    Ok(render(&OverviewPage {
        nav: Nav::new(&s, "compliance"),
        devices_violating,
        rules: rows
            .into_iter()
            .map(|(id, name, severity, violating, unknown, exempt)| {
                let sev = severity_of(&severity);
                RuleSummary {
                    id,
                    name,
                    severity: sev.label(),
                    severity_class: sev.as_str(),
                    violating,
                    unknown,
                    exempt,
                }
            })
            .collect(),
        running: p.running,
        progress_done: p.done,
        progress_total: p.total,
        trend: trend
            .into_iter()
            .map(|(d, v)| TrendRow {
                day: d.format("%m-%d").to_string(),
                violating: v,
            })
            .collect(),
        trend_max,
        channels: if s.all_devices() {
            channels(&st).await?
        } else {
            vec![]
        },
    }))
}

/// 每個欄位都加引號；以 = + - @ Tab CR 開頭時前面加 '，避免 Excel 當公式執行（CSV 注入）。
pub fn csv_field(s: &str) -> String {
    let risky = s.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let body = s.replace('"', "\"\"");
    if risky {
        format!("\"'{body}\"")
    } else {
        format!("\"{body}\"")
    }
}

const CSV_BATCH: i64 = 5000;
const CSV_HEADER: &str = "\u{feff}裝置ID,電腦名稱,群組,規則,嚴重度,狀態,細節,開始時間(UTC)\r\n";

fn csv_rows(rows: &[RawViolation]) -> String {
    let mut chunk = String::new();
    for (device, _, host, group, rule, sev, status, detail, since) in rows {
        let detail: serde_json::Value = serde_json::from_str(detail).unwrap_or_default();
        let fields = [
            device.to_string(),
            host.clone(),
            group.clone().unwrap_or_else(|| "未分組".into()),
            rule.clone(),
            severity_of(sev).label().into(),
            status_label(status).into(),
            summarize(&detail),
            since.format("%Y-%m-%d %H:%M:%S").to_string(),
        ];
        let line: Vec<String> = fields.iter().map(|x| csv_field(x)).collect();
        chunk.push_str(&line.join(","));
        chunk.push_str("\r\n");
    }
    chunk
}

/// 依清單的篩選條件匯出 CSV。以 (device_id, rule_id) 分批讀取、邊讀邊送，不把全部結果放進記憶體。
pub async fn export_csv(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(f): Query<ViolationFilter>,
) -> Result<Response, AppError> {
    let mut conn = st.pool.acquire().await?;
    crate::audit::record(
        &mut conn,
        &s.username,
        "compliance_export",
        None,
        serde_json::json!({
            "rule": f.rule, "severity": f.severity, "status": f.status,
            "group": f.group, "q": f.q
        }),
    )
    .await?;
    drop(conn);

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(4);
    tokio::spawn(async move {
        if tx.send(Ok(CSV_HEADER.into())).await.is_err() {
            return;
        }
        let sql = format!(
            "{} AND (v.device_id, v.rule_id) > ($9, $10) \
             ORDER BY v.device_id, v.rule_id LIMIT $11",
            violation_select()
        );
        let mut after: (Uuid, i64) = (Uuid::nil(), -1);
        loop {
            let rows: Result<Vec<RawViolation>, _> =
                sqlx::query_as(sqlx::AssertSqlSafe(sql.clone()))
                    .bind(s.all_devices())
                    .bind(&s.groups)
                    .bind(&f.rule)
                    .bind(&f.severity)
                    .bind(&f.status)
                    .bind(&f.group)
                    .bind(&f.q)
                    .bind(escape_like(&f.q))
                    .bind(after.0)
                    .bind(after.1)
                    .bind(CSV_BATCH)
                    .fetch_all(&st.pool)
                    .await;
            let rows = match rows {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "csv export failed");
                    let _ = tx.send(Err(std::io::Error::other("database error"))).await;
                    return;
                }
            };
            let Some(last) = rows.last() else { return };
            after = (last.0, last.1);
            if tx.send(Ok(csv_rows(&rows))).await.is_err() || (rows.len() as i64) < CSV_BATCH {
                return;
            }
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (item, rx))
    });
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"violations.csv\"",
            ),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

pub struct ResultRow {
    pub rule: String,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub since: String,
}

pub struct ExemptionRow {
    pub id: i64,
    pub rule: String,
    pub reason: String,
    pub expires: String,
    pub created_by: String,
}

pub struct EventRow {
    pub at: String,
    pub rule: String,
    pub change: String,
    pub summary: String,
}

#[derive(Template)]
#[template(path = "compliance_tab.html")]
struct TabFragment {
    device_id: Uuid,
    csrf: String,
    platform: bool,
    /// 有沒有任何啟用中的規則（沒有結果時區分「沒有違規」與「還沒建規則」）
    has_rules: bool,
    results: Vec<ResultRow>,
    exemptions: Vec<ExemptionRow>,
    events: Vec<EventRow>,
    rules: Vec<SelectOption>,
    max_days: i64,
}

/// 歷程的狀態文字；none 表示無結果
fn status_word(s: &str) -> &'static str {
    Status::parse(s).map(Status::label).unwrap_or("無")
}

type ResultDbRow = (String, String, String, String, DateTime<Utc>);
type ExemptionDbRow = (i64, String, String, DateTime<Utc>, String);
type EventDbRow = (DateTime<Utc>, String, String, String, String);

/// 裝置頁的「合規」分頁（htmx 片段）。範圍外的裝置回 404。
pub async fn device_tab(st: &AppState, s: &Session, id: Uuid) -> Result<Response, AppError> {
    if device_group_in_scope(st, s, id).await?.is_none() {
        return Ok(not_found());
    }
    let results: Vec<ResultDbRow> = sqlx::query_as(
        "SELECT r.name, r.severity, v.status, v.detail::text, v.since FROM device_violations v \
         JOIN compliance_rules r ON r.id = v.rule_id WHERE v.device_id = $1 \
         ORDER BY CASE v.status WHEN 'violating' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, r.name",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let exemptions: Vec<ExemptionDbRow> = sqlx::query_as(
        "SELECT e.id, r.name, e.reason, e.expires_at, e.created_by FROM compliance_exemptions e \
         JOIN compliance_rules r ON r.id = e.rule_id WHERE e.device_id = $1 ORDER BY e.expires_at",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let events: Vec<EventDbRow> = sqlx::query_as(
        "SELECT at, rule_name, from_status, to_status, detail::text FROM violation_events \
         WHERE device_id = $1 ORDER BY at DESC, id DESC LIMIT 50",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let rules: Vec<(i64, String)> = if s.all_devices() {
        sqlx::query_as("SELECT id, name FROM compliance_rules WHERE enabled ORDER BY name")
            .fetch_all(&st.pool)
            .await?
    } else {
        vec![]
    };
    let has_rules: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM compliance_rules WHERE enabled)")
            .fetch_one(&st.pool)
            .await?;
    let summary = |d: &str| summarize(&serde_json::from_str(d).unwrap_or_default());
    Ok(render(&TabFragment {
        device_id: id,
        has_rules,
        csrf: s.csrf.clone(),
        platform: s.all_devices(),
        results: results
            .into_iter()
            .map(|(rule, severity, status, detail, since)| {
                let sev = severity_of(&severity);
                ResultRow {
                    rule,
                    severity: sev.label(),
                    severity_class: sev.as_str(),
                    status: status_word(&status),
                    summary: summary(&detail),
                    since: fmt_time(st, Some(since)),
                }
            })
            .collect(),
        exemptions: exemptions
            .into_iter()
            .map(|(id, rule, reason, expires, created_by)| ExemptionRow {
                id,
                rule,
                reason,
                expires: fmt_time(st, Some(expires)),
                created_by,
            })
            .collect(),
        events: events
            .into_iter()
            .map(|(at, rule, from, to, detail)| EventRow {
                at: fmt_time(st, Some(at)),
                rule,
                change: format!("{} → {}", status_word(&from), status_word(&to)),
                summary: summary(&detail),
            })
            .collect(),
        rules: rules
            .into_iter()
            .map(|(id, name)| SelectOption {
                value: id.to_string(),
                label: name,
                selected: false,
            })
            .collect(),
        max_days: crate::compliance::admin::MAX_EXEMPTION_DAYS,
    }))
}

#[derive(Deserialize)]
pub struct ExemptionForm {
    csrf: String,
    #[serde(default)]
    rule_id: String,
    #[serde(default)]
    reason: String,
    /// 文字：格式不對時回中文訊息，不回 axum 的英文錯誤
    #[serde(default)]
    days: String,
}

pub async fn create_exemption(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<ExemptionForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let max = crate::compliance::admin::MAX_EXEMPTION_DAYS;
    let days = f
        .days
        .trim()
        .parse::<i64>()
        .ok()
        .filter(|d| (1..=max).contains(d))
        .ok_or_else(|| action_error(anyhow::anyhow!("有效天數須為 1–{max} 的整數")))?;
    let rule_id = f
        .rule_id
        .trim()
        .parse::<i64>()
        .map_err(|_| action_error(anyhow::anyhow!("請選擇規則")))?;
    crate::compliance::admin::create_exemption(
        &st.pool,
        id,
        rule_id,
        &f.reason,
        Utc::now() + chrono::Duration::days(days),
        &s.username,
    )
    .await
    .map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}

pub async fn revoke_exemption(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let device: Option<Uuid> =
        sqlx::query_scalar("SELECT device_id FROM compliance_exemptions WHERE id = $1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await
            .map_err(db_error)?;
    let device = device.ok_or_else(not_found)?;
    crate::compliance::admin::revoke_exemption(&st.pool, id, &s.username)
        .await
        .map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{device}")).into_response())
}

#[cfg(test)]
mod tests {
    use super::csv_field;

    #[test]
    fn csv_quotes_and_neutralizes_formulas() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
        for p in ["+1", "-1", "@SUM(A1)", "\tx", "\rx"] {
            assert!(csv_field(p).starts_with("\"'"), "{p:?}");
        }
        assert_eq!(csv_field("多行\n文字"), "\"多行\n文字\"");
    }
}

/// 安全設定分頁的一列：項目、值；error 為收集失敗時的訊息
pub struct SecurityLine {
    pub label: String,
    pub value: String,
    pub error: bool,
}

#[derive(Template)]
#[template(path = "security_tab.html")]
struct SecurityTab {
    updated: Option<String>,
    lines: Vec<SecurityLine>,
}

fn security_lines(st: &AppState, info: &protocol::SecurityInfo) -> Vec<SecurityLine> {
    use protocol::Probe;
    let on = |b: bool| if b { "啟用" } else { "停用" };
    let mut out = vec![];
    let mut push = |label: &str, value: String, error: bool| {
        out.push(SecurityLine {
            label: label.into(),
            value,
            error,
        })
    };
    match &info.firewall {
        Probe::Ok(f) => push(
            "防火牆",
            format!(
                "網域：{}、私人：{}、公用：{}",
                on(f.domain),
                on(f.private),
                on(f.public)
            ),
            false,
        ),
        Probe::Error(e) => push("防火牆", e.clone(), true),
    }
    match &info.bitlocker {
        Probe::Ok(v) if v.is_empty() => push("BitLocker", "沒有固定磁碟".into(), false),
        Probe::Ok(v) => push(
            "BitLocker",
            v.iter()
                .map(|x| {
                    format!(
                        "{}{}：{}",
                        x.drive,
                        if x.is_system { "（系統）" } else { "" },
                        if x.protected {
                            "保護中"
                        } else {
                            "未保護"
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("、"),
            false,
        ),
        Probe::Error(e) => push("BitLocker", e.clone(), true),
    }
    match &info.defender {
        Probe::Ok(d) => push(
            "Defender",
            format!(
                "作用中：{}、即時保護：{}、防竄改：{}、病毒碼更新：{}",
                if d.active { "是" } else { "否" },
                on(d.realtime),
                on(d.tamper),
                d.signature_updated
                    .map(|t| super::fmt_time(st, Some(t)))
                    .unwrap_or_else(|| "未知".into())
            ),
            false,
        ),
        Probe::Error(e) => push("Defender", e.clone(), true),
    }
    match &info.password {
        Probe::Ok(p) => push(
            "密碼原則（本機）",
            format!(
                "最短 {} 碼、最長使用：{}、鎖定門檻：{}",
                p.min_length,
                if p.max_age_days == 0 {
                    "永不過期".to_string()
                } else {
                    format!("{} 天", p.max_age_days)
                },
                if p.lockout_threshold == 0 {
                    "不鎖定".to_string()
                } else {
                    format!("{} 次", p.lockout_threshold)
                }
            ),
            false,
        ),
        Probe::Error(e) => push("密碼原則（本機）", e.clone(), true),
    }
    match &info.admins {
        Probe::Ok(a) => push(
            "本機管理員",
            a.iter()
                .map(|x| format!("{}（{}）", x.name, x.sid))
                .collect::<Vec<_>>()
                .join("、"),
            false,
        ),
        Probe::Error(e) => push("本機管理員", e.clone(), true),
    }
    out
}

type SecurityDbRow = (String, String, String, String, String, DateTime<Utc>);

/// 裝置頁的「安全設定」分頁（htmx 片段）。範圍外的裝置回 404。
pub async fn security_tab(st: &AppState, s: &Session, id: Uuid) -> Result<Response, AppError> {
    if device_group_in_scope(st, s, id).await?.is_none() {
        return Ok(not_found());
    }
    let row: Option<SecurityDbRow> = sqlx::query_as(
        "SELECT sec.firewall::text, sec.bitlocker::text, sec.defender::text, \
                sec.password::text, sec.admins::text, i.updated_at \
         FROM device_security sec JOIN inventory_sections i \
              ON i.device_id = sec.device_id AND i.section = 'security' \
         WHERE sec.device_id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let (updated, lines) = match row {
        None => (None, vec![]),
        Some((a, b, c, d, e, at)) => {
            let info = crate::inventory::security_from_row((a, b, c, d, e));
            (
                Some(super::fmt_time(st, Some(at))),
                security_lines(st, &info),
            )
        }
    };
    Ok(render(&SecurityTab { updated, lines }))
}
