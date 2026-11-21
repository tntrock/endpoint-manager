//! 總覽：指標、違規趨勢、需要處理、各據點狀態、違規最多的規則與待核准清單。
//! 這些區塊也用在主管報告（`report.rs`）。

use askama::Template;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use time::{Date, Duration, OffsetDateTime};
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session};
use super::chart::{self, LineChart};
use super::devices::online_cutoff;
use super::{fmt_time, render};
use crate::AppState;
use crate::compliance::rules::Severity;
use crate::error::AppError;
use crate::stats::{self, Counts};

/// 管理範圍內的受管裝置（`d` 是 devices）
const SCOPED: &str = "d.status NOT IN ('retired', 'pending_approval') \
     AND ($1::bool OR d.group_id = ANY($2::bigint[]))";

type PendingDbRow = (Uuid, String, Uuid, String, Option<String>, OffsetDateTime);

pub struct PendingRow {
    pub id: Uuid,
    pub hostname: String,
    pub old_id: Uuid,
    pub old_hostname: String,
    pub group: String,
    pub enrolled_at: String,
}

#[derive(Deserialize, Default)]
pub struct RangeQuery {
    #[serde(default)]
    days: String,
}

/// 期間：7、30、90 天，其他值當 30
pub(super) fn range_days(q: &RangeQuery) -> i32 {
    match q.days.as_str() {
        "7" => 7,
        "90" => 90,
        _ => 30,
    }
}

pub struct RangeLink {
    pub days: i32,
    pub on: bool,
}

pub(super) fn range_links(days: i32) -> Vec<RangeLink> {
    [7, 30, 90]
        .into_iter()
        .map(|d| RangeLink {
            days: d,
            on: d == days,
        })
        .collect()
}

/// 變化量的文字與方向（up／down／flat）
pub struct Delta {
    pub dir: &'static str,
    pub text: String,
}

fn delta(diff: f64, unit: &str, decimals: usize) -> Delta {
    let shown = format!("{:.*}", decimals, diff.abs());
    let zero = shown.trim_end_matches(['0', '.']).is_empty();
    if zero {
        Delta {
            dir: "flat",
            text: "持平".into(),
        }
    } else if diff > 0.0 {
        Delta {
            dir: "up",
            text: format!("▲ {shown}{unit}"),
        }
    } else {
        Delta {
            dir: "down",
            text: format!("▼ {shown}{unit}"),
        }
    }
}

fn pct_text(p: Option<f64>) -> String {
    p.map(|p| format!("{p:.0}")).unwrap_or_else(|| "—".into())
}

/// 指標卡與趨勢圖
pub struct Overview {
    pub now: Counts,
    pub online_pct: String,
    pub ring: String,
    pub compliance_pct: String,
    /// 與比較基準（總覽是 7 天前，報告是期初）的差
    pub total_delta: Option<Delta>,
    pub compliance_delta: Option<Delta>,
    pub high_delta: Option<Delta>,
    pub spark_total: Option<String>,
    pub spark_compliance: Option<String>,
    pub spark_high: Option<String>,
    pub chart: Option<LineChart>,
}

pub(super) fn today(st: &AppState) -> Date {
    OffsetDateTime::now_utc()
        .to_offset(st.display_offset)
        .date()
}

/// `baseline`：比較基準是哪一天以前最近的快照；None 表示期初（第一筆）
pub(super) async fn overview(
    st: &AppState,
    s: &Session,
    days: i32,
    baseline_days_ago: Option<i64>,
) -> Result<Overview, AppError> {
    let cutoff = online_cutoff(st).await?;
    let now = stats::live(&st.pool, s.all_devices(), &s.groups, cutoff).await?;
    let today = today(st);
    let trend = stats::trend(&st.pool, s.all_devices(), &s.groups, today, days).await?;
    let base = match baseline_days_ago {
        Some(n) => {
            let at = today - Duration::days(n);
            trend.iter().rev().find(|(d, _)| *d <= at).map(|r| r.1)
        }
        None => trend.first().filter(|(d, _)| *d < today).map(|r| r.1),
    };
    let online_pct = (now.managed > 0).then(|| now.seen as f64 * 100.0 / now.managed as f64);
    let start = today - Duration::days(i64::from(days) - 1);
    let line = |f: fn(&Counts) -> i64| -> Vec<(Date, i64)> {
        trend.iter().map(|(d, c)| (*d, f(c))).collect()
    };
    Ok(Overview {
        online_pct: pct_text(online_pct),
        ring: chart::ring_dash(online_pct.unwrap_or(0.0)),
        compliance_pct: pct_text(now.compliance_pct()),
        total_delta: base.map(|b| delta((now.managed - b.managed) as f64, " 台", 0)),
        compliance_delta: base.and_then(|b| {
            Some(delta(
                now.compliance_pct()? - b.compliance_pct()?,
                " 個百分點",
                1,
            ))
        }),
        high_delta: base.map(|b| delta((now.high_risk - b.high_risk) as f64, " 台", 0)),
        spark_total: chart::sparkline(
            &trend.iter().map(|r| r.1.managed as f64).collect::<Vec<_>>(),
        ),
        spark_compliance: chart::sparkline(
            &trend
                .iter()
                .filter_map(|r| r.1.compliance_pct())
                .collect::<Vec<_>>(),
        ),
        spark_high: chart::sparkline(
            &trend
                .iter()
                .map(|r| r.1.high_risk as f64)
                .collect::<Vec<_>>(),
        ),
        chart: chart::line_chart(
            start,
            today,
            &[
                ("line-a", line(|c| c.violating())),
                ("line-b", line(|c| c.high_risk)),
            ],
        ),
        now,
    })
}

pub struct RuleBar {
    pub id: i64,
    pub name: String,
    pub severity: &'static str,
    pub severity_label: &'static str,
    pub count: i64,
    /// 長條寬度（相對第一名，0–100）
    pub width: String,
}

pub(super) async fn top_rules(
    st: &AppState,
    s: &Session,
    limit: i64,
) -> Result<Vec<RuleBar>, sqlx::Error> {
    let sql = format!(
        "SELECT r.id, r.name, r.severity, count(*) FROM device_violations v \
         JOIN compliance_rules r ON r.id = v.rule_id JOIN devices d ON d.id = v.device_id \
         WHERE v.status = 'violating' AND r.enabled AND {SCOPED} \
         GROUP BY r.id ORDER BY 4 DESC, r.name LIMIT $3"
    );
    let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(limit)
        .fetch_all(&st.pool)
        .await?;
    let max = rows.first().map(|r| r.3).unwrap_or(1).max(1);
    Ok(rows
        .into_iter()
        .map(|(id, name, severity, count)| {
            let sev = Severity::parse(&severity).unwrap_or(Severity::Medium);
            RuleBar {
                id,
                name,
                severity: sev.as_str(),
                severity_label: sev.label(),
                count,
                width: format!("{:.1}", count as f64 * 100.0 / max as f64),
            }
        })
        .collect())
}

pub struct SiteRow {
    pub name: String,
    pub total: i64,
    pub ok: i64,
    pub bad: i64,
    pub off: i64,
    /// 堆疊長條的三段 (x, 寬度)
    pub segs: Vec<(f64, f64)>,
}

/// 各據點的（在線且合規、在線但有違規、離線）；沒有設定據點時回空的
pub(super) async fn sites(st: &AppState, s: &Session) -> Result<Vec<SiteRow>, sqlx::Error> {
    let any: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sites)")
        .fetch_one(&st.pool)
        .await?;
    if !any {
        return Ok(vec![]);
    }
    let cutoff = online_cutoff(st).await?;
    // 符合多個據點時取網段最精確的（與派送的套件來源相同）
    let sql = format!(
        "SELECT site.name, count(*), \
                count(*) FILTER (WHERE d.last_seen_at > $3 AND NOT v.bad), \
                count(*) FILTER (WHERE d.last_seen_at > $3 AND v.bad), \
                count(*) FILTER (WHERE d.last_seen_at IS NULL OR d.last_seen_at <= $3) \
         FROM devices d \
         CROSS JOIN LATERAL (SELECT EXISTS (SELECT 1 FROM device_violations x \
             WHERE x.device_id = d.id AND x.status = 'violating') AS bad) v \
         LEFT JOIN LATERAL (SELECT s.id, s.name FROM sites s, unnest(s.cidrs) c \
             WHERE try_inet(d.last_ip) <<= c ORDER BY masklen(c) DESC, s.id LIMIT 1) site ON true \
         WHERE {SCOPED} \
         GROUP BY site.id, site.name ORDER BY site.name IS NULL, site.name"
    );
    let rows: Vec<(Option<String>, i64, i64, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(cutoff)
        .fetch_all(&st.pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(name, total, ok, bad, off)| SiteRow {
            name: name.unwrap_or_else(|| "其他".into()),
            total,
            ok,
            bad,
            off,
            segs: chart::stack(&[ok, bad, off]),
        })
        .collect())
}

pub struct TodoItem {
    /// high／medium／low
    pub severity: &'static str,
    pub title: String,
    pub detail: &'static str,
    pub count: i64,
    pub href: String,
}

async fn todo(st: &AppState, s: &Session, pending: i64) -> Result<Vec<TodoItem>, sqlx::Error> {
    let (all, groups) = (s.all_devices(), &s.groups);
    let mut out = vec![];
    let sql = format!(
        "SELECT r.id, r.name, count(*) FROM device_violations v \
         JOIN compliance_rules r ON r.id = v.rule_id JOIN devices d ON d.id = v.device_id \
         WHERE v.status = 'violating' AND r.enabled AND r.severity = 'high' AND {SCOPED} \
         GROUP BY r.id ORDER BY 3 DESC, r.name LIMIT 3"
    );
    let rules: Vec<(i64, String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_all(&st.pool)
        .await?;
    out.extend(rules.into_iter().map(|(id, name, n)| TodoItem {
        severity: "high",
        title: name,
        detail: "高風險規則的違規",
        count: n,
        href: format!("/compliance/violations?rule={id}&status=violating"),
    }));
    let sql = format!(
        "SELECT dep.id, dep.name, count(*) FROM deployment_status ds \
         JOIN deployments dep ON dep.id = ds.deployment_id JOIN devices d ON d.id = ds.device_id \
         WHERE ds.status = 'failed' AND dep.stage <> 'stopped' AND {SCOPED} \
         GROUP BY dep.id ORDER BY 3 DESC, dep.name LIMIT 3"
    );
    let deploys: Vec<(i64, String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_all(&st.pool)
        .await?;
    out.extend(deploys.into_iter().map(|(id, name, n)| TodoItem {
        severity: "high",
        title: name,
        detail: "派送失敗",
        count: n,
        href: format!("/deployments/{id}"),
    }));
    let sql = format!(
        "SELECT \
           (SELECT count(*) FROM update_policy_status u JOIN devices d ON d.id = u.device_id \
            WHERE u.reboot_pending AND u.reboot_pending_since < now() - interval '7 days' \
              AND d.status = 'active' AND d.os_family = 'windows' AND {SCOPED}), \
           (SELECT count(*) FROM devices d WHERE {SCOPED} \
              AND (d.last_seen_at IS NULL OR d.last_seen_at < now() - interval '7 days')), \
           (SELECT count(*) FROM devices d WHERE d.status = 'duplicate_suspect' AND {SCOPED})"
    );
    let (reboot, stale, duplicate): (i64, i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_one(&st.pool)
        .await?;
    for (n, title, detail, href) in [
        (
            reboot,
            "等待重新開機超過 7 天",
            "Windows Update",
            "/updates/overview",
        ),
        (
            stale,
            "離線超過 7 天",
            "確認是否已停用或需要除役",
            "/devices?status=stale",
        ),
        (
            duplicate,
            "疑似重複的裝置",
            "硬體識別與其他裝置相同",
            "/devices?status=duplicate_suspect",
        ),
    ] {
        if n > 0 {
            out.push(TodoItem {
                severity: "medium",
                title: title.into(),
                detail,
                count: n,
                href: href.into(),
            });
        }
    }
    if pending > 0 {
        out.push(TodoItem {
            severity: "low",
            title: "待核准的重新註冊".into(),
            detail: "通常是重灌",
            count: pending,
            href: "#pending".into(),
        });
    }
    Ok(out)
}

/// 範圍說明：「全部裝置」或群組名稱
pub(super) async fn scope_label(st: &AppState, s: &Session) -> Result<String, sqlx::Error> {
    if s.all_devices() {
        return Ok("全部裝置".into());
    }
    let names: Vec<String> =
        sqlx::query_scalar("SELECT name FROM device_groups WHERE id = ANY($1) ORDER BY name")
            .bind(&s.groups)
            .fetch_all(&st.pool)
            .await?;
    Ok(if names.is_empty() {
        "沒有群組".into()
    } else {
        names.join("、")
    })
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: Nav,
    scope: String,
    days: i32,
    ranges: Vec<RangeLink>,
    o: Overview,
    todo: Vec<TodoItem>,
    sites: Vec<SiteRow>,
    rules: Vec<RuleBar>,
    pending: Vec<PendingRow>,
    /// 全部核准的結果：(核准, 略過)
    approve_result: Option<(u32, u32)>,
}

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<RangeQuery>,
) -> Response {
    match build(&st, &s, range_days(&q)).await {
        Ok(p) => render(&p),
        Err(e) => e.into_response(),
    }
}

/// 儀表板；`approve_result` 只由「全部核准」的 POST 帶入（不從網址參數讀，連結無法偽造結果）
pub(super) async fn with_result(
    st: &AppState,
    s: &Session,
    approve_result: Option<(u32, u32)>,
) -> Response {
    match build(st, s, 30).await {
        Ok(mut p) => {
            p.approve_result = approve_result;
            render(&p)
        }
        Err(e) => e.into_response(),
    }
}

/// 範圍內的（總數, 在線, 疑似重複）；不含已除役與待核准
pub(super) async fn device_counts(
    st: &AppState,
    s: &Session,
) -> Result<(i64, i64, i64), sqlx::Error> {
    let cutoff = online_cutoff(st).await?;
    sqlx::query_as(
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
    .await
}

/// 外殼的狀態數字：htmx out-of-band 片段，每 60 秒更新。未登入回 401（htmx 不更新畫面）
pub async fn status(
    State(st): State<AppState>,
    session: Result<AdminSession, Response>,
) -> Response {
    let Ok(AdminSession(s)) = session else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let counts = async {
        let (total, online, _) = device_counts(&st, &s).await?;
        let violating = super::compliance::devices_violating(&st.pool, &s).await?;
        Ok::<_, sqlx::Error>((total, online, violating))
    };
    match counts.await {
        Ok((total, online, violating)) => Html(format!(
            r#"<span id="st-online" hx-swap-oob="true">{online} 台在線</span><span class="count num" id="st-devices" hx-swap-oob="true">{total}</span><span class="count num{hot}" id="st-violating" hx-swap-oob="true">{violating}</span>"#,
            hot = if violating > 0 { " hot" } else { "" },
        ))
        .into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}

async fn build(st: &AppState, s: &Session, days: i32) -> Result<DashboardPage, AppError> {
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
        nav: Nav::new(s, "overview"),
        scope: scope_label(st, s).await?,
        days,
        ranges: range_links(days),
        o: overview(st, s, days, Some(7)).await?,
        todo: todo(st, s, rows.len() as i64).await?,
        sites: sites(st, s).await?,
        rules: top_rules(st, s, 5).await?,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deltas_and_ranges() {
        let d = delta(3.0, " 台", 0);
        assert_eq!((d.dir, d.text.as_str()), ("up", "▲ 3 台"));
        let d = delta(-1.26, " 個百分點", 1);
        assert_eq!((d.dir, d.text.as_str()), ("down", "▼ 1.3 個百分點"));
        let d = delta(0.04, " 個百分點", 1);
        assert_eq!((d.dir, d.text.as_str()), ("flat", "持平"));
        for (raw, want) in [("7", 7), ("90", 90), ("30", 30), ("", 30), ("365", 30)] {
            assert_eq!(range_days(&RangeQuery { days: raw.into() }), want);
        }
        assert_eq!(pct_text(None), "—");
        assert_eq!(pct_text(Some(44.6)), "45");
    }
}
