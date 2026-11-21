//! 主管報告：可列印的單頁摘要（瀏覽器列印或存成 PDF）。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;

use super::auth::{AdminSession, Session};
use super::dashboard::{
    self, Overview, RangeQuery, RuleBar, SiteRow, overview, range_days, scope_label, sites,
    top_rules,
};
use super::{fmt_time, render};
use crate::AppState;
use crate::compliance::rules::Severity;
use crate::error::AppError;

/// 管理範圍內的受管裝置（`d` 是 devices）
const SCOPED: &str = "d.status NOT IN ('retired', 'pending_approval') \
     AND ($1::bool OR d.group_id = ANY($2::bigint[]))";

pub struct SeverityRow {
    pub severity: &'static str,
    pub label: &'static str,
    pub rules: i64,
    pub devices: i64,
}

pub struct DeployRow {
    pub name: String,
    pub stage: &'static str,
    pub succeeded: i64,
    pub failed: i64,
}

#[derive(Template)]
#[template(path = "report.html")]
struct ReportPage {
    version: &'static str,
    scope: String,
    days: i32,
    period: String,
    generated: String,
    user: String,
    o: Overview,
    severities: Vec<SeverityRow>,
    rules: Vec<RuleBar>,
    sites: Vec<SiteRow>,
    reboot: i64,
    reboot_week: i64,
    update_states: Vec<(&'static str, i64)>,
    deploys: Vec<DeployRow>,
}

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<RangeQuery>,
) -> Result<Response, AppError> {
    let days = range_days(&q);
    Ok(render(&build(&st, &s, days).await?))
}

async fn build(st: &AppState, s: &Session, days: i32) -> Result<ReportPage, AppError> {
    let (all, groups) = (s.all_devices(), &s.groups);
    let today = dashboard::today(st);
    let start = today - time::Duration::days(i64::from(days) - 1);
    let fmt_day = |d: time::Date| protocol::timefmt::format_date(d);

    let sql = format!(
        "SELECT r.severity, count(DISTINCT r.id), count(DISTINCT d.id) FROM device_violations v \
         JOIN compliance_rules r ON r.id = v.rule_id JOIN devices d ON d.id = v.device_id \
         WHERE v.status = 'violating' AND r.enabled AND {SCOPED} GROUP BY r.severity"
    );
    let sev: Vec<(String, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_all(&st.pool)
        .await?;
    let severities = Severity::ALL
        .into_iter()
        .map(|x| {
            let (rules, devices) = sev
                .iter()
                .find(|r| r.0 == x.as_str())
                .map(|r| (r.1, r.2))
                .unwrap_or((0, 0));
            SeverityRow {
                severity: x.as_str(),
                label: x.label(),
                rules,
                devices,
            }
        })
        .collect();

    let sql = format!(
        "SELECT count(*) FILTER (WHERE u.reboot_pending), \
                count(*) FILTER (WHERE u.reboot_pending \
                                   AND u.reboot_pending_since < now() - interval '7 days') \
         FROM update_policy_status u JOIN devices d ON d.id = u.device_id \
         WHERE d.status = 'active' AND d.os_family = 'windows' AND {SCOPED}"
    );
    let (reboot, reboot_week): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_one(&st.pool)
        .await?;
    let sql = format!(
        "SELECT coalesce(u.state, ''), count(*) FROM devices d \
         LEFT JOIN update_policy_status u ON u.device_id = d.id \
         WHERE d.status = 'active' AND d.os_family = 'windows' AND {SCOPED} \
         GROUP BY 1 ORDER BY 2 DESC"
    );
    let states: Vec<(String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_all(&st.pool)
        .await?;
    let update_states = states
        .into_iter()
        .map(|(state, n)| {
            let label = if state.is_empty() {
                "尚未回報"
            } else {
                super::updates::state_label(&state)
            };
            (label, n)
        })
        .collect();

    let sql = format!(
        "SELECT dep.id, dep.name, dep.stage, \
                count(d.id) FILTER (WHERE ds.status IN ('compliant', 'succeeded', 'reboot_required')), \
                count(d.id) FILTER (WHERE ds.status = 'failed') \
         FROM deployments dep \
         LEFT JOIN deployment_status ds ON ds.deployment_id = dep.id \
         LEFT JOIN devices d ON d.id = ds.device_id AND {SCOPED} \
         WHERE dep.stage <> 'stopped' GROUP BY dep.id \
         HAVING $1::bool OR count(d.id) > 0 ORDER BY dep.created_at DESC LIMIT 20"
    );
    let deploys: Vec<(i64, String, String, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .fetch_all(&st.pool)
        .await?;

    Ok(ReportPage {
        version: env!("CARGO_PKG_VERSION"),
        scope: scope_label(st, s).await?,
        days,
        period: format!("{} ～ {}", fmt_day(start), fmt_day(today)),
        generated: fmt_time(st, Some(time::OffsetDateTime::now_utc())),
        user: s.username.clone(),
        o: overview(st, s, days, None).await?,
        severities,
        rules: top_rules(st, s, 10).await?,
        sites: sites(st, s).await?,
        reboot,
        reboot_week,
        update_states,
        deploys: deploys
            .into_iter()
            .map(|(_, name, stage, succeeded, failed)| DeployRow {
                name,
                stage: super::deployments::stage_label(&stage),
                succeeded,
                failed,
            })
            .collect(),
    })
}
