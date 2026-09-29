//! 規則與豁免的增刪改（權限由網頁層檢查）。每個動作寫入稽核記錄。

use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::rules::{Params, Severity};
use super::store::refresh_device_fresh;
use crate::audit;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_DESCRIPTION_LEN: usize = 1000;
pub const MAX_REASON_LEN: usize = 500;
pub const MAX_EXEMPTION_DAYS: i64 = 365;

#[derive(Debug, Clone)]
pub struct RuleInput {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub severity: String,
    pub enabled: bool,
    pub params: serde_json::Value,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
}

struct Valid {
    name: String,
    description: String,
    severity: Severity,
    params: Params,
}

fn validate(i: &RuleInput) -> anyhow::Result<Valid> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "規則名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    let description = i.description.trim().to_string();
    ensure!(
        description.chars().count() <= MAX_DESCRIPTION_LEN,
        "說明最多 {MAX_DESCRIPTION_LEN} 字"
    );
    let severity = Severity::parse(&i.severity).context("嚴重度無效")?;
    let params = Params::parse(&i.kind, &i.params).map_err(anyhow::Error::msg)?;
    ensure!(
        !i.include.iter().any(|g| i.exclude.contains(g)),
        "同一個群組不能同時「只套用」又「排除」"
    );
    Ok(Valid {
        name,
        description,
        severity,
        params,
    })
}

async fn bump(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE compliance_state SET generation = generation + 1")
        .execute(conn)
        .await?;
    Ok(())
}

async fn write_groups(conn: &mut PgConnection, id: i64, i: &RuleInput) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM compliance_rule_groups WHERE rule_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    for (groups, mode) in [(&i.include, "include"), (&i.exclude, "exclude")] {
        for g in groups {
            sqlx::query(
                "INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, $3) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(g)
            .bind(mode)
            .execute(&mut *conn)
            .await
            .map_err(|_| anyhow::anyhow!("群組不存在：{g}"))?;
        }
    }
    Ok(())
}

fn detail(id: i64, v: &Valid, i: &RuleInput) -> serde_json::Value {
    json!({
        "id": id, "kind": v.params.kind(), "severity": v.severity.as_str(),
        "params": v.params.to_json(), "include": i.include, "exclude": i.exclude,
        "enabled": i.enabled
    })
}

pub async fn create_rule(pool: &PgPool, i: &RuleInput, actor: &str) -> anyhow::Result<i64> {
    let v = validate(i)?;
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_rules \
         (name, description, kind, severity, enabled, params, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7) RETURNING id",
    )
    .bind(&v.name)
    .bind(&v.description)
    .bind(v.params.kind())
    .bind(v.severity.as_str())
    .bind(i.enabled)
    .bind(v.params.to_json().to_string())
    .bind(actor)
    .fetch_one(&mut *tx)
    .await?;
    write_groups(&mut tx, id, i).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "rule_create",
        Some(&v.name),
        detail(id, &v, i),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_rule(pool: &PgPool, id: i64, i: &RuleInput, actor: &str) -> anyhow::Result<()> {
    let v = validate(i)?;
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE compliance_rules SET name = $2, description = $3, kind = $4, severity = $5, \
         enabled = $6, params = $7::jsonb, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&v.name)
    .bind(&v.description)
    .bind(v.params.kind())
    .bind(v.severity.as_str())
    .bind(i.enabled)
    .bind(v.params.to_json().to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    ensure!(n == 1, "規則不存在");
    write_groups(&mut tx, id, i).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "rule_update",
        Some(&v.name),
        detail(id, &v, i),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_rule(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    // 違規會隨規則 cascade 刪除；先寫「→ none」事件，歷程與通知才知道違規已結束
    // （規則刪除後這些事件的 rule_id 會被設為 NULL，名稱保留在快照）
    sqlx::query(
        "INSERT INTO violation_events          (device_id, rule_id, rule_name, severity, from_status, to_status, detail)          SELECT v.device_id, v.rule_id, r.name, r.severity, v.status, 'none', v.detail          FROM device_violations v JOIN compliance_rules r ON r.id = v.rule_id          WHERE v.rule_id = $1",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM compliance_rules WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let name = name.context("規則不存在")?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "rule_delete",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 同一台裝置同一條規則只有一筆豁免；再次建立會覆蓋原因與到期日。
pub async fn create_exemption(
    pool: &PgPool,
    device_id: Uuid,
    rule_id: i64,
    reason: &str,
    expires_at: DateTime<Utc>,
    actor: &str,
) -> anyhow::Result<i64> {
    let reason = reason.trim();
    ensure!(
        !reason.is_empty() && reason.chars().count() <= MAX_REASON_LEN,
        "豁免原因必填，最多 {MAX_REASON_LEN} 字"
    );
    let now = Utc::now();
    ensure!(
        expires_at > now && expires_at <= now + Duration::days(MAX_EXEMPTION_DAYS),
        "到期日須在今天之後、{MAX_EXEMPTION_DAYS} 天之內"
    );
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_exemptions (device_id, rule_id, reason, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (device_id, rule_id) DO UPDATE SET reason = EXCLUDED.reason, \
           expires_at = EXCLUDED.expires_at, created_by = EXCLUDED.created_by, created_at = now() \
         RETURNING id",
    )
    .bind(device_id)
    .bind(rule_id)
    .bind(reason)
    .bind(expires_at)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| anyhow::anyhow!("裝置或規則不存在"))?;
    audit::record(
        &mut tx,
        actor,
        "exemption_create",
        Some(&device_id.to_string()),
        json!({"id": id, "rule_id": rule_id, "reason": reason, "expires_at": expires_at}),
    )
    .await?;
    refresh_device_fresh(&mut tx, device_id).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn revoke_exemption(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let row: Option<(Uuid, i64)> = sqlx::query_as(
        "DELETE FROM compliance_exemptions WHERE id = $1 RETURNING device_id, rule_id",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let (device_id, rule_id) = row.context("豁免不存在")?;
    audit::record(
        &mut tx,
        actor,
        "exemption_revoke",
        Some(&device_id.to_string()),
        json!({"id": id, "rule_id": rule_id}),
    )
    .await?;
    refresh_device_fresh(&mut tx, device_id).await?;
    tx.commit().await?;
    Ok(())
}
