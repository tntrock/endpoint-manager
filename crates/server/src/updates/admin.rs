//! 更新原則的管理（平台管理員）：驗證、CRUD、暫停、稽核。

use anyhow::{Context, bail, ensure};
use chrono::NaiveDate;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use super::policy::PolicySettings;
use crate::audit;

pub const MAX_NAME_LEN: usize = 100;

#[derive(Debug, Clone)]
pub struct PolicyInput {
    pub name: String,
    /// 暫停日不看這裡：表單不含暫停，更新時沿用資料庫的值
    pub settings: PolicySettings,
    pub groups: Vec<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseKind {
    Quality,
    Feature,
}

struct Valid {
    name: String,
    groups: Vec<i64>,
}

fn validate(i: &PolicyInput) -> anyhow::Result<Valid> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "原則名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "原則名稱不能包含控制字元"
    );
    i.settings.validate()?;
    let mut groups = i.groups.clone();
    groups.sort_unstable();
    groups.dedup();
    ensure!(!groups.is_empty(), "至少要選一個群組");
    Ok(Valid { name, groups })
}

async fn bump(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE update_state SET generation = generation + 1")
        .execute(conn)
        .await?;
    Ok(())
}

/// 鎖住原則列並回傳 (名稱, 設定)
async fn lock_policy(conn: &mut PgConnection, id: i64) -> anyhow::Result<(String, PolicySettings)> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, settings::text FROM update_policies WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let (name, settings) = row.context("原則不存在")?;
    Ok((
        name,
        serde_json::from_str(&settings).context("原則設定無法解析")?,
    ))
}

/// 寫入原則的群組；群組已屬於其他原則時回錯誤（寫出是哪個原則）
async fn set_groups(conn: &mut PgConnection, id: i64, groups: &[i64]) -> anyhow::Result<()> {
    // 依 id 順序鎖住群組列：同時加入同一群組的另一個交易會等這邊完成後再檢查
    // （錯誤訊息才能寫出原則名稱），固定順序也避免死結。groups 已排序。
    // 用 NO KEY UPDATE：不擋裝置、金鑰寫入時外鍵檢查的 KEY SHARE 鎖。
    sqlx::query("SELECT id FROM device_groups WHERE id = ANY($1) ORDER BY id FOR NO KEY UPDATE")
        .bind(groups)
        .execute(&mut *conn)
        .await?;
    let taken: Option<(String, String)> = sqlx::query_as(
        "SELECT g.name, p.name FROM update_policy_groups x \
         JOIN device_groups g ON g.id = x.group_id JOIN update_policies p ON p.id = x.policy_id \
         WHERE x.group_id = ANY($1) AND x.policy_id <> $2 ORDER BY g.name LIMIT 1",
    )
    .bind(groups)
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((group, policy)) = taken {
        bail!("群組「{group}」已屬於原則「{policy}」");
    }
    sqlx::query("DELETE FROM update_policy_groups WHERE policy_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO update_policy_groups (group_id, policy_id) SELECT g, $2 FROM UNNEST($1::bigint[]) g",
    )
    .bind(groups)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => {
            anyhow::anyhow!("群組不存在")
        }
        // 檢查後有人同時把群組加進別的原則
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            anyhow::anyhow!("群組已屬於其他原則，請重新整理後再試")
        }
        _ => e.into(),
    })?;
    Ok(())
}

fn name_taken(e: sqlx::Error) -> anyhow::Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => anyhow::anyhow!("原則名稱已存在"),
        _ => e.into(),
    }
}

pub async fn create_policy(pool: &PgPool, i: &PolicyInput, actor: &str) -> anyhow::Result<i64> {
    let v = validate(i)?;
    let settings = PolicySettings {
        quality_pause_start: None,
        feature_pause_start: None,
        ..i.settings.clone()
    };
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO update_policies (name, settings, created_by) VALUES ($1, $2::jsonb, $3) \
         RETURNING id",
    )
    .bind(&v.name)
    .bind(serde_json::to_string(&settings)?)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(name_taken)?;
    set_groups(&mut tx, id, &v.groups).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "update_policy_create",
        Some(&v.name),
        json!({"id": id, "settings": settings, "groups": v.groups}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_policy(
    pool: &PgPool,
    id: i64,
    i: &PolicyInput,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (_, old) = lock_policy(&mut tx, id).await?;
    let v = validate(i)?;
    let settings = PolicySettings {
        quality_pause_start: old.quality_pause_start,
        feature_pause_start: old.feature_pause_start,
        ..i.settings.clone()
    };
    sqlx::query(
        "UPDATE update_policies SET name = $2, settings = $3::jsonb, revision = revision + 1, \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&v.name)
    .bind(serde_json::to_string(&settings)?)
    .execute(&mut *tx)
    .await
    .map_err(name_taken)?;
    set_groups(&mut tx, id, &v.groups).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "update_policy_update",
        Some(&v.name),
        json!({"id": id, "settings": settings, "groups": v.groups}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `start` 為 None 表示恢復
pub async fn set_pause(
    pool: &PgPool,
    id: i64,
    kind: PauseKind,
    start: Option<NaiveDate>,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, mut settings) = lock_policy(&mut tx, id).await?;
    match kind {
        PauseKind::Quality => settings.quality_pause_start = start,
        PauseKind::Feature => settings.feature_pause_start = start,
    }
    sqlx::query(
        "UPDATE update_policies SET settings = $2::jsonb, revision = revision + 1, \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(serde_json::to_string(&settings)?)
    .execute(&mut *tx)
    .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        if start.is_some() {
            "update_policy_pause"
        } else {
            "update_policy_resume"
        },
        Some(&name),
        json!({
            "id": id,
            "kind": match kind { PauseKind::Quality => "quality", PauseKind::Feature => "feature" },
            "start": start,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_policy(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, _) = lock_policy(&mut tx, id).await?;
    sqlx::query("DELETE FROM update_policies WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "update_policy_delete",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
