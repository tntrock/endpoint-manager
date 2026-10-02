//! 更新原則的管理（平台管理員）：驗證、CRUD、暫停、稽核。

use anyhow::{bail, ensure};
use chrono::NaiveDate;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use super::policy::{PAUSE_DAYS, PolicySettings};
use crate::audit;
use crate::commands::CmdError;

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

/// 鎖住原則列並回傳 (名稱, 設定, revision)；設定無法解析（被手動改壞）時為 None
async fn lock_policy(
    conn: &mut PgConnection,
    id: i64,
) -> anyhow::Result<(String, Option<PolicySettings>, i32)> {
    let row: Option<(String, String, i32)> = sqlx::query_as(
        "SELECT name, settings::text, revision FROM update_policies WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let (name, settings, revision) =
        row.ok_or_else(|| anyhow::Error::from(CmdError::NotFound("原則不存在".into())))?;
    let parsed = serde_json::from_str(&settings)
        .map_err(|e| tracing::error!(policy_id = id, error = %e, "更新原則設定無法解析"))
        .ok();
    Ok((name, parsed, revision))
}

async fn groups_of(conn: &mut PgConnection, id: i64) -> Result<Vec<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT group_id FROM update_policy_groups WHERE policy_id = $1 ORDER BY group_id",
    )
    .bind(id)
    .fetch_all(conn)
    .await
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

/// `expected_revision`：表單開啟時的 revision；之後有人改過（含暫停／恢復）就回 409
pub async fn update_policy(
    pool: &PgPool,
    id: i64,
    i: &PolicyInput,
    expected_revision: Option<i32>,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (old_name, old, revision) = lock_policy(&mut tx, id).await?;
    if expected_revision.is_some_and(|r| r != revision) {
        return Err(CmdError::Conflict("原則已被其他人修改，請重新整理後再編輯".into()).into());
    }
    let v = validate(i)?;
    // 設定無法解析時以表單內容整個取代（暫停日一併清除）
    let old = old.unwrap_or_default();
    let old_groups = groups_of(&mut tx, id).await?;
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
        json!({
            "id": id, "settings": settings, "groups": v.groups,
            "old": {"name": old_name, "settings": old, "groups": old_groups},
        }),
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
    // Windows 從暫停開始日起算 35 天自動恢復：太舊的日期等於沒暫停，未來的日期行為不確定
    if let Some(d) = start {
        let today = chrono::Utc::now().date_naive();
        if d < today - chrono::Duration::days(PAUSE_DAYS) || d > today + chrono::Duration::days(1) {
            return Err(CmdError::Invalid(format!("暫停日期必須是最近 {PAUSE_DAYS} 天內")).into());
        }
    }
    let mut tx = pool.begin().await?;
    let (name, settings, _) = lock_policy(&mut tx, id).await?;
    let mut settings = settings.ok_or_else(|| {
        anyhow::Error::from(CmdError::Invalid(
            "原則設定無法解析，請先編輯原則重新儲存".into(),
        ))
    })?;
    let slot = match kind {
        PauseKind::Quality => &mut settings.quality_pause_start,
        PauseKind::Feature => &mut settings.feature_pause_start,
    };
    let old_start = std::mem::replace(slot, start);
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
            "old_start": old_start,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_policy(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, settings, _) = lock_policy(&mut tx, id).await?;
    let groups = groups_of(&mut tx, id).await?;
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
        json!({"id": id, "settings": settings, "groups": groups}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
