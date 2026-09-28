//! 裝置群組：分權的單位。

use sqlx::{PgConnection, PgPool};

pub async fn find_or_create(conn: &mut PgConnection, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO device_groups (name) VALUES ($1) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(conn)
    .await
}

pub async fn move_device(
    pool: &PgPool,
    device_id: uuid::Uuid,
    group_id: Option<i64>,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE devices SET group_id = $2 WHERE id = $1")
        .bind(device_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    anyhow::ensure!(n == 1, "device not found");
    crate::audit::record(
        &mut tx,
        actor,
        "device_move",
        Some(&device_id.to_string()),
        serde_json::json!({ "group_id": group_id }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn create(pool: &PgPool, name: &str, actor: &str) -> anyhow::Result<i64> {
    let name = name.trim();
    anyhow::ensure!(
        !name.is_empty() && name.chars().count() <= 100,
        "群組名稱必填，最多 100 字"
    );
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar("INSERT INTO device_groups (name) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| anyhow::anyhow!("群組名稱已存在"))?;
    crate::audit::record(
        &mut tx,
        actor,
        "group_create",
        Some(name),
        serde_json::json!({ "id": id }),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// 群組內「仍有效」的裝置與金鑰（與群組頁面顯示的數字相同）。
pub const ACTIVE_DEVICES: &str =
    "SELECT count(*) FROM devices WHERE group_id = $1 AND status <> 'retired'";
pub const ACTIVE_TOKENS: &str = "SELECT count(*) FROM enroll_tokens WHERE group_id = $1 \
     AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) \
     AND used_count < max_uses";

/// 還有有效裝置、有效金鑰或被指派的管理員時不能刪除（管理員可能因此沒有任何群組）。
/// 已除役的裝置與失效的金鑰改為未分組。
pub async fn delete(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    // 鎖住群組列，避免檢查後又有人把裝置、金鑰或管理員加進來
    sqlx::query("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("群組不存在"))?;
    let count = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql).bind(id);
    let devices = count(ACTIVE_DEVICES).fetch_one(&mut *tx).await?;
    let tokens = count(ACTIVE_TOKENS).fetch_one(&mut *tx).await?;
    let admins = count("SELECT count(*) FROM admin_groups WHERE group_id = $1")
        .fetch_one(&mut *tx)
        .await?;
    anyhow::ensure!(
        devices == 0 && tokens == 0 && admins == 0,
        "群組內還有 {devices} 台裝置、{tokens} 把有效金鑰、{admins} 位管理員，無法刪除"
    );
    for sql in [
        "UPDATE devices SET group_id = NULL WHERE group_id = $1",
        "UPDATE enroll_tokens SET group_id = NULL WHERE group_id = $1",
    ] {
        sqlx::query(sql).bind(id).execute(&mut *tx).await?;
    }
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM device_groups WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let name = name.ok_or_else(|| anyhow::anyhow!("群組不存在"))?;
    crate::audit::record(
        &mut tx,
        actor,
        "group_delete",
        Some(&name),
        serde_json::json!({ "id": id }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = false)]
    async fn find_or_create_is_idempotent(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let a = find_or_create(&mut c, "高雄廠").await.unwrap();
        let b = find_or_create(&mut c, "高雄廠").await.unwrap();
        assert_eq!(a, b);
    }
}
