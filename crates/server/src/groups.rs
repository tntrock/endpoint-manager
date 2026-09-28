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

/// 只能刪除沒有裝置與金鑰的群組；指派給管理員的關聯會一併移除。
pub async fn delete(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (devices, tokens): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM devices WHERE group_id = $1), \
                (SELECT count(*) FROM enroll_tokens WHERE group_id = $1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    anyhow::ensure!(
        devices == 0 && tokens == 0,
        "群組內還有 {devices} 台裝置、{tokens} 把金鑰，無法刪除"
    );
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
