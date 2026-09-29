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
    // 群組影響規則的套用範圍
    crate::compliance::store::refresh_device_fresh(&mut tx, device_id).await?;
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

/// 群組的使用情形：有效裝置（未除役）、有效金鑰（未作廢、未過期、未用完）、被指派的管理員
/// （含停用中的，重新啟用時才不會沒有群組）、引用它的合規規則。群組頁與刪除檢查共用這個定義。
pub async fn usage(conn: &mut PgConnection, id: i64) -> Result<(i64, i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM devices WHERE group_id = $1 AND status <> 'retired'),                 (SELECT count(*) FROM enroll_tokens WHERE group_id = $1                    AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())                    AND used_count < max_uses),                 (SELECT count(*) FROM admin_groups WHERE group_id = $1),                 (SELECT count(DISTINCT rule_id) FROM compliance_rule_groups WHERE group_id = $1)",
    )
    .bind(id)
    .fetch_one(conn)
    .await
}

/// 還有有效裝置、有效金鑰、被指派的管理員（管理員可能因此沒有任何群組）或被合規規則引用時
/// 不能刪除。
/// 已除役的裝置與失效的金鑰改為未分組。
pub async fn delete(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    // 鎖住群組列，避免檢查後又有人把裝置、金鑰或管理員加進來
    sqlx::query("SELECT id FROM device_groups WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| anyhow::anyhow!("群組不存在"))?;
    let (devices, tokens, admins, rules) = usage(&mut tx, id).await?;
    anyhow::ensure!(
        devices == 0 && tokens == 0 && admins == 0 && rules == 0,
        "群組內還有 {devices} 台裝置、{tokens} 把有效金鑰、{admins} 位管理員，\
         並被 {rules} 條規則引用，無法刪除"
    );
    let mut ungrouped = vec![];
    for sql in [
        "UPDATE devices SET group_id = NULL WHERE group_id = $1",
        "UPDATE enroll_tokens SET group_id = NULL WHERE group_id = $1",
    ] {
        ungrouped.push(
            sqlx::query(sql)
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected(),
        );
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
        serde_json::json!({
            "id": id, "ungrouped_devices": ungrouped[0], "ungrouped_tokens": ungrouped[1]
        }),
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

    /// 被規則引用的群組不能刪除：否則「只套用」清單變空，規則會默默套用到全部裝置
    #[sqlx::test(migrations = false)]
    async fn group_referenced_by_rule_cannot_be_deleted(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let g = find_or_create(&mut c, "資訊亭").await.unwrap();
        let rule: i64 = sqlx::query_scalar(
            "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
             VALUES ('r', 'required_kb', 'high', '{\"kb\":\"KB5034439\"}', 't') RETURNING id",
        )
        .fetch_one(&mut *c)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, 'include')",
        )
        .bind(rule)
        .bind(g)
        .execute(&mut *c)
        .await
        .unwrap();
        assert_eq!(usage(&mut c, g).await.unwrap().3, 1);
        drop(c);
        let err = delete(&pool, g, "t").await.unwrap_err();
        assert!(
            format!("{err:#}").contains("位管理員，並被 1 條規則"),
            "{err:#}"
        );
    }
}
