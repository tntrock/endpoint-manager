//! 裝置生命週期：核准／拒絕重新註冊、除役。每個動作都寫入 audit_log。
//! 權限（角色、群組範圍）由網頁層檢查。

use anyhow::Context;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::audit;

async fn revoke_certs(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_certs SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(conn)
    .await?;
    Ok(())
}

/// 核准待核准的重新註冊：新憑證接手舊裝置記錄，新記錄刪除。回傳舊裝置 id。
pub async fn approve_in(
    conn: &mut PgConnection,
    pending: Uuid,
    actor: &str,
) -> anyhow::Result<Uuid> {
    let (old, hostname): (Option<Uuid>, String) = sqlx::query_as(
        "SELECT reenroll_of, hostname FROM devices \
         WHERE id = $1 AND status = 'pending_approval' FOR UPDATE",
    )
    .bind(pending)
    .fetch_optional(&mut *conn)
    .await?
    .context("device is not pending approval")?;
    let old = old.context("pending device has no original device")?;
    // 待核准期間原裝置可能已被除役：不可讓它復活
    let old_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM devices WHERE id = $1 FOR UPDATE")
            .bind(old)
            .fetch_optional(&mut *conn)
            .await?;
    anyhow::ensure!(
        matches!(old_status.as_deref(), Some("active" | "duplicate_suspect")),
        "原裝置已除役或不存在，請拒絕這筆重新註冊"
    );

    revoke_certs(conn, old).await?;
    sqlx::query("UPDATE device_certs SET device_id = $1 WHERE device_id = $2")
        .bind(old)
        .bind(pending)
        .execute(&mut *conn)
        .await?;
    // 清空（不刪除）舊裝置的區段 hash：Agent 下次報到時伺服器會要求重新上傳全部區段，
    // 而舊資料仍是比對基準，重灌前後的差異會記入變更歷史
    sqlx::query("UPDATE inventory_sections SET hash = '' WHERE device_id = $1")
        .bind(old)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE devices SET status = 'active', hostname = $2 WHERE id = $1")
        .bind(old)
        .bind(&hostname)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM devices WHERE id = $1")
        .bind(pending)
        .execute(&mut *conn)
        .await?;
    // 變更歷史是分割資料表、沒有外鍵，要自己刪
    sqlx::query("DELETE FROM inventory_changes WHERE device_id = $1")
        .bind(pending)
        .execute(&mut *conn)
        .await?;
    audit::record(
        conn,
        actor,
        "device_approve",
        Some(&old.to_string()),
        serde_json::json!({ "pending_id": pending, "hostname": hostname }),
    )
    .await?;
    Ok(old)
}

pub async fn approve(pool: &PgPool, pending: Uuid, actor: &str) -> anyhow::Result<Uuid> {
    let mut tx = pool.begin().await?;
    let old = approve_in(&mut tx, pending, actor).await?;
    tx.commit().await?;
    Ok(old)
}

pub async fn reject(pool: &PgPool, pending: Uuid, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE devices SET status = 'retired' WHERE id = $1 AND status = 'pending_approval'",
    )
    .bind(pending)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(n == 1, "device is not pending approval");
    revoke_certs(&mut tx, pending).await?;
    audit::record(
        &mut tx,
        actor,
        "device_reject",
        Some(&pending.to_string()),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn retire(pool: &PgPool, id: Uuid, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n =
        sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1 AND status <> 'retired'")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    anyhow::ensure!(n == 1, "device not found or already retired");
    revoke_certs(&mut tx, id).await?;
    audit::record(
        &mut tx,
        actor,
        "device_retire",
        Some(&id.to_string()),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
