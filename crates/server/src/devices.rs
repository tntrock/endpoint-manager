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

/// 核准待核准的重新註冊：新憑證接手舊裝置記錄，新記錄刪除。回傳保留下來的裝置 id。
/// 原裝置在待核准期間已被除役（或已不存在）時不讓它復活，改為讓新記錄成為獨立裝置
/// ——拒絕會撤銷這台電腦可用的憑證，只能重新註冊。
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
    let old_status: Option<String> = match old {
        Some(old) => {
            sqlx::query_scalar("SELECT status FROM devices WHERE id = $1 FOR UPDATE")
                .bind(old)
                .fetch_optional(&mut *conn)
                .await?
        }
        None => None,
    };
    let old = match old {
        Some(old) if matches!(old_status.as_deref(), Some("active" | "duplicate_suspect")) => old,
        _ => {
            sqlx::query("UPDATE devices SET status = 'active', reenroll_of = NULL WHERE id = $1")
                .bind(pending)
                .execute(&mut *conn)
                .await?;
            audit::record(
                conn,
                actor,
                "device_approve",
                Some(&pending.to_string()),
                serde_json::json!({
                    "hostname": hostname, "standalone": true,
                    "original": old, "original_status": old_status
                }),
            )
            .await?;
            return Ok(pending);
        }
    };

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
