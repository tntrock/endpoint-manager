//! 分點快取的管理（平台管理員）：核准、拒絕、停用／啟用、指定據點、刪除。
//! 會影響報到下發 package_source 的異動都推進 branch_state.generation。

use anyhow::{Context, bail, ensure};
use chrono::Utc;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::ca::{Ca, IssuedCert};

async fn bump(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE branch_state SET generation = generation + 1")
        .execute(conn)
        .await?;
    Ok(())
}

/// 鎖住快取列並回傳 (名稱, 狀態)
async fn lock_cache(conn: &mut PgConnection, id: i64) -> anyhow::Result<(String, String)> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, status FROM caches WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    row.context("快取不存在")
}

pub async fn insert_cert(
    conn: &mut PgConnection,
    cache_id: i64,
    c: &IssuedCert,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO cache_certs (serial, fingerprint, cache_id, not_after, pem) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&c.serial)
    .bind(&c.fingerprint)
    .bind(cache_id)
    .bind(c.not_after)
    .bind(&c.pem)
    .execute(conn)
    .await?;
    Ok(())
}

/// 用註冊時存下的 CSR 與名稱簽發新憑證
async fn issue(conn: &mut PgConnection, ca: &Ca, id: i64) -> anyhow::Result<()> {
    let (csr, dns): (String, Vec<String>) =
        sqlx::query_as("SELECT csr_pem, dns_names FROM caches WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    let cert = ca.sign_cache_csr(&csr, id, &dns, Utc::now())?;
    insert_cert(conn, id, &cert).await?;
    Ok(())
}

/// 據點不存在或已有其他快取時回錯誤
async fn set_site(conn: &mut PgConnection, id: i64, site_id: Option<i64>) -> anyhow::Result<()> {
    sqlx::query("UPDATE caches SET site_id = $2 WHERE id = $1")
        .bind(id)
        .bind(site_id)
        .execute(conn)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => {
                anyhow::anyhow!("據點不存在")
            }
            sqlx::Error::Database(d) if d.is_unique_violation() => {
                anyhow::anyhow!("據點已有其他快取")
            }
            _ => e.into(),
        })?;
    Ok(())
}

pub async fn approve(
    pool: &PgPool,
    ca: &Ca,
    id: i64,
    site_id: i64,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, status) = lock_cache(&mut tx, id).await?;
    ensure!(status == "pending", "只能核准待核准的快取");
    set_site(&mut tx, id, Some(site_id)).await?;
    issue(&mut tx, ca, id).await?;
    sqlx::query("UPDATE caches SET status = 'active' WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "cache_approve",
        Some(&name),
        json!({"id": id, "site_id": site_id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn reject(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, status) = lock_cache(&mut tx, id).await?;
    ensure!(status == "pending", "只能拒絕待核准的快取");
    sqlx::query("UPDATE caches SET status = 'rejected' WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        actor,
        "cache_reject",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 停用時撤銷所有憑證；啟用時用存下的 CSR 簽發新憑證（快取的 mTLS 被拒後改用輪詢取得）
pub async fn set_disabled(
    pool: &PgPool,
    ca: &Ca,
    id: i64,
    disabled: bool,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, status) = lock_cache(&mut tx, id).await?;
    let action = match (disabled, status.as_str()) {
        (true, "active") => {
            sqlx::query(
                "UPDATE cache_certs SET revoked_at = now() WHERE cache_id = $1 AND revoked_at IS NULL",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            "cache_disable"
        }
        (false, "disabled") => {
            issue(&mut tx, ca, id).await?;
            "cache_enable"
        }
        (true, _) => bail!("只能停用使用中的快取"),
        (false, _) => bail!("只能啟用已停用的快取"),
    };
    sqlx::query("UPDATE caches SET status = $2 WHERE id = $1")
        .bind(id)
        .bind(if disabled { "disabled" } else { "active" })
        .execute(&mut *tx)
        .await?;
    bump(&mut tx).await?;
    audit::record(&mut tx, actor, action, Some(&name), json!({"id": id})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn assign_site(
    pool: &PgPool,
    id: i64,
    site_id: Option<i64>,
    actor: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, status) = lock_cache(&mut tx, id).await?;
    ensure!(
        matches!(status.as_str(), "active" | "disabled"),
        "待核准或已拒絕的快取請用核准"
    );
    set_site(&mut tx, id, site_id).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "cache_assign_site",
        Some(&name),
        json!({"id": id, "site_id": site_id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_cache(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (name, _) = lock_cache(&mut tx, id).await?;
    sqlx::query("DELETE FROM caches WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "cache_delete",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
