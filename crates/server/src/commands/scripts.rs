//! 腳本管理（平台管理員）：新增、修改、核准、停用／啟用、刪除；雙人核准設定。

use anyhow::{Context, bail, ensure};
use protocol::command::MAX_SCRIPT_BYTES;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};

use super::Actor;
use crate::audit;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_DESCRIPTION_LEN: usize = 1000;
const SETTING: &str = "scripts_require_second_approver";

#[derive(Debug, Clone)]
pub struct ScriptInput {
    pub name: String,
    pub description: String,
    pub content: String,
    pub timeout_minutes: i32,
}

struct Valid {
    name: String,
    description: String,
    sha256: String,
}

fn platform(actor: &Actor) -> anyhow::Result<()> {
    ensure!(actor.platform, "只有平台管理員能管理腳本");
    Ok(())
}

fn validate(i: &ScriptInput) -> anyhow::Result<Valid> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "腳本名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "腳本名稱不能包含控制字元"
    );
    let description = i.description.trim().to_string();
    ensure!(
        description.chars().count() <= MAX_DESCRIPTION_LEN,
        "說明最多 {MAX_DESCRIPTION_LEN} 字"
    );
    ensure!(
        !i.content.is_empty() && i.content.len() <= MAX_SCRIPT_BYTES,
        "腳本內容必填，最多 {} KiB",
        MAX_SCRIPT_BYTES / 1024
    );
    ensure!(!i.content.contains('\0'), "腳本內容不能包含 NUL 字元");
    ensure!(
        (1..=120).contains(&i.timeout_minutes),
        "逾時必須是 1–120 分鐘"
    );
    Ok(Valid {
        name,
        description,
        sha256: hex::encode(Sha256::digest(i.content.as_bytes())),
    })
}

/// 讀不到或被改壞時回 true（比較安全的預設）
pub async fn require_second_approver(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let v: Option<Option<String>> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM settings WHERE key = $1")
            .bind(SETTING)
            .fetch_optional(pool)
            .await?;
    Ok(v.flatten().as_deref() != Some("false"))
}

pub async fn set_require_second_approver(
    pool: &PgPool,
    on: bool,
    actor: &Actor,
) -> anyhow::Result<()> {
    platform(actor)?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(SETTING)
    .bind(on.to_string())
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &actor.username,
        "setting_scripts_second_approver",
        None,
        json!({ "on": on }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn name_taken(e: sqlx::Error) -> anyhow::Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => anyhow::anyhow!("腳本名稱已存在"),
        _ => e.into(),
    }
}

/// 內容變更後的狀態：需要雙人核准時待核准，否則由修改者直接核准
fn status_after_change(second: bool) -> &'static str {
    if second { "pending" } else { "approved" }
}

pub async fn create_script(pool: &PgPool, i: &ScriptInput, actor: &Actor) -> anyhow::Result<i64> {
    platform(actor)?;
    let v = validate(i)?;
    let status = status_after_change(require_second_approver(pool).await?);
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO scripts (name, description, content, sha256, timeout_minutes, status, \
           created_by, updated_by, approved_by, approved_at, editors) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, \
           CASE WHEN $6 = 'approved' THEN $7 END, CASE WHEN $6 = 'approved' THEN now() END, \
           ARRAY[$7]) \
         RETURNING id",
    )
    .bind(&v.name)
    .bind(&v.description)
    .bind(&i.content)
    .bind(&v.sha256)
    .bind(i.timeout_minutes)
    .bind(status)
    .bind(&actor.username)
    .fetch_one(&mut *tx)
    .await
    .map_err(name_taken)?;
    audit::record(
        &mut tx,
        &actor.username,
        "script_create",
        Some(&v.name),
        json!({"id": id, "sha256": v.sha256, "status": status}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

struct Locked {
    name: String,
    sha256: String,
    timeout: i32,
    status: String,
    approved_by: Option<String>,
    /// 上次核准後修改過內容或逾時的人
    editors: Vec<String>,
}

/// 雙人核准下，這份核准是否真的由另一個人檢視（核准者不是任何一位修改者；
/// 切換模式前自己核准的不算）
pub fn approval_is_independent(approved_by: Option<&str>, editors: &[String]) -> bool {
    approved_by.is_some_and(|a| !editors.iter().any(|e| e == a))
}

async fn lock(conn: &mut PgConnection, id: i64) -> anyhow::Result<Locked> {
    type Row = (String, String, i32, String, Option<String>, Vec<String>);
    let row: Option<Row> = sqlx::query_as(
        "SELECT name, sha256, timeout_minutes, status, approved_by, editors FROM scripts \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let (name, sha256, timeout, status, approved_by, editors) = row.context("腳本不存在")?;
    Ok(Locked {
        name,
        sha256,
        timeout,
        status,
        approved_by,
        editors,
    })
}

pub async fn update_script(
    pool: &PgPool,
    id: i64,
    i: &ScriptInput,
    actor: &Actor,
) -> anyhow::Result<()> {
    platform(actor)?;
    let v = validate(i)?;
    let second = require_second_approver(pool).await?;
    let mut tx = pool.begin().await?;
    let old = lock(&mut tx, id).await?;
    let changed = old.sha256 != v.sha256 || old.timeout != i.timeout_minutes;
    if changed {
        ensure!(old.status != "disabled", "腳本已停用，請先啟用");
        let status = status_after_change(second);
        // 修改者清單：上次核准後重新開始，之後每位修改者都加進去
        sqlx::query(
            "UPDATE scripts SET name = $2, description = $3, content = $4, sha256 = $5, \
               timeout_minutes = $6, status = $7, updated_by = $8, updated_at = now(), \
               approved_by = CASE WHEN $7 = 'approved' THEN $8 END, \
               approved_at = CASE WHEN $7 = 'approved' THEN now() END, \
               editors = CASE WHEN status = 'approved' OR $7 = 'approved' THEN ARRAY[$8] \
                              WHEN $8 = ANY(editors) THEN editors \
                              ELSE array_append(editors, $8) END \
             WHERE id = $1",
        )
        .bind(id)
        .bind(&v.name)
        .bind(&v.description)
        .bind(&i.content)
        .bind(&v.sha256)
        .bind(i.timeout_minutes)
        .bind(status)
        .bind(&actor.username)
        .execute(&mut *tx)
        .await
        .map_err(name_taken)?;
    } else {
        // 只改名稱或說明：不影響核准，也不算修改內容
        sqlx::query("UPDATE scripts SET name = $2, description = $3 WHERE id = $1")
            .bind(id)
            .bind(&v.name)
            .bind(&v.description)
            .execute(&mut *tx)
            .await
            .map_err(name_taken)?;
    }
    audit::record(
        &mut tx,
        &actor.username,
        "script_update",
        Some(&v.name),
        json!({"id": id, "sha256": v.sha256, "content_changed": changed}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// `expected_sha256` 是核准者檢視時看到的內容雜湊：內容在那之後被改過就不核准
pub async fn approve_script(
    pool: &PgPool,
    id: i64,
    expected_sha256: &str,
    actor: &Actor,
) -> anyhow::Result<()> {
    platform(actor)?;
    let second = require_second_approver(pool).await?;
    let mut tx = pool.begin().await?;
    let s = lock(&mut tx, id).await?;
    let (name, sha) = (s.name.clone(), s.sha256.clone());
    ensure!(
        sha == expected_sha256.to_ascii_lowercase(),
        "腳本內容已變更，請重新檢視後再核准"
    );
    // 雙人核准下，自己核准過的（例如單人模式時）可以由另一位重新核准
    let reapprove = second
        && s.status == "approved"
        && !approval_is_independent(s.approved_by.as_deref(), &s.editors);
    ensure!(
        s.status == "pending" || reapprove,
        "只有待核准的腳本可以核准"
    );
    ensure!(
        !second || !s.editors.contains(&actor.username),
        "不能核准自己修改的腳本，請由另一位平台管理員核准"
    );
    sqlx::query(
        "UPDATE scripts SET status = 'approved', approved_by = $2, approved_at = now() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(&actor.username)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &actor.username,
        "script_approve",
        Some(&name),
        json!({"id": id, "sha256": sha}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_disabled(
    pool: &PgPool,
    id: i64,
    disabled: bool,
    actor: &Actor,
) -> anyhow::Result<()> {
    platform(actor)?;
    let second = require_second_approver(pool).await?;
    let mut tx = pool.begin().await?;
    let s = lock(&mut tx, id).await?;
    let (name, sha) = (s.name, s.sha256);
    let new_status = if disabled {
        ensure!(s.status != "disabled", "腳本已停用");
        "disabled"
    } else {
        ensure!(s.status == "disabled", "腳本沒有停用");
        status_after_change(second)
    };
    sqlx::query(
        "UPDATE scripts SET status = $2, \
           approved_by = CASE WHEN $2 = 'approved' THEN $3 WHEN $2 = 'pending' THEN NULL \
                              ELSE approved_by END, \
           approved_at = CASE WHEN $2 = 'approved' THEN now() WHEN $2 = 'pending' THEN NULL \
                              ELSE approved_at END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(new_status)
    .bind(&actor.username)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        &actor.username,
        if disabled {
            "script_disable"
        } else {
            "script_enable"
        },
        Some(&name),
        json!({"id": id, "sha256": sha, "status": new_status}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_script(pool: &PgPool, id: i64, actor: &Actor) -> anyhow::Result<()> {
    platform(actor)?;
    let mut tx = pool.begin().await?;
    let s = lock(&mut tx, id).await?;
    let (name, sha) = (s.name, s.sha256);
    let used: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM command_runs WHERE script_id = $1)")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if used {
        bail!("腳本已被指令使用，只能停用");
    }
    sqlx::query("DELETE FROM scripts WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => {
                anyhow::anyhow!("腳本已被指令使用，只能停用")
            }
            _ => e.into(),
        })?;
    audit::record(
        &mut tx,
        &actor.username,
        "script_delete",
        Some(&name),
        json!({"id": id, "sha256": sha}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
