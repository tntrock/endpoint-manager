//! 管理員兩步驟驗證（TOTP）：設定、停用、復原碼、重設與「必須使用」的系統設定。

use anyhow::Context;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::totp;

const REQUIRED_KEY: &str = "mfa_required";
pub const ISSUER: &str = "Endpoint Manager";

/// 使用者看得懂的錯誤（重新顯示表單）
#[derive(Debug, thiserror::Error)]
pub enum MfaError {
    #[error("驗證碼不正確")]
    BadCode,
    #[error("尚未啟用兩步驟驗證")]
    NotEnabled,
    #[error("已經啟用兩步驟驗證")]
    AlreadyEnabled,
    #[error("系統要求所有帳號使用兩步驟驗證，不能停用")]
    Required,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// 驗證成功的方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Totp,
    Recovery,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Totp => "totp",
            Method::Recovery => "recovery",
        }
    }
}

/// 讀不到或被改壞時視為關閉（預設值）
pub async fn required(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let v: Option<Option<String>> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM settings WHERE key = $1")
            .bind(REQUIRED_KEY)
            .fetch_optional(pool)
            .await?;
    Ok(v.flatten().as_deref() == Some("true"))
}

pub async fn set_required(pool: &PgPool, on: bool, actor: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let old: Option<Option<String>> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM settings WHERE key = $1 FOR UPDATE")
            .bind(REQUIRED_KEY)
            .fetch_optional(&mut *tx)
            .await?;
    let old = old.flatten().as_deref() == Some("true");
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(REQUIRED_KEY)
    .bind(on.to_string())
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        actor,
        "mfa_required_changed",
        None,
        json!({ "on": on, "old": old }),
    )
    .await?;
    tx.commit().await
}

pub struct Status {
    pub enabled_at: Option<time::OffsetDateTime>,
    pub recovery_left: i64,
}

pub async fn status(pool: &PgPool, admin_id: i64) -> Result<Status, sqlx::Error> {
    let (enabled_at, recovery_left) = sqlx::query_as(
        "SELECT a.mfa_enabled_at, \
                (SELECT count(*) FROM admin_recovery_codes r \
                 WHERE r.admin_id = a.id AND r.used_at IS NULL) \
         FROM admins a WHERE a.id = $1",
    )
    .bind(admin_id)
    .fetch_one(pool)
    .await?;
    Ok(Status {
        enabled_at,
        recovery_left,
    })
}

/// 設定中的金鑰：沒有就產生一把。重新整理頁面沿用同一把，掃過的 QR code 才不會失效
pub async fn pending_secret(pool: &PgPool, admin_id: i64) -> Result<String, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE admins SET mfa_pending_secret = coalesce(mfa_pending_secret, $2) \
         WHERE id = $1 RETURNING mfa_pending_secret",
    )
    .bind(admin_id)
    .bind(totp::new_secret())
    .fetch_one(pool)
    .await
}

fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// 用驗證碼或復原碼驗證。成功時更新最後使用的時間步，或把復原碼標成已用。
/// 呼叫端須已鎖住該帳號的列（FOR UPDATE）。
pub(crate) async fn check_code(
    conn: &mut PgConnection,
    admin_id: i64,
    secret_b32: &str,
    last_step: Option<i64>,
    code: &str,
) -> Result<Option<Method>, sqlx::Error> {
    if totp::looks_like_recovery(code) {
        let used: Option<i64> = sqlx::query_scalar(
            "UPDATE admin_recovery_codes SET used_at = now() \
             WHERE admin_id = $1 AND code_hash = $2 AND used_at IS NULL RETURNING admin_id",
        )
        .bind(admin_id)
        .bind(totp::recovery_hash(code))
        .fetch_optional(&mut *conn)
        .await?;
        return Ok(used.map(|_| Method::Recovery));
    }
    let Some(secret) = totp::base32_decode(secret_b32) else {
        return Ok(None);
    };
    let Some(step) = totp::verify(&secret, code, now_secs(), last_step) else {
        return Ok(None);
    };
    sqlx::query("UPDATE admins SET mfa_last_step = $2 WHERE id = $1")
        .bind(admin_id)
        .bind(step)
        .execute(&mut *conn)
        .await?;
    Ok(Some(Method::Totp))
}

/// 產生新的復原碼（作廢舊的），回傳明文，只顯示這一次
async fn replace_recovery_codes(
    conn: &mut PgConnection,
    admin_id: i64,
) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query("DELETE FROM admin_recovery_codes WHERE admin_id = $1")
        .bind(admin_id)
        .execute(&mut *conn)
        .await?;
    let mut codes = Vec::with_capacity(totp::RECOVERY_CODES);
    while codes.len() < totp::RECOVERY_CODES {
        let c = totp::new_recovery_code();
        if !codes.contains(&c) {
            codes.push(c);
        }
    }
    let hashes: Vec<String> = codes.iter().map(|c| totp::recovery_hash(c)).collect();
    sqlx::query(
        "INSERT INTO admin_recovery_codes (admin_id, code_hash) SELECT $1, unnest($2::text[])",
    )
    .bind(admin_id)
    .bind(&hashes)
    .execute(&mut *conn)
    .await?;
    Ok(codes)
}

/// 登出這個帳號的其他工作階段，`keep` 這個升級成一般工作階段
async fn other_sessions_out(
    conn: &mut PgConnection,
    admin_id: i64,
    keep: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1 AND token_hash <> $2")
        .bind(admin_id)
        .bind(keep)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE sessions SET setup_only = false WHERE token_hash = $1")
        .bind(keep)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

type MfaRow = (String, Option<String>, Option<String>, Option<i64>);

async fn lock_admin(conn: &mut PgConnection, admin_id: i64) -> Result<MfaRow, sqlx::Error> {
    sqlx::query_as(
        "SELECT username, mfa_secret, mfa_pending_secret, mfa_last_step \
         FROM admins WHERE id = $1 FOR UPDATE",
    )
    .bind(admin_id)
    .fetch_one(conn)
    .await
}

/// 以設定中的金鑰確認驗證碼後啟用。回傳復原碼
pub async fn enable(
    pool: &PgPool,
    admin_id: i64,
    code: &str,
    keep_session: &str,
) -> Result<Vec<String>, MfaError> {
    let mut tx = pool.begin().await?;
    let (username, secret, pending, _) = lock_admin(&mut tx, admin_id).await?;
    if secret.is_some() {
        return Err(MfaError::AlreadyEnabled);
    }
    let pending = pending.ok_or(MfaError::BadCode)?;
    let step = totp::base32_decode(&pending)
        .and_then(|k| totp::verify(&k, code, now_secs(), None))
        .ok_or(MfaError::BadCode)?;
    sqlx::query(
        "UPDATE admins SET mfa_secret = mfa_pending_secret, mfa_pending_secret = NULL, \
                mfa_enabled_at = now(), mfa_last_step = $2 WHERE id = $1",
    )
    .bind(admin_id)
    .bind(step)
    .execute(&mut *tx)
    .await?;
    let codes = replace_recovery_codes(&mut tx, admin_id).await?;
    other_sessions_out(&mut tx, admin_id, keep_session).await?;
    audit::record(&mut tx, &username, "mfa_enabled", None, json!({})).await?;
    tx.commit().await?;
    Ok(codes)
}

/// 鎖住帳號並確認目前的驗證碼（或復原碼）；成功時交易交給呼叫端繼續
async fn with_code(
    pool: &PgPool,
    admin_id: i64,
    code: &str,
) -> Result<(sqlx::Transaction<'static, sqlx::Postgres>, String, Method), MfaError> {
    let mut tx = pool.begin().await?;
    let (username, secret, _, last_step) = lock_admin(&mut tx, admin_id).await?;
    let secret = secret.ok_or(MfaError::NotEnabled)?;
    let method = check_code(&mut tx, admin_id, &secret, last_step, code)
        .await?
        .ok_or(MfaError::BadCode)?;
    Ok((tx, username, method))
}

pub async fn disable(
    pool: &PgPool,
    admin_id: i64,
    code: &str,
    keep_session: &str,
) -> Result<(), MfaError> {
    if required(pool).await? {
        return Err(MfaError::Required);
    }
    let (mut tx, username, method) = with_code(pool, admin_id, code).await?;
    clear(&mut tx, admin_id).await?;
    other_sessions_out(&mut tx, admin_id, keep_session).await?;
    audit::record(
        &mut tx,
        &username,
        "mfa_disabled",
        None,
        json!({ "method": method.as_str() }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn regenerate_recovery(
    pool: &PgPool,
    admin_id: i64,
    code: &str,
) -> Result<Vec<String>, MfaError> {
    let (mut tx, username, method) = with_code(pool, admin_id, code).await?;
    let codes = replace_recovery_codes(&mut tx, admin_id).await?;
    audit::record(
        &mut tx,
        &username,
        "mfa_recovery_regenerated",
        None,
        json!({ "method": method.as_str() }),
    )
    .await?;
    tx.commit().await?;
    Ok(codes)
}

async fn clear(conn: &mut PgConnection, admin_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE admins SET mfa_secret = NULL, mfa_pending_secret = NULL, mfa_enabled_at = NULL, \
                mfa_last_step = NULL WHERE id = $1",
    )
    .bind(admin_id)
    .execute(&mut *conn)
    .await?;
    for sql in [
        "DELETE FROM admin_recovery_codes WHERE admin_id = $1",
        "DELETE FROM mfa_challenges WHERE admin_id = $1",
    ] {
        sqlx::query(sql).bind(admin_id).execute(&mut *conn).await?;
    }
    Ok(())
}

/// 平台管理員或指令列重設別人的兩步驟驗證：清除金鑰與復原碼，登出所有工作階段
pub async fn reset(pool: &PgPool, admin_id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let username: String =
        sqlx::query_scalar("SELECT username FROM admins WHERE id = $1 FOR UPDATE")
            .bind(admin_id)
            .fetch_optional(&mut *tx)
            .await?
            .context("帳號不存在")?;
    clear(&mut tx, admin_id).await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, actor, "mfa_reset", Some(&username), json!({})).await?;
    tx.commit().await?;
    Ok(())
}

/// 指令列：依帳號名稱重設
pub async fn reset_by_username(pool: &PgPool, username: &str) -> anyhow::Result<()> {
    let id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = $1")
        .bind(username)
        .fetch_optional(pool)
        .await?
        .with_context(|| format!("帳號 {username} 不存在"))?;
    reset(pool, id, "cli").await
}
