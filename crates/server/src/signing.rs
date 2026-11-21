//! 腳本與套件簽章：保存、預先檢查、簽章請求。
//!
//! 簽章金鑰在伺服器以外；伺服器只保存與轉送簽章。端點回報的公鑰只用來在上傳時
//! 預先檢查、及早發現貼錯的簽章，Agent 的判斷不依賴伺服器。

use protocol::command::ScriptLanguage;
use protocol::deploy::PackageKind;
use protocol::signing::{Payload, SigningRequest, key_id, parse_signature, verify};
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use crate::audit;

/// 使用者看得懂的錯誤（重新顯示頁面）
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("{0}")]
    Invalid(String),
    #[error("找不到")]
    NotFound,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// 上傳時預先檢查的結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precheck {
    /// 用端點回報的公鑰驗證通過（金鑰 ID）
    Verified(String),
    /// 還沒有端點回報公鑰，只檢查了格式
    Unverifiable(String),
}

/// 使用中的端點回報過的所有公鑰
pub async fn known_keys(conn: &mut PgConnection) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT DISTINCT k FROM devices, unnest(signing_keys) AS k \
         WHERE status <> 'retired' AND cardinality(signing_keys) > 0 ORDER BY k",
    )
    .fetch_all(conn)
    .await
}

/// 要求簽章的使用中端點數
pub async fn enforcing_devices(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM devices WHERE status = 'active' AND cardinality(signing_keys) > 0",
    )
    .fetch_one(pool)
    .await
}

/// 裝置的公鑰金鑰 ID（顯示用）
pub fn key_ids(keys: &[String]) -> Vec<String> {
    keys.iter()
        .filter_map(|k| protocol::signing::decode_public_key(k).ok())
        .map(|raw| key_id(&raw))
        .collect()
}

async fn precheck(
    conn: &mut PgConnection,
    payload: &Payload,
    signature: &str,
) -> Result<Precheck, SignError> {
    let (id, _) = parse_signature(signature).map_err(|e| SignError::Invalid(e.to_string()))?;
    let keys = known_keys(conn).await?;
    if keys.is_empty() {
        return Ok(Precheck::Unverifiable(id));
    }
    match verify(&keys, payload, Some(signature)) {
        Ok(id) => Ok(Precheck::Verified(id)),
        Err(e) => Err(SignError::Invalid(format!(
            "{e}。請確認簽的是目前的版本，而且是端點信任的金鑰"
        ))),
    }
}

fn language(s: &str) -> ScriptLanguage {
    ScriptLanguage::parse(s).unwrap_or_default()
}

fn timeout_u32(t: i32) -> u32 {
    u32::try_from(t).unwrap_or(30)
}

type ScriptRow = (String, String, String, i32, String, String);

async fn script_row(conn: &mut PgConnection, id: i64, lock: bool) -> Result<ScriptRow, SignError> {
    let sql = if lock {
        "SELECT name, content, sha256, timeout_minutes, language, status FROM scripts \
         WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT name, content, sha256, timeout_minutes, language, status FROM scripts \
         WHERE id = $1"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or(SignError::NotFound)
}

fn script_payload(r: &ScriptRow) -> Payload {
    Payload::Script {
        sha256: r.2.to_ascii_lowercase(),
        language: language(&r.4),
        timeout_minutes: timeout_u32(r.3),
    }
}

pub async fn script_request(pool: &PgPool, id: i64) -> Result<SigningRequest, SignError> {
    let mut conn = pool.acquire().await?;
    let r = script_row(&mut conn, id, false).await?;
    Ok(SigningRequest {
        kind: SigningRequest::TYPE.into(),
        name: r.0.clone(),
        payload: script_payload(&r),
        content: Some(r.1.clone()),
    })
}

/// 腳本必須已核准；簽章對應目前的內容、語言與逾時
pub async fn sign_script(
    pool: &PgPool,
    id: i64,
    signature: &str,
    actor: &str,
) -> Result<Precheck, SignError> {
    let mut tx = pool.begin().await?;
    let r = script_row(&mut tx, id, true).await?;
    if r.5 != "approved" {
        return Err(SignError::Invalid("腳本必須先核准才能上傳簽章".into()));
    }
    let signature = signature.trim();
    let check = precheck(&mut tx, &script_payload(&r), signature).await?;
    sqlx::query("UPDATE scripts SET signature = $2 WHERE id = $1")
        .bind(id)
        .bind(signature)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        actor,
        "script_signed",
        Some(&r.0),
        json!({ "id": id, "sha256": r.2, "key_id": precheck_id(&check),
                "verified": matches!(check, Precheck::Verified(_)) }),
    )
    .await?;
    tx.commit().await?;
    Ok(check)
}

fn precheck_id(p: &Precheck) -> &str {
    match p {
        Precheck::Verified(id) | Precheck::Unverifiable(id) => id,
    }
}

type PackageRow = (String, String, String, i64, String, String, Option<String>);

async fn package_row(
    conn: &mut PgConnection,
    id: i64,
    lock: bool,
) -> Result<PackageRow, SignError> {
    let sql = if lock {
        "SELECT name, kind, sha256, size, install_args, uninstall_args, msi_product_code \
         FROM packages WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT name, kind, sha256, size, install_args, uninstall_args, msi_product_code \
         FROM packages WHERE id = $1"
    };
    sqlx::query_as(sql)
        .bind(id)
        .fetch_optional(conn)
        .await?
        .ok_or(SignError::NotFound)
}

fn package_payload(r: &PackageRow) -> Payload {
    Payload::Package {
        sha256: r.2.to_ascii_lowercase(),
        size: r.3.max(0) as u64,
        package_kind: if r.1 == "msi" {
            PackageKind::Msi
        } else {
            PackageKind::Exe
        },
        install_args: r.4.clone(),
        uninstall_args: r.5.clone(),
        msi_product_code: r.6.clone(),
    }
}

pub async fn package_request(pool: &PgPool, id: i64) -> Result<SigningRequest, SignError> {
    let mut conn = pool.acquire().await?;
    let r = package_row(&mut conn, id, false).await?;
    Ok(SigningRequest {
        kind: SigningRequest::TYPE.into(),
        name: r.0.clone(),
        payload: package_payload(&r),
        content: None,
    })
}

pub async fn sign_package(
    pool: &PgPool,
    id: i64,
    signature: &str,
    actor: &str,
) -> Result<Precheck, SignError> {
    let mut tx = pool.begin().await?;
    let r = package_row(&mut tx, id, true).await?;
    let signature = signature.trim();
    let check = precheck(&mut tx, &package_payload(&r), signature).await?;
    sqlx::query("UPDATE packages SET signature = $2 WHERE id = $1")
        .bind(id)
        .bind(signature)
        .execute(&mut *tx)
        .await?;
    // 派送清單有快取：讓下次報到重新載入，帶上新簽章
    crate::deploy::admin::bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "package_signed",
        Some(&r.0),
        json!({ "id": id, "sha256": r.2, "key_id": precheck_id(&check),
                "verified": matches!(check, Precheck::Verified(_)) }),
    )
    .await?;
    tx.commit().await?;
    Ok(check)
}

/// 下載檔名（ASCII，避免各瀏覽器對非 ASCII 檔名處理不一）
pub fn request_file_name(kind: &str, id: i64) -> String {
    format!("{kind}-{id}-signing-request.json")
}

/// 簽章欄位的顯示文字
pub fn signature_label(signature: Option<&str>) -> Option<String> {
    signature.map(|s| {
        parse_signature(s)
            .map(|(id, _)| id)
            .unwrap_or_else(|_| "格式錯誤".into())
    })
}
