//! 網路設備（SNMP，由據點的快取主機查詢）：帳密與設備的管理、下發給快取的查詢工作。
//! 規格：docs/superpowers/specs/2026-11-23-network-devices-design.md

pub mod api;
pub mod ingest;

use std::net::IpAddr;

use anyhow::{Context, anyhow};
use protocol::netdev::{
    CiscoVlanMode, SnmpAuthProtocol, SnmpCredential, SnmpJob, SnmpPrivProtocol, SnmpTarget,
};
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::commands::CmdError;
use crate::secret::SecretBox;

/// 加密帳密時的用途字串（AAD）
const PURPOSE: &str = "snmp_credential";
pub const MAX_NAME_LEN: usize = 100;
/// USM 的使用者名稱上限
const MAX_V3_USER: usize = 32;
/// USM 的密碼至少 8 個字元（RFC 3414）
const MIN_V3_PASS: usize = 8;
const MAX_SECRET_LEN: usize = 255;
/// 連續失敗幾輪算「無法連線」
pub const UNREACHABLE_AFTER: i32 = 3;

/// 查詢間隔的設定鍵（秒）、預設、下限、上限
pub const SYSTEM_INTERVAL: (&str, u32) = ("snmp_system_interval_secs", 900);
pub const TABLE_INTERVAL: (&str, u32) = ("snmp_table_interval_secs", 300);
pub const MIN_INTERVAL_SECS: u32 = 60;
pub const MAX_INTERVAL_SECS: u32 = 24 * 3600;

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    CmdError::Invalid(msg.into()).into()
}

fn check_name(name: &str, what: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME_LEN {
        return Err(invalid(format!("{what}必填，最多 {MAX_NAME_LEN} 字")));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid(format!("{what}不能包含控制字元")));
    }
    Ok(name.to_string())
}

fn check_secret(v: &str, what: &str, min: usize) -> anyhow::Result<()> {
    let n = v.chars().count();
    if n < min.max(1) || n > MAX_SECRET_LEN {
        return Err(invalid(if min > 1 {
            format!("{what}要 {min}–{MAX_SECRET_LEN} 個字元")
        } else {
            format!("{what}必填，最多 {MAX_SECRET_LEN} 個字元")
        }));
    }
    if v.chars().any(char::is_control) {
        return Err(invalid(format!("{what}不能包含控制字元")));
    }
    Ok(())
}

pub fn auth_label(p: SnmpAuthProtocol) -> &'static str {
    match p {
        SnmpAuthProtocol::Sha1 => "SHA",
        SnmpAuthProtocol::Sha256 => "SHA-256",
    }
}

pub fn priv_label(p: SnmpPrivProtocol) -> &'static str {
    match p {
        SnmpPrivProtocol::Aes128 => "AES-128",
        SnmpPrivProtocol::Aes256 => "AES-256",
        SnmpPrivProtocol::Aes256Cisco => "AES-256（Cisco）",
    }
}

pub fn parse_auth(s: &str) -> Option<SnmpAuthProtocol> {
    match s {
        "sha1" => Some(SnmpAuthProtocol::Sha1),
        "sha256" => Some(SnmpAuthProtocol::Sha256),
        _ => None,
    }
}

pub fn parse_priv(s: &str) -> Option<SnmpPrivProtocol> {
    match s {
        "aes128" => Some(SnmpPrivProtocol::Aes128),
        "aes256" => Some(SnmpPrivProtocol::Aes256),
        "aes256c" => Some(SnmpPrivProtocol::Aes256Cisco),
        _ => None,
    }
}

/// 帳密表單。編輯時機密欄位留空表示沿用原本的值。
#[derive(Debug, Clone, Default)]
pub struct CredentialInput {
    pub name: String,
    /// "v2c" | "v3"
    pub version: String,
    pub community: String,
    pub user: String,
    pub auth: String,
    pub auth_pass: String,
    pub privacy: String,
    pub priv_pass: String,
}

/// 依表單組出帳密；`old` 是編輯前的值（同版本時，留空的機密沿用）
pub fn build_credential(
    i: &CredentialInput,
    old: Option<&SnmpCredential>,
) -> anyhow::Result<SnmpCredential> {
    match i.version.as_str() {
        "v2c" => {
            let community = match (i.community.is_empty(), old) {
                (true, Some(SnmpCredential::V2c { community })) => community.clone(),
                _ => {
                    check_secret(&i.community, "Community", 1)?;
                    i.community.clone()
                }
            };
            Ok(SnmpCredential::V2c { community })
        }
        "v3" => {
            let user = i.user.trim();
            if user.is_empty() || user.chars().count() > MAX_V3_USER {
                return Err(invalid(format!("使用者名稱必填，最多 {MAX_V3_USER} 字")));
            }
            if user.chars().any(char::is_control) {
                return Err(invalid("使用者名稱不能包含控制字元"));
            }
            let auth = parse_auth(&i.auth).ok_or_else(|| invalid("請選擇驗證演算法"))?;
            let privacy = parse_priv(&i.privacy).ok_or_else(|| invalid("請選擇加密演算法"))?;
            let (old_auth, old_priv) = match old {
                Some(SnmpCredential::V3 {
                    auth_pass,
                    priv_pass,
                    ..
                }) => (Some(auth_pass), Some(priv_pass)),
                _ => (None, None),
            };
            let pick = |new: &str, old: Option<&String>, what: &str| -> anyhow::Result<String> {
                match (new.is_empty(), old) {
                    (true, Some(o)) => Ok(o.clone()),
                    _ => {
                        check_secret(new, what, MIN_V3_PASS)?;
                        Ok(new.to_string())
                    }
                }
            };
            Ok(SnmpCredential::V3 {
                user: user.to_string(),
                auth,
                auth_pass: pick(&i.auth_pass, old_auth, "驗證密碼")?,
                privacy,
                priv_pass: pick(&i.priv_pass, old_priv, "加密密碼")?,
            })
        }
        _ => Err(invalid("請選擇 SNMP 版本")),
    }
}

fn username_of(c: &SnmpCredential) -> Option<&str> {
    match c {
        SnmpCredential::V2c { .. } => None,
        SnmpCredential::V3 { user, .. } => Some(user),
    }
}

pub fn seal(secrets: &SecretBox, c: &SnmpCredential) -> Vec<u8> {
    secrets.seal(PURPOSE, &serde_json::to_vec(c).expect("credential json"))
}

pub fn open(secrets: &SecretBox, sealed: &[u8]) -> anyhow::Result<SnmpCredential> {
    let plain = secrets.open(PURPOSE, sealed)?;
    serde_json::from_slice(&plain).context("credential json")
}

fn secrets_required(secrets: Option<&SecretBox>) -> anyhow::Result<&SecretBox> {
    secrets
        .ok_or_else(|| invalid("伺服器沒有設定加密金鑰（EM_SECRET_KEY_FILE），不能保存 SNMP 帳密"))
}

fn credential_name_taken(e: sqlx::Error) -> anyhow::Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => invalid("帳密名稱已存在"),
        _ => e.into(),
    }
}

pub async fn create_credential(
    pool: &PgPool,
    secrets: Option<&SecretBox>,
    i: &CredentialInput,
    actor: &str,
) -> anyhow::Result<i64> {
    let secrets = secrets_required(secrets)?;
    let name = check_name(&i.name, "名稱")?;
    let c = build_credential(i, None)?;
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO snmp_credentials (name, version, username, secret_enc) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&name)
    .bind(c.version_label())
    .bind(username_of(&c))
    .bind(seal(secrets, &c))
    .fetch_one(&mut *tx)
    .await
    .map_err(credential_name_taken)?;
    // 不記機密內容
    audit::record(
        &mut tx,
        actor,
        "snmp_credential_create",
        Some(&name),
        json!({"id": id, "version": c.version_label(), "user": username_of(&c)}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_credential(
    pool: &PgPool,
    secrets: Option<&SecretBox>,
    id: i64,
    i: &CredentialInput,
    actor: &str,
) -> anyhow::Result<()> {
    let secrets = secrets_required(secrets)?;
    let name = check_name(&i.name, "名稱")?;
    let mut tx = pool.begin().await?;
    let old: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT secret_enc FROM snmp_credentials WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let old = old.ok_or_else(|| anyhow::Error::from(CmdError::NotFound("帳密不存在".into())))?;
    // 解不開（換過金鑰）時當作沒有舊值：機密欄位都要重新填
    let old = open(secrets, &old).ok();
    let c = build_credential(i, old.as_ref())?;
    sqlx::query(
        "UPDATE snmp_credentials SET name = $2, version = $3, username = $4, secret_enc = $5, \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&name)
    .bind(c.version_label())
    .bind(username_of(&c))
    .bind(seal(secrets, &c))
    .execute(&mut *tx)
    .await
    .map_err(credential_name_taken)?;
    // 用這組帳密的設備：下一次報到時立即查詢一次
    sqlx::query("UPDATE net_devices SET poll_requested = true WHERE credential_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        actor,
        "snmp_credential_update",
        Some(&name),
        json!({"id": id, "version": c.version_label(), "user": username_of(&c)}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_credential(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM net_devices WHERE credential_id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    if used > 0 {
        return Err(CmdError::Conflict(format!(
            "還有 {used} 台網路設備使用這組帳密，請先改用其他帳密"
        ))
        .into());
    }
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM snmp_credentials WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let name = name.ok_or_else(|| anyhow::Error::from(CmdError::NotFound("帳密不存在".into())))?;
    audit::record(
        &mut tx,
        actor,
        "snmp_credential_delete",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct DeviceInput {
    pub name: String,
    pub site_id: i64,
    pub address: String,
    pub port: String,
    pub credential_id: i64,
    pub enabled: bool,
    /// "auto" | "on" | "off"
    pub cisco_vlan: String,
}

struct ValidDevice {
    name: String,
    address: String,
    port: i32,
    cisco_vlan: &'static str,
}

/// IP 位址，或主機名稱（英數字、連字號、點，最長 253）
pub fn check_address(a: &str) -> anyhow::Result<String> {
    let a = a.trim();
    if a.parse::<IpAddr>().is_ok() {
        return Ok(a.to_string());
    }
    let ok = !a.is_empty()
        && a.len() <= 253
        && a.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if !ok {
        return Err(invalid(format!("位址「{a}」不是 IP 位址或主機名稱")));
    }
    Ok(a.to_ascii_lowercase())
}

fn validate_device(i: &DeviceInput) -> anyhow::Result<ValidDevice> {
    let name = check_name(&i.name, "設備名稱")?;
    let address = check_address(&i.address)?;
    let port = match i.port.trim() {
        "" => 161,
        p => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| invalid("埠號要在 1–65535"))?,
    };
    let cisco_vlan = match i.cisco_vlan.as_str() {
        "" | "auto" => "auto",
        "on" => "on",
        "off" => "off",
        _ => return Err(invalid("Cisco 逐 VLAN 查詢的設定無效")),
    };
    Ok(ValidDevice {
        name,
        address,
        port: i32::from(port),
        cisco_vlan,
    })
}

async fn check_refs(conn: &mut PgConnection, i: &DeviceInput) -> anyhow::Result<()> {
    let site: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sites WHERE id = $1)")
        .bind(i.site_id)
        .fetch_one(&mut *conn)
        .await?;
    if !site {
        return Err(invalid("請選擇據點"));
    }
    let cred: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM snmp_credentials WHERE id = $1)")
            .bind(i.credential_id)
            .fetch_one(&mut *conn)
            .await?;
    if !cred {
        return Err(invalid("請選擇 SNMP 帳密"));
    }
    Ok(())
}

fn device_taken(e: sqlx::Error) -> anyhow::Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            invalid("這個據點已經有相同位址與埠號的設備")
        }
        _ => e.into(),
    }
}

fn device_detail(id: i64, i: &DeviceInput, v: &ValidDevice) -> serde_json::Value {
    json!({
        "id": id,
        "site_id": i.site_id,
        "address": v.address,
        "port": v.port,
        "credential_id": i.credential_id,
        "enabled": i.enabled,
        "cisco_vlan": v.cisco_vlan,
    })
}

pub async fn create_device(pool: &PgPool, i: &DeviceInput, actor: &str) -> anyhow::Result<i64> {
    let v = validate_device(i)?;
    let mut tx = pool.begin().await?;
    check_refs(&mut tx, i).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO net_devices (name, site_id, address, port, credential_id, enabled, cisco_vlan) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&v.name)
    .bind(i.site_id)
    .bind(&v.address)
    .bind(v.port)
    .bind(i.credential_id)
    .bind(i.enabled)
    .bind(v.cisco_vlan)
    .fetch_one(&mut *tx)
    .await
    .map_err(device_taken)?;
    audit::record(
        &mut tx,
        actor,
        "netdevice_create",
        Some(&v.name),
        device_detail(id, i, &v),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_device(
    pool: &PgPool,
    id: i64,
    i: &DeviceInput,
    actor: &str,
) -> anyhow::Result<()> {
    let v = validate_device(i)?;
    let mut tx = pool.begin().await?;
    check_refs(&mut tx, i).await?;
    let n = sqlx::query(
        "UPDATE net_devices SET name = $2, site_id = $3, address = $4, port = $5, \
         credential_id = $6, enabled = $7, cisco_vlan = $8, poll_requested = true, \
         updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&v.name)
    .bind(i.site_id)
    .bind(&v.address)
    .bind(v.port)
    .bind(i.credential_id)
    .bind(i.enabled)
    .bind(v.cisco_vlan)
    .execute(&mut *tx)
    .await
    .map_err(device_taken)?
    .rows_affected();
    if n == 0 {
        return Err(CmdError::NotFound("網路設備不存在".into()).into());
    }
    audit::record(
        &mut tx,
        actor,
        "netdevice_update",
        Some(&v.name),
        device_detail(id, i, &v),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_device(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let name: Option<String> =
        sqlx::query_scalar("DELETE FROM net_devices WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let name =
        name.ok_or_else(|| anyhow::Error::from(CmdError::NotFound("網路設備不存在".into())))?;
    audit::record(
        &mut tx,
        actor,
        "netdevice_delete",
        Some(&name),
        json!({"id": id}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 「立即查詢」：下一次快取報到時（最多約 60 秒）查詢
pub async fn request_poll(pool: &PgPool, id: i64) -> anyhow::Result<()> {
    let n = sqlx::query("UPDATE net_devices SET poll_requested = true WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(CmdError::NotFound("網路設備不存在".into()).into());
    }
    Ok(())
}

/// 查詢間隔（秒）：(系統資訊, MAC 與 ARP 表)
pub async fn intervals<'e>(pool: impl sqlx::PgExecutor<'e>) -> Result<(u32, u32), sqlx::Error> {
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT key, value #>> '{}' FROM settings WHERE key = ANY($1)")
            .bind([SYSTEM_INTERVAL.0, TABLE_INTERVAL.0])
            .fetch_all(pool)
            .await?;
    let get = |(key, default): (&str, u32)| {
        rows.iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref()?.parse::<u32>().ok())
            .filter(|v| (MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(v))
            .unwrap_or(default)
    };
    Ok((get(SYSTEM_INTERVAL), get(TABLE_INTERVAL)))
}

pub async fn save_intervals(
    pool: &PgPool,
    system: u32,
    tables: u32,
    actor: &str,
) -> anyhow::Result<()> {
    for v in [system, tables] {
        if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(&v) {
            return Err(invalid("查詢間隔要在 1 分鐘到 24 小時之間"));
        }
    }
    let mut tx = pool.begin().await?;
    for (key, v) in [(SYSTEM_INTERVAL.0, system), (TABLE_INTERVAL.0, tables)] {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, to_jsonb($2::int)) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(v as i32)
        .execute(&mut *tx)
        .await?;
    }
    audit::record(
        &mut tx,
        actor,
        "netdevice_intervals",
        None,
        json!({"system_secs": system, "table_secs": tables}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

fn cisco_mode(s: &str) -> CiscoVlanMode {
    match s {
        "on" => CiscoVlanMode::On,
        "off" => CiscoVlanMode::Off,
        _ => CiscoVlanMode::Auto,
    }
}

type TargetRow = (i64, String, i32, String, Vec<u8>, bool);

/// 快取報到時下發的查詢工作：只有該據點、啟用中的設備。
/// 沒有據點或沒設定金鑰時回 None（快取就停止查詢）。帳密解不開的設備略過並記錄。
pub async fn job_for(
    pool: &PgPool,
    secrets: Option<&SecretBox>,
    site_id: Option<i64>,
) -> anyhow::Result<Option<SnmpJob>> {
    let (Some(site), Some(secrets)) = (site_id, secrets) else {
        return Ok(None);
    };
    let mut tx = pool.begin().await?;
    // 讀出後清掉「立即查詢」：快取拿到後就會查，失敗時照排程重試
    let rows: Vec<TargetRow> = sqlx::query_as(
        "WITH req AS (UPDATE net_devices SET poll_requested = false \
                      WHERE site_id = $1 AND enabled AND poll_requested RETURNING id) \
         SELECT d.id, d.address, d.port, d.cisco_vlan, c.secret_enc, \
                d.id IN (SELECT id FROM req) \
         FROM net_devices d JOIN snmp_credentials c ON c.id = d.credential_id \
         WHERE d.site_id = $1 AND d.enabled ORDER BY d.id LIMIT $2",
    )
    .bind(site)
    .bind(protocol::netdev::MAX_TARGETS as i64)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let (system, tables) = intervals(pool).await?;
    let mut targets = Vec::with_capacity(rows.len());
    for (id, address, port, cisco, sealed, poll_now) in rows {
        let credential = match open(secrets, &sealed) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(device_id = id, error = %format!("{e:#}"), "cannot decrypt SNMP credential");
                continue;
            }
        };
        targets.push(SnmpTarget {
            id,
            address,
            port: u16::try_from(port).map_err(|_| anyhow!("bad port {port}"))?,
            credential,
            cisco_vlan: cisco_mode(&cisco),
            poll_now,
        });
    }
    Ok(Some(SnmpJob {
        targets,
        system_interval_secs: system,
        table_interval_secs: tables,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v3(user: &str, a: &str, p: &str) -> CredentialInput {
        CredentialInput {
            name: "n".into(),
            version: "v3".into(),
            user: user.into(),
            auth: "sha256".into(),
            auth_pass: a.into(),
            privacy: "aes128".into(),
            priv_pass: p.into(),
            ..Default::default()
        }
    }

    #[test]
    fn credential_validation() {
        let c = build_credential(
            &CredentialInput {
                version: "v2c".into(),
                community: "public".into(),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(
            c,
            SnmpCredential::V2c {
                community: "public".into()
            }
        );
        assert!(build_credential(&CredentialInput::default(), None).is_err());
        let err = |i: &CredentialInput| format!("{:#}", build_credential(i, None).unwrap_err());
        assert!(err(&v3("mon", "short", "privpass1")).contains("驗證密碼"));
        assert!(err(&v3("mon", "authpass1", "")).contains("加密密碼"));
        assert!(err(&v3("", "authpass1", "privpass1")).contains("使用者名稱"));
        assert!(err(&v3(&"u".repeat(33), "authpass1", "privpass1")).contains("使用者名稱"));
        let mut bad = v3("mon", "authpass1", "privpass1");
        bad.auth = "md5".into();
        assert!(err(&bad).contains("驗證演算法"));
        let mut bad = v3("mon", "authpass1", "privpass1");
        bad.privacy = "des".into();
        assert!(err(&bad).contains("加密演算法"));
        assert!(
            err(&CredentialInput {
                version: "v2c".into(),
                community: "a\u{7}".into(),
                ..Default::default()
            })
            .contains("控制字元")
        );
    }

    #[test]
    fn empty_secret_keeps_old_value_only_for_same_version() {
        let old = build_credential(&v3("mon", "authpass1", "privpass1"), None).unwrap();
        let kept = build_credential(&v3("mon2", "", ""), Some(&old)).unwrap();
        assert_eq!(
            kept,
            SnmpCredential::V3 {
                user: "mon2".into(),
                auth: SnmpAuthProtocol::Sha256,
                auth_pass: "authpass1".into(),
                privacy: SnmpPrivProtocol::Aes128,
                priv_pass: "privpass1".into(),
            }
        );
        // 只改加密密碼
        let changed = build_credential(&v3("mon", "", "newpriv12"), Some(&old)).unwrap();
        assert!(
            matches!(changed, SnmpCredential::V3 { ref auth_pass, ref priv_pass, .. }
            if auth_pass == "authpass1" && priv_pass == "newpriv12")
        );
        // 改版本時要重新填
        let to_v2 = CredentialInput {
            version: "v2c".into(),
            ..Default::default()
        };
        assert!(build_credential(&to_v2, Some(&old)).is_err());
        let v2 = SnmpCredential::V2c {
            community: "c1".into(),
        };
        assert_eq!(build_credential(&to_v2, Some(&v2)).unwrap(), v2);
        assert!(build_credential(&v3("mon", "", ""), Some(&v2)).is_err());
    }

    #[test]
    fn seal_roundtrip() {
        let k = SecretBox::new(&[7; 32]);
        let c = SnmpCredential::V2c {
            community: "public".into(),
        };
        let sealed = seal(&k, &c);
        assert_eq!(open(&k, &sealed).unwrap(), c);
        assert!(open(&SecretBox::new(&[8; 32]), &sealed).is_err());
        // 用途不同的密文不能拿來當帳密
        assert!(open(&k, &k.seal("other", b"{}")).is_err());
    }

    #[test]
    fn address_validation() {
        assert_eq!(check_address(" 10.0.0.1 ").unwrap(), "10.0.0.1");
        assert_eq!(check_address("fd00::1").unwrap(), "fd00::1");
        assert_eq!(check_address("SW-Core.corp").unwrap(), "sw-core.corp");
        for bad in ["", "a b", "-x.corp", "x..corp", "http://x", &"a".repeat(64)] {
            assert!(check_address(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn device_validation() {
        let ok = DeviceInput {
            name: "核心交換器".into(),
            site_id: 1,
            address: "10.0.0.1".into(),
            port: String::new(),
            credential_id: 1,
            enabled: true,
            cisco_vlan: String::new(),
        };
        let v = validate_device(&ok).unwrap();
        assert_eq!((v.port, v.cisco_vlan), (161, "auto"));
        for (port, cisco) in [
            ("0", "auto"),
            ("70000", "auto"),
            ("x", "auto"),
            ("161", "maybe"),
        ] {
            let i = DeviceInput {
                port: port.into(),
                cisco_vlan: cisco.into(),
                ..ok.clone()
            };
            assert!(validate_device(&i).is_err(), "{port} {cisco}");
        }
        assert!(
            validate_device(&DeviceInput {
                name: " ".into(),
                ..ok.clone()
            })
            .is_err()
        );
        assert_eq!(cisco_mode("on"), CiscoVlanMode::On);
        assert_eq!(cisco_mode("off"), CiscoVlanMode::Off);
        assert_eq!(cisco_mode("x"), CiscoVlanMode::Auto);
    }

    #[test]
    fn labels() {
        assert_eq!(auth_label(SnmpAuthProtocol::Sha1), "SHA");
        assert_eq!(auth_label(SnmpAuthProtocol::Sha256), "SHA-256");
        assert_eq!(priv_label(SnmpPrivProtocol::Aes128), "AES-128");
        assert_eq!(priv_label(SnmpPrivProtocol::Aes256), "AES-256");
        assert_eq!(
            priv_label(SnmpPrivProtocol::Aes256Cisco),
            "AES-256（Cisco）"
        );
        assert_eq!(parse_priv("aes256c"), Some(SnmpPrivProtocol::Aes256Cisco));
        assert_eq!(parse_auth("sha1"), Some(SnmpAuthProtocol::Sha1));
    }
}
