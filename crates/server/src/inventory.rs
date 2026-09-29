//! /v1/inventory/{section}：接收整個區段，比對差異後在同一交易內替換。

use std::io::Read;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use flate2::read::GzDecoder;
use protocol::{
    Arch, BasicInfo, Disk, HardwareInfo, InventoryPayload, InventoryUpload, PatchItem, Probe,
    RegKind, RegState, RegistryValue, SCHEMA_VERSION, Section, SecurityInfo, ServiceItem,
    SoftwareItem,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::AppState;
use crate::diff::{diff, items_of};
use crate::error::AppError;
use crate::identity::AuthedDevice;

pub const MAX_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024;

/// 同時在 blocking 執行緒上解析的上傳數量上限（最壞約 8 × 50MB 加上解析後的資料）
static UPLOAD_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

pub fn decode_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, AppError> {
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    if !gzip {
        return Ok(body.to_vec());
    }
    let mut out = Vec::new();
    GzDecoder::new(body)
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|_| AppError::BadRequest("invalid gzip".into()))?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    Ok(out)
}

pub async fn upload(
    State(st): State<AppState>,
    device: AuthedDevice,
    Path(section): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let section =
        Section::parse(&section).ok_or_else(|| AppError::BadRequest("unknown section".into()))?;
    // 解壓縮（最多 50MB）、JSON 解析、驗證與雜湊都是 CPU 工作，放到 blocking 執行緒，
    // 不佔住處理報到的 async 執行緒。同時解析的數量有上限：每個可能解壓成 50MB，
    // 全車隊同時上傳時不能把記憶體撐爆
    let _slot = UPLOAD_SLOTS
        .acquire()
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
    let (payload, mut hash) =
        tokio::task::spawn_blocking(move || parse_upload(section, &headers, &body))
            .await
            .map_err(|e| AppError::Internal(e.into()))??;
    // 只保存規則需要的登錄檔值（比對不分大小寫）。有值被濾掉時改存過濾後的雜湊：
    // 和 Agent 的雜湊不同，下次報到會被要求重傳，查詢清單剛變時也能收斂
    let payload = match payload {
        InventoryPayload::Registry(v) => {
            let rules = st.rules.get(&st.pool).await?;
            let total = v.len();
            let kept: Vec<_> = v
                .into_iter()
                .filter(|r| {
                    rules
                        .registry_keys
                        .contains(&crate::compliance::rules::registry_key(&r.path, &r.name))
                })
                .collect();
            let filtered = InventoryPayload::Registry(kept);
            if let InventoryPayload::Registry(k) = &filtered
                && k.len() != total
            {
                hash = filtered.canonical_hash();
            }
            filtered
        }
        other => other,
    };
    store_section(&st.pool, device.device_id, &payload, &hash).await?;
    // 評估失敗不影響上傳：盤點已寫入，結果在這台下次上傳（或規則變更觸發的全量重算）時補上
    if crate::compliance::affects_compliance(section)
        && let Err(e) = crate::compliance::refresh_after_upload(&st, device.device_id).await
    {
        tracing::error!(device_id = %device.device_id, error = %e, "compliance evaluation failed");
    }
    Ok(StatusCode::NO_CONTENT)
}

fn parse_upload(
    section: Section,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(InventoryPayload, String), AppError> {
    let raw = decode_body(headers, body)?;
    let upload: InventoryUpload =
        serde_json::from_slice(&raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version > SCHEMA_VERSION {
        return Err(AppError::BadRequest("unsupported schema_version".into()));
    }
    if upload.payload.section() != section {
        return Err(AppError::BadRequest("section mismatch".into()));
    }
    upload.payload.validate()?;
    let hash = upload.payload.canonical_hash();
    Ok((upload.payload, hash))
}

/// hash 須為 payload.canonical_hash()（呼叫端已在 blocking 執行緒算好）。
pub async fn store_section(
    pool: &PgPool,
    device_id: Uuid,
    payload: &InventoryPayload,
    hash: &str,
) -> Result<(), AppError> {
    let section = payload.section();
    let mut tx = pool.begin().await?;
    // 同一裝置同一區段的並發上傳依序處理
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("{device_id}:{}", section.as_str()))
        .execute(&mut *tx)
        .await?;

    // 第一次上傳只當基準線，不寫變更記錄
    if let Some(old) = load_payload(&mut tx, device_id, section).await? {
        let changes = diff(&items_of(&old), &items_of(payload));
        if !changes.is_empty() {
            // 一次寫入所有變更（重灌後可能有上千筆）
            let kinds: Vec<&str> = changes.iter().map(|c| c.kind.as_str()).collect();
            let keys: Vec<&str> = changes.iter().map(|c| c.key.as_str()).collect();
            let olds: Vec<Option<&str>> = changes.iter().map(|c| c.old.as_deref()).collect();
            let news: Vec<Option<&str>> = changes.iter().map(|c| c.new.as_deref()).collect();
            sqlx::query(
                "INSERT INTO inventory_changes \
                 (device_id, section, change, item_key, old_value, new_value) \
                 SELECT $1, $2, * FROM UNNEST($3::text[], $4::text[], $5::text[], $6::text[])",
            )
            .bind(device_id)
            .bind(section.as_str())
            .bind(&kinds)
            .bind(&keys)
            .bind(&olds)
            .bind(&news)
            .execute(&mut *tx)
            .await?;
        }
    }

    write_payload(&mut tx, device_id, payload).await?;
    sqlx::query(
        "INSERT INTO inventory_sections (device_id, section, hash) VALUES ($1, $2, $3) \
         ON CONFLICT (device_id, section) DO UPDATE SET hash = EXCLUDED.hash, updated_at = now()",
    )
    .bind(device_id)
    .bind(section.as_str())
    .bind(hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

type BasicRow = (
    String,
    Option<String>,
    bool,
    Option<String>,
    Option<String>,
    Option<i32>,
);
type HardwareRow = (Option<String>, Option<String>, Option<String>, i64, String);
type SoftwareRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);
type ServiceRow = (String, Option<String>, String, String, Option<String>);
pub(crate) type SecurityRow = (String, String, String, String, String);

fn json<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_string(v).expect("serializable")
}

/// serde 的 enum 標籤（例如 RegState::Present → "present"）
fn label<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub(crate) fn from_label<T: serde::de::DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.into())).ok()
}

/// 讀回的 jsonb 解析失敗時（手動改壞）當成收集失敗，不讓整個讀取失敗
pub(crate) fn security_from_row(r: SecurityRow) -> SecurityInfo {
    fn parse<T: serde::de::DeserializeOwned>(s: &str) -> Probe<T> {
        serde_json::from_str(s)
            .unwrap_or_else(|e| Probe::Error(format!("stored data unreadable: {e}")))
    }
    SecurityInfo {
        firewall: parse(&r.0),
        bitlocker: parse(&r.1),
        defender: parse(&r.2),
        password: parse(&r.3),
        admins: parse(&r.4),
    }
}

/// 從資料庫重建區段內容；從未上傳過（無 inventory_sections 列）則回 None。
pub async fn load_payload(
    conn: &mut PgConnection,
    device_id: Uuid,
    section: Section,
) -> Result<Option<InventoryPayload>, sqlx::Error> {
    let exists: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM inventory_sections WHERE device_id = $1 AND section = $2",
    )
    .bind(device_id)
    .bind(section.as_str())
    .fetch_optional(&mut *conn)
    .await?;
    if exists.is_none() {
        return Ok(None);
    }
    let payload = match section {
        Section::Security => {
            let row: SecurityRow = sqlx::query_as(
                "SELECT firewall::text, bitlocker::text, defender::text, password::text, \
                        admins::text FROM device_security WHERE device_id = $1",
            )
            .bind(device_id)
            .fetch_one(&mut *conn)
            .await?;
            InventoryPayload::Security(security_from_row(row))
        }
        Section::Registry => {
            let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
                "SELECT path, name, state, kind, data FROM device_registry \
                 WHERE device_id = $1 ORDER BY path, name",
            )
            .bind(device_id)
            .fetch_all(&mut *conn)
            .await?;
            InventoryPayload::Registry(
                rows.into_iter()
                    .map(|(path, name, state, kind, data)| RegistryValue {
                        path,
                        name,
                        state: from_label(&state).unwrap_or(RegState::Absent),
                        kind: from_label(&kind).unwrap_or(RegKind::Other),
                        data,
                    })
                    .collect(),
            )
        }
        Section::Basic => {
            let (hostname, domain, is_domain_joined, os_caption, os_build, os_ubr): BasicRow =
                sqlx::query_as(
                    "SELECT hostname, domain, is_domain_joined, os_caption, os_build, os_ubr \
                     FROM devices WHERE id = $1",
                )
                .bind(device_id)
                .fetch_one(&mut *conn)
                .await?;
            InventoryPayload::Basic(BasicInfo {
                hostname,
                domain,
                is_domain_joined,
                os_caption: os_caption.unwrap_or_default(),
                os_build: os_build.unwrap_or_default(),
                os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
            })
        }
        Section::Hardware => {
            let (manufacturer, model, cpu, ram_mb, disks): HardwareRow = sqlx::query_as(
                "SELECT manufacturer, model, cpu, ram_mb, disks::text \
                 FROM device_hardware WHERE device_id = $1",
            )
            .bind(device_id)
            .fetch_one(&mut *conn)
            .await?;
            let disks: Vec<Disk> = serde_json::from_str(&disks).unwrap_or_default();
            InventoryPayload::Hardware(HardwareInfo {
                manufacturer,
                model,
                cpu,
                ram_mb: ram_mb as u64,
                disks,
            })
        }
        Section::Software => {
            let rows: Vec<SoftwareRow> = sqlx::query_as(
                "SELECT name, version, publisher, install_date, arch \
                 FROM device_software WHERE device_id = $1",
            )
            .bind(device_id)
            .fetch_all(&mut *conn)
            .await?;
            InventoryPayload::Software(
                rows.into_iter()
                    .map(
                        |(name, version, publisher, install_date, arch)| SoftwareItem {
                            name,
                            version,
                            publisher,
                            install_date,
                            arch: Arch::parse(&arch).unwrap_or(Arch::X64),
                        },
                    )
                    .collect(),
            )
        }
        Section::Patches => {
            let rows: Vec<(String, Option<String>)> =
                sqlx::query_as("SELECT kb, installed_on FROM device_patches WHERE device_id = $1")
                    .bind(device_id)
                    .fetch_all(&mut *conn)
                    .await?;
            InventoryPayload::Patches(
                rows.into_iter()
                    .map(|(kb, installed_on)| PatchItem { kb, installed_on })
                    .collect(),
            )
        }
        Section::Services => {
            let rows: Vec<ServiceRow> = sqlx::query_as(
                "SELECT name, display_name, start_mode, state, binary_path \
                 FROM device_services WHERE device_id = $1",
            )
            .bind(device_id)
            .fetch_all(&mut *conn)
            .await?;
            InventoryPayload::Services(
                rows.into_iter()
                    .map(
                        |(name, display_name, start_mode, state, binary_path)| ServiceItem {
                            name,
                            display_name,
                            start_mode,
                            state,
                            binary_path,
                        },
                    )
                    .collect(),
            )
        }
    };
    Ok(Some(payload))
}

async fn write_payload(
    conn: &mut PgConnection,
    device_id: Uuid,
    payload: &InventoryPayload,
) -> Result<(), sqlx::Error> {
    match payload {
        InventoryPayload::Security(s) => {
            sqlx::query(
                "INSERT INTO device_security \
                 (device_id, firewall, bitlocker, defender, password, admins) \
                 VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5::jsonb, $6::jsonb) \
                 ON CONFLICT (device_id) DO UPDATE SET firewall = EXCLUDED.firewall, \
                   bitlocker = EXCLUDED.bitlocker, defender = EXCLUDED.defender, \
                   password = EXCLUDED.password, admins = EXCLUDED.admins, updated_at = now()",
            )
            .bind(device_id)
            .bind(json(&s.firewall))
            .bind(json(&s.bitlocker))
            .bind(json(&s.defender))
            .bind(json(&s.password))
            .bind(json(&s.admins))
            .execute(&mut *conn)
            .await?;
        }
        InventoryPayload::Registry(v) => {
            // 只寫入有變動的值（每台可能有上千個值，大多數上傳都沒變）：
            // 刪掉不在新清單的值，新增或更新有差異的值，相同的值不產生寫入
            let paths: Vec<&str> = v.iter().map(|r| r.path.as_str()).collect();
            let names: Vec<&str> = v.iter().map(|r| r.name.as_str()).collect();
            let states: Vec<String> = v.iter().map(|r| label(&r.state)).collect();
            let kinds: Vec<String> = v.iter().map(|r| label(&r.kind)).collect();
            let data: Vec<&str> = v.iter().map(|r| r.data.as_str()).collect();
            sqlx::query(
                "DELETE FROM device_registry r WHERE r.device_id = $1 AND NOT EXISTS ( \
                   SELECT 1 FROM UNNEST($2::text[], $3::text[]) AS x(p, n) \
                   WHERE x.p = r.path AND x.n = r.name)",
            )
            .bind(device_id)
            .bind(&paths)
            .bind(&names)
            .execute(&mut *conn)
            .await?;
            // 同一個值重複時只取第一筆（ON CONFLICT DO UPDATE 不能在同一句更新同一列兩次）
            sqlx::query(
                "INSERT INTO device_registry (device_id, path, name, state, kind, data) \
                 SELECT DISTINCT ON (p, n) $1, p, n, s, k, d \
                 FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[]) \
                      WITH ORDINALITY AS x(p, n, s, k, d, i) \
                 ORDER BY p, n, i \
                 ON CONFLICT (device_id, path, name) DO UPDATE \
                 SET state = EXCLUDED.state, kind = EXCLUDED.kind, data = EXCLUDED.data \
                 WHERE (device_registry.state, device_registry.kind, device_registry.data) \
                       IS DISTINCT FROM (EXCLUDED.state, EXCLUDED.kind, EXCLUDED.data)",
            )
            .bind(device_id)
            .bind(&paths)
            .bind(&names)
            .bind(&states)
            .bind(&kinds)
            .bind(&data)
            .execute(&mut *conn)
            .await?;
        }
        InventoryPayload::Basic(b) => {
            sqlx::query(
                "UPDATE devices SET hostname = $2, domain = $3, is_domain_joined = $4, \
                 os_caption = $5, os_build = $6, os_ubr = $7 WHERE id = $1",
            )
            .bind(device_id)
            .bind(&b.hostname)
            .bind(&b.domain)
            .bind(b.is_domain_joined)
            .bind(&b.os_caption)
            .bind(&b.os_build)
            .bind(b.os_ubr.and_then(|u| i32::try_from(u).ok()))
            .execute(&mut *conn)
            .await?;
        }
        InventoryPayload::Hardware(h) => {
            sqlx::query(
                "INSERT INTO device_hardware (device_id, manufacturer, model, cpu, ram_mb, disks) \
                 VALUES ($1, $2, $3, $4, $5, $6::jsonb) \
                 ON CONFLICT (device_id) DO UPDATE SET manufacturer = EXCLUDED.manufacturer, \
                 model = EXCLUDED.model, cpu = EXCLUDED.cpu, ram_mb = EXCLUDED.ram_mb, \
                 disks = EXCLUDED.disks",
            )
            .bind(device_id)
            .bind(&h.manufacturer)
            .bind(&h.model)
            .bind(&h.cpu)
            .bind(h.ram_mb as i64)
            .bind(serde_json::to_string(&h.disks).expect("serializable"))
            .execute(&mut *conn)
            .await?;
        }
        InventoryPayload::Software(v) => {
            sqlx::query("DELETE FROM device_software WHERE device_id = $1")
                .bind(device_id)
                .execute(&mut *conn)
                .await?;
            let names: Vec<&str> = v.iter().map(|s| s.name.as_str()).collect();
            let versions: Vec<Option<&str>> = v.iter().map(|s| s.version.as_deref()).collect();
            let publishers: Vec<Option<&str>> = v.iter().map(|s| s.publisher.as_deref()).collect();
            let dates: Vec<Option<&str>> = v.iter().map(|s| s.install_date.as_deref()).collect();
            let arches: Vec<&str> = v.iter().map(|s| s.arch.as_str()).collect();
            sqlx::query(
                "INSERT INTO device_software (device_id, name, version, publisher, install_date, arch) \
                 SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])",
            )
            .bind(device_id)
            .bind(&names)
            .bind(&versions)
            .bind(&publishers)
            .bind(&dates)
            .bind(&arches)
            .execute(&mut *conn)
            .await?;
        }
        InventoryPayload::Patches(v) => {
            sqlx::query("DELETE FROM device_patches WHERE device_id = $1")
                .bind(device_id)
                .execute(&mut *conn)
                .await?;
            let kbs: Vec<&str> = v.iter().map(|p| p.kb.as_str()).collect();
            let dates: Vec<Option<&str>> = v.iter().map(|p| p.installed_on.as_deref()).collect();
            sqlx::query(
                "INSERT INTO device_patches (device_id, kb, installed_on) \
                 SELECT $1, * FROM UNNEST($2::text[], $3::text[])",
            )
            .bind(device_id)
            .bind(&kbs)
            .bind(&dates)
            .execute(&mut *conn)
            .await?;
        }
        InventoryPayload::Services(v) => {
            sqlx::query("DELETE FROM device_services WHERE device_id = $1")
                .bind(device_id)
                .execute(&mut *conn)
                .await?;
            let names: Vec<&str> = v.iter().map(|s| s.name.as_str()).collect();
            let display: Vec<Option<&str>> = v.iter().map(|s| s.display_name.as_deref()).collect();
            let modes: Vec<&str> = v.iter().map(|s| s.start_mode.as_str()).collect();
            let states: Vec<&str> = v.iter().map(|s| s.state.as_str()).collect();
            let paths: Vec<Option<&str>> = v.iter().map(|s| s.binary_path.as_deref()).collect();
            sqlx::query(
                "INSERT INTO device_services \
                 (device_id, name, display_name, start_mode, state, binary_path) \
                 SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])",
            )
            .bind(device_id)
            .bind(&names)
            .bind(&display)
            .bind(&modes)
            .bind(&states)
            .bind(&paths)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}
