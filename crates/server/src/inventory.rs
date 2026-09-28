//! /v1/inventory/{section}：接收整個區段，比對差異後在同一交易內替換。

use std::io::Read;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use flate2::read::GzDecoder;
use protocol::{
    Arch, BasicInfo, Disk, HardwareInfo, InventoryPayload, InventoryUpload, PatchItem,
    SCHEMA_VERSION, Section, ServiceItem, SoftwareItem,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::AppState;
use crate::diff::{diff, items_of};
use crate::error::AppError;
use crate::identity::AuthedDevice;

pub const MAX_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024;

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
    // 不佔住處理報到的 async 執行緒
    let (payload, hash) =
        tokio::task::spawn_blocking(move || parse_upload(section, &headers, &body))
            .await
            .map_err(|e| AppError::Internal(e.into()))??;
    store_section(&st.pool, device.device_id, &payload, &hash).await?;
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

type BasicRow = (String, Option<String>, bool, Option<String>, Option<String>);
type HardwareRow = (Option<String>, Option<String>, Option<String>, i64, String);
type SoftwareRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);
type ServiceRow = (String, Option<String>, String, String, Option<String>);

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
        Section::Basic => {
            let (hostname, domain, is_domain_joined, os_caption, os_build): BasicRow =
                sqlx::query_as(
                    "SELECT hostname, domain, is_domain_joined, os_caption, os_build \
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
        InventoryPayload::Basic(b) => {
            sqlx::query(
                "UPDATE devices SET hostname = $2, domain = $3, is_domain_joined = $4, \
                 os_caption = $5, os_build = $6 WHERE id = $1",
            )
            .bind(device_id)
            .bind(&b.hostname)
            .bind(&b.domain)
            .bind(b.is_domain_joined)
            .bind(&b.os_caption)
            .bind(&b.os_build)
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
