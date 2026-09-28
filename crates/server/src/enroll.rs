//! /v1/enroll：以註冊金鑰換取裝置憑證。

use std::net::SocketAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use chrono::Utc;
use protocol::{EnrollRequest, EnrollResponse, SCHEMA_VERSION, validate_strings};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::tokens;

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceMatch {
    Reuse(Uuid),
    NewDuplicateSuspect,
    New,
}

/// 候選裝置：(id, bios_serial, 最近 10 分鐘內有報到)。
/// 仍在線上的裝置不會被接管，避免硬體識別重複或被偽造時把正常電腦踢下線。
pub fn match_device(
    candidates: &[(Uuid, Option<String>, bool)],
    bios_serial: Option<&str>,
) -> DeviceMatch {
    if let Some(serial) = normalize_serial(bios_serial)
        && let Some((id, _, recent)) = candidates
            .iter()
            .find(|(_, s, _)| s.as_deref() == Some(serial))
        && !recent
    {
        return DeviceMatch::Reuse(*id);
    }
    if candidates.is_empty() {
        DeviceMatch::New
    } else {
        DeviceMatch::NewDuplicateSuspect
    }
}

/// 白牌主機板常見的共用 SMBIOS UUID。
const PLACEHOLDER_SMBIOS: &[&str] = &["03000200-0400-0500-0006-000700080009"];

/// 常見的佔位序號（比對時忽略大小寫）。
const PLACEHOLDER_SERIALS: &[&str] = &[
    "0",
    "default string",
    "to be filled by o.e.m.",
    "system serial number",
    "chassis serial number",
    "not specified",
    "not applicable",
    "none",
    "n/a",
    "123456789",
];

pub fn normalize_smbios(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim().to_ascii_uppercase();
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.is_empty()
        || hex.chars().all(|c| c == '0')
        || hex.chars().all(|c| c == 'F')
        || PLACEHOLDER_SMBIOS.contains(&s.as_str())
    {
        None
    } else {
        Some(s)
    }
}

pub fn normalize_serial(raw: Option<&str>) -> Option<&str> {
    let s = raw?.trim();
    let placeholder = s.is_empty()
        || PLACEHOLDER_SERIALS
            .iter()
            .any(|p| p.eq_ignore_ascii_case(s));
    (!placeholder).then_some(s)
}

pub async fn enroll(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, AppError> {
    if !st.enroll_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    if req.schema_version > SCHEMA_VERSION {
        return Err(AppError::BadRequest("unsupported schema_version".into()));
    }
    validate_strings(&(
        &req.hostname,
        &req.smbios_uuid,
        &req.bios_serial,
        &req.mac_addresses,
    ))?;

    let mut tx = st.pool.begin().await?;
    let (token_id, group_id) = tokens::consume_token(&mut tx, &req.enroll_token)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let smbios = normalize_smbios(req.smbios_uuid.as_deref());
    let serial = normalize_serial(req.bios_serial.as_deref());
    let candidates: Vec<(Uuid, Option<String>, bool)> = match &smbios {
        Some(u) => {
            sqlx::query_as(
                "SELECT id, bios_serial, \
                        coalesce(last_seen_at > now() - interval '10 minutes', false) \
                 FROM devices \
                 WHERE smbios_uuid = $1 AND status <> 'retired' FOR UPDATE",
            )
            .bind(u)
            .fetch_all(&mut *tx)
            .await?
        }
        None => vec![],
    };

    let device_id = match match_device(&candidates, serial) {
        DeviceMatch::Reuse(id) => {
            sqlx::query(
                "UPDATE device_certs SET revoked_at = now() \
                 WHERE device_id = $1 AND revoked_at IS NULL",
            )
            .bind(id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("UPDATE devices SET hostname = $2, enroll_token_id = $3 WHERE id = $1")
                .bind(id)
                .bind(&req.hostname)
                .bind(token_id)
                .execute(&mut *tx)
                .await?;
            id
        }
        m => {
            let id = Uuid::new_v4();
            let status = if m == DeviceMatch::NewDuplicateSuspect {
                "duplicate_suspect"
            } else {
                "active"
            };
            sqlx::query(
                "INSERT INTO devices (id, hostname, smbios_uuid, bios_serial, status, enroll_token_id, group_id) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(id)
            .bind(&req.hostname)
            .bind(&smbios)
            .bind(serial)
            .bind(status)
            .bind(token_id)
            .bind(group_id)
            .execute(&mut *tx)
            .await?;
            id
        }
    };

    let issued = st
        .ca
        .sign_device_csr(&req.csr_pem, device_id, Utc::now())
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    sqlx::query(
        "INSERT INTO device_certs (serial, fingerprint, device_id, not_after) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&issued.serial)
    .bind(&issued.fingerprint)
    .bind(device_id)
    .bind(issued.not_after)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    tracing::info!(%device_id, token_id, "device enrolled");
    Ok(Json(EnrollResponse {
        device_id,
        certificate_chain_pem: format!("{}{}", issued.pem, st.ca.chain_pem()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_serial_reuses() {
        let id = Uuid::new_v4();
        assert_eq!(
            match_device(&[(id, Some("SN1".into()), false)], Some("SN1")),
            DeviceMatch::Reuse(id)
        );
    }

    #[test]
    fn recently_seen_device_is_never_taken_over() {
        assert_eq!(
            match_device(&[(Uuid::new_v4(), Some("SN1".into()), true)], Some("SN1")),
            DeviceMatch::NewDuplicateSuspect
        );
    }

    #[test]
    fn different_serial_is_duplicate_suspect() {
        assert_eq!(
            match_device(&[(Uuid::new_v4(), Some("SN1".into()), false)], Some("SN2")),
            DeviceMatch::NewDuplicateSuspect
        );
    }

    #[test]
    fn missing_serial_never_reuses() {
        assert_eq!(
            match_device(&[(Uuid::new_v4(), None, false)], None),
            DeviceMatch::NewDuplicateSuspect
        );
    }

    #[test]
    fn no_candidates_is_new() {
        assert_eq!(match_device(&[], Some("SN1")), DeviceMatch::New);
    }

    #[test]
    fn bogus_smbios_ignored() {
        for bogus in [
            "00000000-0000-0000-0000-000000000000",
            "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
            "03000200-0400-0500-0006-000700080009",
            "  ",
        ] {
            assert_eq!(normalize_smbios(Some(bogus)), None, "{bogus}");
        }
        assert_eq!(
            normalize_smbios(Some("4c4c4544-0042")),
            Some("4C4C4544-0042".into())
        );
    }

    #[test]
    fn placeholder_serials_ignored() {
        for bogus in [
            "Default string",
            "To Be Filled By O.E.M.",
            "System Serial Number",
            "0",
            "  none ",
            "",
        ] {
            assert_eq!(normalize_serial(Some(bogus)), None, "{bogus}");
        }
        assert_eq!(normalize_serial(Some(" 5CG1234XYZ ")), Some("5CG1234XYZ"));
    }
}
