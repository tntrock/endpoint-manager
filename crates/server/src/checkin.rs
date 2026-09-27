//! /v1/checkin：記錄心跳，告訴 Agent 要上傳哪些區段。

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Duration, Utc};
use protocol::{CheckinRequest, CheckinResponse, SCHEMA_VERSION, Section, validate_strings};

use crate::AppState;
use crate::db::load_settings;
use crate::error::AppError;
use crate::heartbeat::HotFields;
use crate::identity::AuthedDevice;

pub const RENEW_BEFORE_DAYS: i64 = 30;

pub fn sections_to_request(
    stored: &HashMap<Section, String>,
    reported: &BTreeMap<Section, String>,
) -> Vec<Section> {
    reported
        .iter()
        .filter(|(s, h)| stored.get(s) != Some(*h))
        .map(|(s, _)| *s)
        .collect()
}

pub async fn checkin(
    State(st): State<AppState>,
    device: AuthedDevice,
    Json(req): Json<CheckinRequest>,
) -> Result<Json<CheckinResponse>, AppError> {
    if req.schema_version > SCHEMA_VERSION {
        return Err(AppError::BadRequest("unsupported schema_version".into()));
    }
    validate_strings(&req)?;
    let now = Utc::now();
    let earliest = DateTime::from_timestamp(946_684_800, 0).expect("2000-01-01");
    if req.boot_time < earliest || req.boot_time > now + Duration::days(1) {
        return Err(AppError::BadRequest("boot_time out of range".into()));
    }

    st.heartbeat.record(
        device.device_id,
        HotFields {
            seen_at: Utc::now(),
            ip: req.ip_addresses.first().cloned(),
            logged_on_user: req.logged_on_user.clone(),
            boot_time: req.boot_time,
            agent_version: req.agent_version.clone(),
            section_errors: serde_json::to_value(&req.section_errors).expect("serializable"),
        },
    );

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT section, hash FROM inventory_sections WHERE device_id = $1")
            .bind(device.device_id)
            .fetch_all(&st.pool)
            .await?;
    let stored: HashMap<Section, String> = rows
        .into_iter()
        .filter_map(|(s, h)| Section::parse(&s).map(|s| (s, h)))
        .collect();

    let settings = load_settings(&st.pool).await?;
    Ok(Json(CheckinResponse {
        next_checkin_seconds: settings.checkin_interval_secs,
        request_sections: sections_to_request(&stored, &req.section_hashes),
        collection_intervals: settings.intervals,
        renew_certificate: device.cert_not_after - Utc::now() < Duration::days(RENEW_BEFORE_DAYS),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_unknown_and_changed_sections_only() {
        let stored = HashMap::from([
            (Section::Software, "a".to_string()),
            (Section::Basic, "b".to_string()),
        ]);
        let reported = BTreeMap::from([
            (Section::Software, "a".to_string()),    // 相同 → 不要求
            (Section::Basic, "CHANGED".to_string()), // 變更 → 要求
            (Section::Patches, "x".to_string()),     // 伺服器沒有 → 要求
        ]);
        assert_eq!(
            sections_to_request(&stored, &reported),
            vec![Section::Basic, Section::Patches]
        );
    }
}
