//! /v1/checkin：記錄心跳，告訴 Agent 要上傳哪些區段。

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Duration, Utc};
use protocol::{
    CheckinRequest, CheckinResponse, OsFamily, SCHEMA_VERSION, Section, validate_strings,
};

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
    // 端點時鐘可能不準：夾限而不拒絕，避免該電腦永遠報到失敗
    let boot_time = req.boot_time.clamp(earliest, now);

    st.heartbeat.record(
        device.device_id,
        HotFields {
            seen_at: now,
            ip: req.ip_addresses.first().cloned(),
            logged_on_user: req.logged_on_user.clone(),
            boot_time,
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
    let rules = st.rules.get_throttled(&st.pool).await?;
    // 只有使用中的裝置會收到派送、更新原則與遠端指令
    let (group_id, status, stored_os): (Option<i64>, String, String) =
        sqlx::query_as("SELECT group_id, status, os_family FROM devices WHERE id = $1")
            .bind(device.device_id)
            .fetch_one(&st.pool)
            .await?;
    // Agent 回報的作業系統類型與記錄不同才寫入；沒帶（舊版 Agent）就維持原值
    let mut is_linux = stored_os == OsFamily::Linux.as_str();
    if let Some(os) = req.os_family
        && os.as_str() != stored_os
    {
        sqlx::query("UPDATE devices SET os_family = $2 WHERE id = $1")
            .bind(device.device_id)
            .bind(os.as_str())
            .execute(&st.pool)
            .await?;
        is_linux = os == OsFamily::Linux;
    }
    let deploy = st.deploy.get_throttled(&st.pool).await?;
    let updates = st.updates.get_throttled(&st.pool).await?;
    let branch = st.branch.get_throttled(&st.pool).await?;
    let commands = if status == "active" {
        crate::commands::api::pending_for(&st.pool, device.device_id).await?
    } else {
        vec![]
    };
    // 派送、更新原則、登錄檔查詢、套件來源都只適用 Windows；Linux 一律回傳「空」與其 hash
    let (deployments, update_policy, package_source) = if status == "active" && !is_linux {
        (
            deploy.assignments_for(group_id),
            updates.policy_for(group_id),
            branch.source_for(&req.ip_addresses),
        )
    } else {
        (vec![], None, None)
    };
    let (registry_queries, registry_queries_hash) = if is_linux {
        (vec![], protocol::regpath::queries_hash(&[]))
    } else {
        (rules.registry_queries.clone(), rules.registry_hash.clone())
    };
    Ok(Json(CheckinResponse {
        next_checkin_seconds: settings.checkin_interval_secs,
        request_sections: sections_to_request(&stored, &req.section_hashes),
        collection_intervals: settings.intervals,
        renew_certificate: device.cert_not_after - Utc::now() < Duration::days(RENEW_BEFORE_DAYS),
        registry_queries,
        registry_queries_hash: Some(registry_queries_hash),
        deployments_hash: Some(protocol::deploy::assignments_hash(&deployments)),
        deployments,
        update_policy_hash: Some(protocol::update::update_policy_hash(update_policy.as_ref())),
        update_policy,
        commands,
        package_source,
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
