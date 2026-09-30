//! 第五期：Windows Update 原則（伺服器下發）與套用狀態（Agent 回報）。

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Agent 唯一會寫入的值（`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` 底下）
pub const VALUE_NAMES: [&str; 17] = [
    "DeferQualityUpdates",
    "DeferQualityUpdatesPeriodInDays",
    "PauseQualityUpdatesStartTime",
    "DeferFeatureUpdates",
    "DeferFeatureUpdatesPeriodInDays",
    "PauseFeatureUpdatesStartTime",
    "SetComplianceDeadline",
    "ConfigureDeadlineForQualityUpdates",
    "ConfigureDeadlineGracePeriod",
    "SetComplianceDeadlineForFU",
    "ConfigureDeadlineForFeatureUpdates",
    "ConfigureDeadlineGracePeriodForFeatureUpdates",
    "ConfigureDeadlineNoAutoReboot",
    "ConfigureDeadlineNoAutoRebootForFeatureUpdates",
    "SetActiveHours",
    "ActiveHoursStart",
    "ActiveHoursEnd",
];

pub const MAX_DETAIL_LEN: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    from = "RawData"
)]
pub enum PolicyData {
    Dword(u32),
    String(String),
    /// 較新伺服器的型別：舊 Agent 仍能解析，但不套用整份原則
    Unknown,
}

/// serde 的 `other` 在 adjacently tagged enum 只接受沒有內容的值，所以先讀成原始形式再轉換
#[derive(Deserialize)]
struct RawData {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    value: serde_json::Value,
}

impl From<RawData> for PolicyData {
    fn from(r: RawData) -> Self {
        match (r.kind.as_str(), r.value) {
            ("dword", serde_json::Value::Number(n)) => n
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .map_or(PolicyData::Unknown, PolicyData::Dword),
            ("string", serde_json::Value::String(s)) => PolicyData::String(s),
            _ => PolicyData::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyValue {
    pub name: String,
    pub data: PolicyData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePolicy {
    pub id: i64,
    pub revision: i32,
    pub values: Vec<PolicyValue>,
}

/// 原則的雜湊（values 依名稱排序）：Agent 用來判斷原則有沒有變；None 也有自己的雜湊
pub fn update_policy_hash(p: Option<&UpdatePolicy>) -> String {
    let sorted = p.map(|p| {
        let mut p = p.clone();
        p.values.sort_by(|a, b| a.name.cmp(&b.name));
        p
    });
    let json = serde_json::to_vec(&sorted).expect("serializable");
    hex::encode(Sha256::digest(&json))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyState {
    Unmanaged,
    Applied,
    Conflict,
    Error,
    #[serde(other)]
    Unknown,
}

impl ApplyState {
    pub fn as_str(self) -> &'static str {
        match self {
            ApplyState::Unmanaged => "unmanaged",
            ApplyState::Applied => "applied",
            ApplyState::Conflict => "conflict",
            ApplyState::Error => "error",
            ApplyState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateStatus {
    pub policy_id: Option<i64>,
    pub revision: Option<i32>,
    pub state: ApplyState,
    /// 衝突的值名稱或錯誤原因
    #[serde(default)]
    pub detail: String,
    pub reboot_pending: bool,
    pub reboot_pending_since: Option<DateTime<Utc>>,
    pub last_patch_date: Option<NaiveDate>,
}

impl UpdateStatus {
    /// 端點時鐘或時區可能差一點：容許比伺服器現在晚 1 天
    pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> {
        if self.detail.chars().count() > MAX_DETAIL_LEN {
            return Err("detail too long");
        }
        if self.detail.contains('\0') {
            return Err("detail contains NUL");
        }
        if self.state == ApplyState::Unknown {
            return Err("unknown state");
        }
        let limit = now + Duration::days(1);
        if self.reboot_pending_since.is_some_and(|t| t > limit) {
            return Err("reboot_pending_since is in the future");
        }
        if self.last_patch_date.is_some_and(|d| d > limit.date_naive()) {
            return Err("last_patch_date is in the future");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn policy(values: Vec<PolicyValue>) -> UpdatePolicy {
        UpdatePolicy {
            id: 1,
            revision: 1,
            values,
        }
    }

    fn dword(name: &str, v: u32) -> PolicyValue {
        PolicyValue {
            name: name.into(),
            data: PolicyData::Dword(v),
        }
    }

    fn status() -> UpdateStatus {
        UpdateStatus {
            policy_id: Some(1),
            revision: Some(1),
            state: ApplyState::Applied,
            detail: String::new(),
            reboot_pending: false,
            reboot_pending_since: None,
            last_patch_date: None,
        }
    }

    #[test]
    fn old_checkin_response_parses_without_policy() {
        let r: crate::CheckinResponse = serde_json::from_str(
            r#"{"next_checkin_seconds":60,"request_sections":[],
                "collection_intervals":{"hardware_secs":1,"software_secs":1,"patches_secs":1,
                "services_secs":1},"renew_certificate":false}"#,
        )
        .unwrap();
        assert!(r.update_policy.is_none() && r.update_policy_hash.is_none());
    }

    #[test]
    fn unknown_data_type_parses() {
        let v: PolicyValue =
            serde_json::from_str(r#"{"name":"X","data":{"type":"qword","value":1}}"#).unwrap();
        assert_eq!(v.data, PolicyData::Unknown);
        let v: PolicyValue = serde_json::from_str(
            r#"{"name":"PauseQualityUpdatesStartTime","data":{"type":"string","value":"2026-09-30"}}"#,
        )
        .unwrap();
        assert_eq!(v.data, PolicyData::String("2026-09-30".into()));
    }

    #[test]
    fn hash_ignores_value_order() {
        let a = policy(vec![dword("A", 1), dword("B", 2)]);
        let b = policy(vec![dword("B", 2), dword("A", 1)]);
        assert_eq!(update_policy_hash(Some(&a)), update_policy_hash(Some(&b)));
        assert_ne!(
            update_policy_hash(None),
            update_policy_hash(Some(&policy(vec![])))
        );
        let c = policy(vec![dword("A", 1), dword("B", 3)]);
        assert_ne!(update_policy_hash(Some(&a)), update_policy_hash(Some(&c)));
    }

    #[test]
    fn unknown_state_parses() {
        let s: ApplyState = serde_json::from_str(r#""weird""#).unwrap();
        assert_eq!(s, ApplyState::Unknown);
        assert_eq!(
            serde_json::to_string(&ApplyState::Conflict).unwrap(),
            r#""conflict""#
        );
    }

    #[test]
    fn status_validation() {
        let now = Utc.with_ymd_and_hms(2026, 9, 30, 12, 0, 0).unwrap();
        assert!(status().validate(now).is_ok());
        let mut s = status();
        s.detail = "字".repeat(MAX_DETAIL_LEN);
        assert!(s.validate(now).is_ok());
        s.detail.push('x');
        assert!(s.validate(now).is_err());
        let mut s = status();
        s.detail = "a\0b".into();
        assert!(s.validate(now).is_err());
        let mut s = status();
        s.state = ApplyState::Unknown;
        assert!(s.validate(now).is_err());
        let mut s = status();
        s.last_patch_date = Some(NaiveDate::from_ymd_opt(2026, 10, 1).unwrap());
        assert!(s.validate(now).is_ok(), "明天（時區差）可接受");
        s.last_patch_date = Some(NaiveDate::from_ymd_opt(2026, 10, 2).unwrap());
        assert!(s.validate(now).is_err());
        let mut s = status();
        s.reboot_pending_since = Some(now + Duration::hours(23));
        assert!(s.validate(now).is_ok());
        s.reboot_pending_since = Some(now + Duration::hours(25));
        assert!(s.validate(now).is_err());
    }

    #[test]
    fn value_names_are_unique() {
        let mut v = VALUE_NAMES.to_vec();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), VALUE_NAMES.len());
    }
}
