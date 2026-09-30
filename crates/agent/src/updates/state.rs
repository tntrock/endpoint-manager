//! WU 原則的本機狀態（`update_policy.json`）：套用結果、待重開機起始時間、上次回報。

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::logic::Applied;

pub const FILE: &str = "update_policy.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateState {
    pub applied: Applied,
    /// 第一次看到待重開機的時間；重開後清除
    pub reboot_pending_since: Option<DateTime<Utc>>,
    /// 上次成功送出的狀態雜湊與時間
    pub sent_hash: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
}

impl UpdateState {
    /// 讀不到或壞掉時當成空的：會重新寫入一次原則，但不會刪掉任何值
    pub fn load(dir: &Path) -> UpdateState {
        match std::fs::read(dir.join(FILE)) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "update policy state unreadable; starting fresh");
                UpdateState::default()
            }),
            Err(_) => UpdateState::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        crate::state::write_atomic(
            &dir.join(FILE),
            &serde_json::to_vec(self).expect("serializable"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::update::{ApplyState, PolicyData};

    #[test]
    fn round_trip_and_bad_files() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(UpdateState::load(dir.path()), UpdateState::default());
        let mut s = UpdateState::default();
        s.applied.policy_id = Some(3);
        s.applied.state = Some(ApplyState::Conflict);
        s.applied
            .written
            .insert("DeferQualityUpdates".into(), PolicyData::Dword(1));
        s.sent_hash = Some("h".into());
        s.save(dir.path()).unwrap();
        assert_eq!(UpdateState::load(dir.path()), s);
        std::fs::write(dir.path().join(FILE), b"{not json").unwrap();
        assert_eq!(UpdateState::load(dir.path()), UpdateState::default());
        std::fs::write(dir.path().join(FILE), br#"{"applied":{"policy_id":5}}"#).unwrap();
        assert_eq!(UpdateState::load(dir.path()).applied.policy_id, Some(5));
    }
}
