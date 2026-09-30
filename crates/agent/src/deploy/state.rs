//! 派送的本機狀態（`deploy.json`）：每個派送的嘗試次數、上次結果、已回報的狀態。

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use protocol::deploy::DeployStatus;
use serde::{Deserialize, Serialize};

pub const STATE_FILE: &str = "deploy.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub revision: i32,
    pub attempts: i32,
    pub last_attempt: Option<DateTime<Utc>>,
    pub last_failed: bool,
    /// 這個 revision 最後回報給伺服器的狀態（回報成功才記錄）
    pub reported: Option<DeployStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeployState {
    pub entries: BTreeMap<i64, Entry>,
}

impl DeployState {
    /// 讀不到或壞掉時當成空的：最多重新回報一次狀態，不影響安全
    pub fn load(dir: &Path) -> DeployState {
        match std::fs::read(dir.join(STATE_FILE)) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "deploy state unreadable; starting fresh");
                DeployState::default()
            }),
            Err(_) => DeployState::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let tmp = dir.join(format!("{STATE_FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec(self).expect("serializable"))?;
        std::fs::rename(&tmp, dir.join(STATE_FILE))
    }

    /// 取得（必要時建立）某派送的狀態；revision 不同時重設（管理員按了「重試失敗」）
    pub fn entry_for(&mut self, id: i64, revision: i32) -> &mut Entry {
        let e = self.entries.entry(id).or_default();
        if e.revision != revision {
            *e = Entry {
                revision,
                ..Entry::default()
            };
        }
        e
    }

    /// 不再被指派的派送不用記
    pub fn prune(&mut self, active: &[i64]) {
        self.entries.retain(|id, _| active.contains(id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::deploy::DeployStatus;

    #[test]
    fn state_roundtrip_reset_and_prune() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = DeployState::load(dir.path());
        assert!(s.entries.is_empty());
        let e = s.entry_for(5, 1);
        e.attempts = 2;
        e.reported = Some(DeployStatus::Failed);
        s.entry_for(6, 1).attempts = 1;
        s.save(dir.path()).unwrap();
        let mut back = DeployState::load(dir.path());
        assert_eq!(back.entries[&5].attempts, 2);
        // revision 改變時重設
        let e = back.entry_for(5, 2);
        assert_eq!((e.revision, e.attempts, e.reported), (2, 0, None));
        back.prune(&[5]);
        assert!(!back.entries.contains_key(&6));
        std::fs::write(dir.path().join(STATE_FILE), b"{broken").unwrap();
        assert!(
            DeployState::load(dir.path()).entries.is_empty(),
            "壞檔當空的"
        );
    }
}
