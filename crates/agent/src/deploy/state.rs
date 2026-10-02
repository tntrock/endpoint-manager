//! 派送的本機狀態（`deploy.json`）：每個派送的嘗試次數、上次結果、已回報的狀態。

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use protocol::deploy::{DeployResult, DeployStatus};
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
    /// 還沒送出的結果（伺服器暫時連不上）：下一輪先補送
    #[serde(default)]
    pub unreported: Option<DeployResult>,
    /// 正在執行安裝程式（執行前寫入）：啟動時仍為 true 代表上次被中斷
    #[serde(default)]
    pub in_progress: bool,
    /// 最後一次出現在指派清單的時間：暫停期間指派會消失，不能立刻清掉紀錄
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
    /// 這個 revision 安裝成功的時間（最近 24 小時）：被其他工具一再移除時不再重裝
    #[serde(default)]
    pub installs: Vec<DateTime<Utc>>,
}

/// 多久沒出現在指派清單才清掉紀錄
pub const FORGET_AFTER_DAYS: i64 = 30;

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
        crate::state::write_atomic(
            &dir.join(STATE_FILE),
            &serde_json::to_vec(self).expect("serializable"),
        )
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

    /// 記下這次出現的派送；超過 FORGET_AFTER_DAYS 沒出現的才清掉
    /// （暫停中的派送不會下發，繼續後仍要沿用嘗試次數與已回報的狀態）
    pub fn prune(&mut self, active: &[i64], now: DateTime<Utc>) {
        for id in active {
            if let Some(e) = self.entries.get_mut(id) {
                e.last_seen = Some(now);
            }
        }
        let cutoff = now - chrono::Duration::days(FORGET_AFTER_DAYS);
        self.entries
            .retain(|id, e| active.contains(id) || e.last_seen.is_some_and(|t| t > cutoff));
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
        let now = chrono::Utc::now();
        back.prune(&[5, 6], now);
        back.prune(&[5], now + chrono::Duration::days(1));
        assert!(
            back.entries.contains_key(&6),
            "暫時沒出現（例如暫停）要保留"
        );
        back.prune(&[5], now + chrono::Duration::days(31));
        assert!(!back.entries.contains_key(&6), "30 天沒出現才清掉");
        std::fs::write(dir.path().join(STATE_FILE), b"{broken").unwrap();
        assert!(
            DeployState::load(dir.path()).entries.is_empty(),
            "壞檔當空的"
        );
    }
}
