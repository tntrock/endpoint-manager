//! 遠端指令的本機狀態（`commands.json`）：哪些指令開始過、結果、是否已回報。

use std::collections::BTreeMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use protocol::command::CommandResult;
use serde::{Deserialize, Serialize};

pub const FILE: &str = "commands.json";
/// 已回報的紀錄保留多久（伺服器最長 30 天過期，之後不會再送同一筆）
pub const FORGET_AFTER_DAYS: i64 = 30;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Entry {
    /// 開始執行的時間（執行前寫入）：有開始時間但沒有結果代表執行中斷
    pub started_at: Option<DateTime<Utc>>,
    pub result: Option<CommandResult>,
    /// 結果已成功送到伺服器
    pub reported: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandsState {
    /// 指令 id → 紀錄
    pub entries: BTreeMap<i64, Entry>,
}

impl CommandsState {
    /// 讀不到或壞掉時當成空的：伺服器重送的指令會被當成新指令再執行一次（README 註明）
    pub fn load(dir: &Path) -> CommandsState {
        match std::fs::read(dir.join(FILE)) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "commands state unreadable; starting fresh");
                CommandsState::default()
            }),
            Err(_) => CommandsState::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        crate::state::write_atomic(
            &dir.join(FILE),
            &serde_json::to_vec(self).expect("serializable"),
        )
    }

    /// 刪掉已回報而且開始超過 30 天的紀錄；還沒回報的保留
    pub fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::days(FORGET_AFTER_DAYS);
        self.entries
            .retain(|_, e| !e.reported || e.started_at.is_none_or(|t| t >= cutoff));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use protocol::command::{CommandResult, CommandStatus};

    fn entry(days_ago: i64, reported: bool) -> Entry {
        Entry {
            started_at: Some(Utc::now() - Duration::days(days_ago)),
            result: Some(CommandResult {
                status: CommandStatus::Failed,
                exit_code: Some(1),
                output: "x".into(),
            }),
            reported,
        }
    }

    #[test]
    fn round_trip_bad_file_and_prune() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(CommandsState::load(dir.path()), CommandsState::default());
        let mut s = CommandsState::default();
        s.entries.insert(1, entry(31, true));
        s.entries.insert(2, entry(31, false));
        s.entries.insert(3, entry(29, true));
        s.save(dir.path()).unwrap();
        assert_eq!(CommandsState::load(dir.path()), s);
        s.prune(Utc::now());
        assert_eq!(s.entries.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        std::fs::write(dir.path().join(FILE), b"{oops").unwrap();
        assert_eq!(CommandsState::load(dir.path()), CommandsState::default());
    }
}
