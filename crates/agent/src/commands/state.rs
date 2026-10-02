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

    /// 刪掉已回報而且開始超過 30 天的紀錄；還沒回報的保留到 31 天
    /// （指令最長 30 天過期，之後伺服器不再接受結果，留著也送不出去）。
    /// 仍在下發清單（active）中的一律保留：清掉會被當成新指令重跑
    pub fn prune(&mut self, active: &[i64], now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::days(FORGET_AFTER_DAYS);
        let hard = now - chrono::Duration::days(FORGET_AFTER_DAYS + 1);
        self.entries.retain(|id, e| match e.started_at {
            _ if active.contains(id) => true,
            None => true,
            Some(t) if t < hard => false,
            Some(t) => !e.reported || t >= cutoff,
        });
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
        s.entries.insert(2, entry(10, false));
        s.entries.insert(3, entry(29, true));
        // 沒回報出去的紀錄：指令最長 30 天過期，超過 31 天也清掉
        s.entries.insert(4, entry(32, false));
        s.save(dir.path()).unwrap();
        assert_eq!(CommandsState::load(dir.path()), s);
        s.prune(&[], Utc::now());
        assert_eq!(s.entries.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        // 仍在伺服器下發清單中的指令一律保留：清掉會被當成新指令重跑
        s.entries.insert(5, entry(40, false));
        s.entries.insert(6, entry(40, true));
        s.prune(&[5, 6], Utc::now());
        assert_eq!(
            s.entries.keys().copied().collect::<Vec<_>>(),
            vec![2, 3, 5, 6]
        );
        std::fs::write(dir.path().join(FILE), b"{oops").unwrap();
        assert_eq!(CommandsState::load(dir.path()), CommandsState::default());
    }
}
