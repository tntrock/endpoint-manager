//! 第六期：遠端指令（伺服器隨報到下發，Agent 執行後回報結果）。

use serde::{Deserialize, Serialize};

/// 腳本內容上限（位元組）
pub const MAX_SCRIPT_BYTES: usize = 65536;
/// 回報輸出上限（位元組）：Agent 只保留最後這麼多
pub const MAX_OUTPUT_BYTES: usize = 65536;
/// 每次報到最多下發幾筆
pub const MAX_COMMANDS_PER_CHECKIN: i64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandAction {
    /// 重新收集全部盤點
    Collect,
    /// 立即套用派送與更新原則
    Apply,
    Reboot,
    Shutdown,
    Script,
    /// 較新伺服器的動作：舊 Agent 回報「不支援的指令」
    #[serde(other)]
    Unknown,
}

impl CommandAction {
    pub const ALL: [CommandAction; 5] = [
        CommandAction::Collect,
        CommandAction::Apply,
        CommandAction::Reboot,
        CommandAction::Shutdown,
        CommandAction::Script,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CommandAction::Collect => "collect",
            CommandAction::Apply => "apply",
            CommandAction::Reboot => "reboot",
            CommandAction::Shutdown => "shutdown",
            CommandAction::Script => "script",
            CommandAction::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> CommandAction {
        CommandAction::ALL
            .into_iter()
            .find(|a| a.as_str() == s)
            .unwrap_or(CommandAction::Unknown)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptSpec {
    pub sha256: String,
    pub content: String,
    pub timeout_minutes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    /// 這台這筆指令的 id（回報結果時用）
    pub id: i64,
    pub action: CommandAction,
    /// 重開機／關機前的延遲
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_minutes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script: Option<ScriptSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Succeeded,
    Failed,
    #[serde(other)]
    Unknown,
}

impl CommandStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CommandStatus::Succeeded => "succeeded",
            CommandStatus::Failed => "failed",
            CommandStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResult {
    pub status: CommandStatus,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub output: String,
}

impl CommandResult {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.status == CommandStatus::Unknown {
            return Err("unknown status");
        }
        if self.output.len() > MAX_OUTPUT_BYTES {
            return Err("output too long");
        }
        if self.output.contains('\0') {
            return Err("output contains NUL");
        }
        Ok(())
    }
}

/// 字串最後 max 個位元組以內的部分（從 UTF-8 字元邊界開始）
pub fn tail_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: CommandStatus, output: String) -> CommandResult {
        CommandResult {
            status,
            exit_code: Some(0),
            output,
        }
    }

    #[test]
    fn old_checkin_response_has_no_commands() {
        let r: crate::CheckinResponse = serde_json::from_str(
            r#"{"next_checkin_seconds":60,"request_sections":[],
                "collection_intervals":{"hardware_secs":1,"software_secs":1,"patches_secs":1,
                "services_secs":1},"renew_certificate":false}"#,
        )
        .unwrap();
        assert!(r.commands.is_empty());
    }

    #[test]
    fn unknown_action_and_round_trip() {
        let c: Command = serde_json::from_str(r#"{"id":1,"action":"format_disk"}"#).unwrap();
        assert_eq!(c.action, CommandAction::Unknown);
        let c = Command {
            id: 7,
            action: CommandAction::Reboot,
            delay_minutes: Some(10),
            script: None,
        };
        let back: Command = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
        assert_eq!(CommandAction::parse("script"), CommandAction::Script);
        assert_eq!(CommandAction::Shutdown.as_str(), "shutdown");
    }

    #[test]
    fn result_validation() {
        assert!(
            result(CommandStatus::Succeeded, "a".repeat(MAX_OUTPUT_BYTES))
                .validate()
                .is_ok()
        );
        assert!(
            result(CommandStatus::Succeeded, "a".repeat(MAX_OUTPUT_BYTES + 1))
                .validate()
                .is_err()
        );
        assert!(
            result(CommandStatus::Failed, "a\0b".into())
                .validate()
                .is_err()
        );
        assert!(
            result(CommandStatus::Unknown, String::new())
                .validate()
                .is_err()
        );
    }

    #[test]
    fn tail_keeps_char_boundaries() {
        assert_eq!(tail_utf8("中文abc", 4), "abc");
        assert_eq!(tail_utf8("中文abc", 6), "文abc");
        assert_eq!(tail_utf8("abc", 10), "abc");
    }
}
