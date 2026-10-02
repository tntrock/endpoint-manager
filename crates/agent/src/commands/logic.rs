//! 遠端指令的判斷（純函式）：這一筆該做什麼、關機參數、腳本雜湊驗證。

use protocol::command::{
    Command, CommandAction, CommandResult, MAX_OUTPUT_BYTES, ScriptSpec, tail_utf8,
};
use sha2::{Digest, Sha256};

pub use super::state::Entry;

pub const INTERRUPTED: &str = "執行中斷（Agent 停止或電腦重新開機）";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// 第一次看到：執行
    Run,
    /// 已有結果、還沒回報成功：只補送
    Report(CommandResult),
    /// 已開始但沒有結果（執行中斷）：回報失敗，不再執行
    Interrupted,
    /// 已回報：伺服器下一輪就不會再送
    Done,
}

/// 伺服器在收到結果前每次報到都重送同一筆：依本機紀錄決定，絕不重跑
pub fn step(entry: Option<&Entry>) -> Step {
    match entry {
        None => Step::Run,
        Some(e) if e.reported => Step::Done,
        Some(Entry {
            result: Some(r), ..
        }) => Step::Report(r.clone()),
        Some(_) => Step::Interrupted,
    }
}

/// shutdown.exe 的參數（不含程式路徑）：延遲並以 Windows 內建通知告訴登入的使用者
pub fn shutdown_args(reboot: bool, delay_minutes: u32) -> String {
    let delay = delay_minutes.min(60);
    let what = if reboot { "重新開機" } else { "關機" };
    let message = if delay > 0 {
        format!("IT 部門排定在 {delay} 分鐘後{what}，請儲存您的工作。")
    } else {
        format!("IT 部門即將{what}。")
    };
    // 延遲大於 0 時 Windows 本來就隱含 /f；立即執行時也要 /f，否則可能被沒存檔的程式擋住
    let force = if delay == 0 { " /f" } else { "" };
    format!(
        "{} /t {}{force} /c \"{message}\" /d p:0:0",
        if reboot { "/r" } else { "/s" },
        delay * 60
    )
}

/// 逾時的輸出：前綴一定保留，輸出只留最後能放得下的部分
pub fn timeout_output(minutes: u32, output: &str) -> String {
    let prefix = format!("逾時（{minutes} 分鐘）\n");
    let room = MAX_OUTPUT_BYTES.saturating_sub(prefix.len());
    format!("{prefix}{}", tail_utf8(output, room))
}

/// 同一批中重新開機／關機最後執行（各自保持原本順序），不會打斷同一批的腳本
pub fn order(commands: &[Command]) -> Vec<&Command> {
    let last = |c: &&Command| matches!(c.action, CommandAction::Reboot | CommandAction::Shutdown);
    let mut v: Vec<&Command> = commands.iter().filter(|c| !last(c)).collect();
    v.extend(commands.iter().filter(|c| last(c)));
    v
}

/// 伺服器下發的內容與雜湊相符才執行
pub fn verify_script(spec: &ScriptSpec) -> bool {
    hex::encode(Sha256::digest(spec.content.as_bytes())).eq_ignore_ascii_case(&spec.sha256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::command::{CommandResult, CommandStatus, ScriptSpec};

    fn result() -> CommandResult {
        CommandResult {
            status: CommandStatus::Succeeded,
            exit_code: Some(0),
            output: String::new(),
        }
    }

    #[test]
    fn steps() {
        assert_eq!(step(None), Step::Run);
        let started = Entry {
            started_at: Some(chrono::Utc::now()),
            result: None,
            reported: false,
        };
        assert_eq!(step(Some(&started)), Step::Interrupted);
        let finished = Entry {
            result: Some(result()),
            ..started.clone()
        };
        assert_eq!(step(Some(&finished)), Step::Report(result()));
        let reported = Entry {
            reported: true,
            ..finished
        };
        assert_eq!(step(Some(&reported)), Step::Done);
    }

    #[test]
    fn shutdown_arguments() {
        assert_eq!(
            shutdown_args(true, 10),
            r#"/r /t 600 /c "IT 部門排定在 10 分鐘後重新開機，請儲存您的工作。" /d p:0:0"#
        );
        assert_eq!(
            shutdown_args(false, 0),
            r#"/s /t 0 /f /c "IT 部門即將關機。" /d p:0:0"#
        );
        assert!(shutdown_args(true, 999).starts_with("/r /t 3600 "));
    }

    #[test]
    fn immediate_shutdown_is_forced() {
        assert!(shutdown_args(true, 0).contains(" /f"));
        assert!(shutdown_args(false, 0).contains(" /f"));
        assert!(!shutdown_args(true, 10).contains("/f"));
    }

    #[test]
    fn timeout_prefix_survives_truncation() {
        let out = timeout_output(5, &"x".repeat(70_000));
        assert!(out.starts_with("逾時（5 分鐘）\n"), "{}", &out[..20]);
        assert!(out.len() <= protocol::command::MAX_OUTPUT_BYTES);
        assert_eq!(timeout_output(1, "短"), "逾時（1 分鐘）\n短");
    }

    #[test]
    fn reboot_and_shutdown_run_last() {
        use protocol::command::{Command, CommandAction};
        let c = |id, action| Command {
            id,
            action,
            delay_minutes: None,
            script: None,
        };
        let cmds = vec![
            c(1, CommandAction::Reboot),
            c(2, CommandAction::Script),
            c(3, CommandAction::Shutdown),
            c(4, CommandAction::Collect),
        ];
        let ids: Vec<i64> = order(&cmds).iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![2, 4, 1, 3]);
    }

    #[test]
    fn script_hash() {
        use sha2::Digest;
        let content = "Write-Output hi".to_string();
        let sha = hex::encode(sha2::Sha256::digest(content.as_bytes()));
        let spec = ScriptSpec {
            sha256: sha.clone(),
            content: content.clone(),
            timeout_minutes: 30,
        };
        assert!(verify_script(&spec));
        assert!(verify_script(&ScriptSpec {
            sha256: sha.to_uppercase(),
            ..spec.clone()
        }));
        assert!(!verify_script(&ScriptSpec {
            content: "Remove-Item C:\\".into(),
            ..spec
        }));
    }
}
