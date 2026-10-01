//! 遠端指令的判斷（純函式）：這一筆該做什麼、關機參數、腳本雜湊驗證。

use protocol::command::{CommandResult, ScriptSpec};
use sha2::{Digest, Sha256};

pub use super::state::Entry;

/// 腳本檔開頭加上的一行（雜湊驗證之後才加）：PowerShell 5.1 預設以系統字碼頁輸出，
/// 中文會變亂碼；改成 UTF-8 才能正確收回輸出。錯誤訊息的行號會多 1。
pub const SCRIPT_PRELUDE: &str = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\r\n";
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
    format!(
        "{} /t {} /c \"{message}\" /d p:0:0",
        if reboot { "/r" } else { "/s" },
        delay * 60
    )
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
            r#"/s /t 0 /c "IT 部門即將關機。" /d p:0:0"#
        );
        assert!(shutdown_args(true, 999).starts_with("/r /t 3600 "));
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
