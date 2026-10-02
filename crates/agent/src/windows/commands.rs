//! 遠端指令在 Windows 上的實際動作：重新收集、立即套用、shutdown.exe、PowerShell 腳本。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use protocol::Section;
use tokio::sync::{Notify, mpsc};

use crate::commands::worker::CommandHost;
use crate::deploy::logic::Cmd;
use crate::deploy::worker::{RunOutput, run_process};

pub struct WindowsHost {
    /// 報到迴圈的收集觸發（與登錄檔監聽共用）
    pub triggers: mpsc::Sender<Section>,
    /// 派送與更新原則背景工作的喚醒
    pub nudges: Vec<Arc<Notify>>,
}

fn system32(exe: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join("System32").join(exe)
}

pub fn powershell() -> PathBuf {
    system32(r"WindowsPowerShell\v1.0\powershell.exe")
}

/// 以一層 -Command 包住腳本：先把輸出改成 UTF-8（PowerShell 5.1 預設系統字碼頁，中文會變亂碼），
/// 腳本內容原樣不動（param()、using 必須在檔案開頭）。結束碼沿用腳本的 exit；
/// 未處理的例外寫到 stderr 並以 1 結束（與 -File 相同）。
pub fn script_args(path: &Path) -> String {
    let p = path.display().to_string().replace('\'', "''");
    format!(
        "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \
         \"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; \
         try {{ & '{p}'; exit $LASTEXITCODE }} catch {{ Write-Error $_; exit 1 }}\""
    )
}

impl CommandHost for WindowsHost {
    async fn collect_all(&self) {
        for s in Section::ALL {
            // 等待送出：佇列滿時不丟掉區段；通道關閉（Agent 正在停止）時略過
            if self.triggers.send(s).await.is_err() {
                return;
            }
        }
    }

    fn apply_now(&self) {
        for n in &self.nudges {
            n.notify_one();
        }
    }

    async fn shutdown(&self, args: &str) -> std::io::Result<()> {
        let cmd = Cmd {
            program: system32("shutdown.exe"),
            args: args.to_string(),
        };
        let out = run_process(&cmd, Duration::from_secs(60), true).await?;
        match out.result {
            crate::deploy::worker::RunResult::Exited(0) => Ok(()),
            r => Err(std::io::Error::other(format!("{r:?}: {}", out.output))),
        }
    }

    async fn run_script(&self, path: &Path, timeout: Duration) -> std::io::Result<RunOutput> {
        let cmd = Cmd {
            program: powershell(),
            args: script_args(path),
        };
        run_process(&cmd, timeout, true).await
    }
}
