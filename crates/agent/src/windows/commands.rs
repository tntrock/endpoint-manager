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

impl CommandHost for WindowsHost {
    fn collect_all(&self) {
        for s in Section::ALL {
            // 通道滿了代表已有大量觸發排隊，丟掉也會在下一輪收集
            let _ = self.triggers.try_send(s);
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
            args: format!(
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\"",
                path.display()
            ),
        };
        run_process(&cmd, timeout, true).await
    }
}
