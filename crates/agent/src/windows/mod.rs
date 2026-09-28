//! Windows 專屬：收集、登錄檔監聽、事件檢視器、服務。

pub mod collect;
pub mod eventlog;
pub mod install;
pub mod registry;
pub mod regwatch;
pub mod secdir;
pub mod service;

use std::path::{Path, PathBuf};

use tokio::sync::{mpsc, watch};
use windows_sys::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, SetPriorityClass,
};

use crate::agent::{Agent, run_agent};

pub fn agent_dir() -> PathBuf {
    std::env::var_os("EM_AGENT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\EndpointManager"))
}

/// 以低優先權執行，避免完整盤點影響使用者。
fn lower_priority() {
    unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) };
}

pub async fn run(dir: &Path, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    lower_priority();
    let agent = Agent::new(dir, collect::WindowsCollector)?;
    // 有界：登錄檔大量變動時多餘的觸發直接丟棄（排程本來就會合併同一區段）
    let (tx, rx) = mpsc::channel(16);
    regwatch::watch_software(tx.clone());
    regwatch::watch_patches(tx);
    run_agent(agent, shutdown, rx).await;
    Ok(())
}

/// 開發／除錯用：在主控台執行，Ctrl+C 結束；不變更目錄 ACL。
/// 必須以 EM_AGENT_DIR 指定目錄：預設目錄繼承 ProgramData 權限（Users 可讀），私鑰會外洩。
pub fn run_console() -> anyhow::Result<()> {
    let dir = std::env::var_os("EM_AGENT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "console mode requires EM_AGENT_DIR (use `service` for the default directory)"
            )
        })?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(true);
        });
        run(&dir, rx).await
    })
}
