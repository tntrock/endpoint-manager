//! Windows 專屬：收集、登錄檔監聽、事件檢視器、服務。

pub mod collect;
pub mod eventlog;
pub mod registry;
pub mod regwatch;
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
    let (tx, rx) = mpsc::unbounded_channel();
    regwatch::watch_software(tx);
    run_agent(agent, shutdown, rx).await;
    Ok(())
}

/// 開發／除錯用：在主控台執行，Ctrl+C 結束；不變更目錄 ACL。
pub fn run_console() -> anyhow::Result<()> {
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
        run(&agent_dir(), rx).await
    })
}
