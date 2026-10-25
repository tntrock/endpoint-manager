//! Linux 平台的資料來源（只在 Linux 編譯）。

pub mod accounts;
pub mod collect;
pub mod commands;
pub mod exec;
pub mod install;
pub mod packages;
pub mod services;
pub mod system;

use std::path::{Path, PathBuf};

use tokio::sync::{mpsc, watch};

use crate::agent::{Agent, run_agent};
use crate::commands::worker::{CommandWorker, run_command_worker};

pub fn agent_dir() -> PathBuf {
    std::env::var_os("EM_AGENT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/endpoint-manager"))
}

/// 只啟動報到迴圈與指令 worker（不派送軟體、不套用更新原則）。
pub async fn run(dir: &Path, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    let (commands_tx, commands_rx) = watch::channel(None);
    let agent = Agent::new(dir, collect::LinuxCollector)?.with_commands(commands_tx);
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(run_command_worker(
        CommandWorker::new(
            dir,
            std::sync::Arc::new(commands::LinuxHost { triggers: tx }),
        ),
        commands_rx,
        shutdown.clone(),
    ));
    run_agent(agent, shutdown, rx).await;
    Ok(())
}

/// systemd 以前景執行；日誌寫 stderr（journal 會收），SIGTERM 或 Ctrl+C 結束。
pub fn run_foreground() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let dir = agent_dir();
    tokio::runtime::Runtime::new()?.block_on(async {
        let (tx, rx) = watch::channel(false);
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            let _ = tx.send(true);
        });
        run(&dir, rx).await
    })
}
