//! Linux 平台的資料來源（只在 Linux 編譯）。

pub mod accounts;
pub mod collect;
pub mod commands;
pub mod containers;
pub mod exec;
pub mod exposure;
pub mod install;
pub mod network;
pub mod oslog;
pub mod packages;
pub mod permissions;
pub mod services;
pub mod shares;
pub mod system;
pub mod vms;

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
    // 只在啟動時讀：設定改變要重新啟動服務（configure 會重新啟動）
    let signing_keys = crate::config::AgentConfig::load(dir)?.signing_keys;
    let agent = Agent::new(dir, collect::LinuxCollector)?.with_commands(commands_tx);
    let (tx, rx) = mpsc::channel(16);
    tokio::spawn(run_command_worker(
        CommandWorker::new(
            dir,
            std::sync::Arc::new(commands::LinuxHost {
                triggers: tx.clone(),
            }),
        )
        .with_signing_keys(signing_keys),
        commands_rx,
        shutdown.clone(),
    ));
    // Linux 沒有通知：每 15 秒讀一次（規格 §4.1）
    let (_wake_tx, wake_rx) = mpsc::channel(1);
    tokio::spawn(crate::netwatch::run(
        agent.collector(),
        agent.journal(),
        tx.clone(),
        wake_rx,
        std::time::Duration::from_secs(15),
        shutdown.clone(),
    ));
    tokio::spawn(crate::eventpush::run(
        agent.journal(),
        agent.push_target(),
        shutdown.clone(),
    ));
    if let Some(info) = crate::lifecycle::begin(dir, &agent, shutdown.clone()).await {
        let journal = agent.journal();
        // 上次不是正常結束：讀 journald 裡 systemd 對 Agent 服務的紀錄
        if !info.clean
            && let Some(since) = info.last_alive
        {
            tokio::task::spawn_blocking(move || oslog::record_since(&journal, since));
        }
    }
    let (journal, target, stopped) = (agent.journal(), agent.push_target(), shutdown.clone());
    run_agent(agent, shutdown, rx).await;
    crate::lifecycle::end(dir, &journal, &target, *stopped.borrow()).await;
    Ok(())
}

/// systemd 以前景執行；日誌寫 stderr（journal 會收），SIGTERM 或 Ctrl+C 結束。
pub fn run_foreground() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let dir = agent_dir();
    let rt = tokio::runtime::Runtime::new()?;
    let res = rt.block_on(async {
        let (tx, rx) = watch::channel(false);
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            if let Ok(true) = tokio::task::spawn_blocking(oslog::system_stopping).await {
                crate::lifecycle::set_stop_reason(protocol::stop_reason::SHUTDOWN);
            }
            let _ = tx.send(true);
        });
        run(&dir, rx).await
    });
    // 同 Windows：不等還在跑的背景工作（例如 spawn_blocking）
    rt.shutdown_timeout(std::time::Duration::from_secs(5));
    res
}
