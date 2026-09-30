//! 派送的背景工作：一次處理一個指派（下載、驗證、執行、偵測、回報），不阻塞報到迴圈。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use protocol::deploy::{
    Assignment, DeployAction, DeployResult, DeployStatus, MAX_RESULT_MESSAGE, PackageKind,
};
use protocol::{InventoryPayload, Section, SoftwareItem};
use tokio::sync::watch;

use super::logic::{Cmd, Outcome, Plan, decide, install_cmd, is_installed, outcome, uninstall_cmd};
use super::state::DeployState;
use crate::client::{ClientError, DownloadError, ServerClient};
use crate::collector::Collector;

/// 安裝程式執行上限
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// 指派沒變時多久重新檢查一次（例如使用者自行移除了必要軟體）
pub const RECHECK: Duration = Duration::from_secs(15 * 60);

/// 報到後交給 worker 的工作：指派清單與建立連線需要的資訊（憑證可能已更新）
#[derive(Debug, Clone)]
pub struct Work {
    pub assignments: Vec<Assignment>,
    pub server_url: String,
    pub root_pem: String,
    pub identity_pem: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunResult {
    Exited(i32),
    TimedOut,
}

pub trait Runner: Send + Sync + 'static {
    fn run(
        &self,
        cmd: &Cmd,
        timeout: Duration,
    ) -> impl Future<Output = std::io::Result<RunResult>> + Send;
}

/// 真實執行：沒有視窗、一般優先權（Agent 本身是低優先權，子程序不必跟著變慢）。
/// 服務停止時不結束進行中的安裝（沒有 kill_on_drop），避免安裝到一半被中斷。
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    async fn run(&self, cmd: &Cmd, timeout: Duration) -> std::io::Result<RunResult> {
        let mut c = tokio::process::Command::new(&cmd.program);
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            const NORMAL_PRIORITY_CLASS: u32 = 0x0000_0020;
            // 管理員填的參數原樣傳入（含引號），不再跳脫
            c.raw_arg(&cmd.args);
            c.creation_flags(CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS);
        }
        #[cfg(not(windows))]
        c.args(cmd.args.split_whitespace());
        c.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut child = c.spawn()?;
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => Ok(RunResult::Exited(status?.code().unwrap_or(-1))),
            Err(_) => {
                let _ = child.kill().await;
                Ok(RunResult::TimedOut)
            }
        }
    }
}

pub struct Worker<C: Collector, R: Runner> {
    dir: PathBuf,
    collector: Arc<C>,
    runner: R,
    state: DeployState,
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn truncate(msg: String) -> String {
    msg.chars().take(MAX_RESULT_MESSAGE).collect()
}

impl<C: Collector, R: Runner> Worker<C, R> {
    pub fn new(dir: &Path, collector: Arc<C>, runner: R) -> Self {
        Worker {
            dir: dir.to_path_buf(),
            collector,
            runner,
            state: DeployState::load(dir),
        }
    }

    async fn software(&self) -> Option<Vec<SoftwareItem>> {
        let c = self.collector.clone();
        match tokio::task::spawn_blocking(move || c.collect(Section::Software)).await {
            Ok(Ok(InventoryPayload::Software(items))) => Some(items),
            Ok(Ok(_)) => None,
            Ok(Err(e)) => {
                tracing::warn!(error = %format!("{e:#}"), "deploy: cannot read installed software");
                None
            }
            Err(e) => {
                tracing::warn!(error = %e, "deploy: software collection panicked");
                None
            }
        }
    }

    fn save(&self) {
        if let Err(e) = self.state.save(&self.dir) {
            tracing::error!(error = %e, "deploy: saving state failed");
        }
    }

    pub async fn pass(&mut self, w: &Work) -> Option<DateTime<Utc>> {
        self.pass_at(w, Utc::now()).await
    }

    /// 處理一輪；回傳最早需要再檢查的時間（失敗後的重試時間）
    pub async fn pass_at(&mut self, w: &Work, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let client = match ServerClient::new(&w.server_url, &w.root_pem, w.identity_pem.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "deploy: cannot build client");
                return None;
            }
        };
        let ids: Vec<i64> = w.assignments.iter().map(|a| a.deployment_id).collect();
        self.state.prune(&ids);
        let mut items = self.software().await?;
        let mut sorted: Vec<&Assignment> = w.assignments.iter().collect();
        sorted.sort_by_key(|a| a.deployment_id);
        let mut next: Option<DateTime<Utc>> = None;
        for a in sorted {
            self.flush_unreported(&client, a).await;
            let entry = self.state.entry_for(a.deployment_id, a.revision).clone();
            let installed = is_installed(&a.package.detect, &items);
            match decide(a, installed, &entry, now) {
                Plan::Nothing => {}
                Plan::Wait(t) => next = Some(next.map_or(t, |n| n.min(t))),
                Plan::ReportCompliant => {
                    let attempts = entry.attempts;
                    self.report(
                        &client,
                        a,
                        DeployStatus::Compliant,
                        None,
                        String::new(),
                        attempts,
                    )
                    .await;
                }
                Plan::Execute => {
                    self.execute(&client, a, now).await;
                    // 安裝／移除可能改變其他指派的偵測結果
                    if let Some(fresh) = self.software().await {
                        items = fresh;
                    }
                }
            }
            self.save();
        }
        next
    }

    /// 上次回報失敗（伺服器暫時連不上）的結果先補送
    async fn flush_unreported(&mut self, client: &ServerClient, a: &Assignment) {
        let e = self.state.entry_for(a.deployment_id, a.revision);
        let Some(r) = e.unreported.clone() else {
            return;
        };
        self.send(client, a.deployment_id, a.revision, r).await;
    }

    async fn report(
        &mut self,
        client: &ServerClient,
        a: &Assignment,
        status: DeployStatus,
        exit_code: Option<i32>,
        message: String,
        attempts: i32,
    ) {
        let r = DeployResult {
            revision: a.revision,
            status,
            exit_code,
            message: truncate(message),
            attempts,
        };
        self.send(client, a.deployment_id, a.revision, r).await;
    }

    async fn send(&mut self, client: &ServerClient, id: i64, revision: i32, r: DeployResult) {
        let sent = client.report(id, &r).await;
        let e = self.state.entry_for(id, revision);
        match sent {
            Ok(()) => {
                e.reported = Some(r.status);
                e.unreported = None;
            }
            // 伺服器不接受這份內容（例如派送已刪除）：不再重送
            Err(ClientError::Rejected(code, msg)) => {
                tracing::warn!(deployment_id = id, code, %msg, "deploy: result rejected");
                e.unreported = None;
            }
            Err(e2) => {
                tracing::warn!(deployment_id = id, error = %e2, "deploy: result not sent; will retry");
                e.unreported = Some(r);
            }
        }
    }

    async fn fail(
        &mut self,
        client: &ServerClient,
        a: &Assignment,
        now: DateTime<Utc>,
        exit_code: Option<i32>,
        message: String,
    ) {
        let e = self.state.entry_for(a.deployment_id, a.revision);
        e.attempts += 1;
        e.last_attempt = Some(now);
        e.last_failed = true;
        let attempts = e.attempts;
        tracing::warn!(deployment_id = a.deployment_id, attempts, %message, "deploy: failed");
        self.report(
            client,
            a,
            DeployStatus::Failed,
            exit_code,
            message,
            attempts,
        )
        .await;
    }

    async fn succeed(
        &mut self,
        client: &ServerClient,
        a: &Assignment,
        now: DateTime<Utc>,
        status: DeployStatus,
        exit_code: i32,
    ) {
        let e = self.state.entry_for(a.deployment_id, a.revision);
        let attempts = e.attempts + 1;
        // 成功後重新計算：之後被使用者移除時還能再裝
        e.attempts = 0;
        e.last_attempt = Some(now);
        e.last_failed = false;
        tracing::info!(deployment_id = a.deployment_id, ?status, "deploy: done");
        self.report(client, a, status, Some(exit_code), String::new(), attempts)
            .await;
    }

    async fn execute(&mut self, client: &ServerClient, a: &Assignment, now: DateTime<Utc>) {
        let spec = &a.package;
        let ext = match spec.kind {
            PackageKind::Msi => "msi",
            PackageKind::Exe => "exe",
            PackageKind::Unknown => return,
        };
        if !is_sha256(&spec.sha256) {
            return self
                .fail(client, a, now, None, "套件雜湊格式錯誤".into())
                .await;
        }
        let dir = self.dir.join("packages");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            return self
                .fail(client, a, now, None, format!("無法建立套件目錄：{e}"))
                .await;
        }
        let file = dir.join(format!("{}.{ext}", spec.sha256.to_ascii_lowercase()));
        let log = dir.join(format!("{}.log", spec.sha256.to_ascii_lowercase()));
        // MSI 以 ProductCode 移除，不需要下載
        let needs_file = a.action == DeployAction::Install || spec.kind == PackageKind::Exe;
        if needs_file {
            match client.download(spec, &file).await {
                Ok(()) => {}
                // 伺服器忙碌或連不上：不算嘗試，下次再試
                Err(DownloadError::Retry(_) | DownloadError::Unauthorized) => return,
                Err(e) => return self.fail(client, a, now, None, e.to_string()).await,
            }
        }
        let cmd = match a.action {
            DeployAction::Install => install_cmd(spec, &file, &log),
            DeployAction::Uninstall => uninstall_cmd(spec, &file),
            DeployAction::Unknown => None,
        };
        let Some(cmd) = cmd else {
            let _ = std::fs::remove_file(&file);
            return self
                .fail(
                    client,
                    a,
                    now,
                    None,
                    "這個套件不能用於此動作（缺少移除參數或 ProductCode）".into(),
                )
                .await;
        };
        tracing::info!(deployment_id = a.deployment_id, program = %cmd.program.display(), "deploy: running");
        let res = self.runner.run(&cmd, EXEC_TIMEOUT).await;
        let _ = std::fs::remove_file(&file);
        match res {
            Err(e) => {
                self.fail(client, a, now, None, format!("無法執行安裝程式：{e}"))
                    .await
            }
            Ok(RunResult::TimedOut) => {
                self.fail(client, a, now, None, "執行超過 60 分鐘，已強制結束".into())
                    .await
            }
            Ok(RunResult::Exited(code)) => match outcome(code, spec) {
                Outcome::Busy => {
                    tracing::info!(
                        deployment_id = a.deployment_id,
                        "deploy: another installation in progress; retry later"
                    );
                }
                Outcome::Status(DeployStatus::Failed) => {
                    self.fail(client, a, now, Some(code), format!("結束碼 {code}"))
                        .await
                }
                Outcome::Status(status) => {
                    let installed = self
                        .software()
                        .await
                        .map(|items| is_installed(&spec.detect, &items));
                    let ok = matches!(
                        (a.action, installed),
                        (DeployAction::Install, Some(true))
                            | (DeployAction::Uninstall, Some(false))
                    );
                    if ok {
                        self.succeed(client, a, now, status, code).await;
                    } else {
                        let msg = if a.action == DeployAction::Install {
                            format!("安裝程式回報成功（結束碼 {code}），但偵測不到軟體")
                        } else {
                            format!("移除程式回報成功（結束碼 {code}），但軟體仍在")
                        };
                        self.fail(client, a, now, Some(code), msg).await;
                    }
                }
            },
        }
    }
}

/// 背景迴圈：指派清單變動時立刻處理，否則每 RECHECK（或下一個重試時間）重新檢查一次。
pub async fn run_worker<C: Collector, R: Runner>(
    mut worker: Worker<C, R>,
    mut rx: watch::Receiver<Option<Work>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let work = rx.borrow_and_update().clone();
        let mut wait = RECHECK;
        if let Some(w) = &work {
            let next = tokio::select! {
                n = worker.pass(w) => n,
                _ = shutdown.changed() => return,
            };
            if let Some(d) = next.and_then(|t| (t - Utc::now()).to_std().ok()) {
                wait = wait.min(d);
            }
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { return },
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn cmd(args: &str) -> Cmd {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        Cmd {
            program: PathBuf::from(format!(r"{root}\System32\cmd.exe")),
            args: args.into(),
        }
    }

    #[tokio::test]
    async fn process_runner_reports_exit_code_and_timeout() {
        let r = ProcessRunner;
        assert_eq!(
            r.run(&cmd("/c exit 3010"), Duration::from_secs(30))
                .await
                .unwrap(),
            RunResult::Exited(3010)
        );
        // 引號原樣傳入：cmd 看得到完整字串
        assert_eq!(
            r.run(
                &cmd(r#"/c if "a b"=="a b" (exit 7) else (exit 1)"#),
                Duration::from_secs(30)
            )
            .await
            .unwrap(),
            RunResult::Exited(7)
        );
        assert_eq!(
            r.run(&cmd("/c ping -n 30 127.0.0.1 >nul"), Duration::from_secs(1))
                .await
                .unwrap(),
            RunResult::TimedOut
        );
    }
}
