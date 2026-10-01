//! 遠端指令的背景工作：依序執行伺服器下發的指令、回報結果；執行前先記錄，絕不重跑。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use protocol::command::{Command, CommandAction, CommandResult, CommandStatus};
use tokio::sync::watch;

use super::logic::{INTERRUPTED, Step, shutdown_args, step, verify_script};
use super::state::{CommandsState, Entry};
use crate::client::{ClientError, ServerClient};
use crate::deploy::worker::{RunOutput, RunResult};

/// 指令清單沒變時多久再檢查一次（補送還沒送出的結果）
pub const RECHECK: Duration = Duration::from_secs(5 * 60);

/// 報到後交給 worker 的工作
#[derive(Debug, Clone)]
pub struct CommandWork {
    pub commands: Vec<Command>,
    pub server_url: String,
    pub root_pem: String,
    pub identity_pem: Option<String>,
}

/// 指令實際作用的對象（Windows 實作在 `windows::commands`；測試用假的）
pub trait CommandHost: Send + Sync + 'static {
    /// 要求報到迴圈下一輪重新收集所有區段
    fn collect_all(&self);
    /// 喚醒派送與更新原則的背景工作
    fn apply_now(&self);
    /// 執行 shutdown.exe（參數由 `logic::shutdown_args` 產生）
    fn shutdown(&self, args: &str) -> impl Future<Output = std::io::Result<()>> + Send;
    /// 執行腳本檔，回傳結果與輸出
    fn run_script(
        &self,
        path: &Path,
        timeout: Duration,
    ) -> impl Future<Output = std::io::Result<RunOutput>> + Send;
}

pub struct CommandWorker<H: CommandHost> {
    dir: PathBuf,
    host: Arc<H>,
    state: CommandsState,
}

fn ok(output: impl Into<String>) -> CommandResult {
    CommandResult {
        status: CommandStatus::Succeeded,
        exit_code: None,
        output: output.into(),
    }
}

fn failed(output: impl Into<String>) -> CommandResult {
    CommandResult {
        status: CommandStatus::Failed,
        exit_code: None,
        output: output.into(),
    }
}

impl<H: CommandHost> CommandWorker<H> {
    pub fn new(dir: &Path, host: Arc<H>) -> Self {
        CommandWorker {
            dir: dir.to_path_buf(),
            host,
            state: CommandsState::load(dir),
        }
    }

    pub fn state(&self) -> &CommandsState {
        &self.state
    }

    fn save(&self) -> bool {
        match self.state.save(&self.dir) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(error = %e, "commands: saving state failed");
                false
            }
        }
    }

    fn set_result(&mut self, id: i64, r: CommandResult) {
        let e = self.state.entries.entry(id).or_default();
        e.result = Some(r);
        e.reported = false;
        self.save();
    }

    /// 送出結果；成功（或伺服器已沒有這筆、拒收）就標成已回報
    async fn report(&mut self, client: Option<&ServerClient>, id: i64, r: &CommandResult) -> bool {
        let Some(c) = client else {
            return false;
        };
        match c.command_result(id, r).await {
            Ok(()) => {}
            Err(ClientError::Rejected(code, msg)) => {
                tracing::warn!(id, code, msg, "commands: result rejected; giving up");
            }
            Err(e) => {
                tracing::warn!(id, error = %e, "commands: reporting result failed; will retry");
                return false;
            }
        }
        if let Some(e) = self.state.entries.get_mut(&id) {
            e.reported = true;
        }
        self.save();
        true
    }

    pub async fn pass(&mut self, w: &CommandWork) {
        let client = ServerClient::new(&w.server_url, &w.root_pem, w.identity_pem.clone())
            .map_err(|e| tracing::warn!(error = %format!("{e:#}"), "commands: no client"))
            .ok();
        for c in &w.commands {
            match step(self.state.entries.get(&c.id)) {
                Step::Done => {}
                Step::Report(r) => {
                    self.report(client.as_ref(), c.id, &r).await;
                }
                Step::Interrupted => {
                    let r = failed(INTERRUPTED);
                    self.set_result(c.id, r.clone());
                    self.report(client.as_ref(), c.id, &r).await;
                }
                Step::Run => self.run(client.as_ref(), c).await,
            }
        }
        let before = self.state.clone();
        self.state.prune(Utc::now());
        if self.state != before {
            self.save();
        }
    }

    async fn run(&mut self, client: Option<&ServerClient>, c: &Command) {
        // 執行前先記錄：執行中被中斷（重開機、服務停止）時下一輪回報「執行中斷」，不重跑
        self.state.entries.insert(
            c.id,
            Entry {
                started_at: Some(Utc::now()),
                result: None,
                reported: false,
            },
        );
        // 記錄寫不進去就不執行：否則執行中斷後會重跑腳本或重複關機
        if !self.save() {
            let r = failed("無法寫入 Agent 狀態檔（磁碟已滿或被鎖住），未執行");
            if let Some(e) = self.state.entries.get_mut(&c.id) {
                e.result = Some(r.clone());
            }
            self.report(client, c.id, &r).await;
            return;
        }
        let r = match c.action {
            CommandAction::Collect => {
                self.host.collect_all();
                ok("已要求重新收集盤點")
            }
            CommandAction::Apply => {
                self.host.apply_now();
                ok("已要求立即套用派送與更新原則")
            }
            CommandAction::Reboot | CommandAction::Shutdown => {
                let args = shutdown_args(
                    c.action == CommandAction::Reboot,
                    c.delay_minutes.unwrap_or(10),
                );
                // 先回報再關機：關機後伺服器已經有結果；回報失敗仍關機，開機後補送
                let r = ok(format!("shutdown.exe {args}"));
                self.set_result(c.id, r.clone());
                self.report(client, c.id, &r).await;
                if let Err(e) = self.host.shutdown(&args).await {
                    let r = failed(format!("執行 shutdown.exe 失敗：{e}"));
                    self.set_result(c.id, r.clone());
                    self.report(client, c.id, &r).await;
                }
                return;
            }
            CommandAction::Script => self.script(c).await,
            CommandAction::Unknown => failed("不支援的指令"),
        };
        self.set_result(c.id, r.clone());
        self.report(client, c.id, &r).await;
    }

    async fn script(&mut self, c: &Command) -> CommandResult {
        let Some(spec) = c.script.as_ref().filter(|s| verify_script(s)) else {
            return failed("腳本雜湊不符，未執行");
        };
        let dir = self.dir.join("scripts");
        let path = dir.join(format!("{}.ps1", c.id));
        // UTF-8 含 BOM：Windows PowerShell 5.1 才不會把中文讀成亂碼
        let write = std::fs::create_dir_all(&dir)
            .and_then(|_| std::fs::write(&path, format!("\u{feff}{}", spec.content)));
        if let Err(e) = write {
            return failed(format!("寫入腳本檔失敗：{e}"));
        }
        let minutes = spec.timeout_minutes.clamp(1, 120);
        let out = self
            .host
            .run_script(&path, Duration::from_secs(u64::from(minutes) * 60))
            .await;
        if let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(error = %e, path = %path.display(), "commands: removing script failed");
        }
        match out {
            Ok(RunOutput {
                result: RunResult::Exited(code),
                output,
            }) => CommandResult {
                status: if code == 0 {
                    CommandStatus::Succeeded
                } else {
                    CommandStatus::Failed
                },
                exit_code: Some(code),
                output,
            },
            Ok(RunOutput {
                result: RunResult::TimedOut,
                output,
            }) => {
                let text = format!("逾時（{minutes} 分鐘）\n{output}");
                failed(protocol::command::tail_utf8(
                    &text,
                    protocol::command::MAX_OUTPUT_BYTES,
                ))
            }
            Err(e) => failed(format!("無法執行 PowerShell：{e}")),
        }
    }
}

/// 背景迴圈：指令清單變動時立刻處理，否則每 RECHECK 再處理一次（補送結果）
pub async fn run_command_worker<H: CommandHost>(
    mut worker: CommandWorker<H>,
    mut rx: watch::Receiver<Option<CommandWork>>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let work = rx.borrow_and_update().clone();
        if let Some(w) = &work {
            tokio::select! {
                _ = worker.pass(w) => {}
                _ = shutdown.changed() => return,
            }
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { return },
            _ = tokio::time::sleep(RECHECK) => {}
            _ = shutdown.changed() => return,
        }
    }
}
