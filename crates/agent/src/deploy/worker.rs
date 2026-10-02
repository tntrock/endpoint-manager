//! 派送的背景工作：一次處理一個指派（下載、驗證、執行、偵測、回報），不阻塞報到迴圈。

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use protocol::branch::DownloadSource;
use protocol::deploy::{
    Assignment, DeployAction, DeployResult, DeployStatus, MAX_RESULT_MESSAGE, PackageKind,
    PackageSpec,
};
use protocol::{InventoryPayload, Section, SoftwareItem};
use tokio::sync::watch;

use super::logic::{Cmd, Outcome, Plan, decide, install_cmd, is_installed, outcome, uninstall_cmd};
use super::state::DeployState;
use crate::backoff::{jitter, with_jitter};
use crate::client::{ClientError, DownloadError, ServerClient};
use crate::collector::Collector;

/// 安裝程式執行上限
pub const EXEC_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// 指派沒變時多久重新檢查一次（例如使用者自行移除了必要軟體）
pub const RECHECK: Duration = Duration::from_secs(15 * 60);
/// 下載遇到忙碌但伺服器沒給 Retry-After 時的等待
pub const DOWNLOAD_RETRY: Duration = Duration::from_secs(5 * 60);
/// 快取連不上而改向中央後，這段時間內都直接向中央下載
pub const CACHE_PAUSE: Duration = Duration::from_secs(5 * 60);

/// 報到後交給 worker 的工作：指派清單與建立連線需要的資訊（憑證可能已更新）
#[derive(Debug, Clone)]
pub struct Work {
    pub assignments: Vec<Assignment>,
    pub server_url: String,
    pub root_pem: String,
    pub identity_pem: Option<String>,
    /// 據點的分點快取（報到時中央下發）；None 表示向中央下載
    pub package_source: Option<protocol::branch::PackageSource>,
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
/// 逾時時以 Job Object 結束整個程序樹（bootstrapper 啟動的子安裝程式也一起結束）；
/// msiexec 交給 Windows Installer 服務執行的部分不在程序樹內，會自行跑完。
pub struct ProcessRunner;

/// 把子程序放進 Job Object，逾時時一次結束整個程序樹。不設 KILL_ON_JOB_CLOSE：
/// Agent 停止時關閉 handle 不會殺掉進行中的安裝。
#[cfg(windows)]
struct Job(windows_sys::Win32::Foundation::HANDLE);

// SAFETY: Job Object 的 handle 可以在任何執行緒使用（Win32 核心物件）
#[cfg(windows)]
unsafe impl Send for Job {}

#[cfg(windows)]
impl Job {
    fn attach(child: &tokio::process::Child) -> Option<Job> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
        let process = child.raw_handle()?;
        // SAFETY: 參數都是有效指標或 null；失敗時回傳 null，由呼叫端退回只結束子程序
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            if AssignProcessToJobObject(job, process as _) == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Job(job))
        }
    }

    fn terminate(&self) {
        // SAFETY: handle 由 attach 建立且尚未關閉
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0, 1);
        }
    }
}

#[cfg(windows)]
impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: 只關閉一次
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

impl Runner for ProcessRunner {
    async fn run(&self, cmd: &Cmd, timeout: Duration) -> std::io::Result<RunResult> {
        Ok(run_process(cmd, timeout, false).await?.result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub result: RunResult,
    /// stdout 後接 stderr（lossy UTF-8），最多 MAX_OUTPUT_BYTES（只留最後的部分）
    pub output: String,
}

type Tail = Arc<std::sync::Mutex<Vec<u8>>>;

/// 讀到結束，只保留最後 MAX_OUTPUT_BYTES。寫進共用的緩衝：讀取被中止（孫程序握著 pipe）時，
/// 已讀到的部分仍在
async fn read_tail(mut r: impl tokio::io::AsyncRead + Unpin, keep: Tail) {
    use tokio::io::AsyncReadExt;
    let max = protocol::command::MAX_OUTPUT_BYTES;
    let mut buf = [0u8; 8192];
    while let Ok(n) = r.read(&mut buf).await {
        if n == 0 {
            break;
        }
        let mut k = keep.lock().expect("output lock");
        k.extend_from_slice(&buf[..n]);
        if k.len() > 2 * max {
            let cut = k.len() - max;
            k.drain(..cut);
        }
    }
}

/// 逾時後等輸出讀完的上限：孫程序繼承了 pipe handle 時不會關，不能一直等
const DRAIN_WAIT: Duration = Duration::from_secs(5);

/// 執行程式。capture = false 時丟棄輸出（派送用）；true 時收集 stdout 與 stderr。
pub async fn run_process(
    cmd: &Cmd,
    timeout: Duration,
    capture: bool,
) -> std::io::Result<RunOutput> {
    use std::process::Stdio;
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
    let pipe = || {
        if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        }
    };
    c.stdin(Stdio::null()).stdout(pipe()).stderr(pipe());
    let mut child = c.spawn()?;
    #[cfg(windows)]
    let job = Job::attach(&child);
    let bufs: [Tail; 2] = Default::default();
    let out = child
        .stdout
        .take()
        .map(|s| tokio::spawn(read_tail(s, bufs[0].clone())));
    let err = child
        .stderr
        .take()
        .map(|s| tokio::spawn(read_tail(s, bufs[1].clone())));
    let result = match tokio::time::timeout(timeout, child.wait()).await {
        Ok(status) => RunResult::Exited(status?.code().unwrap_or(-1)),
        Err(_) => {
            #[cfg(windows)]
            if let Some(j) = &job {
                j.terminate();
            }
            let _ = child.kill().await;
            RunResult::TimedOut
        }
    };
    // 兩個串流共用同一個等待期限；期限到了就中止讀取，用已讀到的部分
    let deadline = tokio::time::Instant::now() + DRAIN_WAIT;
    for task in [out, err].into_iter().flatten() {
        let abort = task.abort_handle();
        if tokio::time::timeout_at(deadline, task).await.is_err() {
            abort.abort();
        }
    }
    let joined = bufs
        .iter()
        .map(|b| {
            let b = b.lock().expect("output lock");
            // UTF-16 輸出（cmd /u 等）含 NUL：伺服器拒收含 NUL 的結果
            String::from_utf8_lossy(&b)
                .replace('\0', "")
                .trim_end_matches(['\r', '\n'])
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    let output =
        protocol::command::tail_utf8(&joined, protocol::command::MAX_OUTPUT_BYTES).to_string();
    Ok(RunOutput { result, output })
}

pub struct Worker<C: Collector, R: Runner> {
    dir: PathBuf,
    collector: Arc<C>,
    runner: R,
    state: DeployState,
    /// 快取暫停期：這個時間之前都直接向中央下載
    cache_paused_until: Option<DateTime<Utc>>,
    /// 這次執行實際下載的來源（回報時帶上）
    source: Option<DownloadSource>,
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn truncate(msg: String) -> String {
    msg.chars().take(MAX_RESULT_MESSAGE).collect()
}

impl<C: Collector, R: Runner> Worker<C, R> {
    pub fn new(dir: &Path, collector: Arc<C>, runner: R) -> Self {
        // 上次中斷留下的安裝檔與下載暫存檔（log 保留供排查）
        if let Ok(entries) = std::fs::read_dir(dir.join("packages")) {
            for e in entries.flatten() {
                if e.path().extension().is_none_or(|x| x != "log") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Worker {
            dir: dir.to_path_buf(),
            collector,
            runner,
            state: DeployState::load(dir),
            cache_paused_until: None,
            source: None,
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

    /// 處理一輪；回傳最早需要再檢查的時間（失敗後的重試、伺服器忙碌後的重試）
    pub async fn pass_at(&mut self, w: &Work, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let client = match ServerClient::new(&w.server_url, &w.root_pem, w.identity_pem.clone()) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "deploy: cannot build client");
                return None;
            }
        };
        let mut items = self.software().await?;
        let mut sorted: Vec<&Assignment> = w.assignments.iter().collect();
        sorted.sort_by_key(|a| a.deployment_id);
        let mut next: Option<DateTime<Utc>> = None;
        let wake = |t: DateTime<Utc>, next: &mut Option<DateTime<Utc>>| {
            *next = Some(next.map_or(t, |n| n.min(t)));
        };
        for a in sorted {
            self.source = None;
            self.flush_unreported(&client, a).await;
            self.report_interrupted(&client, a).await;
            let entry = self.state.entry_for(a.deployment_id, a.revision).clone();
            let installed = is_installed(&a.package.detect, &items);
            match decide(a, installed, &entry, now) {
                Plan::Nothing => {}
                Plan::Wait(t) => wake(t, &mut next),
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
                    if let Some(t) = self.execute(w, &client, a, now).await {
                        wake(t, &mut next);
                    }
                    // 安裝／移除可能改變其他指派的偵測結果
                    if let Some(fresh) = self.software().await {
                        items = fresh;
                    }
                }
            }
            self.save();
        }
        // 一輪結束才記錄與清理（這輪新建立的紀錄也要記下出現時間）
        let ids: Vec<i64> = w.assignments.iter().map(|a| a.deployment_id).collect();
        self.state.prune(&ids, now);
        self.save();
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

    /// 上次執行到一半（服務被停止或電腦重開機）：那次已記為一次嘗試，回報失敗
    async fn report_interrupted(&mut self, client: &ServerClient, a: &Assignment) {
        let e = self.state.entry_for(a.deployment_id, a.revision);
        if !e.in_progress {
            return;
        }
        e.in_progress = false;
        let attempts = e.attempts;
        self.save();
        self.report(
            client,
            a,
            DeployStatus::Failed,
            None,
            "安裝中斷（Agent 服務或電腦在安裝途中被停止或重新開機）".into(),
            attempts,
        )
        .await;
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
            source: self.source.take(),
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
            // 伺服器不接受這份內容：不再重送
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

    /// 還沒執行就失敗（下載不符、無法組出指令）：記一次嘗試並回報
    async fn fail_before_run(
        &mut self,
        client: &ServerClient,
        a: &Assignment,
        now: DateTime<Utc>,
        message: String,
    ) {
        let e = self.state.entry_for(a.deployment_id, a.revision);
        e.attempts += 1;
        e.last_attempt = Some(now);
        e.last_failed = true;
        let attempts = e.attempts;
        tracing::warn!(deployment_id = a.deployment_id, attempts, %message, "deploy: failed");
        self.report(client, a, DeployStatus::Failed, None, message, attempts)
            .await;
    }

    /// 執行後失敗：嘗試次數在執行前已記下
    async fn fail_after_run(
        &mut self,
        client: &ServerClient,
        a: &Assignment,
        exit_code: Option<i32>,
        message: String,
    ) {
        let attempts = self.state.entry_for(a.deployment_id, a.revision).attempts;
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
        status: DeployStatus,
        exit_code: i32,
    ) {
        let e = self.state.entry_for(a.deployment_id, a.revision);
        let attempts = e.attempts;
        // 成功後重新計算：之後被使用者移除時還能再裝
        e.attempts = 0;
        e.last_failed = false;
        tracing::info!(deployment_id = a.deployment_id, ?status, "deploy: done");
        self.report(client, a, status, Some(exit_code), String::new(), attempts)
            .await;
    }

    /// 依來源下載（規格 §4）：有分點快取且不在暫停期時向快取下載；
    /// 快取忙碌（503）稍後再試，不改向；連不上或 5xx 時依據點設定改向中央並暫停快取 5 分鐘；
    /// 檔案不符時允許的話改向中央一次；403／404 照下載失敗處理
    async fn download(
        &mut self,
        w: &Work,
        central: &ServerClient,
        spec: &PackageSpec,
        file: &Path,
        now: DateTime<Utc>,
    ) -> Result<(), DownloadError> {
        if let Some(src) = &w.package_source
            && self.cache_paused_until.is_none_or(|t| now >= t)
        {
            match ServerClient::new(&src.url, &w.root_pem, w.identity_pem.clone()) {
                Ok(cache) => match cache.download(spec, file).await {
                    Ok(()) => {
                        self.source = Some(DownloadSource::Cache);
                        return Ok(());
                    }
                    Err(DownloadError::Retry(after)) => return Err(DownloadError::Retry(after)),
                    Err(DownloadError::Unreachable | DownloadError::Unauthorized) => {
                        if !src.fallback_to_central {
                            return Err(DownloadError::Retry(None));
                        }
                        tracing::warn!(url = %src.url, "deploy: cache unreachable; using central for a while");
                        self.cache_paused_until =
                            Some(now + chrono::Duration::from_std(CACHE_PAUSE).unwrap_or_default());
                    }
                    Err(DownloadError::Mismatch) if src.fallback_to_central => {
                        tracing::warn!(url = %src.url, "deploy: file from cache does not match; trying central");
                    }
                    Err(e) => return Err(e),
                },
                Err(e) => tracing::warn!(error = %e, "deploy: cannot build cache client"),
            }
        }
        central.download(spec, file).await?;
        self.source = Some(DownloadSource::Central);
        Ok(())
    }

    /// 回傳需要再檢查的時間（伺服器忙碌時依 Retry-After）
    async fn execute(
        &mut self,
        w: &Work,
        client: &ServerClient,
        a: &Assignment,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        let spec = &a.package;
        let ext = match spec.kind {
            PackageKind::Msi => "msi",
            PackageKind::Exe => "exe",
            PackageKind::Unknown => return None,
        };
        if !is_sha256(&spec.sha256) {
            self.fail_before_run(client, a, now, "套件雜湊格式錯誤".into())
                .await;
            return None;
        }
        let dir = self.dir.join("packages");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            self.fail_before_run(client, a, now, format!("無法建立套件目錄：{e}"))
                .await;
            return None;
        }
        let sha = spec.sha256.to_ascii_lowercase();
        let file = dir.join(format!("{sha}.{ext}"));
        let log = dir.join(format!("{sha}.log"));
        // 先確認能組出指令（例如 EXE 沒有移除參數），不能執行就不必下載
        let cmd = match a.action {
            DeployAction::Install => install_cmd(spec, &file, &log),
            DeployAction::Uninstall => uninstall_cmd(spec, &file),
            DeployAction::Unknown => None,
        };
        let Some(cmd) = cmd else {
            self.fail_before_run(
                client,
                a,
                now,
                "這個套件不能用於此動作（缺少移除參數或 ProductCode）".into(),
            )
            .await;
            return None;
        };
        // MSI 以 ProductCode 移除，不需要下載
        let needs_file = a.action == DeployAction::Install || spec.kind == PackageKind::Exe;
        if needs_file && !verified(&file, spec).await {
            match self.download(w, client, spec, &file, now).await {
                Ok(()) => {}
                // 伺服器忙碌或連不上：不算嘗試，依 Retry-After（加上隨機延遲）再試
                Err(e @ (DownloadError::Retry(_) | DownloadError::Unreachable)) => {
                    let after = match e {
                        DownloadError::Retry(a) => a,
                        _ => None,
                    };
                    let wait = with_jitter(after.unwrap_or(DOWNLOAD_RETRY), jitter());
                    return Some(now + chrono::Duration::from_std(wait).unwrap_or_default());
                }
                Err(DownloadError::Unauthorized) => return None,
                Err(e) => {
                    self.fail_before_run(client, a, now, e.to_string()).await;
                    return None;
                }
            }
        }
        // 執行前先記下這次嘗試並存檔：安裝途中服務被停止或電腦重開機時，
        // 下次啟動不會立刻再執行（避免重開機迴圈），且仍受次數上限與自動暫停約束
        let prev = self.state.entry_for(a.deployment_id, a.revision).clone();
        {
            let e = self.state.entry_for(a.deployment_id, a.revision);
            e.attempts += 1;
            e.last_attempt = Some(now);
            e.last_failed = true;
            e.in_progress = true;
        }
        self.save();
        tracing::info!(deployment_id = a.deployment_id, program = %cmd.program.display(), "deploy: running");
        let res = self.runner.run(&cmd, EXEC_TIMEOUT).await;
        self.state
            .entry_for(a.deployment_id, a.revision)
            .in_progress = false;
        let code = match res {
            Err(e) => {
                let _ = std::fs::remove_file(&file);
                self.fail_after_run(client, a, None, format!("無法執行安裝程式：{e}"))
                    .await;
                return None;
            }
            Ok(RunResult::TimedOut) => {
                let _ = std::fs::remove_file(&file);
                self.fail_after_run(client, a, None, "執行超過 60 分鐘，已強制結束".into())
                    .await;
                return None;
            }
            Ok(RunResult::Exited(code)) => code,
        };
        match outcome(code, spec) {
            Outcome::Busy => {
                // 另一個安裝進行中：不算嘗試；保留已驗證的檔案，下次驗證後直接使用
                let e = self.state.entry_for(a.deployment_id, a.revision);
                e.attempts = prev.attempts;
                e.last_attempt = prev.last_attempt;
                e.last_failed = prev.last_failed;
                tracing::info!(
                    deployment_id = a.deployment_id,
                    "deploy: another installation in progress; retry later"
                );
            }
            Outcome::Status(DeployStatus::Failed) => {
                let _ = std::fs::remove_file(&file);
                self.fail_after_run(client, a, Some(code), format!("結束碼 {code}"))
                    .await;
            }
            Outcome::Status(status) => {
                let _ = std::fs::remove_file(&file);
                let installed = self
                    .software()
                    .await
                    .map(|items| is_installed(&spec.detect, &items));
                let ok = matches!(
                    (a.action, installed),
                    (DeployAction::Install, Some(true)) | (DeployAction::Uninstall, Some(false))
                );
                if ok {
                    self.succeed(client, a, status, code).await;
                } else {
                    let msg = if a.action == DeployAction::Install {
                        format!("安裝程式回報成功（結束碼 {code}），但偵測不到軟體")
                    } else {
                        format!("移除程式回報成功（結束碼 {code}），但軟體仍在")
                    };
                    self.fail_after_run(client, a, Some(code), msg).await;
                }
            }
        }
        None
    }
}

/// 本機已有的檔案大小與 SHA-256 都相符（例如上次遇到 1618 保留下來的）
async fn verified(file: &Path, spec: &protocol::deploy::PackageSpec) -> bool {
    let (file, size, sha) = (file.to_path_buf(), spec.size, spec.sha256.clone());
    tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = match std::fs::File::open(&file) {
            Ok(f) => f,
            Err(_) => return Ok(false),
        };
        if f.metadata()?.len() != size {
            return Ok(false);
        }
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()).eq_ignore_ascii_case(&sha))
    })
    .await
    .ok()
    .and_then(Result::ok)
    .unwrap_or(false)
}

/// 背景迴圈：指派清單變動時立刻處理，否則每 RECHECK（或下一個重試時間）重新檢查一次。
pub async fn run_worker<C: Collector, R: Runner>(
    mut worker: Worker<C, R>,
    mut rx: watch::Receiver<Option<Work>>,
    mut shutdown: watch::Receiver<bool>,
    nudge: Arc<tokio::sync::Notify>,
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
            // 遠端指令「立即套用」
            _ = nudge.notified() => {}
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

    #[tokio::test]
    async fn run_process_captures_output_and_exit_code() {
        let r = run_process(
            &cmd(r#"/c "echo hello & echo oops 1>&2 & exit 3""#),
            Duration::from_secs(30),
            true,
        )
        .await
        .unwrap();
        assert_eq!(r.result, RunResult::Exited(3));
        assert!(
            r.output.contains("hello") && r.output.contains("oops"),
            "{}",
            r.output
        );
    }

    /// UTF-16 輸出（cmd /u、部分系統工具）含 NUL：伺服器會拒收，要先去掉
    #[tokio::test]
    async fn run_process_strips_nul() {
        let r = run_process(&cmd("/u /c echo wide"), Duration::from_secs(30), true)
            .await
            .unwrap();
        assert!(!r.output.contains('\0'), "{:?}", r.output);
        assert!(r.output.contains("wide"), "{:?}", r.output);
    }

    /// 程式正常結束、但背景的孫程序還握著 pipe：已讀到的輸出不能丟
    #[tokio::test]
    async fn run_process_keeps_output_when_grandchild_holds_pipe() {
        let start = std::time::Instant::now();
        let r = run_process(
            &cmd(r#"/c "echo hello & start /b ping -n 30 127.0.0.1 >nul""#),
            Duration::from_secs(30),
            true,
        )
        .await
        .unwrap();
        assert_eq!(r.result, RunResult::Exited(0));
        assert!(r.output.contains("hello"), "{:?}", r.output);
        assert!(start.elapsed() < Duration::from_secs(15));
    }

    #[tokio::test]
    async fn run_process_keeps_tail() {
        let r = run_process(
            &cmd(r#"/c "for /l %i in (1,1,20000) do @echo line%i""#),
            Duration::from_secs(60),
            true,
        )
        .await
        .unwrap();
        assert!(
            r.output.len() <= protocol::command::MAX_OUTPUT_BYTES,
            "{}",
            r.output.len()
        );
        assert!(r.output.trim_end().ends_with("line20000"));
    }

    #[tokio::test]
    async fn run_process_timeout_returns_partial_output() {
        let start = std::time::Instant::now();
        let r = run_process(
            &cmd(r#"/c "echo started & ping -n 30 127.0.0.1 >nul""#),
            Duration::from_secs(1),
            true,
        )
        .await
        .unwrap();
        assert_eq!(r.result, RunResult::TimedOut);
        assert!(r.output.contains("started"), "{}", r.output);
        assert!(start.elapsed() < Duration::from_secs(10));
    }

    /// 逾時時整個程序樹都結束：背景啟動的孫程序 3 秒後才寫檔，被結束就不會寫
    #[tokio::test]
    async fn timeout_kills_the_whole_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("grandchild.txt");
        let args = format!(
            r#"/c start "" /b cmd /c "ping -n 4 127.0.0.1 >nul & echo x > "{}"" & ping -n 30 127.0.0.1 >nul"#,
            marker.display()
        );
        let r = ProcessRunner
            .run(&cmd(&args), Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(r, RunResult::TimedOut);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!marker.exists(), "孫程序也被結束");
    }
}
