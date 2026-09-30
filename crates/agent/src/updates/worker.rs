//! WU 原則的背景工作：套用原則、偵測衝突、收集待重開機與最後裝更新日期、回報狀態。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use protocol::update::{ApplyState, MAX_DETAIL_LEN, PolicyData, UpdatePolicy, UpdateStatus};
use protocol::{InventoryPayload, Section};
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use super::host::WuHost;
use super::logic::{Decision, decide, last_patch_date};
use super::state::UpdateState;
use crate::client::ServerClient;
use crate::collector::Collector;

/// 原則沒變時多久重新檢查一次（衝突、待重開機）
pub const RECHECK: Duration = Duration::from_secs(60 * 60);
/// 狀態沒變時多久重送一次
pub const RESEND: chrono::Duration = chrono::Duration::hours(24);

/// 報到後交給 worker 的工作。None（整個 Option）表示伺服器不支援：完全不動 WU 設定
#[derive(Debug, Clone)]
pub struct UpdateWork {
    pub policy: Option<UpdatePolicy>,
    pub server_url: String,
    pub root_pem: String,
    pub identity_pem: Option<String>,
}

pub struct UpdateWorker<C: Collector, H: WuHost> {
    dir: PathBuf,
    collector: Arc<C>,
    host: Arc<H>,
    state: UpdateState,
    patch_timeout: Duration,
    /// 上一次的 patches 收集還卡在 WMI：不再多開一條執行緒
    patch_inflight: Arc<AtomicBool>,
}

/// 登錄檔操作的結果：(狀態, 說明)
fn failed(what: &str, name: &str, e: &std::io::Error) -> (ApplyState, String) {
    (ApplyState::Error, format!("{what} {name} 失敗：{e}"))
}

impl<C: Collector, H: WuHost> UpdateWorker<C, H> {
    pub fn new(dir: &Path, collector: Arc<C>, host: Arc<H>) -> Self {
        UpdateWorker {
            dir: dir.to_path_buf(),
            collector,
            host,
            state: UpdateState::load(dir),
            patch_timeout: crate::agent::COLLECT_TIMEOUT,
            patch_inflight: Arc::new(AtomicBool::new(false)),
        }
    }

    /// 測試用：縮短等待 WMI 的時間
    pub fn with_patch_timeout(mut self, d: Duration) -> Self {
        self.patch_timeout = d;
        self
    }

    fn save(&self) {
        if let Err(e) = self.state.save(&self.dir) {
            tracing::error!(error = %e, "update policy: saving state failed");
        }
    }

    pub fn state(&self) -> &UpdateState {
        &self.state
    }

    pub async fn pass(&mut self, w: &UpdateWork) {
        self.pass_at(w, Utc::now()).await
    }

    pub async fn pass_at(&mut self, w: &UpdateWork, now: DateTime<Utc>) {
        let before = self.state.clone();
        // 登錄檔操作很快但是同步的：放到 blocking 執行緒
        let host = self.host.clone();
        let policy = w.policy.clone();
        let mut applied = self.state.applied.clone();
        let applied = tokio::task::spawn_blocking(move || {
            apply(&*host, policy.as_ref(), &mut applied);
            let reboot = host.reboot_pending();
            (applied, reboot)
        })
        .await;
        let reboot = match applied {
            Ok((a, reboot)) => {
                // 寫完登錄檔立刻存檔：之後等 WMI 或回報時被中斷（服務停止、重開機），
                // 下次仍記得自己寫過哪些值
                if a != self.state.applied {
                    self.state.applied = a;
                    self.save();
                }
                reboot
            }
            Err(e) => {
                tracing::error!(error = %e, "update policy: registry task panicked");
                return;
            }
        };
        self.state.reboot_pending_since = match (reboot, self.state.reboot_pending_since) {
            (true, Some(t)) => Some(t),
            (true, None) => Some(now),
            (false, _) => None,
        };
        let status = UpdateStatus {
            policy_id: self.state.applied.policy_id,
            revision: self.state.applied.revision,
            state: self.state.applied.state.unwrap_or(ApplyState::Unmanaged),
            detail: self
                .state
                .applied
                .detail
                .chars()
                .take(MAX_DETAIL_LEN)
                .collect(),
            reboot_pending: reboot,
            reboot_pending_since: self.state.reboot_pending_since,
            last_patch_date: self.last_patch_date(now).await,
        };
        let hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&status).expect("serializable"),
        ));
        let due = self.state.sent_hash.as_deref() != Some(hash.as_str())
            || self.state.sent_at.is_none_or(|t| t <= now - RESEND);
        if due {
            match ServerClient::new(&w.server_url, &w.root_pem, w.identity_pem.clone()) {
                Ok(c) => match c.update_status(&status).await {
                    Ok(()) => {
                        self.state.sent_hash = Some(hash);
                        self.state.sent_at = Some(now);
                    }
                    Err(e) => tracing::warn!(error = %e, "update policy: status report failed"),
                },
                Err(e) => tracing::warn!(error = %format!("{e:#}"), "update policy: no client"),
            }
        }
        if self.state != before {
            self.save();
        }
    }

    /// WMI 可能卡住：逾時或失敗時沿用上次的日期（不在「未知」與正常之間跳動，也不重送）。
    /// 上一次還卡著時不再收集，避免每小時多疊一條卡住的執行緒。
    async fn last_patch_date(&mut self, now: DateTime<Utc>) -> Option<chrono::NaiveDate> {
        let last = self.state.last_patch_date;
        if self.patch_inflight.swap(true, Ordering::SeqCst) {
            return last;
        }
        let c = self.collector.clone();
        let inflight = self.patch_inflight.clone();
        let task = tokio::task::spawn_blocking(move || {
            let r = c.collect(Section::Patches);
            inflight.store(false, Ordering::SeqCst);
            r
        });
        // 伺服器拒收晚於現在 1 天的日期：垃圾或未來的 InstalledOn 不算
        let not_after = (now + chrono::Duration::days(1)).date_naive();
        let date = match tokio::time::timeout(self.patch_timeout, task).await {
            Ok(Ok(Ok(InventoryPayload::Patches(items)))) => last_patch_date(&items, not_after),
            Ok(Ok(Ok(_))) => last,
            Ok(Ok(Err(e))) => {
                tracing::warn!(error = %format!("{e:#}"), "update policy: cannot read patches");
                last
            }
            Ok(Err(_)) => last,
            Err(_) => {
                tracing::warn!("update policy: patches collection timed out");
                last
            }
        };
        self.state.last_patch_date = date;
        date
    }
}

/// 依 decide 的結果操作登錄檔並更新 applied
fn apply<H: WuHost>(host: &H, desired: Option<&UpdatePolicy>, applied: &mut super::logic::Applied) {
    let current = |name: &str| -> Option<PolicyData> {
        host.read(name).unwrap_or_else(|e| {
            tracing::warn!(name, error = %e, "update policy: cannot read value");
            None
        })
    };
    let (state, detail) = match decide(desired, applied, &current) {
        Decision::Report { state, detail } => (state, detail),
        Decision::Apply { writes, deletes } => 'apply: {
            let p = desired.expect("Apply 只在有原則時出現");
            for name in &deletes {
                if let Err(e) = host.delete(name) {
                    break 'apply failed("刪除", name, &e);
                }
                applied.written.remove(name);
            }
            for (name, data) in &writes {
                if let Err(e) = host.write(name, data) {
                    break 'apply failed("寫入", name, &e);
                }
                // 已寫入的值馬上記住：之後失敗或改版時仍能清除
                applied.written.insert(name.clone(), data.clone());
            }
            if let Some((name, _)) = writes.iter().find(|(n, d)| current(n).as_ref() != Some(d)) {
                break 'apply (ApplyState::Error, format!("讀回不符：{name}"));
            }
            applied.written = writes.into_iter().collect();
            applied.policy_id = Some(p.id);
            applied.revision = Some(p.revision);
            (ApplyState::Applied, String::new())
        }
        Decision::Release { deletes } => 'release: {
            for name in &deletes {
                if let Err(e) = host.delete(name) {
                    break 'release failed("刪除", name, &e);
                }
                applied.written.remove(name);
            }
            // 被別人改過的值不刪，也不再管
            applied.written.clear();
            applied.policy_id = None;
            applied.revision = None;
            (ApplyState::Unmanaged, String::new())
        }
    };
    applied.state = Some(state);
    applied.detail = detail;
}

/// 背景迴圈：原則變動時立刻處理，否則每 RECHECK 檢查一次；伺服器不支援（None）時什麼都不做。
pub async fn run_update_worker<C: Collector, H: WuHost>(
    mut worker: UpdateWorker<C, H>,
    mut rx: watch::Receiver<Option<UpdateWork>>,
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
