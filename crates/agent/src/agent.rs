//! Agent 主迴圈：註冊 → 收集到期區段 → 報到 → 上傳伺服器要求的區段 → 視需要續期。

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use chrono::Utc;
use protocol::{
    CheckinRequest, CollectionIntervals, EnrollRequest, InventoryPayload, InventoryUpload,
    RenewRequest, SCHEMA_VERSION, Section,
};
use tokio::sync::{mpsc, watch};

use crate::backoff::{Backoff, jitter, with_jitter};
use crate::client::{ClientError, ServerClient};
use crate::collector::{Collector, Heartbeat};
use crate::config::AgentConfig;
use crate::sanitize::{clean, sanitize};
use crate::schedule::{DEFAULT_INTERVALS, Schedule};
use crate::state::AgentState;

pub const DEBOUNCE: Duration = Duration::from_secs(10);
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(60);
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, PartialEq)]
pub enum Cycle {
    Next(Duration),
    Stop,
}

/// 伺服器要求、手上有資料、且不是「同一份內容已被拒絕」的區段。
pub fn plan_uploads(
    requested: &[Section],
    hashes: &BTreeMap<Section, String>,
    rejected: &BTreeMap<Section, String>,
) -> Vec<Section> {
    requested
        .iter()
        .copied()
        .filter(|s| hashes.contains_key(s) && rejected.get(s) != hashes.get(s))
        .collect()
}

pub struct Agent<C: Collector> {
    dir: PathBuf,
    config: AgentConfig,
    root_pem: String,
    state: AgentState,
    collector: Arc<C>,
    schedule: Schedule,
    cache: BTreeMap<Section, InventoryPayload>,
    errors: BTreeMap<Section, String>,
    intervals: CollectionIntervals,
    backoff: Backoff,
    collect_timeout: Duration,
    inflight: HashMap<&'static str, Arc<AtomicBool>>,
    /// 目前在退避（連不上伺服器或伺服器要求稍後再試）：這段等待不因軟體變更提早結束
    backing_off: bool,
    /// 上一次取得心跳資訊失敗的訊息：相同錯誤不重複寫入事件檢視器
    heartbeat_error: Option<String>,
}

/// 錯誤訊息和上次不同才需要記錄（避免每分鐘重複寫入事件檢視器）。
pub fn error_changed(prev: Option<&String>, new: &str) -> bool {
    prev.map(String::as_str) != Some(new)
}

/// 呼叫結束（含 panic）時清除「執行中」旗標。
struct ClearOnDrop(Arc<AtomicBool>);

impl Drop for ClearOnDrop {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

fn new_csr() -> anyhow::Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)?
        .pem()?;
    Ok((csr, key.serialize_pem()))
}

impl<C: Collector> Agent<C> {
    pub fn new(dir: &Path, collector: C) -> anyhow::Result<Self> {
        let mut config = AgentConfig::load(dir)?;
        let root_path = dir.join("root.pem");
        let root_pem = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        let state = AgentState::load(dir)?;
        // 註冊後、清除金鑰前中斷過（例如寫 config.json 失敗）：補清，金鑰不留在磁碟上
        if state.is_enrolled() && config.enroll_token.is_some() {
            config.enroll_token = None;
            if let Err(e) = config.save(dir) {
                tracing::error!(error = %format!("{e:#}"), "cannot clear enroll token");
            }
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            config,
            root_pem,
            state,
            collector: Arc::new(collector),
            schedule: Schedule::default(),
            cache: BTreeMap::new(),
            errors: BTreeMap::new(),
            intervals: DEFAULT_INTERVALS,
            backoff: Backoff::default(),
            collect_timeout: COLLECT_TIMEOUT,
            inflight: HashMap::new(),
            backing_off: false,
            heartbeat_error: None,
        })
    }

    /// 測試用：縮短 collector 逾時。
    pub fn with_collect_timeout(mut self, d: Duration) -> Self {
        self.collect_timeout = d;
        self
    }

    pub fn state(&self) -> &AgentState {
        &self.state
    }

    pub fn trigger(&mut self, s: Section) {
        self.schedule.trigger(s);
    }

    fn retry_later(&mut self) -> Cycle {
        self.backing_off = true;
        Cycle::Next(self.backoff.next_delay(jitter()))
    }

    /// 這次等待是不是退避（不應被軟體變更提早結束）。
    pub fn backing_off(&self) -> bool {
        self.backing_off
    }

    /// 在 blocking 執行緒上呼叫 collector，並限制時間。
    /// 逾時無法取消執行緒（例如 WMI 卡住），所以同一個 key 的上一次呼叫還沒結束時直接回報錯誤，
    /// 不再開新執行緒、也不再等一次逾時。
    async fn blocking<T: Send + 'static>(
        &mut self,
        key: &'static str,
        f: impl FnOnce(&C) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let busy = self.inflight.entry(key).or_default().clone();
        if busy.swap(true, Ordering::AcqRel) {
            anyhow::bail!("previous call still running (hung?)");
        }
        let c = self.collector.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _done = ClearOnDrop(busy);
            f(&c)
        });
        match tokio::time::timeout(self.collect_timeout, task).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => Err(anyhow::anyhow!("collector panicked: {e}")),
            Err(_) => Err(anyhow::anyhow!(
                "timed out after {}s",
                self.collect_timeout.as_secs()
            )),
        }
    }

    async fn enroll(&mut self) -> anyhow::Result<()> {
        let token = self
            .config
            .enroll_token
            .clone()
            .context("not enrolled and no enroll token in config.json (reinstall required)")?;
        let id = self.blocking("identity", |c| c.identity()).await?;
        let (csr_pem, key_pem) = new_csr()?;
        let client = ServerClient::new(&self.config.server_url, &self.root_pem, None)?;
        let resp = client
            .enroll(&EnrollRequest {
                schema_version: SCHEMA_VERSION,
                enroll_token: token,
                csr_pem,
                hostname: clean(&id.hostname),
                smbios_uuid: id.smbios_uuid.as_deref().map(clean),
                bios_serial: id.bios_serial.as_deref().map(clean),
                mac_addresses: id.mac_addresses.iter().map(|m| clean(m)).collect(),
            })
            .await?;
        self.state.device_id = Some(resp.device_id);
        self.state.chain_pem = Some(resp.certificate_chain_pem);
        self.state.key_pem = Some(key_pem);
        self.state.save(&self.dir)?;
        self.config.enroll_token = None;
        self.config.save(&self.dir)?;
        tracing::info!(device_id = %resp.device_id, "enrolled");
        Ok(())
    }

    async fn collect_due(&mut self) {
        let now = Instant::now();
        for s in self.schedule.due(now, &self.intervals) {
            match self.blocking(s.as_str(), move |c| c.collect(s)).await {
                Ok(mut p) => {
                    sanitize(&mut p);
                    let still_rejected = self.state.rejected.get(&s) == Some(&p.canonical_hash());
                    if !still_rejected {
                        self.errors.remove(&s);
                    }
                    self.cache.insert(s, p);
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    if error_changed(self.errors.get(&s), &msg) {
                        tracing::warn!(section = s.as_str(), error = %msg, "collection failed");
                    }
                    self.errors.insert(s, msg);
                }
            }
            self.schedule.mark_collected(s, now);
        }
    }

    async fn renew(&mut self, client: &ServerClient) -> anyhow::Result<()> {
        let (csr_pem, key_pem) = new_csr()?;
        let r = client.renew(&RenewRequest { csr_pem }).await?;
        self.state.chain_pem = Some(r.certificate_chain_pem);
        self.state.key_pem = Some(key_pem);
        self.state.save(&self.dir)?;
        tracing::info!("certificate renewed");
        Ok(())
    }

    pub async fn run_cycle(&mut self) -> Cycle {
        if !self.state.is_enrolled()
            && let Err(e) = self.enroll().await
        {
            tracing::warn!(error = %format!("{e:#}"), "enrollment failed");
            return self.retry_later();
        }
        // 憑證已過期（離線超過一年）：伺服器必定拒絕，停止並要求重新安裝
        if self.state.cert_not_after().is_some_and(|t| t <= Utc::now()) {
            tracing::error!("device certificate expired; agent stops (reinstall required)");
            return Cycle::Stop;
        }

        self.collect_due().await;
        let hb = match self.blocking("heartbeat", |c| c.heartbeat()).await {
            Ok(hb) => {
                self.heartbeat_error = None;
                hb
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if error_changed(self.heartbeat_error.as_ref(), &msg) {
                    tracing::warn!(error = %msg, "heartbeat info unavailable");
                }
                self.heartbeat_error = Some(msg);
                Heartbeat {
                    boot_time: Utc::now(),
                    logged_on_user: None,
                    ip_addresses: vec![],
                }
            }
        };
        let client = match ServerClient::new(
            &self.config.server_url,
            &self.root_pem,
            self.state.identity_pem(),
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "cannot build client (bad certificate or root.pem?)");
                return self.retry_later();
            }
        };

        let hashes: BTreeMap<Section, String> = self
            .cache
            .iter()
            .map(|(s, p)| (*s, p.canonical_hash()))
            .collect();
        let req = CheckinRequest {
            schema_version: SCHEMA_VERSION,
            agent_version: AGENT_VERSION.into(),
            boot_time: hb.boot_time,
            logged_on_user: hb.logged_on_user.as_deref().map(clean),
            ip_addresses: hb.ip_addresses.iter().map(|i| clean(i)).collect(),
            section_hashes: hashes.clone(),
            section_errors: self.errors.iter().map(|(s, e)| (*s, clean(e))).collect(),
        };
        let resp = match client.checkin(&req).await {
            Ok(r) => r,
            Err(ClientError::Unauthorized) => {
                tracing::error!("certificate rejected by server; agent stops (reinstall required)");
                return Cycle::Stop;
            }
            Err(ClientError::Retry(Some(after))) => {
                self.backing_off = true;
                return Cycle::Next(after);
            }
            Err(e) => {
                tracing::warn!(error = %e, "checkin failed");
                return self.retry_later();
            }
        };
        self.backoff.reset();
        self.backing_off = false;
        self.intervals = resp.collection_intervals.clone();

        let rejected_before = self.state.rejected.clone();
        for s in plan_uploads(&resp.request_sections, &hashes, &self.state.rejected) {
            let up = InventoryUpload {
                schema_version: SCHEMA_VERSION,
                payload: self.cache[&s].clone(),
            };
            match client.upload(&up).await {
                Ok(()) => {
                    self.state.rejected.remove(&s);
                }
                Err(ClientError::Rejected(code, msg)) => {
                    tracing::warn!(section = s.as_str(), code, %msg, "section rejected by server");
                    self.state.rejected.insert(s, hashes[&s].clone());
                    self.errors
                        .insert(s, format!("rejected by server ({code}): {msg}"));
                }
                Err(ClientError::Unauthorized) => return Cycle::Stop,
                Err(ClientError::Retry(_)) => break,
            }
        }

        if resp.renew_certificate
            && let Err(e) = self.renew(&client).await
        {
            tracing::warn!(error = %format!("{e:#}"), "certificate renewal failed");
        }
        // 只在內容變動時寫檔（enroll／renew 已各自存檔），減少私鑰檔被寫壞的機會
        if self.state.rejected != rejected_before
            && let Err(e) = self.state.save(&self.dir)
        {
            tracing::error!(error = %e, "saving state failed");
        }
        Cycle::Next(with_jitter(
            Duration::from_secs(resp.next_checkin_seconds.into()),
            jitter(),
        ))
    }
}

/// 等到下一個週期。收到變更觸發時記下；可中斷（正常等待）時先等 DEBOUNCE 合併短時間內的
/// 多次變更再提早結束，退避中則繼續等到原本的時間。回傳 false 表示要停止。
pub async fn wait_next(
    wait: Duration,
    interruptible: bool,
    shutdown: &mut watch::Receiver<bool>,
    triggers: &mut mpsc::Receiver<Section>,
    mut on_trigger: impl FnMut(Section),
) -> bool {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return true,
            _ = shutdown.changed() => return false,
            Some(s) = triggers.recv() => {
                on_trigger(s);
                if interruptible {
                    tokio::select! {
                        _ = tokio::time::sleep(DEBOUNCE) => {}
                        _ = shutdown.changed() => return false,
                    }
                    while let Ok(s) = triggers.try_recv() {
                        on_trigger(s);
                    }
                    return true;
                }
            }
        }
    }
}

/// 反覆執行 run_cycle，直到收到停止訊號或伺服器拒絕憑證。
pub async fn run_agent<C: Collector>(
    mut agent: Agent<C>,
    mut shutdown: watch::Receiver<bool>,
    mut triggers: mpsc::Receiver<Section>,
) {
    loop {
        // 停止訊號可中斷進行中的週期（例如 WMI 卡住時），服務才能及時停止
        let cycle = tokio::select! {
            c = agent.run_cycle() => c,
            _ = shutdown.changed() => return,
        };
        let wait = match cycle {
            Cycle::Stop => return,
            Cycle::Next(d) => d,
        };
        let interruptible = !agent.backing_off();
        if !wait_next(wait, interruptible, &mut shutdown, &mut triggers, |s| {
            agent.trigger(s)
        })
        .await
        {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 退避等待中（伺服器連不上）收到軟體變更：只記下，不提早報到；
    /// 正常等待中收到：去抖動後提早報到。
    #[tokio::test(start_paused = true)]
    async fn triggers_do_not_cut_short_a_backoff() {
        for (interruptible, expect_secs) in [(false, 100), (true, 11)] {
            let (_stx, mut srx) = watch::channel(false);
            let (ttx, mut trx) = mpsc::channel(4);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let _ = ttx.send(Section::Software).await;
                // 讓 sender 活到測試結束
                tokio::time::sleep(Duration::from_secs(1000)).await;
            });
            let mut seen = vec![];
            let start = tokio::time::Instant::now();
            let go_on = wait_next(
                Duration::from_secs(100),
                interruptible,
                &mut srx,
                &mut trx,
                |s| seen.push(s),
            )
            .await;
            assert!(go_on);
            assert_eq!(
                start.elapsed().as_secs(),
                expect_secs,
                "interruptible={interruptible}"
            );
            assert_eq!(seen, vec![Section::Software], "變更都要記下");
        }
    }

    #[test]
    fn repeated_errors_are_logged_once() {
        assert!(error_changed(None, "boom"));
        assert!(!error_changed(Some(&"boom".to_string()), "boom"));
        assert!(error_changed(Some(&"boom".to_string()), "other"));
    }

    struct NoCollector;
    impl Collector for NoCollector {
        fn identity(&self) -> anyhow::Result<crate::collector::Identity> {
            unimplemented!()
        }
        fn heartbeat(&self) -> anyhow::Result<Heartbeat> {
            unimplemented!()
        }
        fn collect(&self, _: Section) -> anyhow::Result<InventoryPayload> {
            unimplemented!()
        }
    }

    /// 註冊成功後若清除金鑰前就中斷（例如寫 config.json 失敗），下次啟動時補清。
    #[test]
    fn lingering_token_is_cleared_when_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("root.pem"), "x").unwrap();
        AgentConfig {
            server_url: "https://a:8443".into(),
            enroll_token: Some("tok".into()),
        }
        .save(dir.path())
        .unwrap();
        AgentState {
            device_id: Some(uuid::Uuid::new_v4()),
            chain_pem: Some("c".into()),
            key_pem: Some("k".into()),
            ..Default::default()
        }
        .save(dir.path())
        .unwrap();
        let _agent = Agent::new(dir.path(), NoCollector).unwrap();
        assert_eq!(AgentConfig::load(dir.path()).unwrap().enroll_token, None);
    }

    #[test]
    fn skips_sections_rejected_with_same_hash() {
        let hashes = BTreeMap::from([
            (Section::Software, "h1".to_string()),
            (Section::Patches, "h2".to_string()),
            (Section::Services, "h3".to_string()),
        ]);
        let rejected = BTreeMap::from([
            (Section::Software, "h1".to_string()), // 同 hash → 跳過
            (Section::Patches, "old".to_string()), // hash 已變 → 重送
        ]);
        let requested = [
            Section::Software,
            Section::Patches,
            Section::Services,
            Section::Basic,
        ];
        assert_eq!(
            plan_uploads(&requested, &hashes, &rejected),
            vec![Section::Patches, Section::Services] // Basic 沒有資料 → 不送
        );
    }
}
