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
        let config = AgentConfig::load(dir)?;
        let root_path = dir.join("root.pem");
        let root_pem = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            config,
            root_pem,
            state: AgentState::load(dir)?,
            collector: Arc::new(collector),
            schedule: Schedule::default(),
            cache: BTreeMap::new(),
            errors: BTreeMap::new(),
            intervals: DEFAULT_INTERVALS,
            backoff: Backoff::default(),
            collect_timeout: COLLECT_TIMEOUT,
            inflight: HashMap::new(),
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
        Cycle::Next(self.backoff.next_delay(jitter()))
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
                    tracing::warn!(section = s.as_str(), error = %format!("{e:#}"), "collection failed");
                    self.errors.insert(s, format!("{e:#}"));
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
        let hb = self
            .blocking("heartbeat", |c| c.heartbeat())
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "heartbeat info unavailable");
                Heartbeat {
                    boot_time: Utc::now(),
                    logged_on_user: None,
                    ip_addresses: vec![],
                }
            });
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
            Err(ClientError::Retry(Some(after))) => return Cycle::Next(after),
            Err(e) => {
                tracing::warn!(error = %e, "checkin failed");
                return self.retry_later();
            }
        };
        self.backoff.reset();
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

/// 反覆執行 run_cycle，直到收到停止訊號或伺服器拒絕憑證。
/// 軟體變更觸發時先等 DEBOUNCE，合併短時間內的多次變更。
pub async fn run_agent<C: Collector>(
    mut agent: Agent<C>,
    mut shutdown: watch::Receiver<bool>,
    mut triggers: mpsc::UnboundedReceiver<Section>,
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
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
            Some(s) = triggers.recv() => {
                agent.trigger(s);
                tokio::select! {
                    _ = tokio::time::sleep(DEBOUNCE) => {}
                    _ = shutdown.changed() => return,
                }
                while let Ok(s) = triggers.try_recv() {
                    agent.trigger(s);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
