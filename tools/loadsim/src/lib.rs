//! 模擬大量 Agent：註冊、心跳、上傳完整軟體清單。每次請求都新建連線（與真實 Agent 相同）。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use endpoint_agent::client::ServerClient;
use protocol::{
    Arch, CheckinRequest, EnrollRequest, InventoryPayload, InventoryUpload, Probe, RegKind,
    RegState, RegistryQuery, RegistryValue, SCHEMA_VERSION, Section, SecurityInfo, SoftwareItem,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Clone)]
pub struct Target {
    pub server: String,
    pub root_pem: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: Uuid,
    pub identity_pem: String,
}

#[derive(Debug)]
pub struct Report {
    pub ok: usize,
    pub errors: usize,
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
    pub elapsed: Duration,
}

impl Report {
    fn new(mut ok_lat: Vec<Duration>, errors: usize, elapsed: Duration) -> Report {
        ok_lat.sort();
        Report {
            ok: ok_lat.len(),
            errors,
            p50: percentile(&ok_lat, 50.0),
            p99: percentile(&ok_lat, 99.0),
            max: ok_lat.last().copied().unwrap_or_default(),
            elapsed,
        }
    }
}

/// nearest-rank 百分位數；輸入須已排序。
pub fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// 每台電腦的軟體清單：名稱在各台之間共用（讓跨電腦搜尋有意義），版本依電腦略有不同。
pub fn software(device: usize, items: usize) -> Vec<SoftwareItem> {
    (0..items)
        .map(|k| SoftwareItem {
            name: format!("Loadsim Product {k:04}"),
            version: Some(format!("{}.{}.{}", k % 7, device % 3, k % 11)),
            publisher: Some(format!("Loadsim Vendor {:02}", k % 20)),
            install_date: Some("20260101".into()),
            arch: Arch::X64,
        })
        .collect()
}

fn client(t: &Target, d: Option<&Device>) -> anyhow::Result<ServerClient> {
    ServerClient::new(&t.server, &t.root_pem, d.map(|d| d.identity_pem.clone()))
}

fn checkin_req(section_hashes: BTreeMap<Section, String>) -> CheckinRequest {
    CheckinRequest {
        schema_version: SCHEMA_VERSION,
        // 模擬支援組態區段的 Agent（組態規則要求 0.3.0 以上）
        agent_version: "0.3.0".into(),
        boot_time: chrono::Utc::now() - chrono::Duration::hours(1),
        logged_on_user: Some(r"LOADSIM\user".into()),
        ip_addresses: vec!["10.0.0.1".into()],
        section_hashes,
        section_errors: BTreeMap::new(),
    }
}

async fn enroll_one(t: &Target, token: &str, n: usize) -> anyhow::Result<Device> {
    let key = rcgen::KeyPair::generate()?;
    let csr_pem = rcgen::CertificateParams::default()
        .serialize_request(&key)?
        .pem()?;
    let resp = client(t, None)?
        .enroll(&EnrollRequest {
            schema_version: SCHEMA_VERSION,
            enroll_token: token.into(),
            csr_pem,
            hostname: format!("LOADSIM-{n:05}"),
            smbios_uuid: Some(Uuid::new_v4().to_string()),
            bios_serial: Some(format!("LS{}", Uuid::new_v4().simple())),
            mac_addresses: vec![],
        })
        .await
        .map_err(|e| anyhow::anyhow!("enroll {n}: {e}"))?;
    Ok(Device {
        device_id: resp.device_id,
        identity_pem: format!("{}{}", resp.certificate_chain_pem, key.serialize_pem()),
    })
}

pub async fn enroll(
    t: &Target,
    token: &str,
    count: usize,
    concurrency: usize,
) -> anyhow::Result<Vec<Device>> {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set = JoinSet::new();
    for n in 0..count {
        let permit = sem.clone().acquire_owned().await?;
        let (t, token) = (t.clone(), token.to_string());
        set.spawn(async move {
            let _permit = permit;
            enroll_one(&t, &token, n).await
        });
    }
    let mut out = Vec::with_capacity(count);
    while let Some(r) = set.join_next().await {
        out.push(r??);
    }
    Ok(out)
}

/// 以固定速率（每秒 rate 次）輪流讓各台報到，量測延遲（不含本機建立 client 的時間）。
pub async fn heartbeat(t: &Target, devices: &[Device], rate: u32, duration: Duration) -> Report {
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate.max(1) as f64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let start = Instant::now();
    let mut set = JoinSet::new();
    let mut i = 0;
    while start.elapsed() < duration && !devices.is_empty() {
        tick.tick().await;
        let (t, d) = (t.clone(), devices[i % devices.len()].clone());
        i += 1;
        set.spawn(async move {
            let c = client(&t, Some(&d)).ok()?;
            let s = Instant::now();
            c.checkin(&checkin_req(BTreeMap::new())).await.ok()?;
            Some(s.elapsed())
        });
    }
    collect(set, start).await
}

/// 每台上傳完整軟體清單，再報到一次確認伺服器不再要求 software（＝已存入）。
pub async fn upload(
    t: &Target,
    devices: &[Device],
    items: usize,
    concurrency: usize,
) -> (Report, usize) {
    let sem = Arc::new(Semaphore::new(concurrency));
    let unverified = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut set = JoinSet::new();
    for (n, d) in devices.iter().enumerate() {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let (t, d, unverified) = (t.clone(), d.clone(), unverified.clone());
        set.spawn(async move {
            let _permit = permit;
            let payload = InventoryPayload::Software(software(n, items));
            let hash = payload.canonical_hash();
            let c = client(&t, Some(&d)).ok()?;
            let s = Instant::now();
            c.upload(&InventoryUpload {
                schema_version: SCHEMA_VERSION,
                payload,
            })
            .await
            .ok()?;
            let resp = c
                .checkin(&checkin_req(BTreeMap::from([(Section::Software, hash)])))
                .await
                .ok()?;
            if resp.request_sections.contains(&Section::Software) {
                unverified.fetch_add(1, Ordering::Relaxed);
            }
            Some(s.elapsed())
        });
    }
    let report = collect(set, start).await;
    (report, unverified.load(Ordering::Relaxed))
}

/// 固定的安全設定：偶數台公用防火牆關閉
pub fn security(device: usize) -> SecurityInfo {
    SecurityInfo {
        firewall: Probe::Ok(protocol::FirewallInfo {
            domain: true,
            private: true,
            public: device % 2 == 1,
        }),
        bitlocker: Probe::Ok(vec![protocol::VolumeInfo {
            drive: "C:".into(),
            is_system: true,
            protected: true,
        }]),
        defender: Probe::Ok(protocol::DefenderInfo {
            active: true,
            realtime: true,
            tamper: true,
            signature_updated: Some(chrono::Utc::now()),
        }),
        password: Probe::Ok(protocol::PasswordPolicy {
            min_length: 8,
            max_age_days: 90,
            lockout_threshold: 10,
        }),
        admins: Probe::Ok(vec![protocol::AccountInfo {
            name: format!(r"LOADSIM-{device:05}\Administrator"),
            sid: "S-1-5-21-1-2-3-500".into(),
        }]),
    }
}

/// 對伺服器下發的每個查詢回一個 DWORD，值為裝置編號 % 2
pub fn registry(device: usize, queries: &[RegistryQuery]) -> Vec<RegistryValue> {
    queries
        .iter()
        .map(|q| RegistryValue {
            path: q.path.clone(),
            name: q.name.clone(),
            state: RegState::Present,
            kind: RegKind::Dword,
            data: (device % 2).to_string(),
        })
        .collect()
}

/// 每台：報到取得查詢清單 → 上傳 security 與 registry → 以新雜湊再報到，確認伺服器不再要求。
pub async fn config(t: &Target, devices: &[Device], concurrency: usize) -> (Report, usize) {
    let sem = Arc::new(Semaphore::new(concurrency));
    let unverified = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut set = JoinSet::new();
    for (n, d) in devices.iter().enumerate() {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let (t, d, unverified) = (t.clone(), d.clone(), unverified.clone());
        set.spawn(async move {
            let _permit = permit;
            let c = client(&t, Some(&d)).ok()?;
            let s = Instant::now();
            let first = c.checkin(&checkin_req(BTreeMap::new())).await.ok()?;
            let mut hashes = BTreeMap::new();
            for payload in [
                InventoryPayload::Security(security(n)),
                InventoryPayload::Registry(registry(n, &first.registry_queries)),
            ] {
                hashes.insert(payload.section(), payload.canonical_hash());
                c.upload(&InventoryUpload {
                    schema_version: SCHEMA_VERSION,
                    payload,
                })
                .await
                .ok()?;
            }
            let resp = c.checkin(&checkin_req(hashes)).await.ok()?;
            if resp.request_sections.contains(&Section::Security)
                || resp.request_sections.contains(&Section::Registry)
            {
                unverified.fetch_add(1, Ordering::Relaxed);
            }
            Some(s.elapsed())
        });
    }
    let report = collect(set, start).await;
    (report, unverified.load(Ordering::Relaxed))
}

/// 負載測試用的套件內容（決定性，任何人重跑都得到同一個雜湊）
pub fn package_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 251) as u8).collect()
}

/// 每台：報到取得指派 → 下載並驗證第一個套件（503 依 Retry-After 重試）→ 回報每個指派
/// （第一個 succeeded，其餘 compliant）。回傳報告、503 重試次數、沒有指派的台數。
pub async fn deploy(t: &Target, devices: &[Device], concurrency: usize) -> (Report, usize, usize) {
    use endpoint_agent::client::DownloadError;
    use protocol::deploy::{DeployResult, DeployStatus};
    let sem = Arc::new(Semaphore::new(concurrency));
    let retries = Arc::new(AtomicUsize::new(0));
    let unassigned = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut set = JoinSet::new();
    for d in devices {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let (t, d, retries, unassigned) =
            (t.clone(), d.clone(), retries.clone(), unassigned.clone());
        set.spawn(async move {
            let _permit = permit;
            let c = client(&t, Some(&d)).ok()?;
            let s = Instant::now();
            let resp = c.checkin(&checkin_req(BTreeMap::new())).await.ok()?;
            let Some(first) = resp.deployments.first() else {
                unassigned.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            let mut tries = 0;
            loop {
                match c.verify_package(&first.package).await {
                    Ok(()) => break,
                    Err(DownloadError::Retry(after)) if tries < 100 => {
                        tries += 1;
                        retries.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(after.unwrap_or(Duration::from_secs(10))).await;
                    }
                    Err(e) => {
                        eprintln!("download {}: {e}", d.device_id);
                        return None;
                    }
                }
            }
            for (i, a) in resp.deployments.iter().enumerate() {
                let status = if i == 0 {
                    DeployStatus::Succeeded
                } else {
                    DeployStatus::Compliant
                };
                c.report(
                    a.deployment_id,
                    &DeployResult {
                        revision: a.revision,
                        status,
                        exit_code: Some(0),
                        message: String::new(),
                        attempts: 1,
                    },
                )
                .await
                .ok()?;
            }
            Some(s.elapsed())
        });
    }
    let report = collect(set, start).await;
    (
        report,
        retries.load(Ordering::Relaxed),
        unassigned.load(Ordering::Relaxed),
    )
}

async fn collect(mut set: JoinSet<Option<Duration>>, start: Instant) -> Report {
    let (mut lat, mut errors) = (Vec::new(), 0);
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Some(d)) => lat.push(d),
            _ => errors += 1,
        }
    }
    Report::new(lat, errors, start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        assert_eq!(percentile(&v, 50.0), Duration::from_millis(50));
        assert_eq!(percentile(&v, 99.0), Duration::from_millis(99));
        assert_eq!(percentile(&v, 100.0), Duration::from_millis(100));
        assert_eq!(percentile(&[], 99.0), Duration::ZERO);
    }

    #[test]
    fn software_is_deterministic_and_valid() {
        let a = software(7, 150);
        assert_eq!(a.len(), 150);
        assert_eq!(a, software(7, 150));
        protocol::InventoryPayload::Software(a).validate().unwrap();
    }

    #[test]
    fn config_payloads_are_valid() {
        let q: Vec<RegistryQuery> = (0..1000)
            .map(|i| RegistryQuery {
                path: format!(r"HKLM\SOFTWARE\Loadsim\K{}", i / 100),
                name: format!("V{i}"),
            })
            .collect();
        let r = registry(3, &q);
        assert_eq!((r.len(), r[0].data.as_str()), (1000, "1"));
        protocol::InventoryPayload::Registry(r).validate().unwrap();
        protocol::InventoryPayload::Security(security(2))
            .validate()
            .unwrap();
    }
}
