//! 目前的套件清單（catalog）與 single-flight 下載：同一個套件同時只向中央下載一次。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use protocol::branch::{CacheCheckinResponse, CachePackage};

use crate::central::{Central, CentralError};
use crate::store::Store;

pub const GB: u64 = 1024 * 1024 * 1024;
/// 中央還沒告訴我們上限前使用的磁碟上限
const DEFAULT_DISK_GB: u64 = 100;
/// 下載失敗後多久內直接回同樣的錯誤（中央卡住時不讓大量請求排隊等逾時）
pub const FAILURE_MEMO: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// 套件不在中央的清單上
    NotListed,
    /// 中央連不上、忙碌或拒絕
    Unavailable,
    /// 中央給的檔案與 sha256／大小不符
    Mismatch,
    /// 本機寫入失敗（磁碟滿等）
    Disk,
}

#[derive(Default)]
struct CatalogState {
    packages: HashMap<i64, CachePackage>,
    bandwidth_limit_mbps: Option<u32>,
    disk_limit_gb: Option<u32>,
}

/// 最近一次報到拿到的清單與上限
#[derive(Default)]
pub struct Catalog {
    state: RwLock<CatalogState>,
}

impl Catalog {
    pub fn replace(&self, r: &CacheCheckinResponse) {
        *self.state.write().expect("catalog lock") = CatalogState {
            packages: r.packages.iter().map(|p| (p.id, p.clone())).collect(),
            bandwidth_limit_mbps: r.bandwidth_limit_mbps,
            disk_limit_gb: Some(r.disk_limit_gb),
        };
    }

    pub fn get(&self, id: i64) -> Option<CachePackage> {
        self.state
            .read()
            .expect("catalog lock")
            .packages
            .get(&id)
            .cloned()
    }

    pub fn all(&self) -> Vec<CachePackage> {
        let mut v: Vec<CachePackage> = self
            .state
            .read()
            .expect("catalog lock")
            .packages
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|p| p.id);
        v
    }

    pub fn listed_shas(&self) -> HashSet<String> {
        self.state
            .read()
            .expect("catalog lock")
            .packages
            .values()
            .map(|p| p.sha256.clone())
            .collect()
    }

    /// (頻寬上限 Mbps, 磁碟上限 bytes)
    pub fn limits(&self) -> (Option<u32>, u64) {
        let s = self.state.read().expect("catalog lock");
        let gb = s.disk_limit_gb.map(u64::from).unwrap_or(DEFAULT_DISK_GB);
        (s.bandwidth_limit_mbps, gb * GB)
    }
}

type Slot = Arc<tokio::sync::Mutex<Option<(Instant, FetchError)>>>;

pub struct Fetcher {
    central: Arc<Central>,
    store: Arc<Store>,
    /// 每個檔案（sha256）一把鎖：不同套件可能是同一個檔案，共用暫存檔。鎖內記錄最近一次失敗
    slots: Mutex<HashMap<String, Slot>>,
}

impl Fetcher {
    pub fn new(central: Arc<Central>, store: Arc<Store>) -> Fetcher {
        Fetcher {
            central,
            store,
            slots: Mutex::new(HashMap::new()),
        }
    }

    fn slot(&self, sha256: &str) -> Slot {
        self.slots
            .lock()
            .expect("slots lock")
            .entry(sha256.to_string())
            .or_default()
            .clone()
    }

    /// 確保套件在本機。同一個檔案同時只有一個下載，其他人等它完成；
    /// 下載寫在暫存檔，等待者只會看到驗證過、改名完成的檔案。
    ///
    /// 下載在獨立的 task 執行：呼叫端放棄（端點逾時斷線）不會中斷下載。
    /// `wait` 有值時最多等這麼久，還沒完成就回 Unavailable（端點稍後重試），下載繼續進行。
    pub async fn ensure(
        self: &Arc<Self>,
        p: &CachePackage,
        limit_mbps: Option<u32>,
        wait: Option<Duration>,
    ) -> Result<PathBuf, FetchError> {
        if self.store.has(&p.sha256, p.size) {
            return Ok(self.store.path(&p.sha256));
        }
        let (me, p) = (self.clone(), p.clone());
        let task = tokio::spawn(async move { me.ensure_locked(&p, limit_mbps).await });
        let joined = match wait {
            Some(w) => match tokio::time::timeout(w, task).await {
                Ok(j) => j,
                Err(_) => return Err(FetchError::Unavailable),
            },
            None => task.await,
        };
        joined.unwrap_or(Err(FetchError::Unavailable))
    }

    async fn ensure_locked(
        &self,
        p: &CachePackage,
        limit_mbps: Option<u32>,
    ) -> Result<PathBuf, FetchError> {
        let path = self.store.path(&p.sha256);
        let slot = self.slot(&p.sha256);
        let mut last_failure = slot.lock().await;
        // 等鎖期間別人可能已下載完成
        if self.store.has(&p.sha256, p.size) {
            return Ok(path);
        }
        if let Some((at, err)) = *last_failure
            && at.elapsed() < FAILURE_MEMO
        {
            return Err(err);
        }
        match self.central.download(p, &path, limit_mbps).await {
            Ok(()) => {
                *last_failure = None;
                self.store.touch(&p.sha256);
                tracing::info!(package_id = p.id, "package downloaded from central");
                Ok(path)
            }
            Err(e) => {
                let err = match e {
                    CentralError::Mismatch => FetchError::Mismatch,
                    CentralError::Io(io) => {
                        tracing::error!(package_id = p.id, error = %io, "writing package failed");
                        FetchError::Disk
                    }
                    other => {
                        tracing::warn!(package_id = p.id, error = %other, "package download failed");
                        FetchError::Unavailable
                    }
                };
                *last_failure = Some((Instant::now(), err));
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::branch::CacheCheckinResponse;

    fn pkg(id: i64, c: char) -> CachePackage {
        CachePackage {
            id,
            sha256: c.to_string().repeat(64),
            size: 1,
        }
    }

    #[test]
    fn catalog_replace_and_limits() {
        let c = Catalog::default();
        assert!(c.get(1).is_none());
        assert_eq!(c.limits(), (None, 100 * GB));
        c.replace(&CacheCheckinResponse {
            packages: vec![pkg(1, 'a'), pkg(2, 'b')],
            bandwidth_limit_mbps: Some(20),
            disk_limit_gb: 5,
            renew_certificate: false,
        });
        assert_eq!(c.get(2).unwrap().sha256, "b".repeat(64));
        assert_eq!(c.limits(), (Some(20), 5 * GB));
        assert_eq!(c.listed_shas().len(), 2);
        assert_eq!(c.all().len(), 2);
    }
}
