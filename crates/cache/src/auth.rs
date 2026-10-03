//! 授權結果快取：(端點憑證指紋, package_id) → 允許與否，保存 AUTH_TTL。
//! 中央連不上時，期限內允許過的組合繼續允許。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const AUTH_TTL: Duration = Duration::from_secs(5 * 60);

/// 向中央詢問授權失敗（逾時、連不上）後多久內不再詢問、直接回 503
pub const FAIL_MEMORY: Duration = Duration::from_secs(30);

pub struct AuthCache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, i64), (Instant, bool)>>,
    /// 最近一次詢問失敗後，到這個時間前直接回 503（中央卡住時不讓每個請求都等）
    failed_until: Mutex<Option<Instant>>,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> AuthCache {
        AuthCache {
            ttl,
            entries: Mutex::new(HashMap::new()),
            failed_until: Mutex::new(None),
        }
    }

    /// 記住詢問失敗，`for_` 期間內 `failing()` 為 true
    pub fn fail(&self, for_: Duration) {
        *self.failed_until.lock().expect("auth lock") = Some(Instant::now() + for_);
    }

    /// 中央恢復（報到成功）時呼叫：不必等記憶期滿
    pub fn clear_failure(&self) {
        *self.failed_until.lock().expect("auth lock") = None;
    }

    pub fn failing(&self) -> bool {
        self.failed_until
            .lock()
            .expect("auth lock")
            .is_some_and(|t| Instant::now() < t)
    }

    /// 未過期的結果
    pub fn get(&self, fingerprint: &str, package_id: i64) -> Option<bool> {
        self.entries
            .lock()
            .expect("auth lock")
            .get(&(fingerprint.to_string(), package_id))
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, allowed)| *allowed)
    }

    pub fn put(&self, fingerprint: &str, package_id: i64, allowed: bool) {
        self.entries.lock().expect("auth lock").insert(
            (fingerprint.to_string(), package_id),
            (Instant::now(), allowed),
        );
    }

    /// 移除過期項目（背景迴圈定期呼叫，避免無限增長）
    pub fn prune(&self) {
        let ttl = self.ttl;
        self.entries
            .lock()
            .expect("auth lock")
            .retain(|_, (at, _)| at.elapsed() < ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("auth lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 每隔 `every` 移除過期項目（與報到成敗無關）
pub async fn prune_loop(auth: std::sync::Arc<AuthCache>, every: Duration) {
    loop {
        tokio::time::sleep(every).await;
        auth.prune();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_expire() {
        let a = AuthCache::new(Duration::from_millis(50));
        assert_eq!(a.get("fp", 1), None);
        a.put("fp", 1, true);
        a.put("fp", 2, false);
        assert_eq!(a.get("fp", 1), Some(true));
        assert_eq!(a.get("fp", 2), Some(false));
        assert_eq!(a.get("other", 1), None);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(a.get("fp", 1), None);
        assert_eq!(a.len(), 2);
        a.prune();
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn failure_can_be_cleared() {
        let a = AuthCache::new(Duration::from_secs(60));
        a.fail(Duration::from_secs(30));
        a.clear_failure();
        assert!(!a.failing());
    }

    #[test]
    fn failure_is_remembered() {
        let a = AuthCache::new(Duration::from_secs(60));
        assert!(!a.failing());
        a.fail(Duration::from_millis(50));
        assert!(a.failing());
        std::thread::sleep(Duration::from_millis(60));
        assert!(!a.failing());
    }

    #[tokio::test]
    async fn prune_runs_on_its_own() {
        let a = std::sync::Arc::new(AuthCache::new(Duration::from_millis(10)));
        a.put("fp", 1, true);
        let task = tokio::spawn(prune_loop(a.clone(), Duration::from_millis(20)));
        tokio::time::sleep(Duration::from_millis(100)).await;
        task.abort();
        assert!(a.is_empty());
    }
}
