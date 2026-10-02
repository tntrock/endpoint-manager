//! 授權結果快取：(端點憑證指紋, package_id) → 允許與否，保存 AUTH_TTL。
//! 中央連不上時，期限內允許過的組合繼續允許。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const AUTH_TTL: Duration = Duration::from_secs(5 * 60);

pub struct AuthCache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, i64), (Instant, bool)>>,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> AuthCache {
        AuthCache {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
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
}
