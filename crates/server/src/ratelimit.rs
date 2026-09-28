//! 依 IP 的固定視窗限速（用於未經 mTLS 的註冊端點）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 同時追蹤的來源 IP 上限
pub const MAX_TRACKED: usize = 100_000;

pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self {
            max,
            window,
            hits: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        let mut hits = self.hits.lock().expect("ratelimit lock");
        if hits.len() >= MAX_TRACKED && !hits.contains_key(&ip) {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            // 視窗內仍有太多不同來源（分散式攻擊）：清空重來，寧可暫時放寬也不讓記憶體無限成長
            if hits.len() >= MAX_TRACKED {
                hits.clear();
            }
        }
        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }

    pub fn tracked(&self) -> usize {
        self.hits.lock().expect("ratelimit lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_up_to_max_then_blocks_until_window_passes() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t0 = Instant::now();
        assert!(rl.check(ip, t0));
        assert!(rl.check(ip, t0));
        assert!(!rl.check(ip, t0));
        assert!(rl.check(ip, t0 + Duration::from_secs(61)));
    }

    /// 視窗內出現大量不同來源 IP（分散式攻擊）時，記憶體不能無限成長。
    #[test]
    fn map_size_is_bounded() {
        let rl = RateLimiter::new(10, Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..(MAX_TRACKED as u32 + 10) {
            rl.check(IpAddr::V4(Ipv4Addr::from(i)), t0);
        }
        assert!(rl.tracked() <= MAX_TRACKED, "{}", rl.tracked());
    }

    #[test]
    fn ips_are_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), t0));
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), t0));
    }
}
