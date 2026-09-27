//! 依 IP 的固定視窗限速（用於未經 mTLS 的註冊端點）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
        if hits.len() > 100_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
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

    #[test]
    fn ips_are_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), t0));
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), t0));
    }
}
