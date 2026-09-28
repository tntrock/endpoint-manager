//! 依 IP 的固定視窗限速（用於未經 mTLS 的註冊端點）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// IPv6 以 /64 為單位（一個使用者或網段通常就有一整個 /64，可以任意換位址）。
fn key_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        IpAddr::V6(v6) => IpAddr::V4(v6.to_ipv4_mapped().expect("mapped")),
        v4 => v4,
    }
}

/// 同時追蹤的來源（IPv4 位址或 IPv6 /64）上限
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
        let ip = key_of(ip);
        let mut hits = self.hits.lock().expect("ratelimit lock");
        if hits.len() >= MAX_TRACKED && !hits.contains_key(&ip) {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
            // 視窗內仍有太多不同來源（分散式攻擊）：清空重來，寧可暫時放寬也不讓記憶體無限成長。
            // 只清出不到一成時也直接清空，避免之後每個新來源都做一次全表掃描。
            if hits.len() >= MAX_TRACKED * 9 / 10 {
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

    /// 一個 IPv6 /64 就有無數個真實位址：同一個 /64 共用限額，不能靠換位址繞過或灌滿表格。
    #[test]
    fn ipv6_is_limited_per_64() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let t0 = Instant::now();
        let ip =
            |last: u16| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, last));
        assert!(rl.check(ip(1), t0));
        assert!(rl.check(ip(2), t0));
        assert!(!rl.check(ip(3), t0), "同一個 /64");
        let other = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
        assert!(rl.check(other, t0), "另一個 /64");
        assert_eq!(rl.tracked(), 2);
    }

    #[test]
    fn ips_are_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), t0));
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), t0));
    }
}
