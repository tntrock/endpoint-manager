//! 連不上伺服器時的退避：60 秒起每次加倍，上限 30 分鐘。

use std::time::Duration;

use uuid::Uuid;

pub const MIN_DELAY: Duration = Duration::from_secs(60);
pub const MAX_DELAY: Duration = Duration::from_secs(1800);

#[derive(Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    pub fn next_delay(&mut self, jitter: f64) -> Duration {
        let base = MIN_DELAY
            .saturating_mul(2u32.saturating_pow(self.failures))
            .min(MAX_DELAY);
        self.failures = self.failures.saturating_add(1);
        with_jitter(base, jitter)
    }

    pub fn reset(&mut self) {
        self.failures = 0;
    }
}

/// 0.8～1.2 的隨機倍率（用 UUID v4 的亂數，不另外引入 rand）。
pub fn jitter() -> f64 {
    // 以整數算出 800～1200 再除以 1000，避免 0.8 + 0.4 的浮點誤差超出上限
    (800 + (Uuid::new_v4().as_u128() % 401) as u32) as f64 / 1000.0
}

pub fn with_jitter(d: Duration, j: f64) -> Duration {
    d.mul_f64(j)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_until_cap_then_resets() {
        let mut b = Backoff::default();
        let secs: Vec<u64> = (0..7).map(|_| b.next_delay(1.0).as_secs()).collect();
        assert_eq!(secs, vec![60, 120, 240, 480, 960, 1800, 1800]);
        b.reset();
        assert_eq!(b.next_delay(1.0).as_secs(), 60);
    }

    #[test]
    fn jitter_in_range() {
        for _ in 0..1000 {
            let j = jitter();
            assert!((0.8..=1.2).contains(&j), "{j}");
        }
        assert_eq!(
            with_jitter(Duration::from_secs(100), 0.8),
            Duration::from_secs(80)
        );
    }
}
