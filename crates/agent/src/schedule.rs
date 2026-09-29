//! 各區段該不該收集：basic 每次心跳；其他依伺服器下發的間隔或被觸發。

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use protocol::{CollectionIntervals, Section};

pub const DEFAULT_INTERVALS: CollectionIntervals = CollectionIntervals {
    software_secs: 3600,
    patches_secs: 3600,
    services_secs: 3600,
    hardware_secs: 86_400,
    security_secs: 3600,
    registry_secs: 3600,
};

#[derive(Default)]
pub struct Schedule {
    last: HashMap<Section, Instant>,
    triggered: HashSet<Section>,
}

fn interval(s: Section, iv: &CollectionIntervals) -> Duration {
    let secs = match s {
        Section::Basic => 0,
        Section::Hardware => iv.hardware_secs,
        Section::Software => iv.software_secs,
        Section::Patches => iv.patches_secs,
        Section::Services => iv.services_secs,
        Section::Security => iv.security_secs,
        Section::Registry => iv.registry_secs,
    };
    Duration::from_secs(secs.into())
}

impl Schedule {
    pub fn due(&self, now: Instant, iv: &CollectionIntervals) -> Vec<Section> {
        Section::ALL
            .into_iter()
            .filter(|s| {
                self.triggered.contains(s)
                    || self
                        .last
                        .get(s)
                        .is_none_or(|t| now.saturating_duration_since(*t) >= interval(*s, iv))
            })
            .collect()
    }

    pub fn mark_collected(&mut self, s: Section, now: Instant) {
        self.last.insert(s, now);
        self.triggered.remove(&s);
    }

    pub fn trigger(&mut self, s: Section) {
        self.triggered.insert(s);
    }
}

/// 限制觸發頻率：距離上次放行不到 min_gap 就忽略（可跨執行緒共用）。
pub struct Throttle {
    min_gap: Duration,
    last: std::sync::Mutex<Option<Instant>>,
}

impl Throttle {
    pub fn new(min_gap: Duration) -> Self {
        Self {
            min_gap,
            last: std::sync::Mutex::new(None),
        }
    }

    pub fn allow(&self, now: Instant) -> bool {
        let mut last = self.last.lock().expect("throttle lock");
        if last.is_some_and(|t| now.duration_since(t) < self.min_gap) {
            return false;
        }
        *last = Some(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Windows 更新期間 CBS 機碼幾乎不停變動：觸發要有最小間隔，
    /// 否則 Agent 每 10 秒就報到一次，也會塞滿觸發通道擠掉軟體變更。
    #[test]
    fn throttle_enforces_minimum_gap() {
        let t = Throttle::new(Duration::from_secs(300));
        let t0 = Instant::now();
        assert!(t.allow(t0));
        assert!(!t.allow(t0 + Duration::from_secs(10)));
        assert!(!t.allow(t0 + Duration::from_secs(299)));
        assert!(t.allow(t0 + Duration::from_secs(300)));
        assert!(!t.allow(t0 + Duration::from_secs(301)));
    }

    #[test]
    fn everything_due_at_start() {
        let s = Schedule::default();
        assert_eq!(
            s.due(Instant::now(), &DEFAULT_INTERVALS),
            Section::ALL.to_vec()
        );
    }

    #[test]
    fn respects_intervals_and_triggers() {
        let mut s = Schedule::default();
        let t0 = Instant::now();
        for sec in Section::ALL {
            s.mark_collected(sec, t0);
        }
        assert_eq!(s.due(t0, &DEFAULT_INTERVALS), vec![Section::Basic]);

        s.trigger(Section::Software);
        assert_eq!(
            s.due(t0, &DEFAULT_INTERVALS),
            vec![Section::Basic, Section::Software]
        );
        s.mark_collected(Section::Software, t0);
        assert_eq!(s.due(t0, &DEFAULT_INTERVALS), vec![Section::Basic]);

        let later = t0 + Duration::from_secs(3600);
        assert_eq!(
            s.due(later, &DEFAULT_INTERVALS),
            vec![
                Section::Basic,
                Section::Software,
                Section::Patches,
                Section::Services,
                Section::Security,
                Section::Registry
            ]
        );
        let much_later = t0 + Duration::from_secs(86_400);
        assert!(
            s.due(much_later, &DEFAULT_INTERVALS)
                .contains(&Section::Hardware)
        );
    }
}
