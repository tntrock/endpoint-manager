//! 各區段該不該收集：basic 每次心跳；其他依伺服器下發的間隔或被觸發。

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use protocol::{CollectionIntervals, Section};

pub const DEFAULT_INTERVALS: CollectionIntervals = CollectionIntervals {
    software_secs: 3600,
    patches_secs: 3600,
    services_secs: 3600,
    hardware_secs: 86_400,
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

#[cfg(test)]
mod tests {
    use super::*;

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
                Section::Services
            ]
        );
        let much_later = t0 + Duration::from_secs(86_400);
        assert!(
            s.due(much_later, &DEFAULT_INTERVALS)
                .contains(&Section::Hardware)
        );
    }
}
