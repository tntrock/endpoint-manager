//! 網路設備查詢：依中央下發的工作排程，查詢後上傳結果。
//!
//! 帳密只放在記憶體（工作每次報到都會重新下發）。

pub mod collect;
pub mod parse;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use protocol::netdev::{SnmpJob, SnmpTarget};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::central::Central;
use collect::Limits;

/// 每台快取同時查詢幾台設備
pub const CONCURRENCY: usize = 4;

#[derive(Debug)]
struct Entry {
    target: SnmpTarget,
    next: Instant,
    running: bool,
}

/// 連線設定是否相同（不同就立即重新查詢）
fn same_config(a: &SnmpTarget, b: &SnmpTarget) -> bool {
    a.address == b.address
        && a.port == b.port
        && a.credential == b.credential
        && a.cisco_vlan == b.cisco_vlan
}

#[derive(Debug, Default)]
pub struct Schedule {
    entries: HashMap<i64, Entry>,
    interval: Duration,
}

impl Schedule {
    /// 套用新的工作：新增或設定改變的設備、要求立即查詢的設備排在現在；移除不在工作裡的
    pub fn apply(&mut self, job: Option<&SnmpJob>, now: Instant) {
        let Some(job) = job else {
            self.entries.clear();
            return;
        };
        self.interval = Duration::from_secs(job.system_interval_secs.max(60).into());
        let ids: std::collections::HashSet<i64> = job.targets.iter().map(|t| t.id).collect();
        self.entries.retain(|id, _| ids.contains(id));
        for t in &job.targets {
            match self.entries.get_mut(&t.id) {
                Some(e) => {
                    if !same_config(&e.target, t) || t.poll_now {
                        e.next = now;
                    }
                    e.target = t.clone();
                }
                None => {
                    self.entries.insert(
                        t.id,
                        Entry {
                            target: t.clone(),
                            next: now,
                            running: false,
                        },
                    );
                }
            }
        }
    }

    /// 到期、還沒在跑的設備（最早到期的優先），最多 n 台；標記為執行中
    pub fn take_due(&mut self, now: Instant, n: usize) -> Vec<SnmpTarget> {
        let mut due: Vec<&mut Entry> = self
            .entries
            .values_mut()
            .filter(|e| !e.running && e.next <= now)
            .collect();
        due.sort_by_key(|e| (e.next, e.target.id));
        due.into_iter()
            .take(n)
            .map(|e| {
                e.running = true;
                e.target.clone()
            })
            .collect()
    }

    /// 一輪結束：排下一次
    pub fn finished(&mut self, id: i64, now: Instant) {
        if let Some(e) = self.entries.get_mut(&id) {
            e.running = false;
            e.next = now + self.interval;
        }
    }

    /// 最近一次到期的時間（沒有設備時 None）
    pub fn next_due(&self) -> Option<Instant> {
        self.entries
            .values()
            .filter(|e| !e.running)
            .map(|e| e.next)
            .min()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// 背景工作：工作有變化時重新排程，到期就查詢並上傳
pub async fn run(
    central: Arc<Central>,
    mut jobs: watch::Receiver<Option<SnmpJob>>,
    limits: Limits,
    mut stop: watch::Receiver<bool>,
) {
    let mut sched = Schedule::default();
    let mut tasks: JoinSet<i64> = JoinSet::new();
    sched.apply(jobs.borrow_and_update().as_ref(), Instant::now());
    loop {
        let now = Instant::now();
        for t in sched.take_due(now, CONCURRENCY.saturating_sub(tasks.len())) {
            let central = central.clone();
            tasks.spawn(async move {
                let d = collect::poll_system(&t, &limits).await;
                if let Some(e) = &d.error {
                    tracing::info!(device_id = t.id, address = %t.address, error = %e, "SNMP poll failed");
                }
                if let Err(e) = central.netdata(&d).await {
                    tracing::warn!(device_id = t.id, error = %e, "uploading SNMP result failed");
                }
                t.id
            });
        }
        // 沒有到期的設備時最多等 60 秒（工作有變化或有一輪結束時會提早醒來）
        let wake = sched
            .next_due()
            .unwrap_or(now + Duration::from_secs(60))
            .max(now + Duration::from_millis(10));
        tokio::select! {
            r = jobs.changed() => {
                if r.is_err() {
                    break;
                }
                sched.apply(jobs.borrow_and_update().as_ref(), Instant::now());
            }
            Some(r) = tasks.join_next(), if !tasks.is_empty() => {
                match r {
                    Ok(id) => sched.finished(id, Instant::now()),
                    Err(e) => tracing::error!(error = %e, "SNMP poll task failed"),
                }
            }
            _ = tokio::time::sleep_until(wake) => {}
            _ = stop.changed() => {}
        }
        if *stop.borrow() {
            break;
        }
    }
    tasks.abort_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::netdev::{CiscoVlanMode, SnmpCredential};

    fn target(id: i64, addr: &str, poll_now: bool) -> SnmpTarget {
        SnmpTarget {
            id,
            address: addr.into(),
            port: 161,
            credential: SnmpCredential::V2c {
                community: "c".into(),
            },
            cisco_vlan: CiscoVlanMode::Auto,
            poll_now,
        }
    }

    fn job(targets: Vec<SnmpTarget>) -> SnmpJob {
        SnmpJob {
            targets,
            system_interval_secs: 900,
            table_interval_secs: 300,
        }
    }

    #[test]
    fn schedule_lifecycle() {
        let t0 = Instant::now();
        let mut s = Schedule::default();
        s.apply(
            Some(&job(vec![target(1, "a", false), target(2, "b", false)])),
            t0,
        );
        assert_eq!(s.len(), 2);
        // 同時上限 1：先跑 id 小的
        let due = s.take_due(t0, 1);
        assert_eq!(due.iter().map(|t| t.id).collect::<Vec<_>>(), vec![1]);
        assert_eq!(s.take_due(t0, 5).len(), 1, "1 在執行中，只剩 2");
        assert!(s.take_due(t0, 5).is_empty());
        s.finished(1, t0);
        s.finished(2, t0);
        assert_eq!(s.next_due(), Some(t0 + Duration::from_secs(900)));
        assert!(s.take_due(t0 + Duration::from_secs(899), 5).is_empty());

        // 下一次報到：1 沒變、2 改了位址、3 是新的
        let t1 = t0 + Duration::from_secs(60);
        s.apply(
            Some(&job(vec![
                target(1, "a", false),
                target(2, "b2", false),
                target(3, "c", false),
            ])),
            t1,
        );
        let mut due: Vec<i64> = s.take_due(t1, 5).iter().map(|t| t.id).collect();
        due.sort();
        assert_eq!(due, vec![2, 3]);

        // 管理員按「立即查詢」
        let t2 = t1 + Duration::from_secs(60);
        s.apply(
            Some(&job(vec![
                target(1, "a", true),
                target(2, "b2", false),
                target(3, "c", false),
            ])),
            t2,
        );
        assert_eq!(s.take_due(t2, 5).len(), 1);

        // 設備被移除、工作消失
        s.apply(Some(&job(vec![target(3, "c", false)])), t2);
        assert_eq!(s.len(), 1);
        s.finished(1, t2);
        assert_eq!(s.len(), 1, "已移除的設備結束時不會加回來");
        s.apply(None, t2);
        assert!(s.is_empty());
        assert_eq!(s.next_due(), None);
    }

    #[test]
    fn interval_has_a_floor() {
        let mut s = Schedule::default();
        let mut j = job(vec![target(1, "a", false)]);
        j.system_interval_secs = 5;
        let t0 = Instant::now();
        s.apply(Some(&j), t0);
        s.take_due(t0, 1);
        s.finished(1, t0);
        assert_eq!(s.next_due(), Some(t0 + Duration::from_secs(60)));
    }
}
