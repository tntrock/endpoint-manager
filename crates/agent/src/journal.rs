//! 本機事件日誌 `events.jsonl`（網路規格 §4.3）。
//!
//! 第一行是標頭 `{"journal_id": …, "next_seq": …}`，之後一行一筆事件。
//! 新增事件只在檔尾附加並 fsync；伺服器確認收到後才刪除（整個檔案重寫）。
//! 連不上伺服器或伺服器還不支援時就一直存著，受筆數與天數上限限制。

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use protocol::AgentEvent;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub const FILE: &str = "events.jsonl";
/// 最多保留的事件數
pub const MAX_EVENTS: usize = 5000;
/// 最多保留的天數
pub const MAX_AGE: Duration = Duration::days(30);

#[derive(Serialize, Deserialize)]
struct Header {
    journal_id: Uuid,
    next_seq: u64,
}

pub struct Journal {
    path: PathBuf,
    id: Uuid,
    next_seq: u64,
    events: VecDeque<AgentEvent>,
}

impl Journal {
    /// 讀取日誌。檔案不存在、標頭壞掉時換一個新的 journal_id；壞掉的事件行略過
    pub fn open(dir: &Path) -> Self {
        let path = dir.join(FILE);
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let mut lines = text.lines();
        let header = lines
            .next()
            .and_then(|l| serde_json::from_str::<Header>(l).ok());
        let mut events: VecDeque<AgentEvent> = lines
            .filter_map(|l| serde_json::from_str::<AgentEvent>(l).ok())
            .collect();
        events.make_contiguous().sort_by_key(|e| e.seq);
        let after_events = events.back().map_or(1, |e| e.seq + 1);
        let (id, next_seq, rewrite) = match header {
            Some(h) => (h.journal_id, h.next_seq.max(after_events), false),
            None => (Uuid::new_v4(), after_events, true),
        };
        let j = Self {
            path,
            id,
            next_seq,
            events,
        };
        if rewrite && let Err(e) = j.rewrite() {
            tracing::warn!(error = %e, "cannot write event journal");
        }
        j
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// 最舊的 n 筆
    pub fn pending(&self, n: usize) -> Vec<AgentEvent> {
        self.events.iter().take(n).cloned().collect()
    }

    fn push(&mut self, kind: &str, data: serde_json::Value, at: OffsetDateTime) -> AgentEvent {
        let e = AgentEvent {
            seq: self.next_seq,
            at,
            kind: kind.to_string(),
            data,
        };
        self.next_seq += 1;
        self.events.push_back(e.clone());
        e
    }

    /// 記一筆事件。超過上限時刪掉最舊的，並記一筆 `journal.dropped`
    pub fn append(
        &mut self,
        kind: &str,
        data: serde_json::Value,
        now: OffsetDateTime,
    ) -> std::io::Result<()> {
        let before = self.events.len();
        self.events.retain(|e| now - e.at <= MAX_AGE);
        // 留兩個位置：journal.dropped 與這一筆
        while self.events.len() + 2 > MAX_EVENTS {
            self.events.pop_front();
        }
        let dropped = before - self.events.len();
        if dropped > 0 {
            self.push(
                AgentEvent::JOURNAL_DROPPED,
                serde_json::json!({ "count": dropped }),
                now,
            );
            self.push(kind, data, now);
            return self.rewrite();
        }
        let e = self.push(kind, data, now);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(
            f,
            "{}",
            serde_json::to_string(&e).expect("event serializes")
        )?;
        f.sync_data()?;
        // 標頭的 next_seq 不用每次更新：開啟時取標頭與最後一筆事件的較大者
        Ok(())
    }

    /// 伺服器確認收到序號不大於 seq 的事件：刪除它們
    pub fn ack(&mut self, seq: u64) -> std::io::Result<()> {
        let before = self.events.len();
        self.events.retain(|e| e.seq > seq);
        if self.events.len() == before {
            return Ok(());
        }
        self.rewrite()
    }

    /// 寫到暫存檔再改名：寫到一半斷電也不會留下半個日誌
    fn rewrite(&self) -> std::io::Result<()> {
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut f = File::create(&tmp)?;
            let header = Header {
                journal_id: self.id,
                next_seq: self.next_seq,
            };
            writeln!(f, "{}", serde_json::to_string(&header).expect("header"))?;
            for e in &self.events {
                writeln!(f, "{}", serde_json::to_string(e).expect("event serializes"))?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn t0() -> OffsetDateTime {
        time::macros::datetime!(2026-11-22 00:00 UTC)
    }

    #[test]
    fn append_reopen_and_ack() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path());
        assert!(j.is_empty());
        let id = j.id();
        j.append("net.up", json!({"name": "eth0"}), t0()).unwrap();
        j.append("net.down", json!({"name": "eth0"}), t0()).unwrap();

        // 重新開啟後內容、序號、ID 都延續
        let mut j = Journal::open(dir.path());
        assert_eq!(j.id(), id);
        assert_eq!(
            j.pending(10).iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(j.pending(1).len(), 1);
        j.ack(1).unwrap();
        j.ack(1).unwrap();
        assert_eq!(j.len(), 1);
        j.ack(2).unwrap();
        assert!(j.is_empty());

        // 全部確認後序號不歸零（伺服器以序號去重）
        let mut j = Journal::open(dir.path());
        j.append("net.up", json!({}), t0()).unwrap();
        assert_eq!(j.pending(1)[0].seq, 3);
        assert_eq!(j.id(), id);
    }

    #[test]
    fn corrupt_lines_are_skipped_and_bad_header_gets_new_id() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path());
        let id = j.id();
        j.append("net.up", json!({}), t0()).unwrap();
        let p = dir.path().join(FILE);
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str("{garbage\n");
        std::fs::write(&p, &text).unwrap();
        let mut j = Journal::open(dir.path());
        assert_eq!((j.id(), j.len()), (id, 1));
        j.append("net.down", json!({}), t0()).unwrap();
        assert_eq!(j.pending(5).last().unwrap().seq, 2);

        // 標頭壞掉（或重新安裝）：換新的 ID，還讀得到的事件保留
        let text = std::fs::read_to_string(&p).unwrap();
        let body: Vec<&str> = text.lines().skip(1).collect();
        std::fs::write(&p, format!("not json\n{}\n", body.join("\n"))).unwrap();
        let j = Journal::open(dir.path());
        assert_ne!(j.id(), id);
        assert_eq!(j.len(), 2);
        let j2 = Journal::open(dir.path());
        assert_eq!(j2.id(), j.id(), "新的標頭已寫回");
    }

    #[test]
    fn caps_count_and_age() {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path());
        // 直接塞滿（不逐筆寫檔，測試才快）
        for _ in 0..MAX_EVENTS {
            j.push("net.changed", json!({}), t0());
        }
        j.append("net.up", json!({}), t0()).unwrap();
        assert_eq!(j.len(), MAX_EVENTS);
        let all = j.pending(MAX_EVENTS);
        let dropped = &all[all.len() - 2];
        assert_eq!(dropped.kind, AgentEvent::JOURNAL_DROPPED);
        assert_eq!(dropped.data["count"], 2);
        assert_eq!(all.last().unwrap().kind, "net.up");

        // 超過 30 天的刪掉
        let later = t0() + Duration::days(31);
        j.append("net.down", json!({}), later).unwrap();
        let all = j.pending(10);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].data["count"], MAX_EVENTS);
        assert_eq!(Journal::open(dir.path()).len(), 2);
    }
}
