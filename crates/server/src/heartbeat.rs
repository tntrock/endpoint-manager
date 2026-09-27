//! 心跳熱欄位先存記憶體，定期批次寫入，避免每次心跳都寫資料庫。

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub const FLUSH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub seen_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub logged_on_user: Option<String>,
    pub boot_time: DateTime<Utc>,
    pub agent_version: String,
    pub section_errors: serde_json::Value,
}

#[derive(Default)]
pub struct HeartbeatBuffer {
    inner: Mutex<HashMap<Uuid, HotFields>>,
}

impl HeartbeatBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, id: Uuid, hot: HotFields) {
        self.inner.lock().expect("heartbeat lock").insert(id, hot);
    }

    /// 寫入失敗時把資料放回（不覆蓋期間收到的較新資料）。
    pub async fn flush(&self, pool: &PgPool) -> Result<usize, sqlx::Error> {
        let batch = std::mem::take(&mut *self.inner.lock().expect("heartbeat lock"));
        if batch.is_empty() {
            return Ok(0);
        }
        let mut ids = Vec::with_capacity(batch.len());
        let (mut seen, mut ips, mut users, mut boots, mut vers, mut errs) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        for (id, h) in &batch {
            ids.push(*id);
            seen.push(h.seen_at);
            ips.push(h.ip.clone());
            users.push(h.logged_on_user.clone());
            boots.push(h.boot_time);
            vers.push(h.agent_version.clone());
            errs.push(h.section_errors.to_string());
        }
        let result = sqlx::query(
            "UPDATE devices d SET last_seen_at = v.seen, last_ip = v.ip, logged_on_user = v.usr, \
                 boot_time = v.boot, agent_version = v.ver, section_errors = v.errs::jsonb \
             FROM UNNEST($1::uuid[], $2::timestamptz[], $3::text[], $4::text[], \
                         $5::timestamptz[], $6::text[], $7::text[]) \
                 AS v(id, seen, ip, usr, boot, ver, errs) \
             WHERE d.id = v.id",
        )
        .bind(&ids)
        .bind(&seen)
        .bind(&ips)
        .bind(&users)
        .bind(&boots)
        .bind(&vers)
        .bind(&errs)
        .execute(pool)
        .await;
        match result {
            Ok(_) => Ok(batch.len()),
            Err(e) => {
                let mut inner = self.inner.lock().expect("heartbeat lock");
                for (id, h) in batch {
                    inner.entry(id).or_insert(h);
                }
                Err(e)
            }
        }
    }
}
