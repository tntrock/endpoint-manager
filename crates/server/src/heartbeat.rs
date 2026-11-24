//! 心跳熱欄位先存記憶體，定期批次寫入，避免每次心跳都寫資料庫。

use std::collections::HashMap;
use std::sync::Mutex;

use sqlx::PgPool;
use uuid::Uuid;

pub const FLUSH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub seen_at: time::OffsetDateTime,
    pub ip: Option<String>,
    /// 全部位址（已驗證格式，見 [`valid_ips`]）
    pub ips: Vec<String>,
    pub logged_on_user: Option<String>,
    pub boot_time: time::OffsetDateTime,
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

    /// 尚未寫入資料庫的筆數
    pub fn len(&self) -> usize {
        self.inner.lock().expect("heartbeat lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn record(&self, id: Uuid, hot: HotFields) {
        self.inner.lock().expect("heartbeat lock").insert(id, hot);
    }

    /// 關閉前的最後一次寫入，最多等 limit（docker stop 預設只給有限時間）。回傳是否成功寫出。
    pub async fn flush_before_exit(&self, pool: &PgPool, limit: std::time::Duration) -> bool {
        match tokio::time::timeout(limit, self.flush(pool)).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "final heartbeat flush failed");
                false
            }
            Err(_) => {
                tracing::error!(?limit, "final heartbeat flush timed out");
                false
            }
        }
    }

    /// 批次寫入。資料庫拒絕某些列（資料錯誤）時改逐列寫入並丟棄壞列；
    /// 連線類錯誤則把資料放回（不覆蓋期間收到的較新資料），下次再試。
    pub async fn flush(&self, pool: &PgPool) -> Result<usize, sqlx::Error> {
        let batch: Vec<(Uuid, HotFields)> =
            std::mem::take(&mut *self.inner.lock().expect("heartbeat lock"))
                .into_iter()
                .collect();
        if batch.is_empty() {
            return Ok(0);
        }
        let err = match write_rows(pool, &batch).await {
            Ok(()) => return Ok(batch.len()),
            Err(e) => e,
        };
        if !matches!(err, sqlx::Error::Database(_)) {
            self.requeue(batch);
            return Err(err);
        }
        let mut written = 0;
        for row in batch {
            match write_rows(pool, std::slice::from_ref(&row)).await {
                Ok(()) => written += 1,
                Err(sqlx::Error::Database(e)) => {
                    tracing::warn!(device_id = %row.0, error = %e, "dropping unwritable heartbeat")
                }
                Err(e) => {
                    self.requeue(vec![row]);
                    return Err(e);
                }
            }
        }
        Ok(written)
    }

    fn requeue(&self, rows: Vec<(Uuid, HotFields)>) {
        let mut inner = self.inner.lock().expect("heartbeat lock");
        for (id, h) in rows {
            inner.entry(id).or_insert(h);
        }
    }
}

async fn write_rows(pool: &PgPool, rows: &[(Uuid, HotFields)]) -> Result<(), sqlx::Error> {
    let mut ids = Vec::with_capacity(rows.len());
    let (mut seen, mut ips, mut users, mut boots, mut vers, mut errs) =
        (vec![], vec![], vec![], vec![], vec![], vec![]);
    // 每列一個以逗號串接的字串：UNNEST 不能展開長度不同的二維陣列
    let mut all_ips = Vec::with_capacity(rows.len());
    for (id, h) in rows {
        ids.push(*id);
        seen.push(h.seen_at);
        ips.push(h.ip.as_deref());
        all_ips.push(h.ips.join(","));
        users.push(h.logged_on_user.as_deref());
        boots.push(h.boot_time);
        vers.push(h.agent_version.as_str());
        errs.push(h.section_errors.to_string());
    }
    sqlx::query(
        "UPDATE devices d SET last_seen_at = v.seen, last_ip = v.ip, logged_on_user = v.usr,              boot_time = v.boot, agent_version = v.ver, section_errors = v.errs::jsonb,               ips = string_to_array(v.ips, ',')::inet[]          FROM UNNEST($1::uuid[], $2::timestamptz[], $3::text[], $4::text[],                      $5::timestamptz[], $6::text[], $7::text[], $8::text[])               AS v(id, seen, ip, usr, boot, ver, errs, ips)          WHERE d.id = v.id",
    )
    .bind(&ids)
    .bind(&seen)
    .bind(&ips)
    .bind(&users)
    .bind(&boots)
    .bind(&vers)
    .bind(&errs)
    .bind(&all_ips)
    .execute(pool)
    .await?;
    // 報到了：「Agent 沒報到但在網路上」結束
    let mut conn = pool.acquire().await?;
    crate::netdev::crosscheck::checked_in(&mut conn, &ids).await?;
    Ok(())
}

/// 每台最多存的位址數
pub const MAX_IPS: usize = 64;

/// Agent 回報的位址：只留解析得了的（寫入時轉 inet，格式錯一個整批都會失敗），去重，最多 [`MAX_IPS`] 個
pub fn valid_ips(raw: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in raw {
        let Ok(ip) = r.trim().parse::<std::net::IpAddr>() else {
            continue;
        };
        let s = ip.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
        if out.len() == MAX_IPS {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ips_filters_dedups_and_caps() {
        let raw: Vec<String> = ["10.0.0.1", "x", " 10.0.0.1 ", "::1"]
            .map(String::from)
            .to_vec();
        assert_eq!(valid_ips(&raw), ["10.0.0.1", "::1"]);
        let many: Vec<String> = (0..100).map(|i| format!("10.0.1.{i}")).collect();
        assert_eq!(valid_ips(&many).len(), MAX_IPS);
    }
    use std::time::{Duration, Instant};

    /// docker stop 只給 30 秒（stop_grace_period）：資料庫卡住時，關閉前的寫入不能無限等待。
    #[tokio::test]
    async fn flush_before_exit_gives_up_after_limit() {
        // 接受連線但永遠不回應的「資料庫」：保證 flush 會卡住，測到的是逾時而不是連線失敗
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((sock, _)) = listener.accept().await {
                held.push(sock);
            }
        });
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(60))
            .connect_lazy(&format!("postgres://u:p@{addr}/db"))
            .unwrap();
        let hb = HeartbeatBuffer::new();
        hb.record(
            Uuid::new_v4(),
            HotFields {
                seen_at: time::OffsetDateTime::now_utc(),
                ip: None,
                ips: vec![],
                logged_on_user: None,
                boot_time: time::OffsetDateTime::now_utc(),
                agent_version: "t".into(),
                section_errors: serde_json::json!({}),
            },
        );
        let start = Instant::now();
        assert!(
            !hb.flush_before_exit(&pool, Duration::from_millis(300))
                .await
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }
}
