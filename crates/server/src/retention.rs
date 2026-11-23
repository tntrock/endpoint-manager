//! 資料保留：定期清除過期的遠端指令結果與稽核記錄。

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sqlx::PgPool;

use crate::audit;
use crate::commands::Actor;
use crate::metrics::{Metrics, RetentionKind};

pub const COMMAND_KEY: &str = "command_history_days";
pub const AUDIT_KEY: &str = "audit_history_days";
pub const DEFAULT_COMMAND_DAYS: i32 = 180;
pub const DEFAULT_AUDIT_DAYS: i32 = 0;
pub const MIN_COMMAND_DAYS: i32 = 30;
pub const MIN_AUDIT_DAYS: i32 = 365;
pub const MAX_DAYS: i32 = 3650;
const BATCH: i64 = 1000;
const MAX_BATCHES: u32 = 100;
const PAUSE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// 0 表示永久保留
    pub command_days: i32,
    pub audit_days: i32,
}

/// 0 或 [min, MAX_DAYS] 之間才有效
pub fn valid(days: i32, min: i32) -> bool {
    days == 0 || (min..=MAX_DAYS).contains(&days)
}

/// 讀不到或被改壞（含超出範圍）時用預設值
fn parse(raw: Option<&str>, default: i32, min: i32) -> i32 {
    raw.and_then(|v| v.trim().parse::<i32>().ok())
        .filter(|d| valid(*d, min))
        .unwrap_or(default)
}

pub async fn load(pool: &PgPool) -> Result<Retention, sqlx::Error> {
    let mut c = pool.acquire().await?;
    load_tx(&mut c).await
}

/// 平台管理員修改保留天數；超出範圍時回錯誤訊息（給使用者看的）。
pub async fn save(pool: &PgPool, new: Retention, actor: &Actor) -> anyhow::Result<()> {
    anyhow::ensure!(actor.platform, "只有平台管理員可以修改");
    anyhow::ensure!(
        valid(new.command_days, MIN_COMMAND_DAYS),
        "遠端指令的保留天數須為 0（永久）或 {MIN_COMMAND_DAYS}–{MAX_DAYS}"
    );
    anyhow::ensure!(
        valid(new.audit_days, MIN_AUDIT_DAYS),
        "稽核記錄的保留天數須為 0（永久）或 {MIN_AUDIT_DAYS}–{MAX_DAYS}"
    );
    let mut tx = pool.begin().await?;
    // 鎖住設定列再讀舊值：兩人同時修改時，稽核記錄的舊值才正確
    sqlx::query("SELECT 1 FROM settings WHERE key = ANY($1) FOR UPDATE")
        .bind([COMMAND_KEY, AUDIT_KEY].as_slice())
        .execute(&mut *tx)
        .await?;
    let old = load_tx(&mut tx).await?;
    for (key, v) in [(COMMAND_KEY, new.command_days), (AUDIT_KEY, new.audit_days)] {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(v.to_string())
        .execute(&mut *tx)
        .await?;
    }
    audit::record(
        &mut tx,
        &actor.username,
        "setting_retention",
        None,
        json!({
            "command_days": new.command_days,
            "audit_days": new.audit_days,
            "old_command_days": old.command_days,
            "old_audit_days": old.audit_days,
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn load_tx(tx: &mut sqlx::PgConnection) -> Result<Retention, sqlx::Error> {
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT key, value #>> '{}' FROM settings WHERE key = ANY($1)")
            .bind([COMMAND_KEY, AUDIT_KEY].as_slice())
            .fetch_all(&mut *tx)
            .await?;
    let get = |k: &str| {
        rows.iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| v.as_deref())
    };
    Ok(Retention {
        command_days: parse(get(COMMAND_KEY), DEFAULT_COMMAND_DAYS, MIN_COMMAND_DAYS),
        audit_days: parse(get(AUDIT_KEY), DEFAULT_AUDIT_DAYS, MIN_AUDIT_DAYS),
    })
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Purged {
    pub commands: u64,
    pub audit: u64,
    /// Agent 上傳的事件與已結束的多重連線期間（固定保留天數）
    pub events: u64,
}

/// Agent 上傳的事件保留天數（固定）
pub const EVENT_DAYS: i32 = 180;
/// 已結束的多重連線期間保留天數（固定，比事件長：合規回溯與稽核要用）
pub const PERIOD_DAYS: i32 = 365;

/// MAC 位址表、ARP 表：最後一次看到超過這麼多天就刪除
pub const SIGHTING_DAYS: i32 = 30;
const DELETE_SIGHTINGS: &str = "DELETE FROM net_mac_sightings WHERE ctid IN ( \
     SELECT ctid FROM net_mac_sightings WHERE last_seen < now() - make_interval(days => $1) \
     LIMIT $2)";
const DELETE_ARP: &str = "DELETE FROM net_arp WHERE ctid IN ( \
     SELECT ctid FROM net_arp WHERE last_seen < now() - make_interval(days => $1) LIMIT $2)";
/// 電腦的網路位置：結束超過 365 天的
const DELETE_LOCATIONS: &str = "DELETE FROM endpoint_locations WHERE id IN ( \
     SELECT id FROM endpoint_locations WHERE ended_at < now() - make_interval(days => $1) \
     LIMIT $2)";
/// 竄改偵測的發現：開始超過 365 天、而且已經結束的
const DELETE_FINDINGS: &str = "DELETE FROM device_findings WHERE id IN ( \
     SELECT id FROM device_findings \
     WHERE started_at < now() - make_interval(days => $1) AND ended_at IS NOT NULL \
     ORDER BY id LIMIT $2)";
const DELETE_EVENTS: &str = "DELETE FROM device_events WHERE ctid IN ( \
     SELECT ctid FROM device_events WHERE received_at < now() - make_interval(days => $1) \
     LIMIT $2)";

const DELETE_PERIODS: &str = "DELETE FROM device_dual_homed_periods WHERE id IN ( \
     SELECT id FROM device_dual_homed_periods \
     WHERE ended_at < now() - make_interval(days => $1) ORDER BY id LIMIT $2)";

/// 已結束（過期、沒有未完成目標）且超過保留天數的指令；目標與輸出隨之刪除
const DELETE_COMMANDS: &str = "DELETE FROM command_runs WHERE id IN ( \
     SELECT r.id FROM command_runs r \
     WHERE r.created_at < now() - make_interval(days => $1) AND r.expires_at < now() \
       AND NOT EXISTS (SELECT 1 FROM command_targets t \
                       WHERE t.run_id = r.id AND t.status IN ('pending', 'sent')) \
     ORDER BY r.id LIMIT $2)";

const DELETE_AUDIT: &str = "DELETE FROM audit_log WHERE id IN ( \
     SELECT id FROM audit_log WHERE at < now() - make_interval(days => $1) \
     ORDER BY id LIMIT $2)";

/// 分批刪除，每次最多 MAX_BATCHES 批，剩下的下次再刪
async fn delete_batches(
    pool: &PgPool,
    sql: &'static str,
    days: i32,
    pause: Duration,
) -> Result<u64, sqlx::Error> {
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let n = sqlx::query(sql)
            .bind(days)
            .bind(BATCH)
            .execute(pool)
            .await?
            .rows_affected();
        total += n;
        if n < BATCH as u64 {
            break;
        }
        tokio::time::sleep(pause).await;
    }
    Ok(total)
}

pub async fn purge(pool: &PgPool) -> Result<Purged, sqlx::Error> {
    purge_with(pool, PAUSE).await
}

async fn purge_with(pool: &PgPool, pause: Duration) -> Result<Purged, sqlx::Error> {
    let r = load(pool).await?;
    let mut p = Purged::default();
    if r.command_days > 0 {
        p.commands = delete_batches(pool, DELETE_COMMANDS, r.command_days, pause).await?;
    }
    if r.audit_days > 0 {
        p.audit = delete_batches(pool, DELETE_AUDIT, r.audit_days, pause).await?;
    }
    p.events = delete_batches(pool, DELETE_EVENTS, EVENT_DAYS, pause).await?
        + delete_batches(pool, DELETE_PERIODS, PERIOD_DAYS, pause).await?
        + delete_batches(pool, DELETE_SIGHTINGS, SIGHTING_DAYS, pause).await?
        + delete_batches(pool, DELETE_ARP, SIGHTING_DAYS, pause).await?
        + delete_batches(pool, DELETE_LOCATIONS, PERIOD_DAYS, pause).await?
        + delete_batches(pool, DELETE_FINDINGS, PERIOD_DAYS, pause).await?;
    if p != Purged::default() {
        let mut c = pool.acquire().await?;
        audit::record(
            &mut c,
            "system",
            "retention_purge",
            None,
            json!({ "commands": p.commands, "audit": p.audit, "events": p.events }),
        )
        .await?;
    }
    Ok(p)
}

/// 啟動 1 分鐘後執行一次，之後每小時一次
pub fn spawn(pool: PgPool, metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            match purge(&pool).await {
                Ok(p) => {
                    metrics.retention_deleted(RetentionKind::Commands, p.commands);
                    metrics.retention_deleted(RetentionKind::Audit, p.audit);
                    metrics.retention_succeeded(time::OffsetDateTime::now_utc());
                    if p != Purged::default() {
                        tracing::info!(
                            commands = p.commands,
                            audit = p.audit,
                            events = p.events,
                            "retention purge"
                        );
                    }
                }
                Err(e) => tracing::error!(error = %e, "retention purge failed"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_validate() {
        assert_eq!(parse(None, 180, 30), 180);
        assert_eq!(parse(Some("abc"), 180, 30), 180);
        assert_eq!(parse(Some("0"), 180, 30), 0);
        assert_eq!(parse(Some(" 90 "), 180, 30), 90);
        assert_eq!(parse(Some("10"), 180, 30), 180);
        assert_eq!(parse(Some("-5"), 180, 30), 180);
        assert_eq!(parse(Some("99999"), 180, 30), 180);
        assert!(valid(0, 365));
        assert!(!valid(364, 365));
        assert!(valid(3650, 365));
        assert!(!valid(3651, 365));
    }

    fn platform() -> Actor {
        Actor {
            username: "root".into(),
            platform: true,
            groups: vec![],
        }
    }

    #[sqlx::test(migrations = false)]
    async fn defaults_and_save(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        assert_eq!(
            load(&pool).await.unwrap(),
            Retention {
                command_days: 180,
                audit_days: 0
            }
        );
        let new = Retention {
            command_days: 30,
            audit_days: 400,
        };
        save(&pool, new, &platform()).await.unwrap();
        assert_eq!(load(&pool).await.unwrap(), new);
        let detail: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_log WHERE action = 'setting_retention'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(detail.contains("\"old_command_days\": 180"), "{detail}");

        let bad = Retention {
            command_days: 10,
            audit_days: 0,
        };
        assert!(save(&pool, bad, &platform()).await.is_err());
        let bad = Retention {
            command_days: 0,
            audit_days: 100,
        };
        assert!(save(&pool, bad, &platform()).await.is_err());
        let group_admin = Actor {
            platform: false,
            ..platform()
        };
        assert!(save(&pool, new, &group_admin).await.is_err());
        assert_eq!(load(&pool).await.unwrap(), new);
    }

    async fn device(pool: &PgPool) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO devices (id, hostname) VALUES ($1, 'pc')")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
        id
    }

    /// 建立一筆 collect 指令：created 天前建立、expires 天後過期（負數＝已過期），目標狀態 status
    async fn run(pool: &PgPool, dev: uuid::Uuid, created: i32, expires: i32, status: &str) -> i64 {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO command_runs (action, target_label, created_by, created_at, expires_at) \
             VALUES ('collect', 'pc', 'root', now() - make_interval(days => $1), \
                     now() + make_interval(days => $2)) RETURNING id",
        )
        .bind(created)
        .bind(expires)
        .fetch_one(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO command_targets (run_id, device_id, status, output) VALUES ($1, $2, $3, 'out')",
        )
        .bind(id)
        .bind(dev)
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn runs(pool: &PgPool) -> Vec<i64> {
        sqlx::query_scalar("SELECT id FROM command_runs ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = false)]
    async fn purges_only_finished_old_commands(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let dev = device(&pool).await;
        let old_done = run(&pool, dev, 200, -190, "succeeded").await;
        let _old_open = run(&pool, dev, 200, -190, "pending").await;
        let _old_not_expired = run(&pool, dev, 200, 5, "failed").await;
        let _recent = run(&pool, dev, 10, -5, "succeeded").await;
        let keep: Vec<i64> = runs(&pool)
            .await
            .into_iter()
            .filter(|id| *id != old_done)
            .collect();

        let p = purge_with(&pool, Duration::ZERO).await.unwrap();
        assert_eq!(
            p,
            Purged {
                commands: 1,
                audit: 0,
                events: 0
            }
        );
        assert_eq!(runs(&pool).await, keep);
        let targets: i64 =
            sqlx::query_scalar("SELECT count(*) FROM command_targets WHERE run_id = $1")
                .bind(old_done)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(targets, 0);
        let logged: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_log WHERE action = 'retention_purge'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(logged.contains("\"commands\": 1"), "{logged}");

        // 0：永久保留
        let _another = run(&pool, dev, 200, -190, "succeeded").await;
        save(
            &pool,
            Retention {
                command_days: 0,
                audit_days: 0,
            },
            &platform(),
        )
        .await
        .unwrap();
        let p = purge_with(&pool, Duration::ZERO).await.unwrap();
        assert_eq!(p, Purged::default());
    }

    #[sqlx::test(migrations = false)]
    async fn purges_old_events_and_periods(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let dev = device(&pool).await;
        for (seq, days) in [(1, 200), (2, 10)] {
            sqlx::query(
                "INSERT INTO device_events (device_id, journal_id, seq, at, received_at, kind, data) \
                 VALUES ($1, gen_random_uuid(), $2, now(), now() - make_interval(days => $3), \
                         'net.up', '{}')",
            )
            .bind(dev)
            .bind(seq as i64)
            .bind(days)
            .execute(&pool)
            .await
            .unwrap();
        }
        // 已結束 400 天、已結束 10 天、持續中（開始於 500 天前）
        for (start, end) in [(500, Some(400)), (20, Some(10)), (500, None)] {
            sqlx::query(
                "INSERT INTO device_dual_homed_periods (device_id, started_at, ended_at, detail) \
                 VALUES ($1, now() - make_interval(days => $2), \
                         now() - make_interval(days => $3), 'x')",
            )
            .bind(dev)
            .bind(start)
            .bind(end)
            .execute(&pool)
            .await
            .unwrap();
        }
        let p = purge_with(&pool, Duration::ZERO).await.unwrap();
        assert_eq!(p.events, 2);
        let left: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM device_events), \
                    (SELECT count(*) FROM device_dual_homed_periods)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(left, (1, 2));
    }

    #[sqlx::test(migrations = false)]
    async fn purges_audit_when_configured(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        for days in [10, 400, 500] {
            sqlx::query(
                "INSERT INTO audit_log (actor, action, at) \
                 VALUES ('root', 'login', now() - make_interval(days => $1))",
            )
            .bind(days)
            .execute(&pool)
            .await
            .unwrap();
        }
        // 預設永久保留
        assert_eq!(purge_with(&pool, Duration::ZERO).await.unwrap().audit, 0);
        save(
            &pool,
            Retention {
                command_days: 180,
                audit_days: 365,
            },
            &platform(),
        )
        .await
        .unwrap();
        assert_eq!(purge_with(&pool, Duration::ZERO).await.unwrap().audit, 2);
        let left: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, ["login", "setting_retention", "retention_purge"]);
    }
}
