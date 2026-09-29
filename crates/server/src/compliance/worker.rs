//! 背景工作：規則變更後全量重算、豁免到期、每日快照、歷程清理。

use std::time::{Duration, Instant};

use chrono::NaiveDate;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::store::{load_ruleset, refresh_device, refresh_device_fresh};

pub const BATCH: i64 = 1000;
pub const DEFAULT_HISTORY_DAYS: i64 = 365;

type StateRow = (i64, i64, i64, Option<Uuid>);

/// 處理一批，回傳是否還有工作。generation 追上 done_generation 就沒事做；run_generation 落後
/// 代表規則在重算途中又變了，從頭再來。
// ponytail: 假設只有一個伺服器實例；多實例時改用 pg_try_advisory_lock 選一個執行者
pub async fn recompute_step(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let (generation, done, run, cursor): StateRow = sqlx::query_as(
        "SELECT generation, done_generation, run_generation, cursor FROM compliance_state",
    )
    .fetch_one(pool)
    .await?;
    if generation == done {
        return Ok(false);
    }
    let cursor = if run == generation {
        cursor
    } else {
        sqlx::query(
            "UPDATE compliance_state SET run_generation = $1, cursor = NULL, started_at = now()",
        )
        .bind(generation)
        .execute(pool)
        .await?;
        None
    };
    let rules = {
        let mut conn = pool.acquire().await?;
        load_ruleset(&mut conn).await?
    };
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM devices WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2",
    )
    .bind(cursor)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for id in &ids {
        refresh_device(pool, &rules, *id).await?;
    }
    if (ids.len() as i64) < BATCH {
        // 用 run_generation（不是現在的 generation）：途中又有變更時 done 仍落後，下一輪從頭來
        let elapsed: Option<f64> = sqlx::query_scalar(
            "UPDATE compliance_state SET done_generation = $1, cursor = NULL \
             WHERE run_generation = $1 \
             RETURNING extract(epoch FROM now() - started_at)::float8",
        )
        .bind(generation)
        .fetch_optional(pool)
        .await?
        .flatten();
        tracing::info!(
            generation,
            elapsed_secs = elapsed.unwrap_or_default(),
            "compliance recompute finished"
        );
    } else {
        sqlx::query("UPDATE compliance_state SET cursor = $2 WHERE run_generation = $1")
            .bind(generation)
            .bind(ids.last().copied())
            .execute(pool)
            .await?;
    }
    Ok(true)
}

pub async fn recompute_all(pool: &PgPool) -> Result<(), sqlx::Error> {
    while recompute_step(pool).await? {
        tokio::task::yield_now().await;
    }
    Ok(())
}

pub struct Progress {
    pub running: bool,
    pub done: i64,
    pub total: i64,
}

pub async fn progress(pool: &PgPool) -> Result<Progress, sqlx::Error> {
    let (running, done, total): (bool, i64, i64) = sqlx::query_as(
        "SELECT s.generation <> s.done_generation, \
                CASE WHEN s.run_generation = s.generation AND s.cursor IS NOT NULL \
                     THEN (SELECT count(*) FROM devices WHERE id <= s.cursor) ELSE 0 END, \
                (SELECT count(*) FROM devices) \
         FROM compliance_state s",
    )
    .fetch_one(pool)
    .await?;
    Ok(Progress {
        running,
        done,
        total,
    })
}

/// 刪除到期豁免並重新評估那些裝置。回傳處理筆數。
pub async fn expire_exemptions(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let expired: Vec<(i64, Uuid, i64)> = sqlx::query_as(
        "SELECT id, device_id, rule_id FROM compliance_exemptions \
         WHERE expires_at <= now() ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut n = 0;
    for (id, device, rule) in expired {
        let mut tx = pool.begin().await?;
        let gone =
            sqlx::query("DELETE FROM compliance_exemptions WHERE id = $1 AND expires_at <= now()")
                .bind(id)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        if gone == 1 {
            crate::audit::record(
                &mut tx,
                "system",
                "exemption_expire",
                Some(&device.to_string()),
                json!({"id": id, "rule_id": rule}),
            )
            .await?;
            refresh_device_fresh(&mut tx, device).await?;
            n += 1;
        }
        tx.commit().await?;
    }
    Ok(n)
}

pub async fn snapshot_daily(pool: &PgPool, day: NaiveDate) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO compliance_daily (day, rule_id, violating, unknown, exempt) \
         SELECT $1, rule_id, count(*) FILTER (WHERE status = 'violating'), \
                count(*) FILTER (WHERE status = 'unknown'), \
                count(*) FILTER (WHERE status = 'exempt') \
         FROM device_violations GROUP BY rule_id \
         ON CONFLICT (day, rule_id) DO UPDATE SET violating = EXCLUDED.violating, \
           unknown = EXCLUDED.unknown, exempt = EXCLUDED.exempt",
    )
    .bind(day)
    .execute(pool)
    .await?;
    Ok(())
}

/// 保留天數設定：壞值用預設，夾在 30–3650。
pub async fn history_days(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value #>> '{}' FROM settings WHERE key = 'violation_history_days'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(raw
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_HISTORY_DAYS)
        .clamp(30, 3650))
}

pub async fn cleanup_history(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let days = history_days(pool).await? as i32;
    let events =
        sqlx::query("DELETE FROM violation_events WHERE at < now() - make_interval(days => $1)")
            .bind(days)
            .execute(pool)
            .await?
            .rows_affected();
    sqlx::query(
        "DELETE FROM compliance_daily WHERE day < (now() - make_interval(days => $1))::date",
    )
    .bind(days)
    .execute(pool)
    .await?;
    Ok(events)
}

pub fn spawn(pool: PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut last_expire: Option<Instant> = None;
        let mut last_hourly: Option<Instant> = None;
        loop {
            tick.tick().await;
            if let Err(e) = recompute_all(&pool).await {
                tracing::error!(error = %e, "compliance recompute failed");
            }
            if last_expire.is_none_or(|t| t.elapsed() >= Duration::from_secs(300)) {
                last_expire = Some(Instant::now());
                if let Err(e) = expire_exemptions(&pool).await {
                    tracing::error!(error = %e, "exemption expiry failed");
                }
            }
            if last_hourly.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
                last_hourly = Some(Instant::now());
                let today = chrono::Utc::now().date_naive();
                if let Err(e) = snapshot_daily(&pool, today).await {
                    tracing::error!(error = %e, "compliance snapshot failed");
                }
                if let Err(e) = cleanup_history(&pool).await {
                    tracing::error!(error = %e, "violation history cleanup failed");
                }
            }
        }
    });
}
