//! 總覽與主管報告的裝置統計：即時數字、每日快照與趨勢。

use sqlx::PgPool;

/// 受管裝置：不含已除役與待核准
const MANAGED: &str = "d.status NOT IN ('retired', 'pending_approval')";
const VIOLATING: &str = "EXISTS (SELECT 1 FROM device_violations v \
     WHERE v.device_id = d.id AND v.status = 'violating')";
const HIGH_RISK: &str = "EXISTS (SELECT 1 FROM device_violations v \
     JOIN compliance_rules r ON r.id = v.rule_id \
     WHERE v.device_id = d.id AND v.status = 'violating' AND r.severity = 'high')";

/// 某一時間點的數字
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::FromRow)]
pub struct Counts {
    pub managed: i64,
    /// 即時數字是「在線」；每日快照是「24 小時內有回報」
    pub seen: i64,
    pub compliant: i64,
    pub high_risk: i64,
}

impl Counts {
    pub fn violating(&self) -> i64 {
        self.managed - self.compliant
    }

    /// 合規率（百分比）；沒有裝置時為 None
    pub fn compliance_pct(&self) -> Option<f64> {
        (self.managed > 0).then(|| self.compliant as f64 * 100.0 / self.managed as f64)
    }
}

/// 範圍內的即時數字。`online_after`：最後回報晚於此時間算在線
pub async fn live(
    pool: &PgPool,
    all: bool,
    groups: &[i64],
    online_after: time::OffsetDateTime,
) -> Result<Counts, sqlx::Error> {
    let sql = format!(
        "SELECT count(*) AS managed, \
                count(*) FILTER (WHERE d.last_seen_at > $3) AS seen, \
                count(*) FILTER (WHERE NOT {VIOLATING}) AS compliant, \
                count(*) FILTER (WHERE {HIGH_RISK}) AS high_risk \
         FROM devices d WHERE {MANAGED} AND ($1::bool OR d.group_id = ANY($2::bigint[]))"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(all)
        .bind(groups)
        .bind(online_after)
        .fetch_one(pool)
        .await
}

/// 寫入 `day` 的快照（覆寫同一天的舊值；當天已沒有裝置的群組也會清掉）
pub async fn snapshot(pool: &PgPool, day: time::Date) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM device_daily WHERE day = $1")
        .bind(day)
        .execute(&mut *tx)
        .await?;
    let sql = format!(
        "INSERT INTO device_daily (day, group_id, managed, seen, compliant, high_risk) \
         SELECT $1, coalesce(d.group_id, 0), count(*), \
                count(*) FILTER (WHERE d.last_seen_at > now() - interval '24 hours'), \
                count(*) FILTER (WHERE NOT {VIOLATING}), \
                count(*) FILTER (WHERE {HIGH_RISK}) \
         FROM devices d WHERE {MANAGED} GROUP BY 2 \
         ON CONFLICT (day, group_id) DO UPDATE SET managed = EXCLUDED.managed, \
           seen = EXCLUDED.seen, compliant = EXCLUDED.compliant, high_risk = EXCLUDED.high_risk"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(day)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}

/// 刪除 `keep_days` 天以前的快照
pub async fn cleanup(pool: &PgPool, today: time::Date, keep_days: i32) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM device_daily WHERE day < $2::date - $1")
        .bind(keep_days)
        .bind(today)
        .execute(pool)
        .await?;
    Ok(())
}

/// 範圍內 `today` 往前 `days` 天（含今天）的每日加總，依日期排序
pub async fn trend(
    pool: &PgPool,
    all: bool,
    groups: &[i64],
    today: time::Date,
    days: i32,
) -> Result<Vec<(time::Date, Counts)>, sqlx::Error> {
    let rows: Vec<(time::Date, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT day, sum(managed)::bigint, sum(seen)::bigint, sum(compliant)::bigint, \
                sum(high_risk)::bigint \
         FROM device_daily \
         WHERE day > $3::date - $4 AND day <= $3::date \
           AND ($1::bool OR group_id = ANY($2::bigint[])) \
         GROUP BY day ORDER BY day",
    )
    .bind(all)
    .bind(groups)
    .bind(today)
    .bind(days)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(day, managed, seen, compliant, high_risk)| {
            (
                day,
                Counts {
                    managed,
                    seen,
                    compliant,
                    high_risk,
                },
            )
        })
        .collect())
}
