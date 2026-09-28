//! 資料庫連線、migration 與 settings。

use protocol::CollectionIntervals;
use sqlx::PgPool;

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// 報到與收集間隔的合理範圍（秒）：0 會讓所有 Agent 不停報到，極大值等於不再收集。
pub const MIN_INTERVAL_SECS: u32 = 30;
pub const MAX_INTERVAL_SECS: u32 = 7 * 24 * 3600;

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub checkin_interval_secs: u32,
    pub intervals: CollectionIntervals,
}

pub async fn load_settings(pool: &PgPool) -> Result<Settings, sqlx::Error> {
    // 以文字取出後在這裡解析：一個被改壞的值不能讓整個查詢（以及每次報到）失敗
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT key, value #>> '{}' FROM settings WHERE key LIKE '%_secs'")
            .fetch_all(pool)
            .await?;
    let get = |k: &str, default: u32| {
        let raw = rows
            .iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| v.as_deref());
        match raw.map(|v| v.trim().parse::<u64>()) {
            Some(Ok(n)) => u32::try_from(n)
                .unwrap_or(u32::MAX)
                .clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS),
            Some(Err(_)) => {
                tracing::warn!(key = k, value = ?raw, "invalid setting; using default");
                default
            }
            None => default,
        }
    };
    Ok(Settings {
        checkin_interval_secs: get("checkin_interval_secs", 60),
        intervals: CollectionIntervals {
            software_secs: get("software_interval_secs", 3600),
            patches_secs: get("patches_interval_secs", 3600),
            services_secs: get("services_interval_secs", 3600),
            hardware_secs: get("hardware_interval_secs", 86400),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test(migrations = false)]
    async fn migrate_and_default_settings(pool: PgPool) {
        migrate(&pool).await.unwrap();
        let s = load_settings(&pool).await.unwrap();
        assert_eq!(s.checkin_interval_secs, 60);
        assert_eq!(s.intervals.hardware_secs, 86400);
    }

    /// 設定值被改壞（不是整數）時整個查詢不能失敗（否則每次報到都 500）；
    /// 0 或極端值要夾在合理範圍（0 秒會讓所有 Agent 不停報到）。
    #[sqlx::test(migrations = false)]
    async fn bad_or_extreme_settings_fall_back(pool: PgPool) {
        migrate(&pool).await.unwrap();
        for (k, v) in [
            ("checkin_interval_secs", "\"abc\""),
            ("software_interval_secs", "1.5"),
            ("patches_interval_secs", "0"),
            ("hardware_interval_secs", "99999999999"),
        ] {
            sqlx::query("UPDATE settings SET value = $2::jsonb WHERE key = $1")
                .bind(k)
                .bind(v)
                .execute(&pool)
                .await
                .unwrap();
        }
        let s = load_settings(&pool).await.unwrap();
        assert_eq!(s.checkin_interval_secs, 60, "壞值用預設");
        assert_eq!(s.intervals.software_secs, 3600, "壞值用預設");
        assert_eq!(s.intervals.patches_secs, MIN_INTERVAL_SECS, "0 夾到下限");
        assert_eq!(
            s.intervals.hardware_secs, MAX_INTERVAL_SECS,
            "極大值夾到上限"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn maintain_partitions_is_idempotent(pool: PgPool) {
        migrate(&pool).await.unwrap();
        let now = chrono::Utc::now();
        crate::partitions::maintain_partitions(&pool, now)
            .await
            .unwrap();
        crate::partitions::maintain_partitions(&pool, now)
            .await
            .unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent \
             WHERE p.relname = 'inventory_changes'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 3);
    }
}
