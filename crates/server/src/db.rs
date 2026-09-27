//! 資料庫連線、migration 與 settings。

use protocol::CollectionIntervals;
use sqlx::PgPool;

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub checkin_interval_secs: u32,
    pub intervals: CollectionIntervals,
}

pub async fn load_settings(pool: &PgPool) -> Result<Settings, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT key, (value #>> '{}')::bigint FROM settings WHERE key LIKE '%_secs'",
    )
    .fetch_all(pool)
    .await?;
    let get = |k: &str, default: u32| {
        rows.iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| u32::try_from(*v).ok())
            .unwrap_or(default)
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
