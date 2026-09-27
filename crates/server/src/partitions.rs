//! inventory_changes 按月分割區的建立與清理。

use chrono::{DateTime, Datelike, Utc};
use sqlx::PgPool;

pub const KEEP_MONTHS: i32 = 12;
const PREFIX: &str = "inventory_changes_y";

pub fn partition_name(y: i32, m: u32) -> String {
    format!("{PREFIX}{y:04}m{m:02}")
}

pub fn month_add(y: i32, m: u32, delta: i32) -> (i32, u32) {
    let idx = y * 12 + (m as i32 - 1) + delta;
    (idx.div_euclid(12), (idx.rem_euclid(12) + 1) as u32)
}

pub fn parse_partition_name(name: &str) -> Option<(i32, u32)> {
    let rest = name.strip_prefix(PREFIX)?;
    let (y, m) = rest.split_once('m')?;
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    (1..=12).contains(&m).then_some((y, m))
}

pub fn partitions_to_drop(
    existing: &[String],
    now_y: i32,
    now_m: u32,
    keep_months: i32,
) -> Vec<String> {
    let cutoff = month_add(now_y, now_m, -(keep_months - 1));
    existing
        .iter()
        .filter(|n| parse_partition_name(n).is_some_and(|ym| ym < cutoff))
        .cloned()
        .collect()
}

/// 建立當月與未來兩個月的分割區，刪除超過保留期限的分割區。
pub async fn maintain_partitions(pool: &PgPool, now: DateTime<Utc>) -> Result<(), sqlx::Error> {
    let (y, m) = (now.year(), now.month());
    for delta in 0..3 {
        let (sy, sm) = month_add(y, m, delta);
        let (ey, em) = month_add(y, m, delta + 1);
        // 名稱與日期全由數字組成，無注入風險
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} PARTITION OF inventory_changes \
             FOR VALUES FROM ('{sy:04}-{sm:02}-01') TO ('{ey:04}-{em:02}-01')",
            partition_name(sy, sm)
        );
        sqlx::query(sqlx::AssertSqlSafe(sql)).execute(pool).await?;
    }
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i \
         JOIN pg_class c ON c.oid = i.inhrelid \
         JOIN pg_class p ON p.oid = i.inhparent \
         WHERE p.relname = 'inventory_changes'",
    )
    .fetch_all(pool)
    .await?;
    for name in partitions_to_drop(&existing, y, m, KEEP_MONTHS) {
        // name 已由 parse_partition_name 驗證為固定格式
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP TABLE IF EXISTS {name}")))
            .execute(pool)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_format() {
        assert_eq!(partition_name(2026, 9), "inventory_changes_y2026m09");
    }

    #[test]
    fn month_add_wraps_years() {
        assert_eq!(month_add(2026, 12, 1), (2027, 1));
        assert_eq!(month_add(2026, 1, -1), (2025, 12));
        assert_eq!(month_add(2026, 9, -11), (2025, 10));
    }

    #[test]
    fn parse_roundtrip_and_rejects_garbage() {
        assert_eq!(
            parse_partition_name("inventory_changes_y2026m09"),
            Some((2026, 9))
        );
        assert_eq!(parse_partition_name("inventory_changes_y2026m13"), None);
        assert_eq!(parse_partition_name("something_else"), None);
    }

    #[test]
    fn drops_only_older_than_keep_window() {
        let existing = vec![
            partition_name(2025, 9),
            partition_name(2025, 10),
            partition_name(2026, 9),
            "unrelated_table".to_string(),
        ];
        // 保留 12 個月（含當月 2026-09）→ 最舊保留 2025-10
        assert_eq!(
            partitions_to_drop(&existing, 2026, 9, 12),
            vec![partition_name(2025, 9)]
        );
    }
}
