//! 資料庫連線、migration 與 settings。

use protocol::CollectionIntervals;
use sqlx::PgPool;

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

/// 報到與收集間隔的合理範圍（秒）：0 會讓所有 Agent 不停報到，極大值等於不再收集。
/// 報到下限 30 秒：30,000 台約每秒 1,000 次。
pub const MIN_INTERVAL_SECS: u32 = 30;
pub const MAX_INTERVAL_SECS: u32 = 7 * 24 * 3600;
/// 收集間隔下限（完整收集比報到重得多）
pub const MIN_COLLECT_SECS: u32 = 300;

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub checkin_interval_secs: u32,
    pub intervals: CollectionIntervals,
}

/// 可在設定頁調整的間隔：(設定鍵, 名稱, 預設秒數, 下限秒數)。報到在第一個
pub const INTERVALS: [(&str, &str, u32, u32); 7] = [
    ("checkin_interval_secs", "報到", 60, MIN_INTERVAL_SECS),
    ("software_interval_secs", "軟體", 3600, MIN_COLLECT_SECS),
    (
        "patches_interval_secs",
        "更新（KB）",
        3600,
        MIN_COLLECT_SECS,
    ),
    (
        "services_interval_secs",
        "服務、容器、網路",
        3600,
        MIN_COLLECT_SECS,
    ),
    ("hardware_interval_secs", "硬體", 86400, MIN_COLLECT_SECS),
    (
        "security_interval_secs",
        "安全設定、帳號",
        3600,
        MIN_COLLECT_SECS,
    ),
    ("registry_interval_secs", "登錄檔", 3600, MIN_COLLECT_SECS),
];

impl Settings {
    /// 依 [`INTERVALS`] 的順序
    pub fn values(&self) -> [u32; 7] {
        let i = &self.intervals;
        [
            self.checkin_interval_secs,
            i.software_secs,
            i.patches_secs,
            i.services_secs,
            i.hardware_secs,
            i.security_secs,
            i.registry_secs,
        ]
    }
}

/// 檢查一組間隔（依 [`INTERVALS`] 的順序）；超出範圍時回給使用者看的訊息
pub fn validate_intervals(values: &[u32; 7]) -> Result<(), String> {
    for ((_, label, _, min), v) in INTERVALS.iter().zip(values) {
        if !(*min..=MAX_INTERVAL_SECS).contains(v) {
            return Err(format!(
                "{label}的間隔必須介於 {} 到 {}",
                crate::network::duration_label(time::Duration::seconds((*min).into())),
                crate::network::duration_label(time::Duration::seconds(MAX_INTERVAL_SECS.into())),
            ));
        }
    }
    Ok(())
}

/// 平台管理員修改報到與收集間隔，寫稽核記錄（含舊值）。各 Agent 下一次報到後生效
pub async fn save_intervals(
    pool: &PgPool,
    values: [u32; 7],
    actor: &crate::commands::Actor,
) -> anyhow::Result<()> {
    anyhow::ensure!(actor.platform, "只有平台管理員可以修改");
    validate_intervals(&values).map_err(anyhow::Error::msg)?;
    let keys: Vec<&str> = INTERVALS.iter().map(|i| i.0).collect();
    let mut tx = pool.begin().await?;
    // 鎖住設定列再讀舊值：兩人同時修改時，稽核記錄的舊值才正確
    sqlx::query("SELECT 1 FROM settings WHERE key = ANY($1) FOR UPDATE")
        .bind(&keys)
        .execute(&mut *tx)
        .await?;
    let old = load_settings(&mut *tx).await?.values();
    let mut detail = serde_json::Map::new();
    for ((key, ..), (new, old)) in INTERVALS.iter().zip(values.iter().zip(old)) {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(new.to_string())
        .execute(&mut *tx)
        .await?;
        if *new != old {
            detail.insert(
                (*key).to_string(),
                serde_json::json!({ "old": old, "new": new }),
            );
        }
    }
    crate::audit::record(
        &mut tx,
        &actor.username,
        "setting_intervals",
        None,
        serde_json::Value::Object(detail),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn load_settings<'e>(pool: impl sqlx::PgExecutor<'e>) -> Result<Settings, sqlx::Error> {
    // 以文字取出後在這裡解析：一個被改壞的值不能讓整個查詢（以及每次報到）失敗
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT key, value #>> '{}' FROM settings WHERE key LIKE '%_secs'")
            .fetch_all(pool)
            .await?;
    let get = |k: &str, default: u32, min: u32| {
        let raw = rows
            .iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| v.as_deref());
        match raw.map(|v| v.trim().parse::<u64>()) {
            Some(Ok(n)) => u32::try_from(n)
                .unwrap_or(u32::MAX)
                .clamp(min, MAX_INTERVAL_SECS),
            Some(Err(_)) => {
                // 每次報到都會讀設定：同一個壞值只警告一次
                static WARNED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
                let mut warned = WARNED.lock().expect("warned lock");
                if !warned.iter().any(|w| w == k) {
                    tracing::warn!(key = k, value = ?raw, "invalid setting; using default");
                    warned.push(k.to_string());
                }
                default
            }
            None => default,
        }
    };
    Ok(Settings {
        checkin_interval_secs: get("checkin_interval_secs", 60, MIN_INTERVAL_SECS),
        intervals: CollectionIntervals {
            software_secs: get("software_interval_secs", 3600, MIN_COLLECT_SECS),
            patches_secs: get("patches_interval_secs", 3600, MIN_COLLECT_SECS),
            services_secs: get("services_interval_secs", 3600, MIN_COLLECT_SECS),
            hardware_secs: get("hardware_interval_secs", 86400, MIN_COLLECT_SECS),
            security_secs: get("security_interval_secs", 3600, MIN_COLLECT_SECS),
            registry_secs: get("registry_interval_secs", 3600, MIN_COLLECT_SECS),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[test]
    fn interval_validation() {
        let ok = [60, 300, 300, 3600, 86400, 3600, 7 * 86400];
        assert_eq!(validate_intervals(&ok), Ok(()));
        let mut v = ok;
        v[0] = 29;
        assert!(
            validate_intervals(&v)
                .unwrap_err()
                .starts_with("報到的間隔")
        );
        let mut v = ok;
        v[1] = 299;
        assert!(validate_intervals(&v).unwrap_err().contains("5 分鐘"));
        let mut v = ok;
        v[4] = 7 * 86400 + 1;
        assert!(validate_intervals(&v).unwrap_err().contains("7 天 0 小時"));
    }

    #[sqlx::test(migrations = false)]
    async fn save_intervals_audits_changes(pool: PgPool) {
        migrate(&pool).await.unwrap();
        let actor = |platform| crate::commands::Actor {
            username: "root".into(),
            platform,
            groups: vec![],
        };
        let mut v = load_settings(&pool).await.unwrap().values();
        v[0] = 120;
        v[3] = 600;
        assert!(save_intervals(&pool, v, &actor(false)).await.is_err());
        let mut bad = v;
        bad[0] = 5;
        assert!(save_intervals(&pool, bad, &actor(true)).await.is_err());
        save_intervals(&pool, v, &actor(true)).await.unwrap();
        let s = load_settings(&pool).await.unwrap();
        assert_eq!(s.checkin_interval_secs, 120);
        assert_eq!(s.intervals.services_secs, 600);
        assert_eq!(s.values(), v);
        let detail: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_log WHERE action = 'setting_intervals'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        // 只記有改變的鍵，含舊值
        assert!(
            detail.contains("\"checkin_interval_secs\": {\"new\": 120, \"old\": 60}"),
            "{detail}"
        );
        assert!(!detail.contains("hardware"), "{detail}");
    }

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
        assert_eq!(
            s.intervals.patches_secs, MIN_COLLECT_SECS,
            "0 夾到收集間隔下限"
        );
        assert_eq!(
            s.intervals.hardware_secs, MAX_INTERVAL_SECS,
            "極大值夾到上限"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn maintain_partitions_is_idempotent(pool: PgPool) {
        migrate(&pool).await.unwrap();
        let now = time::OffsetDateTime::now_utc();
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
