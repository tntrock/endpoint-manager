//! 合規通知（Webhook）：設定、機密與背景送出。

pub mod digest;
pub mod send;
pub mod worker;

use anyhow::ensure;
use sqlx::PgPool;

use crate::compliance::rules::Severity;

pub const DEFAULT_INTERVAL_MINUTES: u32 = 10;

/// 機密只從環境變數來。Debug 不印出內容。
#[derive(Default, Clone)]
pub struct NotifySecrets {
    pub webhook_secret: Option<String>,
}

impl std::fmt::Debug for NotifySecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifySecrets")
            .field(
                "webhook_secret",
                &self.webhook_secret.as_ref().map(|_| "***"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct NotifySettings {
    pub min_severity: Severity,
    pub interval_minutes: u32,
    pub webhook_url: Option<String>,
}

pub fn validate_webhook_url(u: &str) -> Result<(), String> {
    let rest = u
        .strip_prefix("https://")
        .ok_or("Webhook 網址必須以 https:// 開頭")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let bad = || "Webhook 網址格式不正確".to_string();
    if host.is_empty() || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(bad());
    }
    // 完整解析（埠號範圍、IPv6 括號等），避免存了之後每次重試都失敗
    let parsed = reqwest::Url::parse(u).map_err(|_| bad())?;
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(bad());
    }
    Ok(())
}

/// 稽核只記主機：Slack、Teams 等 Webhook 網址本身就是權杖
fn webhook_host(u: &Option<String>) -> Option<String> {
    u.as_deref()
        .and_then(|u| reqwest::Url::parse(u).ok())
        .and_then(|u| u.host_str().map(str::to_string))
}

async fn setting(pool: &PgPool, key: &str) -> Result<Option<serde_json::Value>, sqlx::Error> {
    let raw: Option<String> = sqlx::query_scalar("SELECT value::text FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await?;
    Ok(raw.and_then(|r| serde_json::from_str(&r).ok()))
}

/// 壞值一律用預設（停用），不讓整個通知停擺在解析錯誤上。
pub async fn load_settings(pool: &PgPool) -> Result<NotifySettings, sqlx::Error> {
    let min_severity = setting(pool, "notify_min_severity")
        .await?
        .and_then(|v| v.as_str().and_then(Severity::parse))
        .unwrap_or(Severity::Medium);
    let interval_minutes = setting(pool, "notify_interval_minutes")
        .await?
        .and_then(|v| v.as_u64())
        .map(|n| n.clamp(1, 1440) as u32)
        .unwrap_or(DEFAULT_INTERVAL_MINUTES);
    let webhook_url = setting(pool, "notify_webhook_url")
        .await?
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|u| !u.is_empty());
    Ok(NotifySettings {
        min_severity,
        interval_minutes,
        webhook_url,
    })
}

pub async fn save_settings(pool: &PgPool, s: &NotifySettings, actor: &str) -> anyhow::Result<()> {
    ensure!(
        (1..=1440).contains(&s.interval_minutes),
        "彙整間隔須為 1–1440 分鐘"
    );
    if let Some(u) = &s.webhook_url {
        validate_webhook_url(u).map_err(anyhow::Error::msg)?;
    }
    let before = load_settings(pool).await?;
    let mut tx = pool.begin().await?;
    for (k, v) in [
        (
            "notify_min_severity",
            serde_json::json!(s.min_severity.as_str()),
        ),
        (
            "notify_interval_minutes",
            serde_json::json!(s.interval_minutes),
        ),
        ("notify_webhook_url", serde_json::json!(s.webhook_url)),
    ] {
        sqlx::query(
            "INSERT INTO settings (key, value) VALUES ($1, $2::jsonb) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(k)
        .bind(v.to_string())
        .execute(&mut *tx)
        .await?;
    }
    // 由停用變啟用：從現在開始送，不補送過去的事件
    if before.webhook_url.is_none() && s.webhook_url.is_some() {
        sqlx::query(
            "UPDATE notify_channels SET last_event_id = \
               (SELECT coalesce(max(id), 0) FROM violation_events), \
             failures = 0, next_attempt_at = NULL, last_error = NULL, dropped = 0 \
             WHERE channel = 'webhook'",
        )
        .execute(&mut *tx)
        .await?;
    } else if s.webhook_url.is_some() && before.webhook_url != s.webhook_url {
        // 換了網址（例如修好故障的網址）：清掉重試等待，游標不動
        sqlx::query(
            "UPDATE notify_channels SET failures = 0, next_attempt_at = NULL, last_error = NULL \
             WHERE channel = 'webhook'",
        )
        .execute(&mut *tx)
        .await?;
    }
    crate::audit::record(
        &mut tx,
        actor,
        "notify_settings",
        None,
        serde_json::json!({
            "min_severity": s.min_severity.as_str(), "interval_minutes": s.interval_minutes,
            "webhook_host": webhook_host(&s.webhook_url)
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_url_must_be_https() {
        assert!(validate_webhook_url("https://hooks.example.com/x").is_ok());
        for bad in [
            "http://hooks.example.com/x",
            "ftp://x",
            "https://",
            "not a url",
            "https://a b/",
            "https://h:99999/",
            "https://[::1",
        ] {
            assert!(validate_webhook_url(bad).is_err(), "{bad}");
        }
    }

    #[sqlx::test(migrations = false)]
    async fn defaults_bad_values_and_enable_sets_cursor(pool: sqlx::PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let s = load_settings(&pool).await.unwrap();
        assert_eq!((s.min_severity, s.interval_minutes), (Severity::Medium, 10));
        assert!(s.webhook_url.is_none());

        sqlx::query("UPDATE settings SET value = '\"x\"' WHERE key = 'notify_interval_minutes'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            load_settings(&pool).await.unwrap().interval_minutes,
            10,
            "壞值用預設"
        );

        // 已有歷程時啟用 webhook：游標設到目前最新事件，不會把舊事件當新違規送出
        let d: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO devices (id, hostname, status) \
             VALUES (gen_random_uuid(), 'PC', 'active') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        for _ in 0..3 {
            sqlx::query(
                "INSERT INTO violation_events \
                 (device_id, rule_name, severity, from_status, to_status, detail) \
                 VALUES ($1, 'r', 'high', 'none', 'violating', '{}')",
            )
            .bind(d)
            .execute(&pool)
            .await
            .unwrap();
        }
        let mut s = load_settings(&pool).await.unwrap();
        s.webhook_url = Some("https://hooks.example.com/x".into());
        save_settings(&pool, &s, "admin").await.unwrap();
        let cursor: i64 = sqlx::query_scalar(
            "SELECT last_event_id FROM notify_channels WHERE channel = 'webhook'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let max: i64 = sqlx::query_scalar("SELECT max(id) FROM violation_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(cursor, max);
        let audit: String = sqlx::query_scalar(
            "SELECT detail::text FROM audit_log WHERE action = 'notify_settings'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audit.contains("hooks.example.com"));
    }
}
