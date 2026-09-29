//! 合規通知：設定、機密與背景送出。

pub mod digest;
pub mod send;
pub mod worker;

use anyhow::ensure;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::compliance::rules::Severity;

pub const DEFAULT_INTERVAL_MINUTES: u32 = 10;

/// 機密只從環境變數來。Debug 不印出內容。
#[derive(Default, Clone)]
pub struct NotifySecrets {
    pub smtp_password: Option<String>,
    pub webhook_secret: Option<String>,
    /// 管理網頁的對外網址（通知內的連結）；空字串表示不附連結
    pub web_public_url: String,
}

impl std::fmt::Debug for NotifySecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotifySecrets")
            .field("smtp_password", &self.smtp_password.as_ref().map(|_| "***"))
            .field(
                "webhook_secret",
                &self.webhook_secret.as_ref().map(|_| "***"),
            )
            .field("web_public_url", &self.web_public_url)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    StartTls,
    Tls,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailSettings {
    pub host: String,
    pub port: u16,
    pub tls: TlsMode,
    #[serde(default)]
    pub username: String,
    pub from: String,
    pub to: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NotifySettings {
    pub min_severity: Severity,
    pub interval_minutes: u32,
    pub email: Option<EmailSettings>,
    pub webhook_url: Option<String>,
}

pub fn validate_webhook_url(u: &str) -> Result<(), String> {
    let rest = u
        .strip_prefix("https://")
        .ok_or("Webhook 網址必須以 https:// 開頭")?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || u.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("Webhook 網址格式不正確".into());
    }
    Ok(())
}

fn valid_address(a: &str) -> bool {
    a.parse::<lettre::Address>().is_ok()
}

pub fn validate_email(e: &EmailSettings) -> Result<(), String> {
    if e.host.trim().is_empty() || e.host.chars().any(char::is_whitespace) {
        return Err("SMTP 主機必填".into());
    }
    if e.port == 0 {
        return Err("SMTP 埠號不正確".into());
    }
    if !valid_address(&e.from) {
        return Err("寄件者地址不正確".into());
    }
    if e.to.is_empty() || e.to.len() > 50 || !e.to.iter().all(|a| valid_address(a)) {
        return Err("收件人需為 1–50 個正確的 Email 地址".into());
    }
    Ok(())
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
    let email = setting(pool, "notify_email")
        .await?
        .and_then(|v| serde_json::from_value::<EmailSettings>(v).ok())
        .filter(|e| validate_email(e).is_ok());
    let webhook_url = setting(pool, "notify_webhook_url")
        .await?
        .and_then(|v| v.as_str().map(str::to_string))
        .filter(|u| !u.is_empty());
    Ok(NotifySettings {
        min_severity,
        interval_minutes,
        email,
        webhook_url,
    })
}

pub async fn save_settings(pool: &PgPool, s: &NotifySettings, actor: &str) -> anyhow::Result<()> {
    ensure!(
        (1..=1440).contains(&s.interval_minutes),
        "彙整間隔須為 1–1440 分鐘"
    );
    if let Some(e) = &s.email {
        validate_email(e).map_err(anyhow::Error::msg)?;
    }
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
        ("notify_email", serde_json::to_value(&s.email)?),
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
    for (channel, was, now) in [
        ("email", before.email.is_some(), s.email.is_some()),
        (
            "webhook",
            before.webhook_url.is_some(),
            s.webhook_url.is_some(),
        ),
    ] {
        if !was && now {
            sqlx::query(
                "UPDATE notify_channels SET last_event_id = \
                   (SELECT coalesce(max(id), 0) FROM violation_events), \
                 failures = 0, next_attempt_at = NULL, last_error = NULL, dropped = 0 \
                 WHERE channel = $1",
            )
            .bind(channel)
            .execute(&mut *tx)
            .await?;
        }
    }
    crate::audit::record(
        &mut tx,
        actor,
        "notify_settings",
        None,
        serde_json::json!({
            "min_severity": s.min_severity.as_str(), "interval_minutes": s.interval_minutes,
            "email": s.email, "webhook_url": s.webhook_url
        }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn email() -> EmailSettings {
        EmailSettings {
            host: "smtp.example.com".into(),
            port: 587,
            tls: TlsMode::StartTls,
            username: "em".into(),
            from: "em@example.com".into(),
            to: vec!["it@example.com".into()],
        }
    }

    #[test]
    fn webhook_url_must_be_https() {
        assert!(validate_webhook_url("https://hooks.example.com/x").is_ok());
        for bad in [
            "http://hooks.example.com/x",
            "ftp://x",
            "https://",
            "not a url",
            "https://a b/",
        ] {
            assert!(validate_webhook_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn email_validation() {
        assert!(validate_email(&email()).is_ok());
        assert!(
            validate_email(&EmailSettings {
                to: vec![],
                ..email()
            })
            .is_err()
        );
        assert!(
            validate_email(&EmailSettings {
                from: "nope".into(),
                ..email()
            })
            .is_err()
        );
        assert!(
            validate_email(&EmailSettings {
                host: " ".into(),
                ..email()
            })
            .is_err()
        );
        assert!(
            validate_email(&EmailSettings {
                to: vec!["a@b.c\r\nBcc: x@y.z".into()],
                ..email()
            })
            .is_err(),
            "不能夾帶標頭"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn defaults_bad_values_and_enable_sets_cursor(pool: sqlx::PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let s = load_settings(&pool).await.unwrap();
        assert_eq!((s.min_severity, s.interval_minutes), (Severity::Medium, 10));
        assert!(s.email.is_none() && s.webhook_url.is_none());

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
