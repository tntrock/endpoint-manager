//! 背景送出：每個管道依游標讀新事件，到彙整間隔就送一份；失敗倍增重試。
//! violation_events 本身就是佇列，每個管道在 notify_channels 記錄送到哪個事件 id。

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::digest::{Digest, EventInfo, MAX_WEBHOOK_ITEMS, email_text, webhook_body};
use super::{NotifySecrets, NotifySettings, load_settings, send};
use crate::compliance::rules::Severity;

/// 積壓超過這個數量的事件時，只看最新的這麼多筆，其餘記為略過
pub const MAX_BACKLOG: i64 = 100_000;

pub struct Senders {
    pub webhook: reqwest::Client,
}

/// 第 n 次失敗後的重試間隔：1、2、4…分鐘，上限 60 分鐘。
pub fn backoff(failures: i32) -> chrono::Duration {
    let exp = (failures.max(1) - 1).min(6) as u32;
    chrono::Duration::minutes((1i64 << exp).min(60))
}

/// 門檻以上、且變成或離開「違規」的事件
const RELEVANT: &str = "e.id > $1 AND e.id <= $2 AND e.severity = ANY($3) \
     AND (e.to_status = 'violating') <> (e.from_status = 'violating')";

type EventRow = (
    i64,
    Uuid,
    Option<String>,
    String,
    String,
    String,
    String,
    String,
);

async fn events(
    pool: &PgPool,
    after: i64,
    upto: i64,
    sev: &[&str],
    new: bool,
) -> Result<Vec<EventInfo>, sqlx::Error> {
    let sql = format!(
        "SELECT e.id, e.device_id, d.hostname, e.rule_name, e.severity, e.from_status, \
                e.to_status, e.detail::text \
         FROM violation_events e LEFT JOIN devices d ON d.id = e.device_id \
         WHERE {RELEVANT} AND (e.to_status = 'violating') = $4 ORDER BY e.id LIMIT $5"
    );
    let rows: Vec<EventRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(after)
        .bind(upto)
        .bind(sev)
        .bind(new)
        .bind(MAX_WEBHOOK_ITEMS as i64)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, device_id, hostname, rule_name, severity, from_status, to_status, detail)| {
                EventInfo {
                    id,
                    device_id,
                    hostname: hostname.unwrap_or_default(),
                    rule_name,
                    severity: Severity::parse(&severity).unwrap_or(Severity::Medium),
                    from_status,
                    to_status,
                    detail: serde_json::from_str(&detail).unwrap_or_default(),
                }
            },
        )
        .collect())
}

/// (after, upto] 之間、嚴重度達門檻的新增與解除事件（各最多 MAX_WEBHOOK_ITEMS 筆＋總數）。
pub async fn load_digest(
    pool: &PgPool,
    after: i64,
    upto: i64,
    min: Severity,
) -> Result<Digest, sqlx::Error> {
    let sev: Vec<&str> = Severity::ALL
        .into_iter()
        .filter(|s| *s >= min)
        .map(Severity::as_str)
        .collect();
    let (total_new, total_resolved): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FILTER (WHERE e.to_status = 'violating'), \
                    count(*) FILTER (WHERE e.to_status <> 'violating') \
             FROM violation_events e WHERE {RELEVANT}"
    )))
    .bind(after)
    .bind(upto)
    .bind(&sev)
    .fetch_one(pool)
    .await?;
    Ok(Digest {
        new: events(pool, after, upto, &sev, true).await?,
        resolved: events(pool, after, upto, &sev, false).await?,
        total_new,
        total_resolved,
        dropped: 0,
    })
}

type ChannelRow = (i64, Option<DateTime<Utc>>, Option<DateTime<Utc>>, i32, i64);

/// 處理一個管道一次：未啟用、重試時間未到、彙整間隔未到都直接返回。
pub async fn run_channel(
    pool: &PgPool,
    channel: &str,
    settings: &NotifySettings,
    secrets: &NotifySecrets,
    senders: &Senders,
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let enabled = match channel {
        "email" => settings.email.is_some(),
        _ => settings.webhook_url.is_some(),
    };
    if !enabled {
        return Ok(());
    }
    let (mut cursor, last_sent, next_attempt, failures, mut dropped): ChannelRow = sqlx::query_as(
        "SELECT last_event_id, last_sent_at, next_attempt_at, failures, dropped \
             FROM notify_channels WHERE channel = $1",
    )
    .bind(channel)
    .fetch_one(pool)
    .await?;
    if next_attempt.is_some_and(|t| now < t) {
        return Ok(());
    }
    // 失敗重試由 next_attempt_at 控制，不受彙整間隔限制
    let interval = chrono::Duration::minutes(settings.interval_minutes.into());
    if failures == 0 && last_sent.is_some_and(|t| now < t + interval) {
        return Ok(());
    }
    let upto: i64 = sqlx::query_scalar("SELECT coalesce(max(id), 0) FROM violation_events")
        .fetch_one(pool)
        .await?;
    if upto - cursor > MAX_BACKLOG {
        dropped += upto - MAX_BACKLOG - cursor;
        tracing::warn!(
            channel,
            dropped,
            "notification backlog too large; skipping oldest events"
        );
        cursor = upto - MAX_BACKLOG;
    }
    let mut digest = load_digest(pool, cursor, upto, settings.min_severity).await?;
    digest.dropped = dropped;
    if digest.is_empty() {
        sqlx::query("UPDATE notify_channels SET last_event_id = $2 WHERE channel = $1")
            .bind(channel)
            .bind(upto)
            .execute(pool)
            .await?;
        return Ok(());
    }
    let result = match (channel, &settings.email, &settings.webhook_url) {
        ("email", Some(e), _) => {
            let (subject, body) = email_text(&digest, &secrets.web_public_url);
            match send::email_message(e, &subject, &body) {
                Ok(msg) => send::send_email(e, secrets.smtp_password.as_deref(), msg).await,
                Err(err) => Err(format!("信件內容錯誤：{err}")),
            }
        }
        (_, _, Some(url)) => {
            send::send_webhook(
                &senders.webhook,
                url,
                secrets.webhook_secret.as_deref(),
                &webhook_body(&digest, now),
            )
            .await
        }
        _ => return Ok(()),
    };
    match result {
        Ok(()) => {
            sqlx::query(
                "UPDATE notify_channels SET last_event_id = $2, last_sent_at = $3, \
                 last_ok_at = $3, failures = 0, next_attempt_at = NULL, last_error = NULL, \
                 dropped = 0 WHERE channel = $1",
            )
            .bind(channel)
            .bind(upto)
            .bind(now)
            .execute(pool)
            .await?;
        }
        Err(err) => {
            tracing::warn!(channel, error = %err, "notification failed");
            // 積壓上限跳過的部分即使送失敗也不回頭
            sqlx::query(
                "UPDATE notify_channels SET last_event_id = $2, failures = failures + 1, \
                 next_attempt_at = $3, last_error = $4, dropped = $5 WHERE channel = $1",
            )
            .bind(channel)
            .bind(cursor)
            .bind(now + backoff(failures + 1))
            .bind(&err)
            .bind(dropped)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

pub fn spawn(pool: PgPool, secrets: Arc<NotifySecrets>) {
    tokio::spawn(async move {
        let senders = match send::webhook_client(&[]) {
            Ok(webhook) => Senders { webhook },
            Err(e) => {
                tracing::error!(error = %e, "cannot build webhook client; notifications disabled");
                return;
            }
        };
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let settings = match load_settings(&pool).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "loading notification settings failed");
                    continue;
                }
            };
            for channel in ["email", "webhook"] {
                if let Err(e) =
                    run_channel(&pool, channel, &settings, &secrets, &senders, Utc::now()).await
                {
                    tracing::error!(channel, error = %e, "notification worker failed");
                }
            }
        }
    });
}
