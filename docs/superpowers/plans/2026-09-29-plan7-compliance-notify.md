# 計畫 7：合規通知與負載測試 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 違規新增或解除時，彙整後以 Email 與 Webhook 通知管理員；並以 30,000 台負載測試驗證合規引擎的效能目標。

**Architecture:** `violation_events` 本身就是通知佇列：每個管道在 `notify_channels` 記錄已送到哪個事件 id，背景工作每分鐘檢查、到彙整間隔就把新事件依嚴重度過濾、彙整成一份送出。組內容（彙整、Email 文字、Webhook JSON、簽章）都是純函式；送出只是薄薄一層 lettre／reqwest。設定存在 `settings`，機密放環境變數。

**Tech Stack:** Rust、lettre 0.11（rustls＋ring）、reqwest（沿用 workspace）、rustls-native-certs、hmac＋sha2。

**Spec:** `docs/superpowers/specs/2026-09-29-compliance-design.md`（§6、§1.1）

**前置：** 計畫 5、6 已合併。

## Global Constraints

- 使用者可見文字用繁體中文。
- 不能引入 openssl／native-tls（`deny.toml` 已禁止）；新套件全部要通過 `cargo deny check`。
- 機密（`EM_SMTP_PASSWORD`、`EM_WEBHOOK_SECRET`）只從環境變數讀，不寫入資料庫、稽核記錄或日誌。
- Webhook 網址只接受 `https://`（存檔時驗證）；不跟隨重新導向；逾時 10 秒。
- 通知設定只有平台管理員能改，改動寫稽核記錄（不含機密）。
- 測試指令：`cargo test -p endpoint-server`；最後 `cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`、`cargo deny check`。

## Review Focus

1. 管道第一次啟用時不能把過去一年的歷程全部當成「新違規」送出——啟用時游標要設到目前最新的事件。
2. 通知管道長期故障時，積壓不能無限成長，也不能讓每次重試都讀十萬筆進記憶體。
3. 送出失敗要倍增重試間隔（1 分鐘起、最長 1 小時），不能每分鐘狂打故障的 SMTP／Webhook。
4. Email 與 Webhook 互不影響：一邊失敗，另一邊照常推進。
5. 機密不能出現在網頁（設定頁只顯示「已設定／未設定」）、稽核記錄或錯誤訊息中。

**Rulings（相對 spec）：**
- spec §4／§6.2 有獨立的 `notify_outbox` 表。改為直接以 `violation_events` 當佇列，每個管道記錄 `last_event_id`：少一張表、少一次寫入，歷程本來就保留 365 天，足夠涵蓋任何積壓。佇列上限 100,000 筆改為「積壓超過 100,000 筆事件時，游標直接跳到最新 100,000 筆之前，並在下一份彙整註明遺失數量」。代價：無。
- spec §1.1 的負載目標以 loadsim `--rules N` 驗證。loadsim 只走 Agent API，沒有資料庫權限，改為提供 `tools/loadsim/rules.sql` 以 psql 建立 50 條規則；上傳時的評估耗時由伺服器 debug 日誌量測。代價：多一個手動步驟。
- 網頁連結需要管理網頁的對外網址，新增選填環境變數 `EM_WEB_PUBLIC_URL`；未設定時通知內不附連結。

---

## File Structure

- Create `crates/server/migrations/0005_notify.sql`
- Modify `Cargo.toml`（workspace deps）、`crates/server/Cargo.toml`
- Modify `crates/server/src/config.rs`（`smtp_password`、`webhook_secret`、`web_public_url`）、`crates/server/src/lib.rs`（`AppState.notify`、啟動 worker）
- Create `crates/server/src/notify/mod.rs`（設定讀寫、`NotifySecrets`）
- Create `crates/server/src/notify/digest.rs`（純函式：彙整、Email 文字、Webhook JSON、簽章）
- Create `crates/server/src/notify/send.rs`（lettre、reqwest）
- Create `crates/server/src/notify/worker.rs`（每管道游標、倍增重試、積壓上限）
- Create `crates/server/src/web/notify.rs`、`crates/server/templates/notify.html`
- Modify `crates/server/src/web/compliance.rs`、`crates/server/templates/compliance.html`（總覽顯示通知狀態）
- Modify `deploy/docker-compose.yml`、`deploy/.env.example`、`README.md`
- Create `tools/loadsim/rules.sql`；Modify `docs/loadtest.md`
- Create `crates/server/tests/notify.rs`

---

### Task 1: 設定、機密與管道狀態表

**Files:**
- Create: `crates/server/migrations/0005_notify.sql`
- Modify: `crates/server/src/config.rs`、`crates/server/src/lib.rs`
- Create: `crates/server/src/notify/mod.rs`
- Test: `crates/server/src/notify/mod.rs`、`crates/server/src/config.rs`

**Interfaces:**
- Produces:
  - `pub struct EmailSettings { pub host: String, pub port: u16, pub tls: TlsMode, pub username: String, pub from: String, pub to: Vec<String> }`，`pub enum TlsMode { StartTls, Tls }`
  - `pub struct NotifySettings { pub min_severity: Severity, pub interval_minutes: u32, pub email: Option<EmailSettings>, pub webhook_url: Option<String> }`
  - `pub async fn load_settings(pool) -> Result<NotifySettings, sqlx::Error>`（壞值用預設）
  - `pub async fn save_settings(pool, &NotifySettings, actor) -> anyhow::Result<()>`（驗證、稽核、管道由停用變啟用時把游標設到最新事件）
  - `pub fn validate_webhook_url(&str) -> Result<(), String>`、`pub fn validate_email(&EmailSettings) -> Result<(), String>`
  - `pub struct NotifySecrets { pub smtp_password: Option<String>, pub webhook_secret: Option<String>, pub web_public_url: String }`，`AppState.notify: Arc<NotifySecrets>`
  - `Config` 新欄位 `smtp_password: Option<String>`、`webhook_secret: Option<String>`、`web_public_url: String`

- [ ] **Step 1: migration**

`0005_notify.sql`：

```sql
-- 通知：每個管道記錄已送到哪個 violation_events.id
CREATE TABLE notify_channels (
    channel         TEXT PRIMARY KEY CHECK (channel IN ('email', 'webhook')),
    last_event_id   BIGINT NOT NULL DEFAULT 0,
    last_sent_at    TIMESTAMPTZ,
    last_ok_at      TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    failures        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    dropped         BIGINT NOT NULL DEFAULT 0
);
INSERT INTO notify_channels (channel) VALUES ('email'), ('webhook');

INSERT INTO settings (key, value) VALUES
    ('notify_min_severity', '"medium"'),
    ('notify_interval_minutes', '10'),
    ('notify_email', 'null'),
    ('notify_webhook_url', 'null');
```

- [ ] **Step 2: 寫失敗測試**（`notify/mod.rs` 的 `mod tests`）

```rust
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
        for bad in ["http://hooks.example.com/x", "ftp://x", "https://", "not a url", "https://a b/"] {
            assert!(validate_webhook_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn email_validation() {
        assert!(validate_email(&email()).is_ok());
        assert!(validate_email(&EmailSettings { to: vec![], ..email() }).is_err());
        assert!(validate_email(&EmailSettings { from: "nope".into(), ..email() }).is_err());
        assert!(validate_email(&EmailSettings { host: " ".into(), ..email() }).is_err());
        assert!(validate_email(&EmailSettings { to: vec!["a@b.c\r\nBcc: x@y.z".into()], ..email() }).is_err(), "不能夾帶標頭");
    }

    #[sqlx::test(migrations = false)]
    async fn defaults_bad_values_and_enable_sets_cursor(pool: sqlx::PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let s = load_settings(&pool).await.unwrap();
        assert_eq!((s.min_severity, s.interval_minutes), (Severity::Medium, 10));
        assert!(s.email.is_none() && s.webhook_url.is_none());

        sqlx::query("UPDATE settings SET value = '\"x\"' WHERE key = 'notify_interval_minutes'")
            .execute(&pool).await.unwrap();
        assert_eq!(load_settings(&pool).await.unwrap().interval_minutes, 10, "壞值用預設");

        // 已有歷程時啟用 webhook：游標設到目前最新事件，不會把舊事件當新違規送出
        let d: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO devices (id, hostname, status) VALUES (gen_random_uuid(), 'PC', 'active') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        for _ in 0..3 {
            sqlx::query(
                "INSERT INTO violation_events (device_id, rule_name, severity, from_status, to_status, detail) \
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
        let cursor: i64 = sqlx::query_scalar("SELECT last_event_id FROM notify_channels WHERE channel = 'webhook'")
            .fetch_one(&pool).await.unwrap();
        let max: i64 = sqlx::query_scalar("SELECT max(id) FROM violation_events").fetch_one(&pool).await.unwrap();
        assert_eq!(cursor, max);
        let audit: String = sqlx::query_scalar("SELECT detail::text FROM audit_log WHERE action = 'notify_settings'")
            .fetch_one(&pool).await.unwrap();
        assert!(audit.contains("hooks.example.com"));
    }
}
```

`config.rs` 的測試加：

```rust
    #[test]
    fn notify_secrets_env() {
        let c = Config::from_lookup(|k| match k {
            "DATABASE_URL" => Some("postgres://x".into()),
            "EM_SMTP_PASSWORD" => Some("pw".into()),
            "EM_WEBHOOK_SECRET" => Some("".into()),
            "EM_WEB_PUBLIC_URL" => Some("https://em.example.com/".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.smtp_password.as_deref(), Some("pw"));
        assert_eq!(c.webhook_secret, None, "空字串視為未設定");
        assert_eq!(c.web_public_url, "https://em.example.com", "去掉結尾斜線");
    }
```

Run: `cargo test -p endpoint-server --lib notify` 與 `config::tests::notify_secrets_env`
Expected: 編譯錯誤。

- [ ] **Step 3: 實作 config 與 `NotifySecrets`**

`config.rs`：`Config` 加三個欄位，`from_lookup` 加：

```rust
            smtp_password: get("EM_SMTP_PASSWORD").filter(|s| !s.is_empty()),
            webhook_secret: get("EM_WEBHOOK_SECRET").filter(|s| !s.is_empty()),
            web_public_url: get("EM_WEB_PUBLIC_URL")
                .unwrap_or_default()
                .trim_end_matches('/')
                .to_string(),
```

`lib.rs`：`pub mod notify;`；`AppState` 加 `pub notify: Arc<notify::NotifySecrets>`，`new` 內預設 `Arc::new(notify::NotifySecrets::default())`；加 builder：

```rust
    pub fn with_notify(mut self, secrets: notify::NotifySecrets) -> Self {
        self.notify = Arc::new(secrets);
        self
    }
```

`serve` 建 state 時 `.with_notify(notify::NotifySecrets { smtp_password: cfg.smtp_password.clone(), webhook_secret: cfg.webhook_secret.clone(), web_public_url: cfg.web_public_url.clone() })`。

- [ ] **Step 4: 實作 `notify/mod.rs`**

```rust
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
            .field("webhook_secret", &self.webhook_secret.as_ref().map(|_| "***"))
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
    let rest = u.strip_prefix("https://").ok_or("Webhook 網址必須以 https:// 開頭")?;
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
    Ok(NotifySettings { min_severity, interval_minutes, email, webhook_url })
}

pub async fn save_settings(pool: &PgPool, s: &NotifySettings, actor: &str) -> anyhow::Result<()> {
    ensure!((1..=1440).contains(&s.interval_minutes), "彙整間隔須為 1–1440 分鐘");
    if let Some(e) = &s.email {
        validate_email(e).map_err(anyhow::Error::msg)?;
    }
    if let Some(u) = &s.webhook_url {
        validate_webhook_url(u).map_err(anyhow::Error::msg)?;
    }
    let before = load_settings(pool).await?;
    let mut tx = pool.begin().await?;
    for (k, v) in [
        ("notify_min_severity", serde_json::json!(s.min_severity.as_str())),
        ("notify_interval_minutes", serde_json::json!(s.interval_minutes)),
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
        ("webhook", before.webhook_url.is_some(), s.webhook_url.is_some()),
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
```

本 task 先建立空的 `digest.rs`、`send.rs`、`worker.rs`（各只有一行模組註解），讓 `mod` 宣告能編譯；`lettre` 在 Task 2 加入——所以本 task 的 `valid_address` 暫時用下面的簡化版，Task 2 再換成 `lettre::Address`：

```rust
fn valid_address(a: &str) -> bool {
    let a = a.trim();
    let Some((local, domain)) = a.split_once('@') else { return false };
    !local.is_empty() && domain.contains('.') && !a.chars().any(|c| c.is_whitespace() || c.is_control())
}
```

- [ ] **Step 5: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A crates/server
git commit -m "通知：設定、機密與管道狀態"
```

---

### Task 2: 彙整內容、Email 文字、Webhook JSON 與簽章（純函式）

**Files:**
- Modify: `Cargo.toml`、`crates/server/Cargo.toml`
- Modify: `crates/server/src/notify/digest.rs`、`crates/server/src/notify/mod.rs`（`valid_address` 改用 lettre）

**Interfaces:**
- Consumes: `compliance::evaluate::summarize`、`compliance::rules::Severity`。
- Produces:
  - `pub struct EventInfo { pub id: i64, pub device_id: Uuid, pub hostname: String, pub rule_name: String, pub severity: Severity, pub from_status: String, pub to_status: String, pub detail: serde_json::Value }`
  - `pub struct Digest { pub new: Vec<EventInfo>, pub resolved: Vec<EventInfo>, pub total_new: i64, pub total_resolved: i64, pub dropped: i64 }`，`Digest::is_empty()`
  - `pub const MAX_WEBHOOK_ITEMS: usize = 500`、`pub const EMAIL_PER_RULE: usize = 20`
  - `pub fn email_text(d: &Digest, web_url: &str) -> (String, String)`（主旨、內文）
  - `pub fn webhook_body(d: &Digest, generated_at: DateTime<Utc>) -> serde_json::Value`
  - `pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String`（`sha256=<hex>`）
  - `pub fn test_digest() -> Digest`（測試通知用的示範內容）

- [ ] **Step 1: 相依套件**

workspace `Cargo.toml` 的 `[workspace.dependencies]` 加（版本以 `cargo add --dry-run` 或 crates.io 當前版本為準；要求：rustls＋ring、系統根憑證、無 native-tls）：

```toml
lettre = { version = "0.11", default-features = false, features = ["builder", "hostname", "smtp-transport", "pool", "tokio1", "tokio1-rustls", "ring", "rustls-native-certs"] }
rustls-native-certs = "0.8"
hmac = "0.13"
```

（若 lettre 的 feature 名稱與上面不同，執行 `cargo build` 看錯誤訊息列出的可用 feature，選「tokio1 + rustls + ring + native certs」的組合，並在 ledger 記錄實際使用的 feature。`hmac` 版本要與 `sha2 = "0.11"` 使用同一個 `digest` 版本；不相容時選能與 sha2 0.11 搭配的版本。）

`crates/server/Cargo.toml` 的 `[dependencies]` 加 `lettre.workspace = true`、`reqwest.workspace = true`、`rustls-native-certs.workspace = true`、`hmac.workspace = true`。

Run: `cargo build -p endpoint-server && cargo deny check`
Expected: 編譯成功，deny 通過（新套件的授權都在允許清單內；若有不在清單的授權，停下來回報，不要自行擴充清單）。

- [ ] **Step 2: 寫失敗測試**（`digest.rs`）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(id: i64, rule: &str, host: &str, from: &str, to: &str) -> EventInfo {
        EventInfo {
            id,
            device_id: Uuid::nil(),
            hostname: host.into(),
            rule_name: rule.into(),
            severity: Severity::High,
            from_status: from.into(),
            to_status: to.into(),
            detail: json!({"kb": "KB5031455"}),
        }
    }

    fn digest(n_new: usize) -> Digest {
        Digest {
            new: (0..n_new).map(|i| ev(i as i64, if i % 2 == 0 { "規則A" } else { "規則B" }, &format!("PC{i:03}"), "none", "violating")).collect(),
            resolved: vec![ev(9999, "規則A", "PC-OK", "violating", "none")],
            total_new: n_new as i64,
            total_resolved: 1,
            dropped: 0,
        }
    }

    #[test]
    fn email_groups_by_rule_and_caps() {
        let (subject, body) = email_text(&digest(60), "https://em.example.com");
        assert_eq!(subject, "[Endpoint Manager] 合規：新增 60 筆違規、解除 1 筆");
        assert!(body.contains("規則A（高）：新增 30 台"), "{body}");
        assert_eq!(body.matches("PC0").count(), 2 * EMAIL_PER_RULE, "每條規則最多列 20 台");
        assert!(body.contains("另有 10 台"));
        assert!(body.contains("PC-OK"));
        assert!(body.contains("https://em.example.com/compliance"));
        let (_, body) = email_text(&digest(1), "");
        assert!(!body.contains("http"), "沒有網址就不附連結");
    }

    #[test]
    fn email_mentions_dropped() {
        let mut d = digest(1);
        d.dropped = 1234;
        assert!(email_text(&d, "").1.contains("1234 筆事件因積壓過多而略過"));
    }

    #[test]
    fn webhook_body_truncates_at_500() {
        let d = digest(600);
        let v = webhook_body(&Digest { new: d.new[..600].to_vec(), ..d }, DateTime::UNIX_EPOCH);
        assert_eq!(v["new"].as_array().unwrap().len() + v["resolved"].as_array().unwrap().len(), MAX_WEBHOOK_ITEMS);
        assert_eq!(v["truncated"], true);
        assert_eq!(v["total_new"], 600);
        assert_eq!(v["new"][0]["summary"], "缺少 KB5031455");
        assert_eq!(v["new"][0]["severity"], "high");
        let small = webhook_body(&digest(2), DateTime::UNIX_EPOCH);
        assert_eq!(small["truncated"], false);
        assert_eq!(small["resolved"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn signature_is_hmac_sha256_over_timestamp_and_body() {
        // 以外部工具算出的固定值，獨立驗證 HMAC 實作：
        // printf '1700000000.{}' | openssl dgst -sha256 -hmac secret
        assert_eq!(
            signature("secret", 1_700_000_000, b"{}"),
            "sha256=b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163"
        );
        assert_ne!(signature("secret", 1, b"{}"), signature("secret", 2, b"{}"));
    }
}
```

Run: `cargo test -p endpoint-server --lib notify::digest`
Expected: 編譯錯誤。

- [ ] **Step 3: 實作 `digest.rs`**

```rust
//! 通知內容：彙整、Email 文字、Webhook JSON 與簽章。全部是純函式。

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::compliance::evaluate::summarize;
use crate::compliance::rules::Severity;

pub const MAX_WEBHOOK_ITEMS: usize = 500;
pub const EMAIL_PER_RULE: usize = 20;

#[derive(Debug, Clone, PartialEq)]
pub struct EventInfo {
    pub id: i64,
    pub device_id: Uuid,
    pub hostname: String,
    pub rule_name: String,
    pub severity: Severity,
    pub from_status: String,
    pub to_status: String,
    pub detail: Value,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Digest {
    /// 最多 MAX_WEBHOOK_ITEMS 筆（呼叫端讀取時已限制）
    pub new: Vec<EventInfo>,
    pub resolved: Vec<EventInfo>,
    pub total_new: i64,
    pub total_resolved: i64,
    /// 因積壓過多而略過的事件數
    pub dropped: i64,
}

impl Digest {
    pub fn is_empty(&self) -> bool {
        self.total_new == 0 && self.total_resolved == 0 && self.dropped == 0
    }
}

fn by_rule(events: &[EventInfo]) -> Vec<(String, Severity, Vec<&EventInfo>)> {
    let mut groups: Vec<(String, Severity, Vec<&EventInfo>)> = vec![];
    for e in events {
        match groups.iter_mut().find(|g| g.0 == e.rule_name) {
            Some(g) => g.2.push(e),
            None => groups.push((e.rule_name.clone(), e.severity, vec![e])),
        }
    }
    groups.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.len().cmp(&a.2.len())).then(a.0.cmp(&b.0)));
    groups
}

fn section(out: &mut String, title: &str, verb: &str, events: &[EventInfo]) {
    if events.is_empty() {
        return;
    }
    out.push_str(&format!("\n== {title} ==\n"));
    for (rule, sev, list) in by_rule(events) {
        out.push_str(&format!("\n{rule}（{}）：{verb} {} 台\n", sev.label(), list.len()));
        for e in list.iter().take(EMAIL_PER_RULE) {
            out.push_str(&format!("  - {}：{}\n", e.hostname, summarize(&e.detail)));
        }
        if list.len() > EMAIL_PER_RULE {
            out.push_str(&format!("  …另有 {} 台\n", list.len() - EMAIL_PER_RULE));
        }
    }
}

pub fn email_text(d: &Digest, web_url: &str) -> (String, String) {
    let subject = format!(
        "[Endpoint Manager] 合規：新增 {} 筆違規、解除 {} 筆",
        d.total_new, d.total_resolved
    );
    let mut body = String::from("Endpoint Manager 合規通知\n");
    if d.new.len() as i64 < d.total_new || (d.resolved.len() as i64) < d.total_resolved {
        body.push_str(&format!(
            "\n（本次共新增 {} 筆、解除 {} 筆，以下只列出部分）\n",
            d.total_new, d.total_resolved
        ));
    }
    section(&mut body, "新增違規", "新增", &d.new);
    section(&mut body, "已解除", "解除", &d.resolved);
    if d.dropped > 0 {
        body.push_str(&format!("\n注意：有 {} 筆事件因積壓過多而略過。\n", d.dropped));
    }
    if !web_url.is_empty() {
        body.push_str(&format!("\n查看：{web_url}/compliance\n"));
    }
    (subject, body)
}

fn item(e: &EventInfo) -> Value {
    json!({
        "rule": e.rule_name,
        "severity": e.severity.as_str(),
        "device_id": e.device_id,
        "hostname": e.hostname,
        "from": e.from_status,
        "to": e.to_status,
        "summary": summarize(&e.detail),
        "detail": e.detail,
    })
}

pub fn webhook_body(d: &Digest, generated_at: DateTime<Utc>) -> Value {
    let new: Vec<Value> = d.new.iter().take(MAX_WEBHOOK_ITEMS).map(item).collect();
    let room = MAX_WEBHOOK_ITEMS - new.len();
    let resolved: Vec<Value> = d.resolved.iter().take(room).map(item).collect();
    let truncated = (new.len() + resolved.len()) as i64 < d.total_new + d.total_resolved;
    json!({
        "generated_at": generated_at,
        "total_new": d.total_new,
        "total_resolved": d.total_resolved,
        "dropped": d.dropped,
        "truncated": truncated,
        "new": new,
        "resolved": resolved,
    })
}

/// HMAC-SHA256(secret, "{timestamp}.{body}")，接收端以 X-EM-Timestamp 防止舊請求被重送。
pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// 「送出測試通知」用的示範內容。
pub fn test_digest() -> Digest {
    let e = EventInfo {
        id: 0,
        device_id: Uuid::nil(),
        hostname: "TEST-PC".into(),
        rule_name: "測試通知".into(),
        severity: Severity::Low,
        from_status: "none".into(),
        to_status: "violating".into(),
        detail: json!({"kb": "KB0000000"}),
    };
    Digest { new: vec![e], resolved: vec![], total_new: 1, total_resolved: 0, dropped: 0 }
}
```

`notify/mod.rs` 的 `valid_address` 改為 `a.parse::<lettre::Address>().is_ok()`，並確認 `email_validation` 測試中含 `\r\n` 的地址仍被拒絕（lettre 的 `Address` 不接受控制字元）。

- [ ] **Step 4: 執行**

Run: `cargo test -p endpoint-server --lib notify`
Expected: 全部 PASS（簽章測試比對 openssl 算出的固定值）。

- [ ] **Step 5: Commit**

```bash
git add -A Cargo.toml Cargo.lock crates/server
git commit -m "通知：彙整、Email 內容、Webhook JSON 與 HMAC 簽章"
```

---

### Task 3: 送出（lettre、reqwest）

**Files:**
- Modify: `crates/server/src/notify/send.rs`
- Test: `crates/server/src/notify/send.rs`、`crates/server/tests/notify.rs`（新檔）

**Interfaces:**
- Produces:
  - `pub fn webhook_client(extra_roots: &[reqwest::Certificate]) -> anyhow::Result<reqwest::Client>`（系統根憑證＋額外根憑證；不跟隨重新導向；逾時 10 秒）
  - `pub async fn send_webhook(client: &reqwest::Client, url: &str, secret: Option<&str>, body: &serde_json::Value) -> Result<(), String>`（非 2xx 視為失敗；錯誤訊息不含機密）
  - `pub fn email_message(e: &EmailSettings, subject: &str, body: &str) -> anyhow::Result<lettre::Message>`
  - `pub async fn send_email(e: &EmailSettings, password: Option<&str>, msg: lettre::Message) -> Result<(), String>`
  - `pub async fn send_email_with<T: lettre::AsyncTransport>(t: &T, msg: lettre::Message) -> Result<(), String>`（`send_email` 呼叫它；測試用 stub transport）

- [ ] **Step 1: 寫失敗測試**

`tests/notify.rs`：

```rust
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use endpoint_server::notify::send;

type Seen = Arc<Mutex<Vec<(HeaderMap, String)>>>;

/// 本機 HTTP 接收端（送出函式本身不檢查 https；https 在存檔時驗證）。
pub async fn receiver(status: StatusCode) -> (String, Seen) {
    let seen: Seen = Arc::default();
    let s2 = seen.clone();
    let app = Router::new().route(
        "/hook",
        post(move |h: HeaderMap, body: String| {
            let s2 = s2.clone();
            async move {
                s2.lock().unwrap().push((h, body));
                status
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

#[tokio::test]
async fn webhook_signs_and_reports_status() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let client = send::webhook_client(&[]).unwrap();
    let (url, seen) = receiver(StatusCode::NO_CONTENT).await;
    let body = serde_json::json!({"a": 1});
    send::send_webhook(&client, &url, Some("s3cret"), &body).await.unwrap();
    let (h, got) = seen.lock().unwrap()[0].clone();
    assert_eq!(got, r#"{"a":1}"#);
    let ts: i64 = h["x-em-timestamp"].to_str().unwrap().parse().unwrap();
    assert_eq!(
        h["x-em-signature"].to_str().unwrap(),
        endpoint_server::notify::digest::signature("s3cret", ts, got.as_bytes())
    );
    assert_eq!(h["content-type"], "application/json");

    let (url, _) = receiver(StatusCode::INTERNAL_SERVER_ERROR).await;
    let err = send::send_webhook(&client, &url, Some("s3cret"), &body).await.unwrap_err();
    assert!(err.contains("500") && !err.contains("s3cret"), "{err}");

    // 不跟隨重新導向
    let (url, seen) = receiver(StatusCode::FOUND).await;
    assert!(send::send_webhook(&client, &url, None, &body).await.is_err());
    assert_eq!(seen.lock().unwrap().len(), 1);
    assert!(seen.lock().unwrap()[0].0.get("x-em-signature").is_none(), "沒有密鑰就不簽");
}
```

`send.rs` 的單元測試：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{EmailSettings, TlsMode};

    #[tokio::test]
    async fn email_message_and_stub_send() {
        let e = EmailSettings {
            host: "smtp.example.com".into(),
            port: 587,
            tls: TlsMode::StartTls,
            username: String::new(),
            from: "em@example.com".into(),
            to: vec!["a@example.com".into(), "b@example.com".into()],
        };
        let msg = email_message(&e, "主旨", "內文").unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("To: a@example.com, b@example.com"), "{raw}");
        assert!(raw.contains("Content-Type: text/plain; charset=utf-8"));
        send_email_with(&lettre::transport::stub::AsyncStubTransport::new_ok(), msg.clone()).await.unwrap();
        let err = send_email_with(&lettre::transport::stub::AsyncStubTransport::new_error(), msg).await.unwrap_err();
        assert!(!err.is_empty());
    }
}
```

Run: `cargo test -p endpoint-server --lib notify::send` 與 `cargo test -p endpoint-server --test notify`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作 `send.rs`**

```rust
//! 實際送出：Webhook（reqwest）與 Email（lettre）。

use std::time::Duration;

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::digest::signature;
use super::{EmailSettings, TlsMode};

pub const TIMEOUT: Duration = Duration::from_secs(10);

/// 系統信任的根憑證（企業內部 CA 通常已裝在伺服器上）加上額外指定的根憑證。
pub fn webhook_client(extra_roots: &[reqwest::Certificate]) -> anyhow::Result<reqwest::Client> {
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        tracing::warn!(error = %e, "loading a system root certificate failed");
    }
    let mut roots: Vec<reqwest::Certificate> = native
        .certs
        .iter()
        .filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok())
        .collect();
    roots.extend(extra_roots.iter().cloned());
    Ok(reqwest::Client::builder()
        .tls_certs_only(roots)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()?)
}

pub async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    body: &serde_json::Value,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let mut req = client.post(url).header("content-type", "application/json");
    if let Some(secret) = secret {
        let ts = chrono::Utc::now().timestamp();
        req = req
            .header("x-em-timestamp", ts.to_string())
            .header("x-em-signature", signature(secret, ts, &bytes));
    }
    let res = req.body(bytes).send().await.map_err(|e| format!("Webhook 連線失敗：{}", e.without_url()))?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("Webhook 回應 {}", res.status().as_u16()))
    }
}

pub fn email_message(e: &EmailSettings, subject: &str, body: &str) -> anyhow::Result<Message> {
    let mut b = Message::builder().from(e.from.parse::<Mailbox>()?).subject(subject);
    for to in &e.to {
        b = b.to(to.parse::<Mailbox>()?);
    }
    Ok(b.header(ContentType::TEXT_PLAIN).body(body.to_string())?)
}

pub async fn send_email_with<T: AsyncTransport>(t: &T, msg: Message) -> Result<(), String>
where
    T::Error: std::fmt::Display,
{
    t.send(msg).await.map(|_| ()).map_err(|e| format!("寄信失敗：{e}"))
}

pub async fn send_email(e: &EmailSettings, password: Option<&str>, msg: Message) -> Result<(), String> {
    let builder = match e.tls {
        TlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&e.host),
        TlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&e.host),
    }
    .map_err(|err| format!("SMTP 設定錯誤：{err}"))?
    .port(e.port)
    .timeout(Some(TIMEOUT));
    let builder = if e.username.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(e.username.clone(), password.unwrap_or_default().to_string()))
    };
    send_email_with(&builder.build(), msg).await
}
```

（`reqwest::Error::without_url` 避免網址中的權杖出現在錯誤訊息；若該方法名稱在 reqwest 0.13 不同，以文件為準。lettre 的 `AsyncStubTransport` 若需要 feature，在 `[dev-dependencies]` 另外打開，不要打開到正式相依。）

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --lib notify` 與 `cargo test -p endpoint-server --test notify`
Expected: 全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A Cargo.toml Cargo.lock crates/server
git commit -m "通知：Webhook 與 Email 送出"
```

---

### Task 4: 背景送出（游標、彙整間隔、倍增重試、積壓上限）

**Files:**
- Modify: `crates/server/src/notify/worker.rs`、`crates/server/src/lib.rs`（啟動）
- Test: `crates/server/tests/notify.rs`

**Interfaces:**
- Consumes: `notify::{load_settings, NotifySecrets}`、`digest::{Digest, EventInfo, email_text, webhook_body, MAX_WEBHOOK_ITEMS}`、`send::*`。
- Produces:
  - `pub const MAX_BACKLOG: i64 = 100_000`
  - `pub struct Senders { pub webhook: reqwest::Client }`
  - `pub async fn load_digest(pool, after: i64, upto: i64, min: Severity) -> Result<Digest, sqlx::Error>`
  - `pub async fn run_channel(pool, channel: &str, settings: &NotifySettings, secrets: &NotifySecrets, senders: &Senders, now: DateTime<Utc>) -> Result<(), sqlx::Error>`
  - `pub fn backoff(failures: i32) -> chrono::Duration`（1、2、4…分鐘，上限 60）
  - `pub fn spawn(pool: PgPool, secrets: Arc<NotifySecrets>)`

- [ ] **Step 1: 寫失敗測試**（`tests/notify.rs` 加）

```rust
mod common;

use chrono::{Duration as CDuration, Utc};
use common::TestServer;
use endpoint_server::notify::{self, worker};
use sqlx::PgPool;

async fn event(s: &TestServer, device: uuid::Uuid, sev: &str, from: &str, to: &str) {
    sqlx::query(
        "INSERT INTO violation_events (device_id, rule_name, severity, from_status, to_status, detail) \
         VALUES ($1, '禁止 TeamViewer', $2, $3, $4, '{\"software\": []}')",
    )
    .bind(device)
    .bind(sev)
    .bind(from)
    .bind(to)
    .execute(&s.pool)
    .await
    .unwrap();
}

async fn enable_webhook(s: &TestServer, url: &str) {
    // 直接寫設定（測試用 http 接收端；網頁存檔時才驗證 https）
    sqlx::query("UPDATE settings SET value = $1::jsonb WHERE key = 'notify_webhook_url'")
        .bind(serde_json::json!(url).to_string())
        .execute(&s.pool)
        .await
        .unwrap();
}

async fn channel_row(s: &TestServer) -> (i64, i32, Option<String>) {
    sqlx::query_as("SELECT last_event_id, failures, last_error FROM notify_channels WHERE channel = 'webhook'")
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn worker_sends_digest_filters_and_backs_off(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (url, seen) = receiver(StatusCode::OK).await;
    enable_webhook(&s, &url).await;
    let senders = worker::Senders { webhook: endpoint_server::notify::send::webhook_client(&[]).unwrap() };
    let secrets = notify::NotifySecrets::default();

    event(&s, a.device_id, "high", "none", "violating").await;
    event(&s, a.device_id, "low", "none", "violating").await; // 低於門檻（預設 medium）
    event(&s, a.device_id, "high", "none", "unknown").await; // 不是違規
    event(&s, a.device_id, "high", "violating", "none").await; // 解除
    let settings = notify::load_settings(&s.pool).await.unwrap();
    let now = Utc::now();
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, now).await.unwrap();
    {
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        let v: serde_json::Value = serde_json::from_str(&got[0].1).unwrap();
        assert_eq!((v["total_new"].as_i64(), v["total_resolved"].as_i64()), (Some(1), Some(1)));
    }
    let max: i64 = sqlx::query_scalar("SELECT max(id) FROM violation_events").fetch_one(&s.pool).await.unwrap();
    assert_eq!(channel_row(&s).await.0, max, "游標推進到最新");

    // 間隔未到：不送
    event(&s, a.device_id, "high", "none", "violating").await;
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, now + CDuration::minutes(1)).await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    // 間隔到了但接收端故障：失敗、游標不動、倍增重試
    let (bad, _) = receiver(StatusCode::SERVICE_UNAVAILABLE).await;
    enable_webhook(&s, &bad).await;
    let t = now + CDuration::minutes(11);
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, t).await.unwrap();
    let (cursor, failures, err) = channel_row(&s).await;
    assert_eq!((cursor, failures), (max, 1));
    assert!(err.unwrap().contains("503"));
    let next: chrono::DateTime<Utc> =
        sqlx::query_scalar("SELECT next_attempt_at FROM notify_channels WHERE channel = 'webhook'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(next >= t + CDuration::minutes(1) - CDuration::seconds(1));
    // 重試時間未到：不嘗試
    worker::run_channel(&s.pool, "webhook", &settings, &secrets, &senders, t + CDuration::seconds(30)).await.unwrap();
    assert_eq!(channel_row(&s).await.1, 1);
}

#[sqlx::test(migrations = false)]
async fn backlog_is_capped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (url, seen) = receiver(StatusCode::OK).await;
    enable_webhook(&s, &url).await;
    sqlx::query(
        "INSERT INTO violation_events (device_id, rule_name, severity, from_status, to_status, detail) \
         SELECT $1, 'r', 'high', 'none', 'violating', '{}' FROM generate_series(1, $2)",
    )
    .bind(a.device_id)
    .bind((worker::MAX_BACKLOG + 5) as i32)
    .execute(&s.pool)
    .await
    .unwrap();
    let senders = worker::Senders { webhook: endpoint_server::notify::send::webhook_client(&[]).unwrap() };
    let settings = notify::load_settings(&s.pool).await.unwrap();
    worker::run_channel(&s.pool, "webhook", &settings, &notify::NotifySecrets::default(), &senders, Utc::now())
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&seen.lock().unwrap()[0].1).unwrap();
    assert_eq!(v["dropped"], 5);
    assert_eq!(v["total_new"], worker::MAX_BACKLOG);
    assert_eq!(v["new"].as_array().unwrap().len(), 500);
}

#[test]
fn backoff_doubles_to_an_hour() {
    let m = |f| worker::backoff(f).num_minutes();
    assert_eq!((m(1), m(2), m(3), m(7), m(30)), (1, 2, 4, 60, 60));
}
```

（檔案最上方原本的 `receiver` 等測試保留；`mod common;` 與 `use` 放到檔案開頭，避免重複宣告。）

Run: `cargo test -p endpoint-server --test notify`
Expected: 編譯錯誤（`worker::run_channel` 不存在）。

- [ ] **Step 2: 實作 `worker.rs`**

```rust
//! 背景送出：每個管道依游標讀新事件，到彙整間隔就送一份；失敗倍增重試。

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::digest::{Digest, EventInfo, MAX_WEBHOOK_ITEMS, email_text, webhook_body};
use super::{NotifySecrets, NotifySettings, load_settings, send};
use crate::compliance::rules::Severity;

pub const MAX_BACKLOG: i64 = 100_000;

pub struct Senders {
    pub webhook: reqwest::Client,
}

pub fn backoff(failures: i32) -> chrono::Duration {
    let exp = (failures.max(1) - 1).min(6) as u32;
    chrono::Duration::minutes((1i64 << exp).min(60))
}

/// 門檻以上、且變成或離開「違規」的事件
const RELEVANT: &str = "id > $1 AND id <= $2 AND severity = ANY($3) \
     AND (to_status = 'violating') <> (from_status = 'violating')";

type EventRow = (i64, Uuid, Option<String>, String, String, String, String, String);

async fn events(pool: &PgPool, after: i64, upto: i64, sev: &[&str], new: bool) -> Result<Vec<EventInfo>, sqlx::Error> {
    let sql = format!(
        "SELECT e.id, e.device_id, d.hostname, e.rule_name, e.severity, e.from_status, e.to_status, e.detail::text \
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
        .map(|(id, device_id, hostname, rule_name, severity, from_status, to_status, detail)| EventInfo {
            id,
            device_id,
            hostname: hostname.unwrap_or_default(),
            rule_name,
            severity: Severity::parse(&severity).unwrap_or(Severity::Medium),
            from_status,
            to_status,
            detail: serde_json::from_str(&detail).unwrap_or_default(),
        })
        .collect())
}

pub async fn load_digest(pool: &PgPool, after: i64, upto: i64, min: Severity) -> Result<Digest, sqlx::Error> {
    let sev: Vec<&str> = Severity::ALL.into_iter().filter(|s| *s >= min).map(Severity::as_str).collect();
    let (total_new, total_resolved): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FILTER (WHERE to_status = 'violating'), \
                count(*) FILTER (WHERE to_status <> 'violating') \
         FROM violation_events WHERE {RELEVANT}"
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
    if last_sent.is_some_and(|t| now < t + chrono::Duration::minutes(settings.interval_minutes.into())) && failures == 0 {
        return Ok(());
    }
    let upto: i64 = sqlx::query_scalar("SELECT coalesce(max(id), 0) FROM violation_events")
        .fetch_one(pool)
        .await?;
    if upto - cursor > MAX_BACKLOG {
        dropped += upto - MAX_BACKLOG - cursor;
        tracing::warn!(channel, dropped, "notification backlog too large; skipping oldest events");
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
    let result = match channel {
        "email" => {
            let e = settings.email.as_ref().expect("enabled");
            let (subject, body) = email_text(&digest, &secrets.web_public_url);
            match send::email_message(e, &subject, &body) {
                Ok(msg) => send::send_email(e, secrets.smtp_password.as_deref(), msg).await,
                Err(err) => Err(format!("信件內容錯誤：{err}")),
            }
        }
        _ => {
            let url = settings.webhook_url.as_deref().expect("enabled");
            send::send_webhook(&senders.webhook, url, secrets.webhook_secret.as_deref(), &webhook_body(&digest, now)).await
        }
    };
    match result {
        Ok(()) => {
            sqlx::query(
                "UPDATE notify_channels SET last_event_id = $2, last_sent_at = $3, last_ok_at = $3, \
                 failures = 0, next_attempt_at = NULL, last_error = NULL, dropped = 0 WHERE channel = $1",
            )
            .bind(channel)
            .bind(upto)
            .bind(now)
            .execute(pool)
            .await?;
        }
        Err(err) => {
            tracing::warn!(channel, error = %err, "notification failed");
            // 游標跳過的部分（積壓上限）即使送失敗也不回頭
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
                if let Err(e) = run_channel(&pool, channel, &settings, &secrets, &senders, Utc::now()).await {
                    tracing::error!(channel, error = %e, "notification worker failed");
                }
            }
        }
    });
}
```

說明「間隔未到」的判斷：`failures > 0` 時由 `next_attempt_at` 控制重試時間，不再受彙整間隔限制。

`lib.rs` 的 `serve`：`compliance::worker::spawn(...)` 之後加 `notify::worker::spawn(pool.clone(), state.notify.clone());`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --test notify`
Expected: 全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server
git commit -m "通知：背景彙整送出、倍增重試、積壓上限"
```

---

### Task 5: 通知設定頁與總覽狀態

**Files:**
- Create: `crates/server/src/web/notify.rs`、`crates/server/templates/notify.html`
- Modify: `crates/server/src/web/mod.rs`、`crates/server/src/web/compliance.rs`、`crates/server/templates/compliance.html`
- Test: `crates/server/tests/notify.rs`

**Interfaces:**
- Produces（路由，全部平台管理員）：`GET /compliance/notify` → `notify::page`；`POST /compliance/notify` → `notify::save`；`POST /compliance/notify/test` → `notify::test`（表單欄位 `channel=email|webhook`）。
- Produces：總覽頁顯示每個管道「已啟用／停用、最後成功時間、最後錯誤」。

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn notify_settings_page(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/compliance/notify").await;
    assert_eq!(st, 200);
    assert!(html.contains("EM_SMTP_PASSWORD") && html.contains("未設定"), "只顯示機密是否已設定");
    let csrf = common::csrf_from(&html);
    let post = |pairs: Vec<(&'static str, String)>| {
        let c = admin.clone();
        let url = s.web_url("/compliance/notify");
        async move { c.post(url).form(&pairs).send().await.unwrap() }
    };
    let r = post(vec![
        ("csrf", csrf.clone()), ("min_severity", "high".into()), ("interval_minutes", "5".into()),
        ("webhook_url", "http://insecure.example.com".into()),
    ])
    .await;
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("https://"));
    let r = post(vec![
        ("csrf", csrf.clone()), ("min_severity", "high".into()), ("interval_minutes", "5".into()),
        ("webhook_url", "https://hooks.example.com/x".into()),
        ("smtp_host", "smtp.example.com".into()), ("smtp_port", "587".into()), ("smtp_tls", "starttls".into()),
        ("smtp_from", "em@example.com".into()), ("smtp_to", "a@example.com, b@example.com".into()),
    ])
    .await;
    assert_eq!(r.status(), 303);
    let n = notify::load_settings(&s.pool).await.unwrap();
    assert_eq!(n.min_severity, endpoint_server::compliance::rules::Severity::High);
    assert_eq!(n.email.unwrap().to, vec!["a@example.com", "b@example.com"]);
    let (_, html) = s.page(&admin, "/compliance").await;
    assert!(html.contains("Webhook") && html.contains("Email"), "總覽顯示通知狀態");

    let g = s.login_as("gary", endpoint_server::web::auth::Role::GroupAdmin, &["台北"]).await;
    assert_eq!(s.page(&g, "/compliance/notify").await.0, 403);
}
```

Run: `cargo test -p endpoint-server --test notify notify_settings_page`
Expected: FAIL（404）。

- [ ] **Step 2: 實作 `web/notify.rs`**

```rust
//! 通知設定（平台管理員）。機密只顯示是否已設定。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf};
use super::devices::{SelectOption, db_error};
use super::{forbidden, render};
use crate::AppState;
use crate::compliance::rules::Severity;
use crate::notify::{self, EmailSettings, NotifySettings, TlsMode, digest, send};

#[derive(Template)]
#[template(path = "notify.html")]
struct NotifyPage {
    nav: Nav,
    severities: Vec<SelectOption>,
    interval_minutes: u32,
    webhook_url: String,
    smtp_host: String,
    smtp_port: String,
    starttls: bool,
    smtp_username: String,
    smtp_from: String,
    smtp_to: String,
    smtp_password_set: bool,
    webhook_secret_set: bool,
}

pub async fn page(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, Response> {
    if !s.all_devices() {
        return Err(forbidden());
    }
    let n = notify::load_settings(&st.pool).await.map_err(db_error)?;
    let e = n.email.clone();
    Ok(render(&NotifyPage {
        nav: Nav::from(&s),
        severities: Severity::ALL
            .into_iter()
            .map(|x| SelectOption { value: x.as_str().into(), label: x.label().into(), selected: x == n.min_severity })
            .collect(),
        interval_minutes: n.interval_minutes,
        webhook_url: n.webhook_url.unwrap_or_default(),
        smtp_host: e.as_ref().map(|e| e.host.clone()).unwrap_or_default(),
        smtp_port: e.as_ref().map(|e| e.port.to_string()).unwrap_or_else(|| "587".into()),
        starttls: e.as_ref().is_none_or(|e| e.tls == TlsMode::StartTls),
        smtp_username: e.as_ref().map(|e| e.username.clone()).unwrap_or_default(),
        smtp_from: e.as_ref().map(|e| e.from.clone()).unwrap_or_default(),
        smtp_to: e.map(|e| e.to.join(", ")).unwrap_or_default(),
        smtp_password_set: st.notify.smtp_password.is_some(),
        webhook_secret_set: st.notify.webhook_secret.is_some(),
    }))
}

#[derive(Deserialize)]
pub struct SaveForm {
    csrf: String,
    min_severity: String,
    interval_minutes: String,
    #[serde(default)]
    webhook_url: String,
    #[serde(default)]
    smtp_host: String,
    #[serde(default)]
    smtp_port: String,
    #[serde(default)]
    smtp_tls: String,
    #[serde(default)]
    smtp_username: String,
    #[serde(default)]
    smtp_from: String,
    #[serde(default)]
    smtp_to: String,
}

fn conflict(msg: impl std::fmt::Display) -> Response {
    (StatusCode::CONFLICT, msg.to_string()).into_response()
}

/// 表單轉設定；SMTP 主機留空＝停用 Email，Webhook 網址留空＝停用 Webhook。
fn to_settings(f: &SaveForm) -> Result<NotifySettings, String> {
    let min_severity = Severity::parse(&f.min_severity).ok_or("嚴重度無效")?;
    let interval_minutes = f.interval_minutes.trim().parse::<u32>().map_err(|_| "彙整間隔必須是數字")?;
    let email = if f.smtp_host.trim().is_empty() {
        None
    } else {
        Some(EmailSettings {
            host: f.smtp_host.trim().into(),
            port: f.smtp_port.trim().parse().map_err(|_| "SMTP 埠號必須是數字")?,
            tls: if f.smtp_tls == "tls" { TlsMode::Tls } else { TlsMode::StartTls },
            username: f.smtp_username.trim().into(),
            from: f.smtp_from.trim().into(),
            to: f.smtp_to.split([',', ';', '\n']).map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect(),
        })
    };
    let webhook_url = Some(f.webhook_url.trim().to_string()).filter(|u| !u.is_empty());
    Ok(NotifySettings { min_severity, interval_minutes, email, webhook_url })
}

pub async fn save(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<SaveForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let n = to_settings(&f).map_err(conflict)?;
    notify::save_settings(&st.pool, &n, &s.username).await.map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/notify").into_response())
}

#[derive(Deserialize)]
pub struct TestForm {
    csrf: String,
    channel: String,
}

pub async fn test(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<TestForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let n = notify::load_settings(&st.pool).await.map_err(db_error)?;
    let d = digest::test_digest();
    let result = match f.channel.as_str() {
        "email" => match &n.email {
            None => Err("尚未設定 Email".to_string()),
            Some(e) => {
                let (subject, body) = digest::email_text(&d, &st.notify.web_public_url);
                match send::email_message(e, &subject, &body) {
                    Ok(msg) => send::send_email(e, st.notify.smtp_password.as_deref(), msg).await,
                    Err(err) => Err(err.to_string()),
                }
            }
        },
        "webhook" => match &n.webhook_url {
            None => Err("尚未設定 Webhook".to_string()),
            Some(url) => match send::webhook_client(&[]) {
                Ok(c) => send::send_webhook(&c, url, st.notify.webhook_secret.as_deref(), &digest::webhook_body(&d, chrono::Utc::now())).await,
                Err(err) => Err(err.to_string()),
            },
        },
        _ => Err("未知的管道".to_string()),
    };
    Ok(match result {
        Ok(()) => (StatusCode::OK, "測試通知已送出").into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e).into_response(),
    })
}
```

`templates/notify.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>通知設定</h1>
<p><a href="/compliance">← 合規總覽</a></p>
<form method="post" action="/compliance/notify">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <p><label>通知門檻 <select name="min_severity">{% for o in severities %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}以上</option>{% endfor %}</select></label>
     <label>彙整間隔 <input name="interval_minutes" type="number" min="1" max="1440" value="{{ interval_minutes }}" required> 分鐘</label></p>
  <fieldset><legend>Email（SMTP 主機留空＝停用）</legend>
    <p><label>SMTP 主機 <input name="smtp_host" value="{{ smtp_host }}" size="30"></label>
       <label>埠 <input name="smtp_port" value="{{ smtp_port }}" size="5"></label>
       <label><input type="radio" name="smtp_tls" value="starttls" {% if starttls %}checked{% endif %}> STARTTLS</label>
       <label><input type="radio" name="smtp_tls" value="tls" {% if !starttls %}checked{% endif %}> TLS</label></p>
    <p><label>帳號 <input name="smtp_username" value="{{ smtp_username }}" autocomplete="off"></label>
       密碼：環境變數 <code>EM_SMTP_PASSWORD</code>（{% if smtp_password_set %}已設定{% else %}未設定{% endif %}）</p>
    <p><label>寄件者 <input name="smtp_from" value="{{ smtp_from }}" size="30"></label></p>
    <p><label>收件人（逗號分隔）<input name="smtp_to" value="{{ smtp_to }}" size="60"></label></p>
  </fieldset>
  <fieldset><legend>Webhook（網址留空＝停用）</legend>
    <p><label>網址 <input name="webhook_url" value="{{ webhook_url }}" size="60" placeholder="https://"></label></p>
    <p class="muted">簽章密鑰：環境變數 <code>EM_WEBHOOK_SECRET</code>（{% if webhook_secret_set %}已設定{% else %}未設定{% endif %}）。設定後每個請求帶 <code>X-EM-Timestamp</code> 與 <code>X-EM-Signature: sha256=HMAC(密鑰, 時間戳記 + "." + 內文)</code>。</p>
  </fieldset>
  <p><button>儲存</button></p>
</form>
<p>
  <button hx-post="/compliance/notify/test" hx-vals='{"channel": "email", "csrf": "{{ nav.csrf }}"}' hx-target="#test-result">送出測試 Email</button>
  <button hx-post="/compliance/notify/test" hx-vals='{"channel": "webhook", "csrf": "{{ nav.csrf }}"}' hx-target="#test-result">送出測試 Webhook</button>
</p>
<div id="test-result"></div>
{% endblock %}
```

（htmx 預設不把非 2xx 回應換進目標；在 `htmx-config` 的 meta 已有設定，若失敗訊息沒有顯示，於 `base.html` 的 `htmx-config` 加 `"responseHandling": [{"code": ".*", "swap": true}]`，這是 htmx 2 的設定方式——以既有 htmx 版本文件為準。）

路由（`web/mod.rs`：`pub mod notify;`）：

```rust
        .route("/compliance/notify", get(notify::page).post(notify::save))
        .route("/compliance/notify/test", post(notify::test))
```

- [ ] **Step 3: 總覽顯示通知狀態**

`web/compliance.rs` 的 `OverviewPage` 加 `channels: Vec<ChannelStatus>`：

```rust
pub struct ChannelStatus {
    pub name: &'static str,
    pub enabled: bool,
    pub last_ok: String,
    pub error: String,
}
```

`overview` 內（只給平台管理員；其他角色給空 vec）：

```rust
    let channels = if s.all_devices() {
        let n = crate::notify::load_settings(&st.pool).await?;
        let rows: Vec<(String, Option<DateTime<Utc>>, Option<String>)> =
            sqlx::query_as("SELECT channel, last_ok_at, last_error FROM notify_channels ORDER BY channel")
                .fetch_all(&st.pool)
                .await?;
        rows.into_iter()
            .map(|(c, ok, err)| ChannelStatus {
                enabled: if c == "email" { n.email.is_some() } else { n.webhook_url.is_some() },
                name: if c == "email" { "Email" } else { "Webhook" },
                last_ok: fmt_time(&st, ok),
                error: err.unwrap_or_default(),
            })
            .collect()
    } else {
        vec![]
    };
```

`compliance.html` 在規則表之後：

```html
{% if !channels.is_empty() %}
<h2>通知 <a href="/compliance/notify">設定</a></h2>
<table>
  <tr><th>管道</th><th>狀態</th><th>最後成功</th><th>最後錯誤</th></tr>
  {% for c in channels %}<tr><td>{{ c.name }}</td><td>{% if c.enabled %}啟用{% else %}<span class="muted">停用</span>{% endif %}</td><td>{{ c.last_ok }}</td><td class="error">{{ c.error }}</td></tr>{% endfor %}
</table>
{% endif %}
```

- [ ] **Step 4: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A crates/server
git commit -m "通知：設定頁、測試送出與總覽狀態"
```

---

### Task 6: 部署文件與負載測試

**Files:**
- Modify: `deploy/docker-compose.yml`、`deploy/.env.example`、`README.md`
- Create: `tools/loadsim/rules.sql`
- Modify: `crates/server/src/compliance/mod.rs`（評估耗時 debug 日誌）
- Modify: `docs/loadtest.md`

**Interfaces:** 無新程式介面。

- [ ] **Step 1: 部署設定**

`docker-compose.yml` 的 server `environment` 加：

```yaml
      EM_SMTP_PASSWORD: ${EM_SMTP_PASSWORD:-}
      EM_WEBHOOK_SECRET: ${EM_WEBHOOK_SECRET:-}
      EM_WEB_PUBLIC_URL: ${EM_WEB_PUBLIC_URL:-}
```

`.env.example` 加：

```bash
# 合規通知（選填）：SMTP 密碼、Webhook 簽章密鑰、通知信內連結用的管理網頁網址
EM_SMTP_PASSWORD=
EM_WEBHOOK_SECRET=
EM_WEB_PUBLIC_URL=https://em.example.com:8444
```

`README.md` 的功能說明加一段「合規」：五種規則、豁免、違規歷程、CSV、Email／Webhook 通知與上面三個環境變數；Webhook 簽章驗證方式（`HMAC-SHA256(密鑰, X-EM-Timestamp + "." + 內文)`，接收端應拒絕時間戳記與現在相差超過 5 分鐘的請求）。

Run: `bash deploy/smoke.sh`（若本機有 Docker；否則交給 CI 的 `deploy` job）
Expected: 通過。

- [ ] **Step 2: 評估耗時日誌**

`compliance::refresh_after_upload` 包一層計時：

```rust
pub async fn refresh_after_upload(st: &AppState, device_id: Uuid) -> Result<(), sqlx::Error> {
    let start = std::time::Instant::now();
    let rules = st.rules.get(&st.pool).await?;
    store::refresh_device(&st.pool, &rules, device_id).await?;
    tracing::debug!(elapsed_us = start.elapsed().as_micros() as u64, "compliance refresh");
    Ok(())
}
```

- [ ] **Step 3: 規則種子**

`tools/loadsim/rules.sql`（50 條：與 loadsim 產生的軟體名稱相符與不相符的都有）：

```sql
-- 負載測試用：50 條合規規則。用法：psql -f tools/loadsim/rules.sql
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load forbidden ' || i, 'forbidden_software', 'high',
       jsonb_build_object('name', '*Software ' || i || '*'), 'loadsim'
FROM generate_series(1, 20) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load required ' || i, 'required_software', 'medium',
       jsonb_build_object('name', '*Software ' || i || '*', 'min_version', '2.0'), 'loadsim'
FROM generate_series(1, 20) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by)
SELECT 'load kb ' || i, 'required_kb', 'low', jsonb_build_object('kb', 'KB50000' || lpad(i::text, 2, '0')), 'loadsim'
FROM generate_series(1, 8) i;
INSERT INTO compliance_rules (name, kind, severity, params, created_by) VALUES
  ('load allowlist', 'software_allowlist', 'low', '{"entries": [{"name": "Software*"}]}', 'loadsim'),
  ('load build', 'os_build', 'high', '{"min_build": 19045}', 'loadsim');
UPDATE compliance_state SET generation = generation + 1;
```

（先看 `tools/loadsim/src/lib.rs` 產生的軟體名稱格式，把 `'*Software ' || i || '*'` 調整成實際會命中一部分裝置的樣式。）

- [ ] **Step 4: 執行負載測試**

依 `docs/loadtest.md`「重跑方法」準備 30,000 台，差別：

```bash
export RUST_LOG=info,endpoint_server::compliance=debug
./endpoint-server serve 2> server.log &
./loadsim upload ... --items 150 --concurrency 100          # 基準：尚無規則
docker exec -i em-postgres psql -U postgres -d em_load < ../../tools/loadsim/rules.sql
# 等 server.log 出現 "compliance recompute finished"，記下 elapsed_secs（目標 < 300）
./loadsim heartbeat ... --rate 500 --secs 120 &             # 重算期間同時量報到
docker exec em-postgres psql -U postgres -d em_load -c "UPDATE compliance_state SET generation = generation + 1"
wait                                                         # 報到 p99 目標 < 100ms
./loadsim upload ... --items 150 --concurrency 100          # 有 50 條規則時再上傳一次
grep 'compliance refresh' server.log | sed -E 's/.*elapsed_us=([0-9]+).*/\1/' | sort -n | awk '{a[NR]=$1} END {print "p99_us", a[int(NR*0.99)]}'
```

（第二次 upload 前，loadsim 需要上傳與上次不同的內容才會真的寫入；若 loadsim 每次內容相同，改 `--items 151`。）

Expected：評估 p99 < 20ms（20,000 us）、全量重算 < 300 秒、重算期間報到 p99 < 100ms。未達標時**不要調整目標**，把數字與瓶頸（慢查詢日誌）寫進文件並回報。

- [ ] **Step 5: 記錄結果**

`docs/loadtest.md` 新增「合規（2026-09-29）」一節：表格列出三個目標、實測值、是否達標，以及環境與限制（同一台電腦跑全部元件）；「重跑方法」補上 Step 4 的指令。

- [ ] **Step 6: 全部檢查**

Run: `cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`、`cargo deny check`
Expected: 全部通過。

- [ ] **Step 7: Commit**

```bash
git add -A deploy README.md tools docs crates/server
git commit -m "合規：部署設定、負載測試與結果"
```
