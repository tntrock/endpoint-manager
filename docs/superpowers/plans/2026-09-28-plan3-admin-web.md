# 計畫 3／4：管理網頁實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在伺服器加上 HTTPS 管理網頁（:443）：管理員登入、儀表板、裝置列表與詳細資料、全公司軟體搜尋、註冊金鑰管理、稽核記錄，以及「重新註冊需管理員核准」與「除役裝置」。

**Architecture:** 同一個 `endpoint-server` 執行檔多開一個 TLS 監聽埠（不要求用戶端憑證），沿用計畫 1 的 `tls::serve_mtls` accept loop 與連線限制。頁面由 askama 在伺服器端產生，htmx（放在專案內的單一 JS 檔）只用於裝置詳細頁的分頁載入。登入採本機帳號（argon2id）；工作階段存在資料庫，cookie 為 `HttpOnly; Secure; SameSite=Strict`；所有寫入動作都是帶 CSRF token 的表單 POST，並寫入 `audit_log`。

**Tech Stack:** axum 0.8、askama 0.16、argon2 0.6、htmx 2.0.11（vendored）、既有的 sqlx／rustls

**Spec:** `docs/superpowers/specs/2026-09-27-endpoint-inventory-design.md`（§5.3 管理資料表、§6.2 管理網頁防護）

**前置：** 計畫 1、2 已合併。計畫 1 最終審查的 I2 決議：「完整修正（重新註冊需管理員核准）放在計畫 3」。

## 設計決定（本計畫新增，執行前請使用者確認）

1. **重新註冊一律需要核准**：硬體識別（SMBIOS UUID＋BIOS 序號）與既有裝置相符時，不再自動沿用舊記錄或撤銷舊憑證。改為建立一筆 `pending_approval` 的新裝置記錄（`reenroll_of` 指向舊裝置），它可以正常報到上傳，但資料獨立存放。
   - **核准**：舊裝置的憑證撤銷，新憑證移到舊裝置，新記錄刪除；舊裝置的區段 hash 清空，下次報到時重新上傳全部資料，差異會記在變更歷史。
   - **拒絕**：新裝置的憑證撤銷，狀態改為 `retired`。
   - 儀表板提供「全部核准」，方便大量重灌時一次處理。
   - 這取代計畫 1 的「10 分鐘內有報到就不接管」暫時防護。
2. **除役**：撤銷該裝置所有憑證、狀態改 `retired`；列表預設不顯示已除役裝置。
3. **管理員帳號**：第一期只有單一角色 `admin`，帳號用 CLI `admin-create` 建立；網頁不提供帳號管理（YAGNI）。
4. **在線判定**：`last_seen_at` 在 3 個報到週期內（依 `settings.checkin_interval_secs`）。
5. **時間顯示**：以 `EM_DISPLAY_UTC_OFFSET`（小時，預設 `8`）換算顯示。
6. **介面語言**：繁體中文。

## Global Constraints

- 授權 `GPL-3.0-only`；Rust edition 2024；TLS 只用 rustls + ring；不用 clap。
- 管理網頁監聽埠預設 `0.0.0.0:443`（`EM_WEB_LISTEN`），使用 `pki/server.pem` 伺服器憑證，不要求用戶端憑證；連線限制沿用 `tls::ConnLimits::default()`。
- 密碼：argon2id 預設參數；最短 12 字元。
- 登入失敗 5 次 → 鎖定 15 分鐘；錯誤訊息一律「帳號或密碼錯誤」，不透露帳號是否存在或已鎖定。
- 工作階段：64 hex 隨機 token，資料庫只存 SHA-256；有效 8 小時；cookie `em_session`，`Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`。
- 每個已登入的 POST 都必須帶 `csrf` 欄位並與工作階段相符，否則 403。
- 所有 HTML 回應加上：`Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: same-origin`、`Cache-Control: no-store`。
- 不使用任何行內 script／style；htmx 設定 `includeIndicatorStyles: false`。
- 所有輸出一律經 askama 自動 HTML escape；不使用 `|safe`。
- 寫入 `audit_log` 的動作：`login`、`login_failed`、`logout`、`token_create`、`token_revoke`、`device_retire`、`device_approve`、`device_reject`、`admin_create`。
- 列表分頁每頁 50 筆；搜尋字串中的 `%`、`_`、`\` 要跳脫。
- 不得出現任何公司專屬資訊。

## Review Focus

1. **裝置名稱、使用者名稱、軟體名稱含 HTML／JavaScript**（例如 `<script>`，這些資料來自端點，可能被竄改）→ 頁面必須顯示為文字，不可執行。→ Task 5 `hostile_hostname_is_escaped`。
2. **跨站請求（CSRF）**：已登入的管理員瀏覽惡意網站，被誘導送出「除役」或「建立金鑰」→ 沒有正確 csrf 必須 403。→ Task 4 `post_without_csrf_is_403`、Task 6 `retire_requires_csrf`。
3. **暴力破解密碼** → 第 5 次失敗後即使密碼正確也登入不了，且訊息與密碼錯誤相同。→ Task 3 `lockout_after_five_failures`、Task 4 `locked_account_shows_generic_error`。
4. **搜尋字串含 `%`／`_`** → 當作一般字元，不是萬用字元。→ Task 5 `search_treats_wildcards_literally`。
5. **核准重新註冊後**，Agent 手上的新憑證要能繼續報到，且資料歸到舊裝置；舊憑證要失效。→ Task 2 `approve_moves_new_cert_to_old_device`。

---

## 檔案結構

```
crates/server/
├─ migrations/0002_admin_web.sql
├─ static/htmx.min.js          vendored htmx 2.0.11
├─ static/app.css
├─ templates/
│  ├─ base.html  login.html  dashboard.html  devices.html  device.html
│  ├─ table.html  software.html  tokens.html  audit.html
├─ src/
│  ├─ audit.rs                  audit_log 寫入
│  ├─ devices.rs                approve / reject / retire（領域邏輯）
│  ├─ enroll.rs                 （修改）相符硬體 → pending_approval
│  ├─ config.rs                 （修改）EM_WEB_LISTEN、EM_DISPLAY_UTC_OFFSET
│  ├─ lib.rs                    （修改）AppState.display_offset、serve 開兩個監聽埠
│  ├─ tls.rs                    （修改）web_server_config
│  ├─ main.rs                   （修改）admin-create
│  └─ web/
│     ├─ mod.rs                 web_router、安全標頭、render、時間格式
│     ├─ auth.rs                密碼、工作階段、鎖定、AdminSession、CSRF
│     ├─ login.rs               /login /logout
│     ├─ dashboard.rs           /
│     ├─ devices.rs             /devices /devices/{id} 與分頁、動作
│     ├─ software.rs            /software
│     ├─ tokens.rs              /tokens
│     └─ audit.rs               /audit
└─ tests/
   ├─ common/mod.rs             （修改）同時啟動管理網頁、登入輔助
   └─ web.rs                    管理網頁整合測試
```

---

### Task 0: 分支

- [x] **Step 1**：本計畫文件提交於分支 `feat/plan3-admin-web`（從合併計畫 2 後的 main 分出）。

---

### Task 1: 資料表、稽核記錄、admin-create

**Files:**
- Create: `crates/server/migrations/0002_admin_web.sql`、`crates/server/src/audit.rs`
- Create: `crates/server/src/web/mod.rs`（先只有 `pub mod auth;`）、`crates/server/src/web/auth.rs`（本 task 只放 `hash_password`／`verify_password`／`create_admin`）
- Modify: `crates/server/src/lib.rs`、`crates/server/src/main.rs`、`crates/server/Cargo.toml`、workspace `Cargo.toml`

**Interfaces:**
- Produces:
  - `audit::record(conn: &mut PgConnection, actor: &str, action: &str, target: Option<&str>, detail: serde_json::Value) -> Result<(), sqlx::Error>`
  - `web::auth::MIN_PASSWORD_LEN: usize = 12`
  - `web::auth::hash_password(pw: &str) -> anyhow::Result<String>`、`verify_password(pw: &str, phc: &str) -> bool`
  - `web::auth::create_admin(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<i64>`（長度不足回錯誤；寫 audit `admin_create`，actor `cli`）
  - CLI：`endpoint-server admin-create <username>`（密碼從標準輸入讀一行）

- [ ] **Step 1: 依賴**

workspace `[workspace.dependencies]` 加：

```toml
askama = "0.16"
argon2 = "0.6"
```

`crates/server/Cargo.toml` `[dependencies]` 加 `askama.workspace = true`、`argon2.workspace = true`；`[dev-dependencies]` 的 reqwest 改為 `reqwest = { workspace = true, features = ["cookies", "form"] }`（若 0.13 沒有 `form` feature，`RequestBuilder::form` 已內建則移除並記 ruling）。

- [ ] **Step 2: migration `0002_admin_web.sql`**

```sql
ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'duplicate_suspect', 'pending_approval'));
ALTER TABLE devices ADD COLUMN reenroll_of UUID REFERENCES devices(id) ON DELETE SET NULL;

CREATE TABLE admins (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    disabled_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id   BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE audit_log (
    id     BIGSERIAL PRIMARY KEY,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail JSONB NOT NULL DEFAULT '{}',
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
```

- [ ] **Step 3: 寫失敗測試**（`web/auth.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong password!!", &h));
        assert!(!verify_password("x", "not a phc string"));
    }

    #[sqlx::test(migrations = false)]
    async fn create_admin_enforces_length_and_audits(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        assert!(create_admin(&pool, "root", "short").await.is_err());
        create_admin(&pool, "root", "a-long-enough-password").await.unwrap();
        let (actor, action): (String, String) =
            sqlx::query_as("SELECT actor, action FROM audit_log")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((actor.as_str(), action.as_str()), ("cli", "admin_create"));
        assert!(create_admin(&pool, "root", "a-long-enough-password").await.is_err(), "duplicate");
    }
}
```

- [ ] **Step 4: 確認失敗**

Run: `cargo test -p endpoint-server --lib web::auth`
Expected: 編譯失敗。

- [ ] **Step 5: 實作**

`audit.rs`：

```rust
//! 稽核記錄：誰在什麼時間做了什麼。

use sqlx::PgConnection;

pub async fn record(
    conn: &mut PgConnection,
    actor: &str,
    action: &str,
    target: Option<&str>,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4::jsonb)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(detail.to_string())
        .execute(conn)
        .await?;
    Ok(())
}
```

`web/auth.rs`（本 task 部分）：

```rust
//! 管理員帳號、密碼、工作階段與 CSRF。

use anyhow::Context;
use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use sqlx::PgPool;
use uuid::Uuid;

pub const MIN_PASSWORD_LEN: usize = 12;

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = Uuid::new_v4().into_bytes();
    Ok(Argon2::default()
        .hash_password_with_salt(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

pub async fn create_admin(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<i64> {
    anyhow::ensure!(
        password.chars().count() >= MIN_PASSWORD_LEN,
        "password must be at least {MIN_PASSWORD_LEN} characters"
    );
    let hash = hash_password(password)?;
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO admins (username, password_hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(username)
    .bind(hash)
    .fetch_one(&mut *tx)
    .await
    .context("creating admin (username taken?)")?;
    crate::audit::record(&mut tx, "cli", "admin_create", Some(username), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(id)
}
```

> argon2 0.6 的 trait 路徑（`argon2::password_hash::phc::PasswordHash`、`PasswordHasher::hash_password_with_salt(&[u8], &[u8])`）以 context7 `/rustcrypto/password-hashes` 為準；若不同請調整並記 ruling。

`web/mod.rs`：

```rust
//! 管理網頁。

pub mod auth;
```

`lib.rs` 加 `pub mod audit; pub mod web;`。

`main.rs` 的 match 加一個分支（USAGE 同步加一行 `endpoint-server admin-create <username>   (password from stdin)`）：

```rust
        Some("admin-create") if args.len() >= 2 => {
            let cfg = Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            endpoint_server::db::migrate(&pool).await?;
            eprintln!("輸入密碼（至少 {} 字元）：", endpoint_server::web::auth::MIN_PASSWORD_LEN);
            let mut pw = String::new();
            std::io::stdin().read_line(&mut pw)?;
            let id = endpoint_server::web::auth::create_admin(&pool, &args[1], pw.trim_end_matches(['\r', '\n'])).await?;
            println!("admin id {id} created");
            Ok(())
        }
```

- [ ] **Step 6: 測試**

Run: `cargo test -p endpoint-server --lib`
Expected: 全部 PASS（含新增 2 個）。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(server): 管理員帳號、稽核記錄資料表與 admin-create"
```

---

### Task 2: 重新註冊需核准、核准／拒絕／除役

**Files:**
- Create: `crates/server/src/devices.rs`；Modify: `lib.rs`（`pub mod devices;`）
- Modify: `crates/server/src/enroll.rs`
- Modify: `crates/server/tests/enroll.rs`

**Interfaces:**
- Consumes: `audit::record`
- Produces:
  - `enroll::match_device(candidates: &[(Uuid, Option<String>)], bios_serial: Option<&str>) -> DeviceMatch`（移除 recently_seen 欄位）
  - `DeviceMatch::{SameHardware(Uuid), NewDuplicateSuspect, New}`（`Reuse` 更名為 `SameHardware`）
  - `devices::approve(pool: &PgPool, pending_id: Uuid, actor: &str) -> anyhow::Result<Uuid>`（回傳舊裝置 id）
  - `devices::reject(pool: &PgPool, pending_id: Uuid, actor: &str) -> anyhow::Result<()>`
  - `devices::retire(pool: &PgPool, id: Uuid, actor: &str) -> anyhow::Result<()>`
  - `devices::approve_all(pool: &PgPool, actor: &str) -> anyhow::Result<usize>`

- [ ] **Step 1: 改寫 enroll 單元測試**（`enroll.rs` 測試模組）

把 `match_device` 相關測試改為兩欄位 tuple，刪除 `recently_seen_device_is_never_taken_over`，`same_serial_reuses` 改名並改期望：

```rust
    #[test]
    fn same_serial_is_same_hardware() {
        let id = Uuid::new_v4();
        assert_eq!(
            match_device(&[(id, Some("SN1".into()))], Some("SN1")),
            DeviceMatch::SameHardware(id)
        );
    }
```

其餘 `different_serial_is_duplicate_suspect`、`missing_serial_never_reuses`、`no_candidates_is_new` 同樣改為兩欄位 tuple。

- [ ] **Step 2: 改寫整合測試**（`tests/enroll.rs`）

把 `reenroll_same_hardware_reuses_device_and_revokes_old_cert` 與 `active_device_is_not_taken_over_by_same_hardware_ids` 換成：

```rust
async fn status_of(s: &TestServer, id: uuid::Uuid) -> (String, Option<uuid::Uuid>) {
    sqlx::query_as("SELECT status, reenroll_of FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn checkin_status(s: &TestServer, a: &common::TestAgent) -> u16 {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&checkin_body())
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[sqlx::test(migrations = false)]
async fn same_hardware_reenroll_waits_for_approval(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("uuid-a"), Some("SN-A")).await;
    assert_ne!(old.device_id, new.device_id);
    assert_eq!(status_of(&s, new.device_id).await, ("pending_approval".into(), Some(old.device_id)));
    assert_eq!(checkin_status(&s, &old).await, 200, "舊裝置不受影響");
    assert_eq!(checkin_status(&s, &new).await, 200, "待核准裝置可報到");
}

#[sqlx::test(migrations = false)]
async fn approve_moves_new_cert_to_old_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let merged = endpoint_server::devices::approve(&s.pool, new.device_id, "tester").await.unwrap();
    assert_eq!(merged, old.device_id);

    assert_eq!(checkin_status(&s, &old).await, 401, "舊憑證失效");
    assert_eq!(checkin_status(&s, &new).await, 200, "新憑證可用");
    let owner: uuid::Uuid = sqlx::query_scalar("SELECT device_id FROM device_certs WHERE revoked_at IS NULL")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(owner, old.device_id, "資料歸到舊裝置");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "待核准記錄已刪除");
    assert_eq!(status_of(&s, old.device_id).await.0, "active");
}

#[sqlx::test(migrations = false)]
async fn reject_revokes_pending_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    endpoint_server::devices::reject(&s.pool, new.device_id, "tester").await.unwrap();
    assert_eq!(checkin_status(&s, &new).await, 401);
    assert_eq!(checkin_status(&s, &old).await, 200);
    assert_eq!(status_of(&s, new.device_id).await.0, "retired");
}

#[sqlx::test(migrations = false)]
async fn retire_revokes_all_certs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    endpoint_server::devices::retire(&s.pool, a.device_id, "tester").await.unwrap();
    assert_eq!(checkin_status(&s, &a).await, 401);
    let action: String = sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(action, "device_retire");
}

#[sqlx::test(migrations = false)]
async fn approve_rejects_non_pending_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    assert!(endpoint_server::devices::approve(&s.pool, a.device_id, "tester").await.is_err());
}
```

- [ ] **Step 3: 確認失敗**

Run: `cargo test -p endpoint-server --test enroll; cargo test -p endpoint-server --lib enroll`
Expected: 編譯失敗（`devices` 模組、`SameHardware` 不存在）。

- [ ] **Step 4: 實作 enroll 修改**

`match_device` 改為：

```rust
/// 候選裝置：(id, bios_serial)。
pub fn match_device(
    candidates: &[(Uuid, Option<String>)],
    bios_serial: Option<&str>,
) -> DeviceMatch {
    if let Some(serial) = normalize_serial(bios_serial)
        && let Some((id, _)) = candidates
            .iter()
            .find(|(_, s)| s.as_deref() == Some(serial))
    {
        return DeviceMatch::SameHardware(*id);
    }
    if candidates.is_empty() {
        DeviceMatch::New
    } else {
        DeviceMatch::NewDuplicateSuspect
    }
}
```

candidates 查詢改回 `SELECT id, bios_serial FROM devices WHERE smbios_uuid = $1 AND status IN ('active', 'duplicate_suspect') FOR UPDATE`，型別 `Vec<(Uuid, Option<String>)>`。`enroll` 內的 match 改為：一律新建裝置；`SameHardware(old)` → status `pending_approval`、`reenroll_of = old`；`NewDuplicateSuspect` → `duplicate_suspect`；`New` → `active`：

```rust
    let (status, reenroll_of) = match match_device(&candidates, serial) {
        DeviceMatch::SameHardware(old) => ("pending_approval", Some(old)),
        DeviceMatch::NewDuplicateSuspect => ("duplicate_suspect", None),
        DeviceMatch::New => ("active", None),
    };
    let device_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO devices (id, hostname, smbios_uuid, bios_serial, status, enroll_token_id, reenroll_of) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(device_id)
    .bind(&req.hostname)
    .bind(&smbios)
    .bind(serial)
    .bind(status)
    .bind(token_id)
    .bind(reenroll_of)
    .execute(&mut *tx)
    .await?;
```

- [ ] **Step 5: 實作 `devices.rs`**

```rust
//! 裝置生命週期：核准／拒絕重新註冊、除役。每個動作都寫入 audit_log。

use anyhow::Context;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::audit;

async fn revoke_certs(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE device_certs SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

async fn approve_in(conn: &mut PgConnection, pending: Uuid, actor: &str) -> anyhow::Result<Uuid> {
    let (old, hostname): (Option<Uuid>, String) = sqlx::query_as(
        "SELECT reenroll_of, hostname FROM devices WHERE id = $1 AND status = 'pending_approval' FOR UPDATE",
    )
    .bind(pending)
    .fetch_optional(&mut *conn)
    .await?
    .context("device is not pending approval")?;
    let old = old.context("pending device has no original device")?;

    revoke_certs(conn, old).await?;
    sqlx::query("UPDATE device_certs SET device_id = $1 WHERE device_id = $2")
        .bind(old)
        .bind(pending)
        .execute(&mut *conn)
        .await?;
    // 清空舊裝置的區段 hash：Agent 下次報到時伺服器會要求重新上傳全部區段
    sqlx::query("DELETE FROM inventory_sections WHERE device_id = $1")
        .bind(old)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE devices SET status = 'active', hostname = $2 WHERE id = $1")
        .bind(old)
        .bind(&hostname)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM devices WHERE id = $1")
        .bind(pending)
        .execute(&mut *conn)
        .await?;
    audit::record(
        conn,
        actor,
        "device_approve",
        Some(&old.to_string()),
        serde_json::json!({ "pending_id": pending, "hostname": hostname }),
    )
    .await?;
    Ok(old)
}

pub async fn approve(pool: &PgPool, pending: Uuid, actor: &str) -> anyhow::Result<Uuid> {
    let mut tx = pool.begin().await?;
    let old = approve_in(&mut tx, pending, actor).await?;
    tx.commit().await?;
    Ok(old)
}

pub async fn approve_all(pool: &PgPool, actor: &str) -> anyhow::Result<usize> {
    let pending: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM devices WHERE status = 'pending_approval' ORDER BY enrolled_at")
            .fetch_all(pool)
            .await?;
    let mut tx = pool.begin().await?;
    for id in &pending {
        approve_in(&mut tx, *id, actor).await?;
    }
    tx.commit().await?;
    Ok(pending.len())
}

pub async fn reject(pool: &PgPool, pending: Uuid, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE devices SET status = 'retired' WHERE id = $1 AND status = 'pending_approval'",
    )
    .bind(pending)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(updated == 1, "device is not pending approval");
    revoke_certs(&mut tx, pending).await?;
    audit::record(&mut tx, actor, "device_reject", Some(&pending.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn retire(pool: &PgPool, id: Uuid, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let updated = sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1 AND status <> 'retired'")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    anyhow::ensure!(updated == 1, "device not found or already retired");
    revoke_certs(&mut tx, id).await?;
    audit::record(&mut tx, actor, "device_retire", Some(&id.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}
```

- [ ] **Step 6: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(server): 重新註冊需管理員核准，新增核准／拒絕／除役"
```

---

### Task 3: 工作階段、登入鎖定、CSRF

**Files:**
- Modify: `crates/server/src/web/auth.rs`

**Interfaces:**
- Produces:
  - `web::auth::SESSION_COOKIE = "em_session"`、`SESSION_HOURS: i64 = 8`、`MAX_FAILED_LOGINS: i32 = 5`、`LOCK_MINUTES: i64 = 15`
  - `web::auth::LoginOutcome { Ok { session_token: String, admin_id: i64 }, Failed }`
  - `web::auth::login(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<LoginOutcome>`（失敗與鎖定都回 `Failed`；寫 audit `login` / `login_failed`）
  - `web::auth::Session { admin_id: i64, username: String, csrf: String, token_hash: String }`
  - `web::auth::lookup_session(pool: &PgPool, token: &str) -> Result<Option<Session>, sqlx::Error>`
  - `web::auth::logout(pool: &PgPool, s: &Session) -> Result<(), sqlx::Error>`
  - `web::auth::csrf_ok(expected: &str, got: &str) -> bool`（constant-time）
  - `web::auth::session_cookie(token: &str) -> String`、`clear_cookie() -> &'static str`

- [ ] **Step 1: 寫失敗測試**（附加到 `web/auth.rs` 測試模組）

```rust
    async fn setup(pool: &PgPool) {
        crate::db::migrate(pool).await.unwrap();
        create_admin(pool, "alice", "alice-long-password").await.unwrap();
    }

    #[sqlx::test(migrations = false)]
    async fn login_creates_session(pool: PgPool) {
        setup(&pool).await;
        let LoginOutcome::Ok { session_token, .. } =
            login(&pool, "alice", "alice-long-password").await.unwrap()
        else {
            panic!("login failed")
        };
        let s = lookup_session(&pool, &session_token).await.unwrap().unwrap();
        assert_eq!(s.username, "alice");
        assert_eq!(s.csrf.len(), 32);
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stored, session_token, "只存 hash");
        logout(&pool, &s).await.unwrap();
        assert!(lookup_session(&pool, &session_token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn lockout_after_five_failures(pool: PgPool) {
        setup(&pool).await;
        for _ in 0..MAX_FAILED_LOGINS {
            assert!(matches!(login(&pool, "alice", "nope-nope-nope").await.unwrap(), LoginOutcome::Failed));
        }
        assert!(
            matches!(login(&pool, "alice", "alice-long-password").await.unwrap(), LoginOutcome::Failed),
            "鎖定期間正確密碼也不行"
        );
        sqlx::query("UPDATE admins SET locked_until = now() - interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            login(&pool, "alice", "alice-long-password").await.unwrap(),
            LoginOutcome::Ok { .. }
        ));
    }

    #[sqlx::test(migrations = false)]
    async fn unknown_user_and_expired_session(pool: PgPool) {
        setup(&pool).await;
        assert!(matches!(login(&pool, "mallory", "whatever-password").await.unwrap(), LoginOutcome::Failed));
        let LoginOutcome::Ok { session_token, .. } =
            login(&pool, "alice", "alice-long-password").await.unwrap()
        else {
            panic!()
        };
        sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(lookup_session(&pool, &session_token).await.unwrap().is_none());
    }

    #[test]
    fn csrf_compare() {
        assert!(csrf_ok("abc", "abc"));
        assert!(!csrf_ok("abc", "abd"));
        assert!(!csrf_ok("abc", ""));
    }
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --lib web::auth`
Expected: 編譯失敗。

- [ ] **Step 3: 實作**（附加到 `web/auth.rs` 的非測試部分；`use` 補上 `chrono`、`sha2`）

```rust
pub const SESSION_COOKIE: &str = "em_session";
pub const SESSION_HOURS: i64 = 8;
pub const MAX_FAILED_LOGINS: i32 = 5;
pub const LOCK_MINUTES: i64 = 15;

/// 帳號不存在時也做一次雜湊驗證，避免以回應時間判斷帳號是否存在。
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$4o9ZDB0Jc3m5cMHKjBVeEZNu9P0eZwUjWS5e6v4Lr0o";

pub enum LoginOutcome {
    Ok { session_token: String, admin_id: i64 },
    Failed,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub admin_id: i64,
    pub username: String,
    pub csrf: String,
    pub token_hash: String,
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

fn random_hex64() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub async fn login(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<LoginOutcome> {
    let row: Option<(i64, String, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
        "SELECT id, password_hash, locked_until FROM admins WHERE username = $1 AND disabled_at IS NULL",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    let Some((admin_id, hash, locked_until)) = row else {
        verify_password(password, DUMMY_HASH);
        let mut c = pool.acquire().await?;
        crate::audit::record(&mut c, username, "login_failed", None, serde_json::json!({"reason": "unknown"})).await?;
        return Ok(LoginOutcome::Failed);
    };
    let locked = locked_until.is_some_and(|t| t > chrono::Utc::now());
    let ok = verify_password(password, &hash) && !locked;

    let mut tx = pool.begin().await?;
    if !ok {
        sqlx::query(
            "UPDATE admins SET \
               failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END, \
               locked_until = CASE WHEN failed_logins + 1 >= $2 \
                                   THEN now() + make_interval(mins => $3) ELSE locked_until END \
             WHERE id = $1",
        )
        .bind(admin_id)
        .bind(MAX_FAILED_LOGINS)
        .bind(LOCK_MINUTES as i32)
        .execute(&mut *tx)
        .await?;
        let reason = if locked { "locked" } else { "password" };
        crate::audit::record(&mut tx, username, "login_failed", None, serde_json::json!({ "reason": reason })).await?;
        tx.commit().await?;
        return Ok(LoginOutcome::Failed);
    }

    sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    let token = random_hex64();
    sqlx::query(
        "INSERT INTO sessions (token_hash, admin_id, csrf_token, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(hours => $4))",
    )
    .bind(sha256_hex(&token))
    .bind(admin_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(SESSION_HOURS as i32)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()").execute(&mut *tx).await?;
    crate::audit::record(&mut tx, username, "login", None, serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(LoginOutcome::Ok { session_token: token, admin_id })
}

pub async fn lookup_session(pool: &PgPool, token: &str) -> Result<Option<Session>, sqlx::Error> {
    let hash = sha256_hex(token);
    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT a.id, a.username, s.csrf_token FROM sessions s JOIN admins a ON a.id = s.admin_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() AND a.disabled_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(admin_id, username, csrf)| Session { admin_id, username, csrf, token_hash: hash }))
}

pub async fn logout(pool: &PgPool, s: &Session) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&s.token_hash)
        .execute(&mut *tx)
        .await?;
    crate::audit::record(&mut tx, &s.username, "logout", None, serde_json::json!({})).await?;
    tx.commit().await
}

pub fn csrf_ok(expected: &str, got: &str) -> bool {
    expected.len() == got.len()
        && expected.bytes().zip(got.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

pub fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        SESSION_HOURS * 3600
    )
}

pub fn clear_cookie() -> &'static str {
    "em_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
}
```

> `DUMMY_HASH` 需是可被 `PasswordHash::new` 解析的有效 PHC 字串；實作時用 `hash_password("dummy")` 產生一次後貼上，並確認 `verify_password` 對它真的會執行 argon2 運算。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server --lib web::auth`
Expected: 6 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(server): 管理員工作階段、登入鎖定與 CSRF"
```

---

### Task 4: 網頁骨架：監聽埠、安全標頭、版面、登入／登出

**Files:**
- Create: `crates/server/static/htmx.min.js`（下載）、`crates/server/static/app.css`
- Create: `crates/server/templates/base.html`、`login.html`、`dashboard.html`（本 task 先放空殼）
- Modify: `crates/server/src/web/mod.rs`、`crates/server/src/web/auth.rs`（`AdminSession` extractor）
- Create: `crates/server/src/web/login.rs`、`crates/server/src/web/dashboard.rs`
- Modify: `crates/server/src/tls.rs`（`web_server_config`）、`crates/server/src/lib.rs`（`AppState.display_offset`）
- Modify: `crates/server/tests/common/mod.rs`；Create: `crates/server/tests/web.rs`

**Interfaces:**
- Produces:
  - `tls::web_server_config(ca_dir: &Path) -> anyhow::Result<Arc<ServerConfig>>`（無用戶端憑證）
  - `AppState.display_offset: chrono::FixedOffset`（`AppState::new` 預設 +8；`AppState::with_display_offset(self, hours: i32) -> Self`）
  - `web::web_router(state: AppState) -> Router`
  - `web::render<T: askama::Template>(t: &T) -> Response`、`web::fmt_time(state: &AppState, t: Option<DateTime<Utc>>) -> String`、`web::escape_like(q: &str) -> String`
  - `web::auth::AdminSession(pub Session)`：axum extractor；未登入 → 303 `/login`
  - `web::auth::check_csrf(s: &Session, got: &str) -> Result<(), Response>`（不符 → 403）
  - 測試：`TestServer.web_addr`、`web_url(path)`、`web_client() -> reqwest::Client`（cookie store）、`admin_client() -> reqwest::Client`（已建立 `admin`／`admin-long-password` 並登入）、`common::csrf_from(html: &str) -> String`

- [ ] **Step 1: 下載 htmx 與建立 CSS**

```bash
mkdir -p crates/server/static crates/server/templates
curl -fsSL https://cdn.jsdelivr.net/npm/htmx.org@2.0.11/dist/htmx.min.js -o crates/server/static/htmx.min.js
head -c 80 crates/server/static/htmx.min.js
```

`crates/server/static/app.css`：

```css
:root { --fg: #1f2328; --muted: #656d76; --line: #d0d7de; --bg: #fff; --accent: #0969da; --bad: #cf222e; --ok: #1a7f37; --warn: #9a6700; }
* { box-sizing: border-box; }
body { margin: 0; font: 14px/1.5 system-ui, "Microsoft JhengHei", sans-serif; color: var(--fg); background: var(--bg); }
header { display: flex; gap: 1.5rem; align-items: center; padding: .6rem 1rem; border-bottom: 1px solid var(--line); flex-wrap: wrap; }
header strong { margin-right: 1rem; }
header nav { display: flex; gap: 1rem; flex-wrap: wrap; flex: 1; }
header form { margin: 0; }
main { padding: 1rem; max-width: 1400px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }
th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; }
.cards { display: flex; gap: 1rem; flex-wrap: wrap; }
.card { border: 1px solid var(--line); border-radius: 6px; padding: .8rem 1rem; min-width: 10rem; }
.card b { display: block; font-size: 1.6rem; }
.badge { display: inline-block; padding: 0 .4rem; border-radius: 4px; font-size: 12px; border: 1px solid currentColor; }
.online { color: var(--ok); } .offline { color: var(--muted); } .pending_approval, .duplicate_suspect { color: var(--warn); } .retired { color: var(--bad); }
.error { color: var(--bad); }
.notice { border: 1px solid var(--warn); padding: .6rem 1rem; border-radius: 6px; word-break: break-all; }
form.inline { display: inline; }
input, select, button { font: inherit; padding: .25rem .5rem; }
button { cursor: pointer; }
button.danger { color: var(--bad); }
.tabs { display: flex; gap: .5rem; margin-top: 1rem; }
.pager { display: flex; gap: 1rem; }
.muted { color: var(--muted); }
```

- [ ] **Step 2: 樣板**

`templates/base.html`：

```html
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="htmx-config" content='{"includeIndicatorStyles": false}'>
<title>{% block title %}Endpoint Manager{% endblock %}</title>
<link rel="stylesheet" href="/static/app.css">
<script src="/static/htmx.min.js" defer></script>
</head>
<body>
{% if let Some(user) = nav_user %}
<header>
  <strong>Endpoint Manager</strong>
  <nav>
    <a href="/">儀表板</a>
    <a href="/devices">裝置</a>
    <a href="/software">軟體搜尋</a>
    <a href="/tokens">註冊金鑰</a>
    <a href="/audit">稽核記錄</a>
  </nav>
  <span class="muted">{{ user }}</span>
  <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button>登出</button></form>
</header>
{% endif %}
<main>
{% block content %}{% endblock %}
</main>
</body>
</html>
```

`templates/login.html`：

```html
{% extends "base.html" %}
{% block title %}登入 - Endpoint Manager{% endblock %}
{% block content %}
<h1>Endpoint Manager</h1>
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/login">
  <p><label>帳號<br><input name="username" autocomplete="username" required autofocus></label></p>
  <p><label>密碼<br><input name="password" type="password" autocomplete="current-password" required></label></p>
  <p><button>登入</button></p>
</form>
{% endblock %}
```

`templates/dashboard.html`（Task 5 補內容，本 task 先只有標題）：

```html
{% extends "base.html" %}
{% block content %}
<h1>儀表板</h1>
{% endblock %}
```

- [ ] **Step 3: 寫失敗測試**

`tests/common/mod.rs` 修改：

1. `TestServer` 加欄位 `pub web_addr: SocketAddr`；`start_with` 裡在 agent 監聽之後加：

```rust
        let web_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let web_addr = web_listener.local_addr().unwrap();
        tokio::spawn(tls::serve_mtls(
            web_listener,
            tls::web_server_config(dir.path()).unwrap(),
            endpoint_server::web::web_router(state.clone()),
            limits,
        ));
```

2. 新增方法與函式：

```rust
    pub fn web_url(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.web_addr.port(), path)
    }

    pub fn web_client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(self.root_pem.as_bytes()).unwrap()])
            .resolve("localhost", self.web_addr)
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    pub async fn admin_client(&self) -> reqwest::Client {
        let _ = endpoint_server::web::auth::create_admin(&self.pool, "admin", "admin-long-password").await;
        let c = self.web_client();
        let r = c
            .post(self.web_url("/login"))
            .form(&[("username", "admin"), ("password", "admin-long-password")])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303, "login should redirect");
        c
    }

    pub async fn page(&self, c: &reqwest::Client, path: &str) -> (u16, String) {
        let r = c.get(self.web_url(path)).send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }
```

```rust
/// 從頁面 HTML 取出 csrf 隱藏欄位的值。
pub fn csrf_from(html: &str) -> String {
    let marker = r#"name="csrf" value=""#;
    let start = html.find(marker).expect("csrf field") + marker.len();
    html[start..].split('"').next().unwrap().to_string()
}
```

`tests/web.rs`：

```rust
mod common;

use common::{TestServer, csrf_from};
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn pages_require_login(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    for path in ["/", "/devices", "/software", "/tokens", "/audit"] {
        let r = c.get(s.web_url(path)).send().await.unwrap();
        assert_eq!(r.status(), 303, "{path}");
        assert_eq!(r.headers()["location"], "/login", "{path}");
    }
    let (status, html) = s.page(&c, "/login").await;
    assert_eq!(status, 200);
    assert!(html.contains("登入"));
}

#[sqlx::test(migrations = false)]
async fn login_logout_roundtrip_and_security_headers(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let r = c.get(s.web_url("/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    assert!(h["content-security-policy"].to_str().unwrap().contains("default-src 'self'"));
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["cache-control"], "no-store");
    let html = r.text().await.unwrap();
    assert!(html.contains("儀表板"));

    let csrf = csrf_from(&html);
    let r = c.post(s.web_url("/logout")).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let r = c.get(s.web_url("/")).send().await.unwrap();
    assert_eq!(r.status(), 303, "logged out");
}

#[sqlx::test(migrations = false)]
async fn wrong_password_shows_generic_error(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.admin_client().await;
    let c = s.web_client();
    let r = c
        .post(s.web_url("/login"))
        .form(&[("username", "admin"), ("password", "wrong-password-xx")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.text().await.unwrap().contains("帳號或密碼錯誤"));
}

#[sqlx::test(migrations = false)]
async fn locked_account_shows_generic_error(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.admin_client().await;
    sqlx::query("UPDATE admins SET locked_until = now() + interval '10 minutes'")
        .execute(&s.pool)
        .await
        .unwrap();
    let r = s
        .web_client()
        .post(s.web_url("/login"))
        .form(&[("username", "admin"), ("password", "admin-long-password")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.text().await.unwrap().contains("帳號或密碼錯誤"));
}

#[sqlx::test(migrations = false)]
async fn post_without_csrf_is_403(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let r = c.post(s.web_url("/logout")).form(&[("csrf", "forged")]).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = c.get(s.web_url("/")).send().await.unwrap();
    assert_eq!(r.status(), 200, "session still valid");
}

#[sqlx::test(migrations = false)]
async fn static_assets_served(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    let r = c.get(s.web_url("/static/htmx.min.js")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().contains("javascript"));
    let r = c.get(s.web_url("/static/app.css")).send().await.unwrap();
    assert!(r.headers()["content-type"].to_str().unwrap().contains("css"));
}
```

- [ ] **Step 4: 確認失敗**

Run: `cargo test -p endpoint-server --test web`
Expected: 編譯失敗（`web_router`、`web_server_config` 不存在）。

- [ ] **Step 5: 實作 `tls::web_server_config`**

```rust
/// 管理網頁用：只提供伺服器憑證，不要求用戶端憑證。
pub fn web_server_config(ca_dir: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = CertificateDer::pem_file_iter(ca_dir.join("server.pem"))?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(ca_dir.join("server.key"))?;
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
```

- [ ] **Step 6: `AppState.display_offset`**（`lib.rs`）

`AppState` 加 `pub display_offset: chrono::FixedOffset`；`AppState::new` 設為 `chrono::FixedOffset::east_opt(8 * 3600).expect("valid")`；加：

```rust
    pub fn with_display_offset(mut self, hours: i32) -> Self {
        if let Some(o) = chrono::FixedOffset::east_opt(hours * 3600) {
            self.display_offset = o;
        }
        self
    }
```

- [ ] **Step 7: `AdminSession` 與 `check_csrf`**（`web/auth.rs`）

```rust
use axum::extract::FromRequestParts;
use axum::http::{StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Redirect, Response};

fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('=').map(str::to_string))
}

/// 已登入的管理員；未登入時轉到登入頁。
pub struct AdminSession(pub Session);

impl FromRequestParts<crate::AppState> for AdminSession {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &crate::AppState) -> Result<Self, Response> {
        let to_login = || Redirect::to("/login").into_response();
        let token = cookie_value(parts, SESSION_COOKIE).ok_or_else(to_login)?;
        match lookup_session(&state.pool, &token).await {
            Ok(Some(s)) => Ok(AdminSession(s)),
            Ok(None) => Err(to_login()),
            Err(e) => Err(crate::error::AppError::from(e).into_response()),
        }
    }
}

pub fn check_csrf(s: &Session, got: &str) -> Result<(), Response> {
    if csrf_ok(&s.csrf, got) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "CSRF token mismatch").into_response())
    }
}
```

> `Redirect::to` 在 axum 0.8 回 303 See Other。

- [ ] **Step 8: `web/mod.rs`**

```rust
//! 管理網頁：路由、安全標頭、樣板輸出與共用格式化。

pub mod auth;
pub mod dashboard;
pub mod login;

use askama::Template;
use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};

use crate::AppState;

const CSP: &str = "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'";

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    h.entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
    res
}

pub fn render<T: Template>(t: &T) -> Response {
    match t.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "template render failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub fn fmt_time(state: &AppState, t: Option<DateTime<Utc>>) -> String {
    t.map(|t| t.with_timezone(&state.display_offset).format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "—".into())
}

/// LIKE 搜尋時把使用者輸入的 % _ \ 當一般字元。
pub fn escape_like(q: &str) -> String {
    let mut out = String::with_capacity(q.len() + 2);
    out.push('%');
    for c in q.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('%');
    out
}

fn asset(body: &'static str, content_type: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        body,
    )
        .into_response()
}

pub fn web_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::page))
        .route("/login", get(login::form).post(login::submit))
        .route("/logout", post(login::logout))
        .route(
            "/static/htmx.min.js",
            get(|| async { asset(include_str!("../../static/htmx.min.js"), "text/javascript; charset=utf-8") }),
        )
        .route(
            "/static/app.css",
            get(|| async { asset(include_str!("../../static/app.css"), "text/css; charset=utf-8") }),
        )
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_like_escapes_wildcards() {
        assert_eq!(escape_like("50%_off\\"), "%50\\%\\_off\\\\%");
    }
}
```

- [ ] **Step 9: `web/login.rs`**

```rust
//! 登入與登出。登入表單沒有工作階段可綁 CSRF；cookie 為 SameSite=Strict，
//! 跨站送出的登入只會讓攻擊者登入自己的帳號，影響有限。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{self, AdminSession, LoginOutcome, check_csrf};
use super::render;
use crate::AppState;
use crate::error::AppError;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    nav_user: Option<String>,
    csrf: String,
    error: Option<&'static str>,
}

pub async fn form() -> Response {
    render(&LoginPage { nav_user: None, csrf: String::new(), error: None })
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn submit(State(st): State<AppState>, Form(f): Form<LoginForm>) -> Result<Response, AppError> {
    match auth::login(&st.pool, f.username.trim(), &f.password).await? {
        LoginOutcome::Ok { session_token, .. } => Ok((
            [(header::SET_COOKIE, auth::session_cookie(&session_token))],
            Redirect::to("/"),
        )
            .into_response()),
        LoginOutcome::Failed => {
            let page = LoginPage { nav_user: None, csrf: String::new(), error: Some("帳號或密碼錯誤") };
            Ok((StatusCode::UNAUTHORIZED, render(&page)).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    pub csrf: String,
}

pub async fn logout(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    auth::logout(&st.pool, &s)
        .await
        .map_err(|e| AppError::from(e).into_response())?;
    Ok(([(header::SET_COOKIE, auth::clear_cookie())], Redirect::to("/login")).into_response())
}
```

`web/dashboard.rs`（Task 5 補完整內容，本 task 先回傳空儀表板）：

```rust
//! 儀表板。

use askama::Template;
use axum::response::Response;

use super::auth::AdminSession;
use super::render;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav_user: Option<String>,
    csrf: String,
}

pub async fn page(AdminSession(s): AdminSession) -> Response {
    render(&DashboardPage { nav_user: Some(s.username), csrf: s.csrf })
}
```

- [ ] **Step 10: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS（web 6 個）。

- [ ] **Step 11: Commit**

```bash
git add -A && git commit -m "feat(server): 管理網頁骨架、安全標頭、登入登出"
```

---

### Task 5: 儀表板與裝置列表

**Files:**
- Modify: `templates/dashboard.html`、`src/web/dashboard.rs`
- Create: `templates/devices.html`、`src/web/devices.rs`；Modify: `src/web/mod.rs`（`pub mod devices;`，路由 `/devices`、`/devices/approve-all`、`/devices/{id}/approve`、`/devices/{id}/reject`）
- Modify: `tests/web.rs`

**Interfaces:**
- Consumes: `devices::{approve, reject, approve_all}`、`db::load_settings`、`web::{fmt_time, escape_like}`
- Produces:
  - `GET /devices?q=&status=&software=&version=&page=`（`status` 空字串 = 除已除役外全部；`all` = 包含已除役）
  - `POST /devices/{id}/approve`、`POST /devices/{id}/reject`、`POST /devices/approve-all`（表單欄位 `csrf`；完成後 303 回 `/`）
  - `web::devices::online_cutoff(st: &AppState) -> Result<DateTime<Utc>, sqlx::Error>`（now − 3 × checkin interval）

- [ ] **Step 1: 寫失敗測試**（附加到 `tests/web.rs`）

```rust
#[sqlx::test(migrations = false)]
async fn dashboard_counts_and_device_list(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;

    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("裝置總數"));
    let (status, html) = s.page(&c, "/devices").await;
    assert_eq!(status, 200);
    assert!(html.contains("PC-001"));
    assert!(html.contains(&format!("/devices/{}", a.device_id)));
}

#[sqlx::test(migrations = false)]
async fn hostile_hostname_is_escaped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE devices SET hostname = '<script>alert(1)</script>', logged_on_user = '\"><img src=x onerror=alert(1)>' WHERE id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices").await;
    assert!(!html.contains("<script>alert(1)"), "hostname must be escaped");
    assert!(!html.contains("<img src=x"), "user must be escaped");
    assert!(html.contains("&lt;script&gt;"));
}

#[sqlx::test(migrations = false)]
async fn search_treats_wildcards_literally(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    for (id, name) in [(a.device_id, "SALES_01"), (b.device_id, "SALESX01")] {
        sqlx::query("UPDATE devices SET hostname = $2 WHERE id = $1")
            .bind(id)
            .bind(name)
            .execute(&s.pool)
            .await
            .unwrap();
    }
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices?q=SALES_").await;
    assert!(html.contains("SALES_01"));
    assert!(!html.contains("SALESX01"), "_ must not act as wildcard");
}

#[sqlx::test(migrations = false)]
async fn pending_device_approved_from_dashboard(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let _new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("待核准"));
    let csrf = csrf_from(&html);

    let r = c
        .post(s.web_url("/devices/approve-all"))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE status = 'pending_approval'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let actor: String = sqlx::query_scalar("SELECT actor FROM audit_log WHERE action = 'device_approve'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(actor, "admin");
    let _ = old;
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web`
Expected: 新測試 FAIL（找不到「裝置總數」、`/devices` 404）。

- [ ] **Step 3: `templates/dashboard.html`**

```html
{% extends "base.html" %}
{% block content %}
<h1>儀表板</h1>
<div class="cards">
  <div class="card">裝置總數<b>{{ total }}</b></div>
  <div class="card online">在線<b>{{ online }}</b></div>
  <div class="card offline">離線<b>{{ total - online }}</b></div>
  <div class="card duplicate_suspect">疑似重複<b>{{ duplicate }}</b></div>
  <div class="card pending_approval">待核准<b>{{ pending.len() }}</b></div>
</div>

{% if !pending.is_empty() %}
<h2>待核准的重新註冊</h2>
<p class="muted">硬體識別與既有裝置相同（通常是重灌）。核准後新憑證會接手原裝置的記錄；若不是預期的重灌，請拒絕。</p>
<form method="post" action="/devices/approve-all">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <button>全部核准（{{ pending.len() }}）</button>
</form>
<table>
  <tr><th>新註冊</th><th>原裝置</th><th>註冊時間</th><th></th></tr>
  {% for p in pending %}
  <tr>
    <td><a href="/devices/{{ p.id }}">{{ p.hostname }}</a></td>
    <td><a href="/devices/{{ p.old_id }}">{{ p.old_hostname }}</a></td>
    <td>{{ p.enrolled_at }}</td>
    <td>
      <form class="inline" method="post" action="/devices/{{ p.id }}/approve"><input type="hidden" name="csrf" value="{{ csrf }}"><button>核准</button></form>
      <form class="inline" method="post" action="/devices/{{ p.id }}/reject"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="danger">拒絕</button></form>
    </td>
  </tr>
  {% endfor %}
</table>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: `web/dashboard.rs`**

```rust
//! 儀表板：數量統計與待核准清單。

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::auth::AdminSession;
use super::devices::online_cutoff;
use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;

pub struct PendingRow {
    pub id: Uuid,
    pub hostname: String,
    pub old_id: Uuid,
    pub old_hostname: String,
    pub enrolled_at: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav_user: Option<String>,
    csrf: String,
    total: i64,
    online: i64,
    duplicate: i64,
    pending: Vec<PendingRow>,
}

pub async fn page(State(st): State<AppState>, AdminSession(s): AdminSession) -> Response {
    match build(&st).await {
        Ok((total, online, duplicate, pending)) => render(&DashboardPage {
            nav_user: Some(s.username),
            csrf: s.csrf,
            total,
            online,
            duplicate,
            pending,
        }),
        Err(e) => e.into_response(),
    }
}

async fn build(st: &AppState) -> Result<(i64, i64, i64, Vec<PendingRow>), AppError> {
    let cutoff = online_cutoff(st).await?;
    let (total, online, duplicate): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status <> 'retired'), \
                count(*) FILTER (WHERE status <> 'retired' AND last_seen_at > $1), \
                count(*) FILTER (WHERE status = 'duplicate_suspect') \
         FROM devices",
    )
    .bind(cutoff)
    .fetch_one(&st.pool)
    .await?;
    let rows: Vec<(Uuid, String, Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT d.id, d.hostname, o.id, o.hostname, d.enrolled_at \
         FROM devices d JOIN devices o ON o.id = d.reenroll_of \
         WHERE d.status = 'pending_approval' ORDER BY d.enrolled_at",
    )
    .fetch_all(&st.pool)
    .await?;
    let pending = rows
        .into_iter()
        .map(|(id, hostname, old_id, old_hostname, at)| PendingRow {
            id,
            hostname,
            old_id,
            old_hostname,
            enrolled_at: fmt_time(st, Some(at)),
        })
        .collect();
    Ok((total, online, duplicate, pending))
}
```

- [ ] **Step 5: `templates/devices.html`**

```html
{% extends "base.html" %}
{% block content %}
<h1>裝置</h1>
<form method="get" action="/devices">
  <input name="q" value="{{ q }}" placeholder="電腦名稱／使用者／IP">
  <select name="status">
    {% for (value, label) in statuses %}
    <option value="{{ value }}" {% if *value == status %}selected{% endif %}>{{ label }}</option>
    {% endfor %}
  </select>
  {% if !software.is_empty() %}
  <input type="hidden" name="software" value="{{ software }}">
  <input type="hidden" name="version" value="{{ version }}">
  <span class="muted">安裝了「{{ software }}{% if !version.is_empty() %} {{ version }}{% endif %}」</span>
  {% endif %}
  <button>搜尋</button>
</form>
<table>
  <tr><th>電腦名稱</th><th>網域</th><th>作業系統</th><th>使用者</th><th>IP</th><th>群組</th><th>最後報到</th><th>狀態</th></tr>
  {% for d in rows %}
  <tr>
    <td><a href="/devices/{{ d.id }}">{{ d.hostname }}</a></td>
    <td>{{ d.domain }}</td>
    <td>{{ d.os }}</td>
    <td>{{ d.user }}</td>
    <td>{{ d.ip }}</td>
    <td>{{ d.group }}</td>
    <td>{{ d.last_seen }}</td>
    <td><span class="badge {{ d.badge }}">{{ d.badge_label }}</span></td>
  </tr>
  {% endfor %}
</table>
<div class="pager">
  {% if page > 0 %}<a href="{{ prev_url }}">上一頁</a>{% endif %}
  <span class="muted">第 {{ page + 1 }} 頁</span>
  {% if has_next %}<a href="{{ next_url }}">下一頁</a>{% endif %}
</div>
{% endblock %}
```

- [ ] **Step 6: `web/devices.rs`（列表與核准動作）**

```rust
//! 裝置列表、詳細資料與動作（核准、拒絕、除役）。

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, check_csrf};
use super::login::CsrfForm;
use super::{escape_like, fmt_time, render};
use crate::AppState;
use crate::db::load_settings;
use crate::error::AppError;

pub const PAGE_SIZE: i64 = 50;

pub async fn online_cutoff(st: &AppState) -> Result<DateTime<Utc>, sqlx::Error> {
    let s = load_settings(&st.pool).await?;
    Ok(Utc::now() - Duration::seconds(3 * i64::from(s.checkin_interval_secs)))
}

fn status_label(status: &str, online: bool) -> (&'static str, &'static str) {
    match status {
        "retired" => ("retired", "已除役"),
        "pending_approval" => ("pending_approval", "待核准"),
        "duplicate_suspect" => ("duplicate_suspect", "疑似重複"),
        _ if online => ("online", "在線"),
        _ => ("offline", "離線"),
    }
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    software: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    page: i64,
}

pub struct DeviceRow {
    pub id: Uuid,
    pub hostname: String,
    pub domain: String,
    pub os: String,
    pub user: String,
    pub ip: String,
    pub group: String,
    pub last_seen: String,
    pub badge: &'static str,
    pub badge_label: &'static str,
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesPage {
    nav_user: Option<String>,
    csrf: String,
    q: String,
    status: String,
    software: String,
    version: String,
    statuses: Vec<(&'static str, &'static str)>,
    rows: Vec<DeviceRow>,
    page: i64,
    has_next: bool,
    prev_url: String,
    next_url: String,
}

type ListRow = (
    Uuid,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<DateTime<Utc>>,
    String,
);

fn page_url(q: &ListQuery, page: i64) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'~' => (b as char).to_string(),
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    format!(
        "/devices?q={}&status={}&software={}&version={}&page={page}",
        enc(&q.q),
        enc(&q.status),
        enc(&q.software),
        enc(&q.version)
    )
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let cutoff = online_cutoff(&st).await?;
    let page = q.page.max(0);
    let mut rows: Vec<ListRow> = sqlx::query_as(
        "SELECT d.id, d.hostname, coalesce(d.domain, ''), coalesce(d.os_caption, ''), \
                coalesce(d.logged_on_user, ''), coalesce(d.last_ip, ''), coalesce(t.group_label, ''), \
                d.last_seen_at, d.status \
         FROM devices d LEFT JOIN enroll_tokens t ON t.id = d.enroll_token_id \
         WHERE ($1 = '' OR d.hostname ILIKE $2 OR d.logged_on_user ILIKE $2 OR d.last_ip ILIKE $2) \
           AND (CASE WHEN $3 = '' THEN d.status <> 'retired' WHEN $3 = 'all' THEN true ELSE d.status = $3 END) \
           AND ($4 = '' OR EXISTS (SELECT 1 FROM device_software sw WHERE sw.device_id = d.id \
                                   AND sw.name = $4 AND ($5 = '' OR coalesce(sw.version, '') = $5))) \
         ORDER BY d.hostname, d.id LIMIT $6 OFFSET $7",
    )
    .bind(&q.q)
    .bind(escape_like(&q.q))
    .bind(&q.status)
    .bind(&q.software)
    .bind(&q.version)
    .bind(PAGE_SIZE + 1)
    .bind(page * PAGE_SIZE)
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rows = rows
        .into_iter()
        .map(|(id, hostname, domain, os, user, ip, group, last_seen, status)| {
            let (badge, badge_label) =
                status_label(&status, last_seen.is_some_and(|t| t > cutoff));
            DeviceRow {
                id,
                hostname,
                domain,
                os,
                user,
                ip,
                group,
                last_seen: fmt_time(&st, last_seen),
                badge,
                badge_label,
            }
        })
        .collect();
    Ok(render(&DevicesPage {
        nav_user: Some(s.username),
        csrf: s.csrf,
        prev_url: page_url(&q, page - 1),
        next_url: page_url(&q, page + 1),
        q: q.q,
        status: q.status,
        software: q.software,
        version: q.version,
        statuses: vec![
            ("", "使用中"),
            ("pending_approval", "待核准"),
            ("duplicate_suspect", "疑似重複"),
            ("retired", "已除役"),
            ("all", "全部"),
        ],
        rows,
        page,
        has_next,
    }))
}

fn action_error(e: anyhow::Error) -> Response {
    (axum::http::StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

pub async fn approve(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    crate::devices::approve(&st.pool, id, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}

pub async fn reject(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    crate::devices::reject(&st.pool, id, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}

pub async fn approve_all(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    crate::devices::approve_all(&st.pool, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}
```

`web/mod.rs` 的 router 加：

```rust
        .route("/devices", get(devices::list))
        .route("/devices/approve-all", post(devices::approve_all))
        .route("/devices/{id}/approve", post(devices::approve))
        .route("/devices/{id}/reject", post(devices::reject))
```

並 `pub mod devices;`。`AppError` 需要在 web handler 回傳 → 已實作 `IntoResponse`。

> askama 0.16 對 `{% for (value, label) in statuses %}` 與 `*value == status` 的語法若不支援，改為在 struct 裡預先算好 `selected: bool` 欄位（`Vec<StatusOption { value, label, selected }>`），並記 ruling。

- [ ] **Step 7: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat(server): 儀表板、裝置列表、搜尋與重新註冊核准"
```

---

### Task 6: 裝置詳細頁與除役

**Files:**
- Create: `templates/device.html`、`templates/table.html`
- Modify: `src/web/devices.rs`、`src/web/mod.rs`（路由 `/devices/{id}`、`/devices/{id}/{tab}`、`/devices/{id}/retire`）
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /devices/{id}`、`GET /devices/{id}/{tab}`（`tab` ∈ `software|patches|services|changes`，回傳 HTML 片段）、`POST /devices/{id}/retire`（303 → `/devices/{id}`）

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn device_detail_and_tabs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let up = protocol::InventoryUpload {
        schema_version: protocol::SCHEMA_VERSION,
        payload: protocol::InventoryPayload::Software(vec![protocol::SoftwareItem {
            name: "<b>7-Zip</b>".into(),
            version: Some("23.01".into()),
            publisher: None,
            install_date: None,
            arch: protocol::Arch::X64,
        }]),
    };
    let r = s
        .client(Some(&a))
        .put(s.url("/v1/inventory/software"))
        .json(&up)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    let c = s.admin_client().await;
    let (status, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert_eq!(status, 200);
    assert!(html.contains("PC-001"));
    assert!(html.contains(&format!("/devices/{}/software", a.device_id)));

    let (status, frag) = s.page(&c, &format!("/devices/{}/software", a.device_id)).await;
    assert_eq!(status, 200);
    assert!(frag.contains("&lt;b&gt;7-Zip&lt;/b&gt;"), "{frag}");
    assert!(!frag.contains("<html"), "fragment only");

    let (status, _) = s.page(&c, &format!("/devices/{}/nope", a.device_id)).await;
    assert_eq!(status, 404);
    let (status, _) = s.page(&c, &format!("/devices/{}", uuid::Uuid::new_v4())).await;
    assert_eq!(status, 404);
}

#[sqlx::test(migrations = false)]
async fn retire_requires_csrf_and_revokes(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;
    let path = format!("/devices/{}/retire", a.device_id);

    let r = c.post(s.web_url(&path)).form(&[("csrf", "forged")]).send().await.unwrap();
    assert_eq!(r.status(), 403);

    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    let csrf = csrf_from(&html);
    let r = c.post(s.web_url(&path)).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(status, "retired");
}
```

`tests/web.rs` 頂部補 `use` 不需要（使用完整路徑 `protocol::...`、`uuid::...`）；`crates/server/Cargo.toml` dev-dependencies 若沒有 `uuid` → 它是一般依賴，整合測試可直接用。

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web device_detail retire`
Expected: FAIL（404）。

- [ ] **Step 3: 樣板**

`templates/device.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>{{ d.hostname }} <span class="badge {{ d.badge }}">{{ d.badge_label }}</span></h1>
<table>
  <tr><th>裝置 ID</th><td>{{ d.id }}</td><th>網域</th><td>{{ d.domain }}</td></tr>
  <tr><th>作業系統</th><td>{{ d.os }}</td><th>組建</th><td>{{ d.build }}</td></tr>
  <tr><th>使用者</th><td>{{ d.user }}</td><th>IP</th><td>{{ d.ip }}</td></tr>
  <tr><th>廠牌／型號</th><td>{{ d.model }}</td><th>CPU</th><td>{{ d.cpu }}</td></tr>
  <tr><th>記憶體</th><td>{{ d.ram }}</td><th>BIOS 序號</th><td>{{ d.serial }}</td></tr>
  <tr><th>最後報到</th><td>{{ d.last_seen }}</td><th>開機時間</th><td>{{ d.boot }}</td></tr>
  <tr><th>註冊時間</th><td>{{ d.enrolled }}</td><th>Agent 版本</th><td>{{ d.agent }}</td></tr>
</table>
{% if !d.errors.is_empty() %}
<h2>收集錯誤</h2>
<table>{% for (section, msg) in d.errors %}<tr><th>{{ section }}</th><td class="error">{{ msg }}</td></tr>{% endfor %}</table>
{% endif %}
{% if d.can_retire %}
<form method="post" action="/devices/{{ d.id }}/retire">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <button class="danger">除役（撤銷憑證，Agent 將停止報到）</button>
</form>
{% endif %}
<div class="tabs">
  {% for (tab, label) in tabs %}
  <button hx-get="/devices/{{ d.id }}/{{ tab }}" hx-target="#tab">{{ label }}</button>
  {% endfor %}
</div>
<div id="tab" hx-get="/devices/{{ d.id }}/software" hx-trigger="load"></div>
{% endblock %}
```

`templates/table.html`：

```html
<p class="muted">共 {{ rows.len() }} 筆{% if truncated %}（僅顯示前 {{ rows.len() }} 筆）{% endif %}</p>
<table>
  <tr>{% for h in headers %}<th>{{ h }}</th>{% endfor %}</tr>
  {% for row in rows %}<tr>{% for cell in row %}<td>{{ cell }}</td>{% endfor %}</tr>{% endfor %}
</table>
```

- [ ] **Step 4: 實作**（附加到 `web/devices.rs`）

```rust
pub struct DeviceView {
    pub id: Uuid,
    pub hostname: String,
    pub domain: String,
    pub os: String,
    pub build: String,
    pub user: String,
    pub ip: String,
    pub model: String,
    pub cpu: String,
    pub ram: String,
    pub serial: String,
    pub last_seen: String,
    pub boot: String,
    pub enrolled: String,
    pub agent: String,
    pub errors: Vec<(String, String)>,
    pub badge: &'static str,
    pub badge_label: &'static str,
    pub can_retire: bool,
}

#[derive(Template)]
#[template(path = "device.html")]
struct DevicePage {
    nav_user: Option<String>,
    csrf: String,
    d: DeviceView,
    tabs: Vec<(&'static str, &'static str)>,
}

#[derive(Template)]
#[template(path = "table.html")]
struct TableFragment {
    headers: Vec<&'static str>,
    rows: Vec<Vec<String>>,
    truncated: bool,
}

type DetailRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    DateTime<Utc>,
    Option<String>,
    String,
    String,
);

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let row: Option<DetailRow> = sqlx::query_as(
        "SELECT hostname, domain, os_caption, os_build, logged_on_user, last_ip, bios_serial, \
                last_seen_at, boot_time, enrolled_at, agent_version, status, section_errors::text \
         FROM devices WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let Some((hostname, domain, os, build, user, ip, serial, last_seen, boot, enrolled, agent, status, errors)) = row
    else {
        return Ok(axum::http::StatusCode::NOT_FOUND.into_response());
    };
    let hw: Option<(Option<String>, Option<String>, Option<String>, i64)> = sqlx::query_as(
        "SELECT manufacturer, model, cpu, ram_mb FROM device_hardware WHERE device_id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let cutoff = online_cutoff(&st).await?;
    let (badge, badge_label) = status_label(&status, last_seen.is_some_and(|t| t > cutoff));
    let errors: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&errors).unwrap_or_default();
    let o = |v: Option<String>| v.unwrap_or_default();
    let (model, cpu, ram) = match hw {
        Some((mf, model, cpu, ram)) => (
            format!("{} {}", o(mf), o(model)).trim().to_string(),
            o(cpu),
            format!("{:.1} GB", ram as f64 / 1024.0),
        ),
        None => Default::default(),
    };
    Ok(render(&DevicePage {
        nav_user: Some(s.username),
        csrf: s.csrf,
        d: DeviceView {
            id,
            hostname,
            domain: o(domain),
            os: o(os),
            build: o(build),
            user: o(user),
            ip: o(ip),
            model,
            cpu,
            ram,
            serial: o(serial),
            last_seen: fmt_time(&st, last_seen),
            boot: fmt_time(&st, boot),
            enrolled: fmt_time(&st, Some(enrolled)),
            agent: o(agent),
            errors: errors.into_iter().collect(),
            badge,
            badge_label,
            can_retire: status != "retired",
        },
        tabs: vec![
            ("software", "軟體"),
            ("patches", "修補（KB）"),
            ("services", "服務"),
            ("changes", "變更歷史"),
        ],
    }))
}

const TAB_LIMIT: i64 = 5000;

pub async fn tab(
    State(st): State<AppState>,
    AdminSession(_s): AdminSession,
    Path((id, tab)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    let (headers, sql): (Vec<&'static str>, &'static str) = match tab.as_str() {
        "software" => (
            vec!["名稱", "版本", "發行者", "架構", "安裝日期"],
            "SELECT name, coalesce(version, ''), coalesce(publisher, ''), arch, coalesce(install_date, '') \
             FROM device_software WHERE device_id = $1 ORDER BY lower(name) LIMIT $2",
        ),
        "patches" => (
            vec!["KB", "安裝日期"],
            "SELECT kb, coalesce(installed_on, '') FROM device_patches WHERE device_id = $1 ORDER BY kb LIMIT $2",
        ),
        "services" => (
            vec!["名稱", "顯示名稱", "啟動類型", "狀態", "執行檔"],
            "SELECT name, coalesce(display_name, ''), start_mode, state, coalesce(binary_path, '') \
             FROM device_services WHERE device_id = $1 ORDER BY lower(name) LIMIT $2",
        ),
        "changes" => (
            vec!["時間", "區段", "變更", "項目", "舊值", "新值"],
            "SELECT to_char(detected_at, 'YYYY-MM-DD HH24:MI') || ' UTC', section, change, item_key, \
                    coalesce(old_value, ''), coalesce(new_value, '') \
             FROM inventory_changes WHERE device_id = $1 ORDER BY detected_at DESC LIMIT $2",
        ),
        _ => return Ok(axum::http::StatusCode::NOT_FOUND.into_response()),
    };
    use sqlx::Row;
    let rows = sqlx::query(sql).bind(id).bind(TAB_LIMIT + 1).fetch_all(&st.pool).await?;
    let truncated = rows.len() as i64 > TAB_LIMIT;
    let rows: Vec<Vec<String>> = rows
        .iter()
        .take(TAB_LIMIT as usize)
        .map(|r| (0..headers.len()).map(|i| r.get::<String, _>(i)).collect())
        .collect();
    Ok(render(&TableFragment { headers, rows, truncated }))
}

pub async fn retire(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    crate::devices::retire(&st.pool, id, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}
```

路由（`/devices/{id}/{tab}` 為 GET，與 POST 的 approve/reject/retire 同路徑模式不衝突，因為 method 不同）：

```rust
        .route("/devices/{id}", get(devices::detail))
        .route("/devices/{id}/{tab}", get(devices::tab))
        .route("/devices/{id}/retire", post(devices::retire))
```

> 若 axum 0.8 不允許 `/devices/{id}/{tab}` 與 `/devices/{id}/retire` 並存（靜態段與參數段衝突），把 GET 分頁改為 `/devices/{id}/tab/{tab}` 並同步修改樣板與測試，記 ruling。

- [ ] **Step 5: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(server): 裝置詳細頁、分頁資料與除役"
```

---

### Task 7: 全公司軟體搜尋

**Files:**
- Create: `templates/software.html`、`src/web/software.rs`；Modify: `src/web/mod.rs`（`/software`）
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /software?q=`：依名稱（ILIKE、跳脫萬用字元）分組列出「名稱／版本／安裝台數」，每列連到 `/devices?software=<名稱>&version=<版本>`；最多 500 列；未除役的裝置才算。

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn software_search_groups_by_version(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    for (agent, ver) in [(&a, "120"), (&b, "121")] {
        let up = protocol::InventoryUpload {
            schema_version: protocol::SCHEMA_VERSION,
            payload: protocol::InventoryPayload::Software(vec![protocol::SoftwareItem {
                name: "Google Chrome".into(),
                version: Some(ver.into()),
                publisher: None,
                install_date: None,
                arch: protocol::Arch::X64,
            }]),
        };
        s.client(Some(agent)).put(s.url("/v1/inventory/software")).json(&up).send().await.unwrap();
    }
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/software?q=chrome").await;
    assert!(html.contains("Google Chrome"));
    assert!(html.contains("120") && html.contains("121"));
    assert!(html.contains("/devices?software=Google%20Chrome&amp;version=120"), "{html}");

    let (_, html) = s.page(&c, "/devices?software=Google%20Chrome&version=121").await;
    assert_eq!(html.matches("/devices/").count() - html.matches("/devices/approve").count(), 1);
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web software_search`
Expected: FAIL（404）。

- [ ] **Step 3: 樣板與實作**

`templates/software.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>軟體搜尋</h1>
<form method="get" action="/software">
  <input name="q" value="{{ q }}" placeholder="軟體名稱（例如 Chrome）" autofocus>
  <button>搜尋</button>
</form>
{% if !q.is_empty() %}
<table>
  <tr><th>名稱</th><th>版本</th><th>安裝台數</th></tr>
  {% for r in rows %}
  <tr><td>{{ r.name }}</td><td>{{ r.version }}</td><td><a href="{{ r.url }}">{{ r.count }}</a></td></tr>
  {% endfor %}
</table>
{% if truncated %}<p class="muted">結果過多，只顯示前 500 筆，請縮小搜尋範圍。</p>{% endif %}
{% endif %}
{% endblock %}
```

`web/software.rs`：

```rust
//! 全公司軟體搜尋：依名稱與版本統計安裝台數。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use super::auth::AdminSession;
use super::{escape_like, render};
use crate::AppState;
use crate::error::AppError;

const LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    q: String,
}

pub struct SoftwareRow {
    pub name: String,
    pub version: String,
    pub count: i64,
    pub url: String,
}

#[derive(Template)]
#[template(path = "software.html")]
struct SoftwarePage {
    nav_user: Option<String>,
    csrf: String,
    q: String,
    rows: Vec<SoftwareRow>,
    truncated: bool,
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub async fn search(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let mut rows: Vec<(String, String, i64)> = if q.q.trim().is_empty() {
        vec![]
    } else {
        sqlx::query_as(
            "SELECT sw.name, coalesce(sw.version, ''), count(DISTINCT sw.device_id) \
             FROM device_software sw JOIN devices d ON d.id = sw.device_id AND d.status <> 'retired' \
             WHERE sw.name ILIKE $1 \
             GROUP BY 1, 2 ORDER BY lower(sw.name), 2 LIMIT $2",
        )
        .bind(escape_like(q.q.trim()))
        .bind(LIMIT + 1)
        .fetch_all(&st.pool)
        .await?
    };
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    Ok(render(&SoftwarePage {
        nav_user: Some(s.username),
        csrf: s.csrf,
        q: q.q,
        rows: rows
            .into_iter()
            .map(|(name, version, count)| SoftwareRow {
                url: format!("/devices?software={}&version={}", enc(&name), enc(&version)),
                name,
                version,
                count,
            })
            .collect(),
        truncated,
    }))
}
```

`web/devices.rs` 的 `page_url` 內的 `enc` 改用 `super::software::enc`（把 `enc` 設為 `pub(super)`），避免重複。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(server): 全公司軟體搜尋"
```

---

### Task 8: 註冊金鑰管理

**Files:**
- Create: `templates/tokens.html`、`src/web/tokens.rs`；Modify: `src/web/mod.rs`（`/tokens`、`/tokens/{id}/revoke`）
- Modify: `crates/server/src/tokens.rs`（`revoke_token`）
- Modify: `tests/web.rs`

**Interfaces:**
- Produces:
  - `tokens::revoke_token(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()>`（寫 audit `token_revoke`）
  - `GET /tokens`：列表；`POST /tokens`（`csrf, name, max_uses, group_label, valid_days`）→ 200，頁面上方顯示一次明碼；`POST /tokens/{id}/revoke` → 303 `/tokens`
  - 建立時寫 audit `token_create`（detail：name、max_uses、group_label、valid_days；**不含明碼**）

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn token_created_in_web_can_enroll_and_be_revoked(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let csrf = csrf_from(&html);

    let r = c
        .post(s.web_url("/tokens"))
        .form(&[("csrf", csrf.as_str()), ("name", "IT pilot"), ("max_uses", "2"), ("group_label", "IT"), ("valid_days", "7")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let html = r.text().await.unwrap();
    let marker = r#"<code id="new-token">"#;
    let start = html.find(marker).expect("token shown once") + marker.len();
    let token = &html[start..start + 64];
    s.enroll_ok(token, None, None).await;

    let detail: String = sqlx::query_scalar("SELECT detail::text FROM audit_log WHERE action = 'token_create'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert!(!detail.contains(token), "明碼不可寫進稽核記錄");

    let id: i64 = sqlx::query_scalar("SELECT id FROM enroll_tokens WHERE name = 'IT pilot'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&c, "/tokens").await;
    assert!(!html.contains(token), "列表不顯示明碼");
    let csrf = csrf_from(&html);
    let r = c
        .post(s.web_url(&format!("/tokens/{id}/revoke")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(s.enroll(token, None, None).await.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn token_form_validates_input(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let csrf = csrf_from(&html);
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[("csrf", csrf.as_str()), ("name", ""), ("max_uses", "0"), ("group_label", ""), ("valid_days", "")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_tokens")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web token_`
Expected: FAIL（404）。

- [ ] **Step 3: `tokens::revoke_token`**（`src/tokens.rs`）

```rust
pub async fn revoke_token(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE enroll_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    anyhow::ensure!(n == 1, "token not found or already revoked");
    crate::audit::record(&mut tx, actor, "token_revoke", Some(&id.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}
```

- [ ] **Step 4: 樣板與 handler**

`templates/tokens.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>註冊金鑰</h1>
{% if let Some(t) = new_token %}
<div class="notice">
  <p>金鑰已建立。<b>明碼只顯示這一次</b>，請立即複製到安裝參數 <code>ENROLL_TOKEN=</code>：</p>
  <p><code id="new-token">{{ t }}</code></p>
</div>
{% endif %}
<h2>建立金鑰</h2>
<form method="post" action="/tokens">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <label>名稱 <input name="name" required maxlength="100"></label>
  <label>可使用次數 <input name="max_uses" type="number" min="1" value="100" required></label>
  <label>群組 <input name="group_label" maxlength="100"></label>
  <label>有效天數 <input name="valid_days" type="number" min="1" placeholder="不限"></label>
  <button>建立</button>
</form>
<h2>現有金鑰</h2>
<table>
  <tr><th>名稱</th><th>群組</th><th>已用／上限</th><th>到期</th><th>建立者</th><th>建立時間</th><th>狀態</th></tr>
  {% for t in rows %}
  <tr>
    <td>{{ t.name }}</td><td>{{ t.group }}</td><td>{{ t.used }} / {{ t.max }}</td><td>{{ t.expires }}</td>
    <td>{{ t.created_by }}</td><td>{{ t.created_at }}</td>
    <td>
      {% if t.active %}
      <form class="inline" method="post" action="/tokens/{{ t.id }}/revoke"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="danger">作廢</button></form>
      {% else %}<span class="muted">{{ t.state }}</span>{% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
```

`web/tokens.rs`：

```rust
//! 註冊金鑰：建立（明碼只顯示一次）、列表、作廢。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Session, check_csrf};
use super::login::CsrfForm;
use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;
use crate::tokens::{NewToken, create_token, revoke_token};

pub struct TokenRow {
    pub id: i64,
    pub name: String,
    pub group: String,
    pub used: i32,
    pub max: i32,
    pub expires: String,
    pub created_by: String,
    pub created_at: String,
    pub active: bool,
    pub state: &'static str,
}

#[derive(Template)]
#[template(path = "tokens.html")]
struct TokensPage {
    nav_user: Option<String>,
    csrf: String,
    new_token: Option<String>,
    rows: Vec<TokenRow>,
}

type Row = (i64, String, Option<String>, i32, i32, Option<DateTime<Utc>>, Option<DateTime<Utc>>, String, DateTime<Utc>);

async fn page_for(st: &AppState, s: Session, new_token: Option<String>) -> Result<Response, AppError> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, name, group_label, used_count, max_uses, expires_at, revoked_at, created_by, created_at \
         FROM enroll_tokens ORDER BY id DESC",
    )
    .fetch_all(&st.pool)
    .await?;
    let now = Utc::now();
    let rows = rows
        .into_iter()
        .map(|(id, name, group, used, max, expires, revoked, created_by, created_at)| {
            let state = if revoked.is_some() {
                "已作廢"
            } else if expires.is_some_and(|e| e <= now) {
                "已過期"
            } else if used >= max {
                "已用完"
            } else {
                ""
            };
            TokenRow {
                id,
                name,
                group: group.unwrap_or_default(),
                used,
                max,
                expires: expires.map(|e| fmt_time(st, Some(e))).unwrap_or_else(|| "不限".into()),
                created_by,
                created_at: fmt_time(st, Some(created_at)),
                active: state.is_empty(),
                state,
            }
        })
        .collect();
    Ok(render(&TokensPage { nav_user: Some(s.username), csrf: s.csrf, new_token, rows }))
}

pub async fn list(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, AppError> {
    page_for(&st, s, None).await
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
    max_uses: String,
    #[serde(default)]
    group_label: String,
    #[serde(default)]
    valid_days: String,
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Form(f): Form<CreateForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string()).into_response();
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(bad("名稱必填，最多 100 字"));
    }
    let max_uses: i32 = f.max_uses.trim().parse().ok().filter(|n| *n >= 1).ok_or_else(|| bad("可使用次數需為正整數"))?;
    let valid_days: Option<i64> = match f.valid_days.trim() {
        "" => None,
        d => Some(d.parse().ok().filter(|n: &i64| (1..=3650).contains(n)).ok_or_else(|| bad("有效天數需為 1～3650"))?),
    };
    let group = Some(f.group_label.trim().to_string()).filter(|g| !g.is_empty());
    let err = |e: sqlx::Error| AppError::from(e).into_response();
    let (id, token) = create_token(
        &st.pool,
        &NewToken {
            name: name.into(),
            group_label: group.clone(),
            expires_at: valid_days.map(|d| Utc::now() + Duration::days(d)),
            max_uses,
            created_by: s.username.clone(),
        },
    )
    .await
    .map_err(err)?;
    let mut c = st.pool.acquire().await.map_err(err)?;
    crate::audit::record(
        &mut c,
        &s.username,
        "token_create",
        Some(&id.to_string()),
        serde_json::json!({ "name": name, "max_uses": max_uses, "group_label": group, "valid_days": valid_days }),
    )
    .await
    .map_err(err)?;
    page_for(&st, s, Some(token)).await.map_err(IntoResponse::into_response)
}

pub async fn revoke(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    revoke_token(&st.pool, id, &s.username)
        .await
        .map_err(|e| (StatusCode::CONFLICT, format!("{e:#}")).into_response())?;
    Ok(Redirect::to("/tokens").into_response())
}
```

路由：`.route("/tokens", get(tokens::list).post(tokens::create))`、`.route("/tokens/{id}/revoke", post(tokens::revoke))`；`pub mod tokens;`（web 模組內，與 crate 的 `tokens` 模組同名但路徑不同：handler 內以 `crate::tokens` 引用）。

- [ ] **Step 5: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(server): 註冊金鑰管理頁"
```

---

### Task 9: 稽核記錄頁

**Files:**
- Create: `templates/audit.html`、`src/web/audit.rs`；Modify: `src/web/mod.rs`（`/audit`）
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /audit?page=`：最新在前，每頁 50 筆；欄位：時間、操作者、動作（中文標籤）、對象、細節。

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn audit_page_lists_logins_and_failures(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s
        .web_client()
        .post(s.web_url("/login"))
        .form(&[("username", "ghost"), ("password", "<script>x</script>")])
        .send()
        .await
        .unwrap();
    let c = s.admin_client().await;
    let (status, html) = s.page(&c, "/audit").await;
    assert_eq!(status, 200);
    assert!(html.contains("登入成功"));
    assert!(html.contains("登入失敗"));
    assert!(html.contains("ghost"));
    assert!(!html.contains("<script>x"), "密碼不應出現在稽核記錄，任何內容都要 escape");
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web audit_page`
Expected: FAIL（404）。

- [ ] **Step 3: 樣板與 handler**

`templates/audit.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>稽核記錄</h1>
<table>
  <tr><th>時間</th><th>操作者</th><th>動作</th><th>對象</th><th>細節</th></tr>
  {% for r in rows %}
  <tr><td>{{ r.at }}</td><td>{{ r.actor }}</td><td>{{ r.action }}</td><td>{{ r.target }}</td><td class="muted">{{ r.detail }}</td></tr>
  {% endfor %}
</table>
<div class="pager">
  {% if page > 0 %}<a href="/audit?page={{ page - 1 }}">上一頁</a>{% endif %}
  <span class="muted">第 {{ page + 1 }} 頁</span>
  {% if has_next %}<a href="/audit?page={{ page + 1 }}">下一頁</a>{% endif %}
</div>
{% endblock %}
```

`web/audit.rs`：

```rust
//! 稽核記錄頁。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::auth::AdminSession;
use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;

const PAGE_SIZE: i64 = 50;

fn label(action: &str) -> &str {
    match action {
        "login" => "登入成功",
        "login_failed" => "登入失敗",
        "logout" => "登出",
        "token_create" => "建立註冊金鑰",
        "token_revoke" => "作廢註冊金鑰",
        "device_retire" => "除役裝置",
        "device_approve" => "核准重新註冊",
        "device_reject" => "拒絕重新註冊",
        "admin_create" => "建立管理員",
        other => other,
    }
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    page: i64,
}

pub struct AuditRow {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    nav_user: Option<String>,
    csrf: String,
    rows: Vec<AuditRow>,
    page: i64,
    has_next: bool,
}

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    let page = q.page.max(0);
    let mut rows: Vec<(DateTime<Utc>, String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT at, actor, action, target, detail::text FROM audit_log ORDER BY id DESC LIMIT $1 OFFSET $2",
    )
    .bind(PAGE_SIZE + 1)
    .bind(page * PAGE_SIZE)
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    Ok(render(&AuditPage {
        nav_user: Some(s.username),
        csrf: s.csrf,
        rows: rows
            .into_iter()
            .map(|(at, actor, action, target, detail)| AuditRow {
                at: fmt_time(&st, Some(at)),
                actor,
                action: label(&action).to_string(),
                target: target.unwrap_or_default(),
                detail: if detail == "{}" { String::new() } else { detail },
            })
            .collect(),
        page,
        has_next,
    }))
}
```

路由 `.route("/audit", get(audit::page))`、`pub mod audit;`。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(server): 稽核記錄頁"
```

---

### Task 10: serve 開兩個監聽埠、設定、README、實機檢查、PR

**Files:**
- Modify: `crates/server/src/config.rs`、`crates/server/src/lib.rs`（`serve`）、`README.md`

**Interfaces:**
- Produces: `Config.web_listen: SocketAddr`（`EM_WEB_LISTEN`，預設 `0.0.0.0:443`）、`Config.display_utc_offset: i32`（`EM_DISPLAY_UTC_OFFSET`，預設 8，範圍 -12～14）

- [ ] **Step 1: 寫失敗測試**（`config.rs` 測試）

```rust
    #[test]
    fn web_defaults_and_offset() {
        let c = Config::from_lookup(|k| (k == "DATABASE_URL").then(|| "postgres://x".into())).unwrap();
        assert_eq!(c.web_listen.port(), 443);
        assert_eq!(c.display_utc_offset, 8);
        let bad = Config::from_lookup(|k| match k {
            "DATABASE_URL" => Some("postgres://x".into()),
            "EM_DISPLAY_UTC_OFFSET" => Some("99".into()),
            _ => None,
        });
        assert!(bad.is_err());
    }
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --lib config::`
Expected: 編譯失敗。

- [ ] **Step 3: 實作**

`Config` 加欄位與解析：

```rust
    pub web_listen: SocketAddr,
    pub display_utc_offset: i32,
```

```rust
            web_listen: get("EM_WEB_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:443".into())
                .parse()
                .context("EM_WEB_LISTEN")?,
            display_utc_offset: {
                let h: i32 = get("EM_DISPLAY_UTC_OFFSET")
                    .unwrap_or_else(|| "8".into())
                    .parse()
                    .context("EM_DISPLAY_UTC_OFFSET")?;
                anyhow::ensure!((-12..=14).contains(&h), "EM_DISPLAY_UTC_OFFSET out of range");
                h
            },
```

`serve`：`AppState::new(...).with_display_offset(cfg.display_utc_offset)`；在建立 agent listener 之後：

```rust
    let web_listener = tokio::net::TcpListener::bind(cfg.web_listen).await?;
    tracing::info!(addr = %cfg.web_listen, "admin web listening");
    let web_tls = tls::web_server_config(&cfg.ca_dir)?;
    tokio::select! {
        r = tls::serve_mtls(listener, tls_cfg, agent_router(state.clone()), tls::ConnLimits::default()) => r?,
        r = tls::serve_mtls(web_listener, web_tls, web::web_router(state.clone()), tls::ConnLimits::default()) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
```

- [ ] **Step 4: README 加「管理網頁」章節**

````markdown
## 管理網頁

伺服器同時在 `EM_WEB_LISTEN`（預設 `0.0.0.0:443`）提供 HTTPS 管理網頁，使用 `ca-init` 產生的伺服器憑證。瀏覽器需信任 `pki/root.pem`（或改用公司 CA 簽發的伺服器憑證）。

建立第一個管理員（密碼從標準輸入讀取，至少 12 字元）：

```bash
echo '<密碼>' | cargo run -p endpoint-server -- admin-create admin
```

功能：儀表板（在線／離線／待核准）、裝置列表與搜尋、裝置詳細（軟體／KB／服務／變更歷史）、除役、重新註冊核准、全公司軟體搜尋、註冊金鑰管理、稽核記錄。

時間以 `EM_DISPLAY_UTC_OFFSET`（小時，預設 8）顯示。

同一台電腦重灌後重新註冊，會列在儀表板「待核准」，需管理員核准後才會接手原裝置記錄。
````

- [ ] **Step 5: 全部檢查**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: 全部通過。

- [ ] **Step 6: 實機檢查**

用開發資料庫啟動 `serve`（`EM_WEB_LISTEN=127.0.0.1:18444`），`admin-create` 建帳號，以瀏覽器（Playwright／Chrome DevTools MCP，忽略自簽憑證錯誤，或匯入 root.pem）登入，逐頁截圖確認：儀表板、裝置列表、裝置詳細（軟體分頁以 htmx 載入）、軟體搜尋、金鑰建立（明碼只顯示一次）、稽核記錄；確認瀏覽器主控台沒有 CSP 錯誤。截圖存 `$CLAUDE_JOB_DIR/tmp/`，重點頁面回報給使用者。

- [ ] **Step 7: 最終審查、PR、合併**（依 executing-plans 與使用者的 PR 流程）
