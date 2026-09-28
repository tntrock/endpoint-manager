# 計畫 3／4：管理網頁（含分權管理）實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在伺服器加上 HTTPS 管理網頁（:443），支援三種角色與「裝置群組」分權：平台管理員管理整個平台（含帳號、群組、稽核），群組管理員只管理被指派群組內的電腦，唯讀檢視者只能看。功能包含儀表板、裝置列表與詳細資料、全公司軟體搜尋、註冊金鑰、重新註冊核准、除役、群組管理、帳號管理、修改自己的密碼、稽核記錄。

**Architecture:** 同一個 `endpoint-server` 執行檔多開一個 TLS 監聽埠（不要求用戶端憑證），沿用計畫 1 的 `tls::serve_mtls` 與連線限制。頁面由 askama 在伺服器端產生，htmx（放在專案內的單一 JS 檔）只用於裝置詳細頁分頁載入。權限集中在 `web::auth::Session`：每個查詢都以 `($all OR d.group_id = ANY($groups))` 過濾，範圍外的裝置一律 404。所有寫入動作都是帶 CSRF token 的表單 POST，並寫入 `audit_log`。帳號、群組、裝置生命週期的規則放在獨立的領域模組（`accounts.rs`、`groups.rs`、`devices.rs`），網頁 handler 只做權限檢查與轉呼叫。

**Tech Stack:** axum 0.8、askama 0.16、argon2 0.6、htmx 2.0.11（vendored）、既有的 sqlx／rustls

**Spec:** `docs/superpowers/specs/2026-09-27-endpoint-inventory-design.md`（§5.3 管理資料表、§6.2 管理網頁防護）

**前置：** 計畫 1、2 已合併。計畫 1 最終審查 I2 決議：「重新註冊需管理員核准」放在計畫 3。

## 設計決定（使用者已確認：裝置群組、三種角色、基本帳號管理）

1. **裝置群組**：`device_groups` 資料表。註冊金鑰綁定一個群組（可不綁＝未分組），用哪把金鑰註冊的電腦就歸哪個群組。平台管理員可在網頁把電腦移到別的群組。既有的 `enroll_tokens.group_label` 轉為群組後移除。
2. **三種角色**：

   | 權限 | 平台管理員 `platform_admin` | 群組管理員 `group_admin` | 唯讀檢視者 `viewer` |
   |---|---|---|---|
   | 可見的裝置 | 全部（含未分組） | 被指派群組 | 被指派群組 |
   | 裝置詳細、軟體搜尋、儀表板 | ✅ 全部 | ✅ 限範圍內 | ✅ 限範圍內 |
   | 除役、核准／拒絕重新註冊 | ✅ | ✅ 限範圍內 | ❌ |
   | 把電腦移到別的群組 | ✅ | ❌ | ❌ |
   | 註冊金鑰（建立、作廢、列表） | ✅ 全部，可不綁群組 | ✅ 只能建立／看／作廢自己群組的 | ❌ |
   | 群組管理、帳號管理、稽核記錄 | ✅ | ❌ | ❌ |
   | 修改自己的密碼 | ✅ | ✅ | ✅ |

   群組管理員與檢視者至少要指派一個群組。
3. **帳號管理**（平台管理員）：建立帳號（帳號、角色、群組、初始密碼）、修改角色與群組、停用／啟用、重設密碼、解除鎖定。安全規則：不能停用自己或變更自己的角色；系統中至少要保留一個啟用中的平台管理員；停用、變更角色／群組、重設密碼時，對方的工作階段全部失效。CLI `admin-create` 建立第一個平台管理員。
4. **重新註冊一律需要核准**：硬體識別與既有裝置相符時，建立 `pending_approval` 的新裝置記錄（`reenroll_of` 指向舊裝置），可以報到，但資料獨立存放。核准：舊裝置憑證撤銷、新憑證移到舊裝置、新記錄刪除、舊裝置區段 hash 清空（下次報到重傳全部，差異記入歷史），舊裝置保留原本的群組。拒絕：新裝置憑證撤銷、狀態 `retired`。取代計畫 1「10 分鐘內有報到就不接管」的暫時防護。
5. **除役**：撤銷該裝置所有憑證、狀態 `retired`；列表預設不顯示已除役裝置。
6. **在線判定**：`last_seen_at` 在 3 個報到週期內。
7. **時間顯示**：`EM_DISPLAY_UTC_OFFSET`（小時，預設 8）。**介面語言**：繁體中文。

## Global Constraints

- 授權 `GPL-3.0-only`；Rust edition 2024；TLS 只用 rustls + ring；不用 clap。
- 管理網頁監聽埠預設 `0.0.0.0:443`（`EM_WEB_LISTEN`），使用 `pki/server.pem`，不要求用戶端憑證，連線限制沿用 `tls::ConnLimits::default()`。
- 密碼 argon2id 預設參數，最短 12 字元。
- 登入失敗 5 次 → 鎖定 15 分鐘；錯誤訊息一律「帳號或密碼錯誤」。
- 工作階段 64 hex 隨機 token，資料庫只存 SHA-256；有效 8 小時；cookie `em_session`，`Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`。
- 每個已登入的 POST 都必須帶 `csrf` 欄位並與工作階段相符，否則 403。
- 權限不足（角色）→ 403；裝置／金鑰不在自己範圍 → 404。
- 所有 HTML 回應加上：`Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: same-origin`、`Cache-Control: no-store`（靜態檔案除外）。
- 不使用行內 script／style；htmx 設定 `includeIndicatorStyles: false`；askama 自動 escape，不使用 `|safe`。
- 稽核動作：`login`、`login_failed`、`logout`、`password_change`、`token_create`、`token_revoke`、`device_retire`、`device_approve`、`device_reject`、`device_move`、`group_create`、`group_delete`、`admin_create`、`admin_update`、`admin_disable`、`admin_enable`、`admin_password_reset`、`admin_unlock`。
- 列表每頁 50 筆；LIKE 搜尋時跳脫 `%`、`_`、`\`。
- 不得出現任何公司專屬資訊。

## Review Focus

1. **群組管理員越權**：直接在網址輸入別的群組的裝置 ID、分頁、除役、核准，或建立別的群組的註冊金鑰 → 一律 404／403，且儀表板數字、軟體搜尋台數不包含範圍外裝置。→ Task 6、7、8、9 的 `group_admin_*` 測試。
2. **把自己鎖在門外**：停用或降級最後一個平台管理員、停用自己 → 必須被拒絕。→ Task 10 `last_platform_admin_is_protected`。
3. **端點傳來的字串含 HTML**（電腦名稱、使用者、軟體名稱）→ 以文字顯示。→ Task 6 `hostile_hostname_is_escaped`、Task 7 `device_detail_and_tabs`。
4. **CSRF**：已登入的管理員被誘導送出表單 → 403。→ Task 5 `post_without_csrf_is_403`、Task 7 `retire_requires_csrf`。
5. **帳號被停用或密碼被重設後**，已登入的工作階段必須立即失效。→ Task 10 `disable_kills_sessions`。

---

## 檔案結構

```
crates/server/
├─ migrations/0002_admin_web.sql
├─ static/htmx.min.js  static/app.css
├─ templates/
│  base.html login.html dashboard.html devices.html device.html table.html
│  software.html tokens.html groups.html accounts.html account.html password.html audit.html
├─ src/
│  ├─ audit.rs         稽核記錄寫入
│  ├─ accounts.rs      管理員帳號規則（建立、修改、停用、重設、解鎖、改自己的密碼）
│  ├─ groups.rs        群組（建立、刪除、find_or_create）、移動裝置
│  ├─ devices.rs       核准／拒絕／除役
│  ├─ tokens.rs        （修改）群組化、revoke_token、consume 回傳群組
│  ├─ enroll.rs        （修改）群組、相符硬體 → pending_approval
│  ├─ config.rs  lib.rs  tls.rs  main.rs  （修改）
│  └─ web/
│     mod.rs auth.rs login.rs dashboard.rs devices.rs software.rs tokens.rs
│     groups.rs accounts.rs password.rs audit.rs
└─ tests/
   ├─ common/mod.rs   （修改）管理網頁、登入輔助、建立各角色帳號
   └─ web.rs
crates/agent/tests/e2e.rs  （修改）NewToken 欄位
```

---

### Task 0: 分支

- [x] **Step 1**：本計畫文件提交於分支 `feat/plan3-admin-web`。

---

### Task 1: 資料表、群組化的註冊金鑰、稽核記錄

**Files:**
- Create: `crates/server/migrations/0002_admin_web.sql`、`crates/server/src/audit.rs`、`crates/server/src/groups.rs`
- Modify: `crates/server/src/tokens.rs`、`crates/server/src/enroll.rs`（只改 consume 回傳值與寫入 group_id）、`crates/server/src/lib.rs`、`crates/server/src/main.rs`（`token-create` 的群組參數）
- Modify: `crates/server/tests/common/mod.rs`、`crates/agent/tests/e2e.rs`（`NewToken` 欄位改名）
- Modify: workspace `Cargo.toml`、`crates/server/Cargo.toml`

**Interfaces:**
- Produces:
  - `audit::record(conn: &mut PgConnection, actor: &str, action: &str, target: Option<&str>, detail: serde_json::Value) -> Result<(), sqlx::Error>`
  - `groups::find_or_create(conn: &mut PgConnection, name: &str) -> Result<i64, sqlx::Error>`
  - `tokens::NewToken { name, group_id: Option<i64>, expires_at, max_uses, created_by }`（取代 `group_label`）
  - `tokens::consume_token(conn, token) -> Result<Option<(i64, Option<i64>)>, sqlx::Error>`（token id、group id）
  - `tokens::revoke_token(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()>`
  - `devices.group_id` 於註冊時設為金鑰的群組

- [ ] **Step 1: 依賴**

workspace `[workspace.dependencies]` 加 `askama = "0.16"`、`argon2 = "0.6"`；`crates/server/Cargo.toml` `[dependencies]` 加 `askama.workspace = true`、`argon2.workspace = true`；`[dev-dependencies]` 的 reqwest 改為 `reqwest = { workspace = true, features = ["cookies", "form"] }`（若 0.13 沒有 `form` feature 而 `RequestBuilder::form` 已內建，移除並記 ruling）。

- [ ] **Step 2: migration `0002_admin_web.sql`**

```sql
CREATE TABLE device_groups (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO device_groups (name)
    SELECT DISTINCT group_label FROM enroll_tokens WHERE coalesce(group_label, '') <> '';

ALTER TABLE enroll_tokens ADD COLUMN group_id BIGINT REFERENCES device_groups(id);
UPDATE enroll_tokens t SET group_id = g.id FROM device_groups g WHERE g.name = t.group_label;
ALTER TABLE enroll_tokens DROP COLUMN group_label;

ALTER TABLE devices ADD COLUMN group_id BIGINT REFERENCES device_groups(id);
UPDATE devices d SET group_id = t.group_id FROM enroll_tokens t WHERE t.id = d.enroll_token_id;
CREATE INDEX devices_group_idx ON devices (group_id);

ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'duplicate_suspect', 'pending_approval'));
ALTER TABLE devices ADD COLUMN reenroll_of UUID REFERENCES devices(id) ON DELETE SET NULL;

CREATE TABLE admins (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('platform_admin', 'group_admin', 'viewer')),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    disabled_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_groups (
    admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (admin_id, group_id)
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id   BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_admin_idx ON sessions (admin_id);

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

- [ ] **Step 3: 寫失敗測試**

`groups.rs` 測試：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = false)]
    async fn find_or_create_is_idempotent(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let a = find_or_create(&mut c, "高雄廠").await.unwrap();
        let b = find_or_create(&mut c, "高雄廠").await.unwrap();
        assert_eq!(a, b);
    }
}
```

`tests/enroll.rs` 追加：

```rust
#[sqlx::test(migrations = false)]
async fn device_joins_token_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let name: String = sqlx::query_scalar(
        "SELECT g.name FROM devices d JOIN device_groups g ON g.id = d.group_id WHERE d.id = $1",
    )
    .bind(a.device_id)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(name, "台北總部");
}
```

`tests/common/mod.rs`：`create_token` 內 `NewToken` 改為 `group_id: None`，並新增：

```rust
    pub async fn create_group_token(&self, group: &str, max_uses: i32) -> String {
        let mut c = self.pool.acquire().await.unwrap();
        let gid = endpoint_server::groups::find_or_create(&mut c, group).await.unwrap();
        tokens::create_token(
            &self.pool,
            &tokens::NewToken {
                name: format!("{group} token"),
                group_id: Some(gid),
                expires_at: None,
                max_uses,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap()
        .1
    }
```

`crates/agent/tests/e2e.rs` 與 `crates/server/src/tokens.rs` 測試模組中的 `group_label: None` 改為 `group_id: None`。

- [ ] **Step 4: 確認失敗**

Run: `cargo test -p endpoint-server`
Expected: 編譯失敗（`groups` 模組、`group_id` 欄位不存在）。

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

`groups.rs`（本 task 部分）：

```rust
//! 裝置群組：分權的單位。

use sqlx::{PgConnection, PgPool};

pub async fn find_or_create(conn: &mut PgConnection, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO device_groups (name) VALUES ($1) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(conn)
    .await
}
```

`tokens.rs`：`NewToken.group_label` → `group_id: Option<i64>`；`create_token` 的 INSERT 改 `group_id`；`consume_token`：

```rust
pub async fn consume_token(
    conn: &mut PgConnection,
    token: &str,
) -> Result<Option<(i64, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE enroll_tokens SET used_count = used_count + 1 \
         WHERE token_hash = $1 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND used_count < max_uses \
         RETURNING id, group_id",
    )
    .bind(hash_token(token))
    .fetch_optional(conn)
    .await
}

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

`tokens.rs` 既有測試 `consume_respects_max_uses` 的期望改為 `Some((id, None))`。

`enroll.rs`：`let (token_id, group_id) = tokens::consume_token(...)...`；INSERT devices 加 `group_id`（`$7`）；沿用舊記錄的分支也不變更群組。

`main.rs` 的 `token-create`：第 4 個參數改為群組名稱，存在則沿用、不存在則建立：

```rust
            let group_id = match args.get(3) {
                Some(name) => {
                    let mut c = pool.acquire().await?;
                    Some(endpoint_server::groups::find_or_create(&mut c, name).await?)
                }
                None => None,
            };
```

USAGE 改為 `token-create <name> <max_uses> [group_name] [valid_days]`。`lib.rs` 加 `pub mod audit; pub mod groups;`。

- [ ] **Step 6: 測試**

Run: `cargo test --workspace`
Expected: 全部 PASS（含 agent e2e）。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(server): 裝置群組、稽核記錄與管理資料表"
```

---

### Task 2: 重新註冊需核准、核准／拒絕／除役、移動群組

**Files:**
- Create: `crates/server/src/devices.rs`；Modify: `lib.rs`（`pub mod devices;`）
- Modify: `crates/server/src/enroll.rs`、`crates/server/src/groups.rs`
- Modify: `crates/server/tests/enroll.rs`

**Interfaces:**
- Produces:
  - `enroll::match_device(candidates: &[(Uuid, Option<String>)], bios_serial: Option<&str>) -> DeviceMatch`；`DeviceMatch::{SameHardware(Uuid), NewDuplicateSuspect, New}`
  - `devices::approve(pool, pending_id: Uuid, actor: &str) -> anyhow::Result<Uuid>`（回傳舊裝置 id）
  - `devices::approve_in(conn: &mut PgConnection, pending_id, actor) -> anyhow::Result<Uuid>`
  - `devices::reject(pool, pending_id, actor) -> anyhow::Result<()>`
  - `devices::retire(pool, id, actor) -> anyhow::Result<()>`
  - `groups::move_device(pool, device_id: Uuid, group_id: Option<i64>, actor: &str) -> anyhow::Result<()>`

- [ ] **Step 1: 改寫 enroll 單元測試**

`match_device` 測試改為兩欄位 tuple；刪除 `recently_seen_device_is_never_taken_over`；`same_serial_reuses` 改為：

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

- [ ] **Step 2: 改寫整合測試**（`tests/enroll.rs`）

刪除 `reenroll_same_hardware_reuses_device_and_revokes_old_cert` 與 `active_device_is_not_taken_over_by_same_hardware_ids`，改為：

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
    assert_eq!(
        status_of(&s, new.device_id).await,
        ("pending_approval".into(), Some(old.device_id))
    );
    assert_eq!(checkin_status(&s, &old).await, 200, "舊裝置不受影響");
    assert_eq!(checkin_status(&s, &new).await, 200, "待核准裝置可報到");
}

#[sqlx::test(migrations = false)]
async fn approve_moves_new_cert_to_old_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let merged = endpoint_server::devices::approve(&s.pool, new.device_id, "tester")
        .await
        .unwrap();
    assert_eq!(merged, old.device_id);
    assert_eq!(checkin_status(&s, &old).await, 401, "舊憑證失效");
    assert_eq!(checkin_status(&s, &new).await, 200, "新憑證可用");
    let owner: uuid::Uuid =
        sqlx::query_scalar("SELECT device_id FROM device_certs WHERE revoked_at IS NULL")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(owner, old.device_id, "資料歸到舊裝置");
    let (n, grouped): (i64, i64) =
        sqlx::query_as("SELECT count(*), count(group_id) FROM devices")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((n, grouped), (1, 1), "待核准記錄已刪除，舊裝置保留群組");
    assert_eq!(status_of(&s, old.device_id).await.0, "active");
}

#[sqlx::test(migrations = false)]
async fn reject_revokes_pending_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let old = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let new = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    endpoint_server::devices::reject(&s.pool, new.device_id, "tester")
        .await
        .unwrap();
    assert_eq!(checkin_status(&s, &new).await, 401);
    assert_eq!(checkin_status(&s, &old).await, 200);
    assert_eq!(status_of(&s, new.device_id).await.0, "retired");
}

#[sqlx::test(migrations = false)]
async fn retire_revokes_all_certs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    endpoint_server::devices::retire(&s.pool, a.device_id, "tester")
        .await
        .unwrap();
    assert_eq!(checkin_status(&s, &a).await, 401);
    let action: String =
        sqlx::query_scalar("SELECT action FROM audit_log ORDER BY id DESC LIMIT 1")
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
    assert!(
        endpoint_server::devices::approve(&s.pool, a.device_id, "tester")
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = false)]
async fn move_device_changes_group_and_audits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let mut c = s.pool.acquire().await.unwrap();
    let kh = endpoint_server::groups::find_or_create(&mut c, "高雄廠").await.unwrap();
    endpoint_server::groups::move_device(&s.pool, a.device_id, Some(kh), "tester")
        .await
        .unwrap();
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, Some(kh));
}
```

- [ ] **Step 3: 確認失敗**

Run: `cargo test -p endpoint-server --test enroll; cargo test -p endpoint-server --lib enroll`
Expected: 編譯失敗。

- [ ] **Step 4: 實作 enroll 修改**

```rust
/// 候選裝置：(id, bios_serial)。
pub fn match_device(candidates: &[(Uuid, Option<String>)], bios_serial: Option<&str>) -> DeviceMatch {
    if let Some(serial) = normalize_serial(bios_serial)
        && let Some((id, _)) = candidates.iter().find(|(_, s)| s.as_deref() == Some(serial))
    {
        return DeviceMatch::SameHardware(*id);
    }
    if candidates.is_empty() { DeviceMatch::New } else { DeviceMatch::NewDuplicateSuspect }
}
```

候選查詢改為 `SELECT id, bios_serial FROM devices WHERE smbios_uuid = $1 AND status IN ('active', 'duplicate_suspect') FOR UPDATE`（`Vec<(Uuid, Option<String>)>`）。handler 內一律新建裝置：

```rust
    let (status, reenroll_of) = match match_device(&candidates, serial) {
        DeviceMatch::SameHardware(old) => ("pending_approval", Some(old)),
        DeviceMatch::NewDuplicateSuspect => ("duplicate_suspect", None),
        DeviceMatch::New => ("active", None),
    };
    let device_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO devices (id, hostname, smbios_uuid, bios_serial, status, enroll_token_id, group_id, reenroll_of) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(device_id).bind(&req.hostname).bind(&smbios).bind(serial)
    .bind(status).bind(token_id).bind(group_id).bind(reenroll_of)
    .execute(&mut *tx)
    .await?;
```

- [ ] **Step 5: 實作 `devices.rs`**

```rust
//! 裝置生命週期：核准／拒絕重新註冊、除役。每個動作都寫入 audit_log。
//! 權限（角色、群組範圍）由網頁層檢查。

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

pub async fn approve_in(conn: &mut PgConnection, pending: Uuid, actor: &str) -> anyhow::Result<Uuid> {
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
        .bind(old).bind(pending).execute(&mut *conn).await?;
    // 清空舊裝置的區段 hash：Agent 下次報到時伺服器會要求重新上傳全部區段
    sqlx::query("DELETE FROM inventory_sections WHERE device_id = $1")
        .bind(old).execute(&mut *conn).await?;
    sqlx::query("UPDATE devices SET status = 'active', hostname = $2 WHERE id = $1")
        .bind(old).bind(&hostname).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(pending).execute(&mut *conn).await?;
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

pub async fn reject(pool: &PgPool, pending: Uuid, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1 AND status = 'pending_approval'")
        .bind(pending).execute(&mut *tx).await?.rows_affected();
    anyhow::ensure!(n == 1, "device is not pending approval");
    revoke_certs(&mut tx, pending).await?;
    audit::record(&mut tx, actor, "device_reject", Some(&pending.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn retire(pool: &PgPool, id: Uuid, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1 AND status <> 'retired'")
        .bind(id).execute(&mut *tx).await?.rows_affected();
    anyhow::ensure!(n == 1, "device not found or already retired");
    revoke_certs(&mut tx, id).await?;
    audit::record(&mut tx, actor, "device_retire", Some(&id.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}
```

`groups.rs` 追加：

```rust
pub async fn move_device(pool: &PgPool, device_id: uuid::Uuid, group_id: Option<i64>, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE devices SET group_id = $2 WHERE id = $1")
        .bind(device_id).bind(group_id).execute(&mut *tx).await?.rows_affected();
    anyhow::ensure!(n == 1, "device not found");
    crate::audit::record(&mut tx, actor, "device_move", Some(&device_id.to_string()),
        serde_json::json!({ "group_id": group_id })).await?;
    tx.commit().await?;
    Ok(())
}
```

- [ ] **Step 6: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(server): 重新註冊需核准，新增核准／拒絕／除役與移動群組"
```

---

### Task 3: 帳號、角色與權限範圍

**Files:**
- Create: `crates/server/src/accounts.rs`、`crates/server/src/web/mod.rs`（先只有 `pub mod auth;`）、`crates/server/src/web/auth.rs`
- Modify: `lib.rs`（`pub mod accounts; pub mod web;`）、`main.rs`（`admin-create`）

**Interfaces:**
- Produces:
  - `web::auth::Role { Platform, GroupAdmin, Viewer }`：`as_str()`（`platform_admin`／`group_admin`／`viewer`）、`parse(&str) -> Option<Role>`、`label()`（平台管理員／群組管理員／唯讀檢視者）、`ALL: [Role; 3]`
  - `web::auth::MIN_PASSWORD_LEN = 12`、`hash_password(pw) -> anyhow::Result<String>`、`verify_password(pw, phc) -> bool`
  - `accounts::NewAdmin { username: String, password: String, role: Role, groups: Vec<i64> }`
  - `accounts::create(pool, a: &NewAdmin, actor: &str) -> anyhow::Result<i64>`
  - `accounts::update(pool, id: i64, role: Role, groups: &[i64], actor_id: i64, actor: &str) -> anyhow::Result<()>`
  - `accounts::set_disabled(pool, id, disabled: bool, actor_id, actor) -> anyhow::Result<()>`
  - `accounts::reset_password(pool, id, new_password: &str, actor) -> anyhow::Result<()>`（同時解除鎖定）
  - `accounts::unlock(pool, id, actor) -> anyhow::Result<()>`
  - `accounts::change_own_password(pool, admin_id, current: &str, new: &str, keep_token_hash: &str) -> anyhow::Result<()>`（驗證目前密碼；刪除自己其他的工作階段）
  - 規則：群組管理員／檢視者至少一個群組；不能停用自己、不能變更自己的角色；變更後至少保留一個啟用中的平台管理員；停用／變更角色群組／重設密碼時刪除對方所有工作階段
  - CLI：`endpoint-server admin-create <username>`（平台管理員，密碼從標準輸入讀一行）

- [ ] **Step 1: 寫失敗測試**（`accounts.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::Role;

    async fn setup(pool: &PgPool) -> (i64, i64) {
        crate::db::migrate(pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let g = crate::groups::find_or_create(&mut c, "台北總部").await.unwrap();
        let root = create(pool, &NewAdmin {
            username: "root".into(), password: "root-long-password".into(), role: Role::Platform, groups: vec![],
        }, "cli").await.unwrap();
        (root, g)
    }

    #[test]
    fn hash_roundtrip() {
        let h = crate::web::auth::hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(crate::web::auth::verify_password("correct horse battery", &h));
        assert!(!crate::web::auth::verify_password("wrong password!!", &h));
        assert!(!crate::web::auth::verify_password("x", "not a phc string"));
    }

    #[sqlx::test(migrations = false)]
    async fn create_validates(pool: PgPool) {
        let (_, g) = setup(&pool).await;
        let mk = |pw: &str, role, groups: Vec<i64>| NewAdmin {
            username: "bob".into(), password: pw.into(), role, groups,
        };
        assert!(create(&pool, &mk("short", Role::Viewer, vec![g]), "root").await.is_err(), "密碼太短");
        assert!(create(&pool, &mk("bob-long-password", Role::GroupAdmin, vec![]), "root").await.is_err(), "需要群組");
        create(&pool, &mk("bob-long-password", Role::GroupAdmin, vec![g]), "root").await.unwrap();
        assert!(create(&pool, &mk("bob-long-password", Role::Viewer, vec![g]), "root").await.is_err(), "帳號重複");
    }

    #[sqlx::test(migrations = false)]
    async fn last_platform_admin_is_protected(pool: PgPool) {
        let (root, g) = setup(&pool).await;
        assert!(set_disabled(&pool, root, true, root, "root").await.is_err(), "不能停用自己");
        assert!(update(&pool, root, Role::Viewer, &[g], root, "root").await.is_err(), "不能改自己的角色");
        let other = create(&pool, &NewAdmin {
            username: "ops".into(), password: "ops-long-password".into(), role: Role::Platform, groups: vec![],
        }, "root").await.unwrap();
        // ops 降級 root 可以（還剩 ops）；root 再降級 ops 不行（會沒有平台管理員）
        update(&pool, root, Role::Viewer, &[g], other, "ops").await.unwrap();
        assert!(set_disabled(&pool, other, true, root, "root").await.is_err());
    }

    #[sqlx::test(migrations = false)]
    async fn change_own_password_checks_current(pool: PgPool) {
        let (root, _) = setup(&pool).await;
        assert!(change_own_password(&pool, root, "wrong-password-xx", "new-long-password", "x").await.is_err());
        assert!(change_own_password(&pool, root, "root-long-password", "short", "x").await.is_err());
        change_own_password(&pool, root, "root-long-password", "new-long-password", "x").await.unwrap();
        let hash: String = sqlx::query_scalar("SELECT password_hash FROM admins WHERE id = $1")
            .bind(root).fetch_one(&pool).await.unwrap();
        assert!(crate::web::auth::verify_password("new-long-password", &hash));
    }
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --lib accounts`
Expected: 編譯失敗。

- [ ] **Step 3: 實作 `web/auth.rs`（角色與密碼部分）**

```rust
//! 管理員角色、密碼、工作階段與 CSRF。

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use uuid::Uuid;

pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Platform,
    GroupAdmin,
    Viewer,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Platform, Role::GroupAdmin, Role::Viewer];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Platform => "platform_admin",
            Role::GroupAdmin => "group_admin",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Role::Platform => "平台管理員",
            Role::GroupAdmin => "群組管理員",
            Role::Viewer => "唯讀檢視者",
        }
    }
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = Uuid::new_v4().into_bytes();
    Ok(Argon2::default()
        .hash_password_with_salt(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}
```

> argon2 0.6 的 trait 路徑以 context7 `/rustcrypto/password-hashes` 為準；若不同請調整並記 ruling。

- [ ] **Step 4: 實作 `accounts.rs`**

```rust
//! 管理員帳號規則。權限（只有平台管理員能呼叫）由網頁層檢查。

use anyhow::{Context, ensure};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::web::auth::{MIN_PASSWORD_LEN, Role, hash_password, verify_password};

pub struct NewAdmin {
    pub username: String,
    pub password: String,
    pub role: Role,
    pub groups: Vec<i64>,
}

fn check_password(pw: &str) -> anyhow::Result<()> {
    ensure!(pw.chars().count() >= MIN_PASSWORD_LEN, "密碼至少 {MIN_PASSWORD_LEN} 字元");
    Ok(())
}

fn check_role_groups(role: Role, groups: &[i64]) -> anyhow::Result<()> {
    ensure!(role == Role::Platform || !groups.is_empty(), "群組管理員與唯讀檢視者至少要指派一個群組");
    Ok(())
}

async fn set_groups(conn: &mut PgConnection, id: i64, role: Role, groups: &[i64]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM admin_groups WHERE admin_id = $1").bind(id).execute(&mut *conn).await?;
    if role != Role::Platform {
        sqlx::query("INSERT INTO admin_groups (admin_id, group_id) SELECT $1, unnest($2::bigint[])")
            .bind(id).bind(groups).execute(&mut *conn).await?;
    }
    Ok(())
}

async fn kill_sessions(conn: &mut PgConnection, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1").bind(id).execute(conn).await?;
    Ok(())
}

/// 交易結束前確認至少還有一個啟用中的平台管理員。
async fn ensure_platform_admin_left(conn: &mut PgConnection) -> anyhow::Result<()> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admins WHERE role = 'platform_admin' AND disabled_at IS NULL",
    )
    .fetch_one(conn)
    .await?;
    ensure!(n >= 1, "至少要保留一個啟用中的平台管理員");
    Ok(())
}

pub async fn create(pool: &PgPool, a: &NewAdmin, actor: &str) -> anyhow::Result<i64> {
    let username = a.username.trim();
    ensure!(!username.is_empty() && username.chars().count() <= 64, "帳號必填，最多 64 字");
    check_password(&a.password)?;
    check_role_groups(a.role, &a.groups)?;
    let hash = hash_password(&a.password)?;
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO admins (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(username).bind(hash).bind(a.role.as_str())
    .fetch_one(&mut *tx).await.context("帳號已存在")?;
    set_groups(&mut tx, id, a.role, &a.groups).await?;
    audit::record(&mut tx, actor, "admin_create", Some(username),
        serde_json::json!({ "role": a.role.as_str(), "groups": a.groups })).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update(pool: &PgPool, id: i64, role: Role, groups: &[i64], actor_id: i64, actor: &str) -> anyhow::Result<()> {
    check_role_groups(role, groups)?;
    let mut tx = pool.begin().await?;
    let current: String = sqlx::query_scalar("SELECT role FROM admins WHERE id = $1 FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await?.context("帳號不存在")?;
    ensure!(id != actor_id || current == role.as_str(), "不能變更自己的角色");
    sqlx::query("UPDATE admins SET role = $2 WHERE id = $1").bind(id).bind(role.as_str()).execute(&mut *tx).await?;
    set_groups(&mut tx, id, role, groups).await?;
    if id != actor_id {
        kill_sessions(&mut tx, id).await?;
    }
    ensure_platform_admin_left(&mut tx).await?;
    audit::record(&mut tx, actor, "admin_update", Some(&id.to_string()),
        serde_json::json!({ "role": role.as_str(), "groups": groups })).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_disabled(pool: &PgPool, id: i64, disabled: bool, actor_id: i64, actor: &str) -> anyhow::Result<()> {
    ensure!(id != actor_id, "不能停用或啟用自己");
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE admins SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) ELSE NULL END WHERE id = $1",
    )
    .bind(id).bind(disabled).execute(&mut *tx).await?.rows_affected();
    ensure!(n == 1, "帳號不存在");
    kill_sessions(&mut tx, id).await?;
    ensure_platform_admin_left(&mut tx).await?;
    audit::record(&mut tx, actor, if disabled { "admin_disable" } else { "admin_enable" },
        Some(&id.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn reset_password(pool: &PgPool, id: i64, new_password: &str, actor: &str) -> anyhow::Result<()> {
    check_password(new_password)?;
    let hash = hash_password(new_password)?;
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE admins SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(id).bind(hash).execute(&mut *tx).await?.rows_affected();
    ensure!(n == 1, "帳號不存在");
    kill_sessions(&mut tx, id).await?;
    audit::record(&mut tx, actor, "admin_password_reset", Some(&id.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn unlock(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(id).execute(&mut *tx).await?.rows_affected();
    ensure!(n == 1, "帳號不存在");
    audit::record(&mut tx, actor, "admin_unlock", Some(&id.to_string()), serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn change_own_password(
    pool: &PgPool,
    admin_id: i64,
    current: &str,
    new: &str,
    keep_token_hash: &str,
) -> anyhow::Result<()> {
    check_password(new)?;
    let (username, hash): (String, String) =
        sqlx::query_as("SELECT username, password_hash FROM admins WHERE id = $1")
            .bind(admin_id).fetch_one(pool).await?;
    ensure!(verify_password(current, &hash), "目前密碼錯誤");
    let new_hash = hash_password(new)?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE admins SET password_hash = $2 WHERE id = $1")
        .bind(admin_id).bind(new_hash).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1 AND token_hash <> $2")
        .bind(admin_id).bind(keep_token_hash).execute(&mut *tx).await?;
    audit::record(&mut tx, &username, "password_change", None, serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(())
}
```

`main.rs` 加 `admin-create`：

```rust
        Some("admin-create") if args.len() >= 2 => {
            let cfg = Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            endpoint_server::db::migrate(&pool).await?;
            eprintln!("輸入密碼（至少 {} 字元）：", endpoint_server::web::auth::MIN_PASSWORD_LEN);
            let mut pw = String::new();
            std::io::stdin().read_line(&mut pw)?;
            let id = endpoint_server::accounts::create(
                &pool,
                &endpoint_server::accounts::NewAdmin {
                    username: args[1].clone(),
                    password: pw.trim_end_matches(['\r', '\n']).to_string(),
                    role: endpoint_server::web::auth::Role::Platform,
                    groups: vec![],
                },
                "cli",
            )
            .await?;
            println!("platform admin id {id} created");
            Ok(())
        }
```

USAGE 加一行 `endpoint-server admin-create <username>   (password from stdin)`。

- [ ] **Step 5: 測試**

Run: `cargo test -p endpoint-server --lib`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(server): 管理員帳號、三種角色與帳號規則"
```

---

### Task 4: 工作階段、登入鎖定、CSRF、權限範圍

**Files:**
- Modify: `crates/server/src/web/auth.rs`

**Interfaces:**
- Produces:
  - 常數：`SESSION_COOKIE = "em_session"`、`SESSION_HOURS = 8`、`MAX_FAILED_LOGINS = 5`、`LOCK_MINUTES = 15`
  - `LoginOutcome { Ok { session_token: String }, Failed }`、`login(pool, username, password) -> anyhow::Result<LoginOutcome>`
  - `Session { admin_id: i64, username: String, csrf: String, token_hash: String, role: Role, groups: Vec<i64> }`，方法：`all_devices(&self) -> bool`（平台管理員）、`can_manage(&self) -> bool`（非檢視者）、`in_scope(&self, group: Option<i64>) -> bool`
  - `lookup_session(pool, token) -> Result<Option<Session>, sqlx::Error>`、`logout(pool, &Session)`
  - `csrf_ok(expected, got) -> bool`、`session_cookie(token) -> String`、`clear_cookie() -> &'static str`

- [ ] **Step 1: 寫失敗測試**（`web/auth.rs` 測試模組）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{NewAdmin, create};

    async fn setup(pool: &PgPool) -> i64 {
        crate::db::migrate(pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let g = crate::groups::find_or_create(&mut c, "台北總部").await.unwrap();
        create(pool, &NewAdmin {
            username: "alice".into(), password: "alice-long-password".into(), role: Role::GroupAdmin, groups: vec![g],
        }, "cli").await.unwrap();
        g
    }

    async fn ok(pool: &PgPool, pw: &str) -> Option<String> {
        match login(pool, "alice", pw).await.unwrap() {
            LoginOutcome::Ok { session_token } => Some(session_token),
            LoginOutcome::Failed => None,
        }
    }

    #[sqlx::test(migrations = false)]
    async fn login_creates_scoped_session(pool: PgPool) {
        let g = setup(&pool).await;
        let token = ok(&pool, "alice-long-password").await.expect("login");
        let s = lookup_session(&pool, &token).await.unwrap().unwrap();
        assert_eq!((s.username.as_str(), s.role), ("alice", Role::GroupAdmin));
        assert_eq!(s.groups, vec![g]);
        assert!(s.in_scope(Some(g)) && !s.in_scope(Some(g + 1)) && !s.in_scope(None));
        assert!(!s.all_devices() && s.can_manage());
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM sessions").fetch_one(&pool).await.unwrap();
        assert_ne!(stored, token, "只存 hash");
        logout(&pool, &s).await.unwrap();
        assert!(lookup_session(&pool, &token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn lockout_after_five_failures(pool: PgPool) {
        setup(&pool).await;
        for _ in 0..MAX_FAILED_LOGINS {
            assert!(ok(&pool, "nope-nope-nope").await.is_none());
        }
        assert!(ok(&pool, "alice-long-password").await.is_none(), "鎖定期間正確密碼也不行");
        sqlx::query("UPDATE admins SET locked_until = now() - interval '1 second'").execute(&pool).await.unwrap();
        assert!(ok(&pool, "alice-long-password").await.is_some());
    }

    #[sqlx::test(migrations = false)]
    async fn disabled_unknown_and_expired(pool: PgPool) {
        setup(&pool).await;
        assert!(matches!(login(&pool, "mallory", "whatever-password").await.unwrap(), LoginOutcome::Failed));
        let token = ok(&pool, "alice-long-password").await.unwrap();
        sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'").execute(&pool).await.unwrap();
        assert!(lookup_session(&pool, &token).await.unwrap().is_none());
        sqlx::query("UPDATE admins SET disabled_at = now()").execute(&pool).await.unwrap();
        assert!(ok(&pool, "alice-long-password").await.is_none());
    }

    #[test]
    fn csrf_compare() {
        assert!(csrf_ok("abc", "abc"));
        assert!(!csrf_ok("abc", "abd"));
        assert!(!csrf_ok("abc", ""));
    }
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --lib web::auth`
Expected: 編譯失敗。

- [ ] **Step 3: 實作**（附加到 `web/auth.rs`）

```rust
use chrono::{DateTime, Utc};
use sqlx::PgPool;

pub const SESSION_COOKIE: &str = "em_session";
pub const SESSION_HOURS: i32 = 8;
pub const MAX_FAILED_LOGINS: i32 = 5;
pub const LOCK_MINUTES: i32 = 15;

pub enum LoginOutcome {
    Ok { session_token: String },
    Failed,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub admin_id: i64,
    pub username: String,
    pub csrf: String,
    pub token_hash: String,
    pub role: Role,
    pub groups: Vec<i64>,
}

impl Session {
    pub fn all_devices(&self) -> bool {
        self.role == Role::Platform
    }

    pub fn can_manage(&self) -> bool {
        self.role != Role::Viewer
    }

    pub fn in_scope(&self, group: Option<i64>) -> bool {
        self.all_devices() || group.is_some_and(|g| self.groups.contains(&g))
    }
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// 帳號不存在時也做一次雜湊，避免以回應時間判斷帳號是否存在。
fn dummy_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| hash_password("dummy-password-for-timing").expect("hash"))
}

pub async fn login(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<LoginOutcome> {
    let row: Option<(i64, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, password_hash, locked_until FROM admins WHERE username = $1 AND disabled_at IS NULL",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?;
    let Some((admin_id, hash, locked_until)) = row else {
        verify_password(password, dummy_hash());
        let mut c = pool.acquire().await?;
        crate::audit::record(&mut c, username, "login_failed", None, serde_json::json!({ "reason": "unknown_or_disabled" })).await?;
        return Ok(LoginOutcome::Failed);
    };
    let locked = locked_until.is_some_and(|t| t > Utc::now());
    let ok = verify_password(password, &hash) && !locked;

    let mut tx = pool.begin().await?;
    if !ok {
        sqlx::query(
            "UPDATE admins SET \
               locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + make_interval(mins => $3) ELSE locked_until END, \
               failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END \
             WHERE id = $1",
        )
        .bind(admin_id).bind(MAX_FAILED_LOGINS).bind(LOCK_MINUTES)
        .execute(&mut *tx).await?;
        let reason = if locked { "locked" } else { "password" };
        crate::audit::record(&mut tx, username, "login_failed", None, serde_json::json!({ "reason": reason })).await?;
        tx.commit().await?;
        return Ok(LoginOutcome::Failed);
    }
    sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(admin_id).execute(&mut *tx).await?;
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO sessions (token_hash, admin_id, csrf_token, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(hours => $4))",
    )
    .bind(sha256_hex(&token)).bind(admin_id).bind(Uuid::new_v4().simple().to_string()).bind(SESSION_HOURS)
    .execute(&mut *tx).await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()").execute(&mut *tx).await?;
    crate::audit::record(&mut tx, username, "login", None, serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(LoginOutcome::Ok { session_token: token })
}

pub async fn lookup_session(pool: &PgPool, token: &str) -> Result<Option<Session>, sqlx::Error> {
    let hash = sha256_hex(token);
    let row: Option<(i64, String, String, String, Vec<i64>)> = sqlx::query_as(
        "SELECT a.id, a.username, s.csrf_token, a.role, \
                ARRAY(SELECT group_id FROM admin_groups g WHERE g.admin_id = a.id ORDER BY group_id) \
         FROM sessions s JOIN admins a ON a.id = s.admin_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() AND a.disabled_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(admin_id, username, csrf, role, groups)| {
        Some(Session { admin_id, username, csrf, token_hash: hash.clone(), role: Role::parse(&role)?, groups })
    }))
}

pub async fn logout(pool: &PgPool, s: &Session) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(&s.token_hash).execute(&mut *tx).await?;
    crate::audit::record(&mut tx, &s.username, "logout", None, serde_json::json!({})).await?;
    tx.commit().await
}

pub fn csrf_ok(expected: &str, got: &str) -> bool {
    expected.len() == got.len()
        && expected.bytes().zip(got.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

pub fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", SESSION_HOURS * 3600)
}

pub fn clear_cookie() -> &'static str {
    "em_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
}
```

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server --lib`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(server): 工作階段、登入鎖定、CSRF 與權限範圍"
```

---

### Task 5: 網頁骨架：監聽埠、安全標頭、版面、登入／登出

**Files:**
- Create: `crates/server/static/htmx.min.js`（下載）、`crates/server/static/app.css`
- Create: `templates/base.html`、`templates/login.html`、`templates/dashboard.html`（先空殼）
- Modify: `src/web/mod.rs`、`src/web/auth.rs`（`AdminSession`、`check_csrf`、`Nav`）
- Create: `src/web/login.rs`、`src/web/dashboard.rs`
- Modify: `src/tls.rs`（`web_server_config`）、`src/lib.rs`（`AppState.display_offset`）
- Modify: `tests/common/mod.rs`；Create: `tests/web.rs`

**Interfaces:**
- Produces:
  - `tls::web_server_config(ca_dir) -> anyhow::Result<Arc<ServerConfig>>`
  - `AppState.display_offset: FixedOffset`（預設 +8）、`AppState::with_display_offset(self, hours: i32) -> Self`
  - `web::web_router(state) -> Router`
  - `web::render(&T) -> Response`、`web::fmt_time(&AppState, Option<DateTime<Utc>>) -> String`、`web::escape_like(&str) -> String`、`web::enc(&str) -> String`（URL query 編碼）
  - `web::forbidden() -> Response`（403 頁）、`web::not_found() -> Response`（404）
  - `web::auth::AdminSession(pub Session)`（未登入 → 303 `/login`）
  - `web::auth::check_csrf(&Session, &str) -> Result<(), Response>`
  - `web::auth::Nav { logged_in: bool, user: String, role: &'static str, csrf: String, platform: bool, manage: bool }`；`Nav::anonymous()`、`Nav::from(&Session)`
  - `web::login::CsrfForm { csrf: String }`
  - 測試：`TestServer.web_addr`、`web_url`、`web_client()`、`page(&client, path) -> (u16, String)`、`login_as(username, role, groups: &[&str]) -> reqwest::Client`（建立帳號並登入；群組不存在則建立）、`admin_client()`（= `login_as("admin", Platform, &[])`）、`common::csrf_from(&str) -> String`

- [ ] **Step 1: 下載 htmx、建立 CSS**

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
.online { color: var(--ok); } .offline { color: var(--muted); } .pending_approval, .duplicate_suspect, .locked { color: var(--warn); } .retired, .disabled { color: var(--bad); }
.error { color: var(--bad); }
.notice { border: 1px solid var(--warn); padding: .6rem 1rem; border-radius: 6px; word-break: break-all; }
form.inline { display: inline; }
fieldset { border: 1px solid var(--line); border-radius: 6px; margin: 1rem 0; }
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
<title>Endpoint Manager</title>
<link rel="stylesheet" href="/static/app.css">
<script src="/static/htmx.min.js" defer></script>
</head>
<body>
{% if nav.logged_in %}
<header>
  <strong>Endpoint Manager</strong>
  <nav>
    <a href="/">儀表板</a>
    <a href="/devices">裝置</a>
    <a href="/software">軟體搜尋</a>
    {% if nav.manage %}<a href="/tokens">註冊金鑰</a>{% endif %}
    {% if nav.platform %}<a href="/groups">群組</a><a href="/accounts">帳號</a><a href="/audit">稽核記錄</a>{% endif %}
  </nav>
  <a href="/password">{{ nav.user }}（{{ nav.role }}）</a>
  <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button>登出</button></form>
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

`templates/dashboard.html`（Task 6 補完）：

```html
{% extends "base.html" %}
{% block content %}
<h1>儀表板</h1>
{% endblock %}
```

- [ ] **Step 3: 寫失敗測試**

`tests/common/mod.rs`：

1. `TestServer` 加 `pub web_addr: SocketAddr`；`start_with` 在 agent 監聽之後：

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

2. 新增：

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

    pub async fn page(&self, c: &reqwest::Client, path: &str) -> (u16, String) {
        let r = c.get(self.web_url(path)).send().await.unwrap();
        (r.status().as_u16(), r.text().await.unwrap())
    }

    pub async fn group_id(&self, name: &str) -> i64 {
        let mut c = self.pool.acquire().await.unwrap();
        endpoint_server::groups::find_or_create(&mut c, name).await.unwrap()
    }

    /// 建立帳號（密碼 = 帳號 + "-long-password"）並登入。
    pub async fn login_as(&self, username: &str, role: endpoint_server::web::auth::Role, groups: &[&str]) -> reqwest::Client {
        let mut ids = vec![];
        for g in groups {
            ids.push(self.group_id(g).await);
        }
        let password = format!("{username}-long-password");
        let _ = endpoint_server::accounts::create(
            &self.pool,
            &endpoint_server::accounts::NewAdmin { username: username.into(), password: password.clone(), role, groups: ids },
            "test",
        )
        .await;
        let c = self.web_client();
        let r = c
            .post(self.web_url("/login"))
            .form(&[("username", username), ("password", password.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303, "login should redirect");
        c
    }

    pub async fn admin_client(&self) -> reqwest::Client {
        self.login_as("admin", endpoint_server::web::auth::Role::Platform, &[]).await
    }
```

```rust
/// 從頁面 HTML 取出第一個 csrf 隱藏欄位的值。
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
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn pages_require_login(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    for path in ["/", "/devices", "/software", "/tokens", "/groups", "/accounts", "/audit", "/password"] {
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
    assert!(html.contains("儀表板") && html.contains("平台管理員"));

    let csrf = csrf_from(&html);
    let r = c.post(s.web_url("/logout")).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(c.get(s.web_url("/")).send().await.unwrap().status(), 303, "logged out");
}

#[sqlx::test(migrations = false)]
async fn wrong_password_and_locked_show_generic_error(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.admin_client().await;
    let try_login = |pw: &'static str| {
        let c = s.web_client();
        let url = s.web_url("/login");
        async move {
            let r = c.post(url).form(&[("username", "admin"), ("password", pw)]).send().await.unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    let (status, html) = try_login("wrong-password-xx").await;
    assert_eq!(status, 401);
    assert!(html.contains("帳號或密碼錯誤"));
    sqlx::query("UPDATE admins SET locked_until = now() + interval '10 minutes'").execute(&s.pool).await.unwrap();
    let (status, html) = try_login("admin-long-password").await;
    assert_eq!(status, 401);
    assert!(html.contains("帳號或密碼錯誤"));
}

#[sqlx::test(migrations = false)]
async fn post_without_csrf_is_403(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let r = c.post(s.web_url("/logout")).form(&[("csrf", "forged")]).send().await.unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(c.get(s.web_url("/")).send().await.unwrap().status(), 200, "session still valid");
}

#[sqlx::test(migrations = false)]
async fn nav_depends_on_role(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let v = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&v, "/").await;
    assert!(!html.contains(r#"href="/tokens""#) && !html.contains(r#"href="/accounts""#));
    let g = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&g, "/").await;
    assert!(html.contains(r#"href="/tokens""#) && !html.contains(r#"href="/accounts""#));
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
Expected: 編譯失敗。

- [ ] **Step 5: 實作**

`tls.rs` 加：

```rust
/// 管理網頁用：只提供伺服器憑證，不要求用戶端憑證。
pub fn web_server_config(ca_dir: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    let certs = CertificateDer::pem_file_iter(ca_dir.join("server.pem"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(ca_dir.join("server.key"))?;
    let mut cfg = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
```

`lib.rs`：`AppState` 加 `pub display_offset: chrono::FixedOffset`（`new` 設 `FixedOffset::east_opt(8 * 3600).expect("valid")`）與：

```rust
    pub fn with_display_offset(mut self, hours: i32) -> Self {
        if let Some(o) = chrono::FixedOffset::east_opt(hours * 3600) {
            self.display_offset = o;
        }
        self
    }
```

`web/auth.rs` 追加：

```rust
use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use axum::response::{IntoResponse, Redirect, Response};

fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts.headers.get_all(header::COOKIE).iter()
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
    if csrf_ok(&s.csrf, got) { Ok(()) } else { Err(super::forbidden()) }
}

/// 版面共用資訊。
pub struct Nav {
    pub logged_in: bool,
    pub user: String,
    pub role: &'static str,
    pub csrf: String,
    pub platform: bool,
    pub manage: bool,
}

impl Nav {
    pub fn anonymous() -> Nav {
        Nav { logged_in: false, user: String::new(), role: "", csrf: String::new(), platform: false, manage: false }
    }
}

impl From<&Session> for Nav {
    fn from(s: &Session) -> Nav {
        Nav {
            logged_in: true,
            user: s.username.clone(),
            role: s.role.label(),
            csrf: s.csrf.clone(),
            platform: s.all_devices(),
            manage: s.can_manage(),
        }
    }
}
```

`web/mod.rs`：

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

pub fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "權限不足").into_response()
}

pub fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "找不到").into_response()
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

/// URL query 參數編碼。
pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn asset(body: &'static str, content_type: &'static str) -> Response {
    ([(header::CONTENT_TYPE, content_type), (header::CACHE_CONTROL, "public, max-age=86400")], body).into_response()
}

pub fn web_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::page))
        .route("/login", get(login::form).post(login::submit))
        .route("/logout", post(login::logout))
        .route("/static/htmx.min.js", get(|| async {
            asset(include_str!("../../static/htmx.min.js"), "text/javascript; charset=utf-8")
        }))
        .route("/static/app.css", get(|| async {
            asset(include_str!("../../static/app.css"), "text/css; charset=utf-8")
        }))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_helpers() {
        assert_eq!(escape_like("50%_off\\"), "%50\\%\\_off\\\\%");
        assert_eq!(enc("Google Chrome&x"), "Google%20Chrome%26x");
    }
}
```

`web/login.rs`：

```rust
//! 登入與登出。登入表單沒有工作階段可綁 CSRF；cookie 為 SameSite=Strict，
//! 跨站送出的登入只會讓攻擊者登入自己的帳號，影響有限。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{self, AdminSession, LoginOutcome, Nav, check_csrf};
use super::render;
use crate::AppState;
use crate::error::AppError;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    nav: Nav,
    error: Option<&'static str>,
}

pub async fn form() -> Response {
    render(&LoginPage { nav: Nav::anonymous(), error: None })
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

pub async fn submit(State(st): State<AppState>, Form(f): Form<LoginForm>) -> Result<Response, AppError> {
    match auth::login(&st.pool, f.username.trim(), &f.password).await? {
        LoginOutcome::Ok { session_token } => Ok((
            [(header::SET_COOKIE, auth::session_cookie(&session_token))],
            Redirect::to("/"),
        ).into_response()),
        LoginOutcome::Failed => {
            let page = LoginPage { nav: Nav::anonymous(), error: Some("帳號或密碼錯誤") };
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
    auth::logout(&st.pool, &s).await.map_err(|e| AppError::from(e).into_response())?;
    Ok(([(header::SET_COOKIE, auth::clear_cookie())], Redirect::to("/login")).into_response())
}
```

`web/dashboard.rs`（先回空儀表板）：

```rust
//! 儀表板。

use askama::Template;
use axum::response::Response;

use super::auth::{AdminSession, Nav};
use super::render;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: Nav,
}

pub async fn page(AdminSession(s): AdminSession) -> Response {
    render(&DashboardPage { nav: Nav::from(&s) })
}
```

> `Redirect::to` 在 axum 0.8 回 303。`/tokens` 等尚未實作的路徑在 `pages_require_login` 中會 404 → 該測試在 Task 11 前會失敗於未實作的路徑；為讓本 task 可驗證，暫時在 router 加上 `.fallback(|AdminSession(_): AdminSession| async { not_found() })`，未登入時 fallback 也會先轉登入頁。

- [ ] **Step 6: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(server): 管理網頁骨架、安全標頭、登入登出、依角色顯示選單"
```

---

### Task 6: 儀表板與裝置列表（依範圍過濾）

**Files:**
- Modify: `templates/dashboard.html`、`src/web/dashboard.rs`
- Create: `templates/devices.html`、`src/web/devices.rs`；Modify: `src/web/mod.rs`
- Modify: `tests/web.rs`

**Interfaces:**
- Produces:
  - `web::devices::online_cutoff(&AppState) -> Result<DateTime<Utc>, sqlx::Error>`
  - `web::devices::scope_sql()`：所有裝置查詢都用 `($N::bool OR d.group_id = ANY($M::bigint[]))`，綁定 `s.all_devices()`、`&s.groups`
  - `GET /devices?q=&status=&group=&software=&version=&page=`
  - `POST /devices/{id}/approve`、`/devices/{id}/reject`（需 `can_manage` 且新、舊裝置都在範圍內）、`POST /devices/approve-all`（只核准範圍內的）

- [ ] **Step 1: 寫失敗測試**（附加到 `tests/web.rs`）

```rust
#[sqlx::test(migrations = false)]
async fn dashboard_counts_and_device_list(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("裝置總數"));
    let (status, html) = s.page(&c, "/devices").await;
    assert_eq!(status, 200);
    assert!(html.contains("PC-001") && html.contains("台北總部"));
    assert!(html.contains(&format!("/devices/{}", a.device_id)));
}

#[sqlx::test(migrations = false)]
async fn group_admin_sees_only_own_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 1).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    let mine = s.enroll_ok(&tp, None, None).await;
    let other = s.enroll_ok(&kh, None, None).await;
    let c = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;

    let (_, html) = s.page(&c, "/devices").await;
    assert!(html.contains(&mine.device_id.to_string()));
    assert!(!html.contains(&other.device_id.to_string()));
    let (_, html) = s.page(&c, "/devices?status=all").await;
    assert!(!html.contains(&other.device_id.to_string()));
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("<b>1</b>"), "儀表板只算自己群組：{html}");
}

#[sqlx::test(migrations = false)]
async fn hostile_hostname_is_escaped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE devices SET hostname = '<script>alert(1)</script>', logged_on_user = '\"><img src=x onerror=alert(1)>' WHERE id = $1")
        .bind(a.device_id).execute(&s.pool).await.unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices").await;
    assert!(!html.contains("<script>alert(1)"));
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&lt;script&gt;"));
}

#[sqlx::test(migrations = false)]
async fn search_treats_wildcards_literally(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    for (id, name) in [(a.device_id, "SALES_01"), (b.device_id, "SALESX01")] {
        sqlx::query("UPDATE devices SET hostname = $2 WHERE id = $1").bind(id).bind(name).execute(&s.pool).await.unwrap();
    }
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices?q=SALES_").await;
    assert!(html.contains("SALES_01"));
    assert!(!html.contains("SALESX01"));
}

#[sqlx::test(migrations = false)]
async fn approvals_respect_role_and_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 5).await;
    let kh = s.create_group_token("高雄廠", 5).await;
    let _ = s.enroll_ok(&tp, Some("UUID-T"), Some("SN-T")).await;
    let tp_new = s.enroll_ok(&tp, Some("UUID-T"), Some("SN-T")).await;
    let _ = s.enroll_ok(&kh, Some("UUID-K"), Some("SN-K")).await;
    let kh_new = s.enroll_ok(&kh, Some("UUID-K"), Some("SN-K")).await;

    let viewer = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&viewer, "/").await;
    let r = viewer
        .post(s.web_url(&format!("/devices/{}/approve", tp_new.device_id)))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send().await.unwrap();
    assert_eq!(r.status(), 403, "檢視者不能核准");

    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&gary, "/").await;
    let csrf = csrf_from(&html);
    let r = gary
        .post(s.web_url(&format!("/devices/{}/approve", kh_new.device_id)))
        .form(&[("csrf", csrf.as_str())])
        .send().await.unwrap();
    assert_eq!(r.status(), 404, "別的群組當作不存在");
    let r = gary.post(s.web_url("/devices/approve-all")).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let pending: Vec<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM devices WHERE status = 'pending_approval'")
        .fetch_all(&s.pool).await.unwrap();
    assert_eq!(pending, vec![kh_new.device_id], "只核准自己群組的");
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web`
Expected: 新測試 FAIL。

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
{% if nav.manage %}
<form method="post" action="/devices/approve-all">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <button>全部核准（{{ pending.len() }}）</button>
</form>
{% endif %}
<table>
  <tr><th>新註冊</th><th>原裝置</th><th>群組</th><th>註冊時間</th><th></th></tr>
  {% for p in pending %}
  <tr>
    <td><a href="/devices/{{ p.id }}">{{ p.hostname }}</a></td>
    <td><a href="/devices/{{ p.old_id }}">{{ p.old_hostname }}</a></td>
    <td>{{ p.group }}</td>
    <td>{{ p.enrolled_at }}</td>
    <td>{% if nav.manage %}
      <form class="inline" method="post" action="/devices/{{ p.id }}/approve"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button>核准</button></form>
      <form class="inline" method="post" action="/devices/{{ p.id }}/reject"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button class="danger">拒絕</button></form>
    {% endif %}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}
{% endblock %}
```

- [ ] **Step 4: `web/dashboard.rs`**

```rust
//! 儀表板：範圍內的數量統計與待核准清單。

use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session};
use super::devices::online_cutoff;
use super::{fmt_time, render};
use crate::AppState;
use crate::error::AppError;

pub struct PendingRow {
    pub id: Uuid,
    pub hostname: String,
    pub old_id: Uuid,
    pub old_hostname: String,
    pub group: String,
    pub enrolled_at: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPage {
    nav: Nav,
    total: i64,
    online: i64,
    duplicate: i64,
    pending: Vec<PendingRow>,
}

pub async fn page(State(st): State<AppState>, AdminSession(s): AdminSession) -> Response {
    match build(&st, &s).await {
        Ok(p) => render(&p),
        Err(e) => e.into_response(),
    }
}

async fn build(st: &AppState, s: &Session) -> Result<DashboardPage, AppError> {
    let cutoff = online_cutoff(st).await?;
    let (total, online, duplicate): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status <> 'retired'), \
                count(*) FILTER (WHERE status <> 'retired' AND last_seen_at > $1), \
                count(*) FILTER (WHERE status = 'duplicate_suspect') \
         FROM devices d WHERE ($2::bool OR d.group_id = ANY($3::bigint[]))",
    )
    .bind(cutoff).bind(s.all_devices()).bind(&s.groups)
    .fetch_one(&st.pool).await?;
    let rows: Vec<(Uuid, String, Uuid, String, Option<String>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT d.id, d.hostname, o.id, o.hostname, g.name, d.enrolled_at \
         FROM devices d JOIN devices o ON o.id = d.reenroll_of \
         LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE d.status = 'pending_approval' \
           AND ($1::bool OR (d.group_id = ANY($2::bigint[]) AND o.group_id = ANY($2::bigint[]))) \
         ORDER BY d.enrolled_at",
    )
    .bind(s.all_devices()).bind(&s.groups)
    .fetch_all(&st.pool).await?;
    Ok(DashboardPage {
        nav: Nav::from(s),
        total,
        online,
        duplicate,
        pending: rows.into_iter().map(|(id, hostname, old_id, old_hostname, group, at)| PendingRow {
            id, hostname, old_id, old_hostname,
            group: group.unwrap_or_else(|| "未分組".into()),
            enrolled_at: fmt_time(st, Some(at)),
        }).collect(),
    })
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
    {% for o in statuses %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}
  </select>
  <select name="group">
    {% for o in groups %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}
  </select>
  {% if !software.is_empty() %}
  <input type="hidden" name="software" value="{{ software }}">
  <input type="hidden" name="version" value="{{ version }}">
  <span class="muted">安裝了「{{ software }} {{ version }}」</span>
  {% endif %}
  <button>搜尋</button>
</form>
<table>
  <tr><th>電腦名稱</th><th>群組</th><th>網域</th><th>作業系統</th><th>使用者</th><th>IP</th><th>最後報到</th><th>狀態</th></tr>
  {% for d in rows %}
  <tr>
    <td><a href="/devices/{{ d.id }}">{{ d.hostname }}</a></td>
    <td>{{ d.group }}</td><td>{{ d.domain }}</td><td>{{ d.os }}</td><td>{{ d.user }}</td><td>{{ d.ip }}</td>
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

- [ ] **Step 6: `web/devices.rs`（列表與核准）**

```rust
//! 裝置列表、詳細資料與動作。所有查詢都以工作階段的群組範圍過濾；範圍外一律 404。

use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::login::CsrfForm;
use super::{enc, escape_like, fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::db::load_settings;
use crate::error::AppError;

pub const PAGE_SIZE: i64 = 50;

pub async fn online_cutoff(st: &AppState) -> Result<DateTime<Utc>, sqlx::Error> {
    let s = load_settings(&st.pool).await?;
    Ok(Utc::now() - Duration::seconds(3 * i64::from(s.checkin_interval_secs)))
}

pub fn status_label(status: &str, online: bool) -> (&'static str, &'static str) {
    match status {
        "retired" => ("retired", "已除役"),
        "pending_approval" => ("pending_approval", "待核准"),
        "duplicate_suspect" => ("duplicate_suspect", "疑似重複"),
        _ if online => ("online", "在線"),
        _ => ("offline", "離線"),
    }
}

pub struct SelectOption {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

/// 範圍內可選的群組（平台管理員另有「未分組」）。
pub async fn group_options(st: &AppState, s: &Session, current: &str, with_all: bool) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM device_groups WHERE ($1::bool OR id = ANY($2::bigint[])) ORDER BY name",
    )
    .bind(s.all_devices()).bind(&s.groups).fetch_all(&st.pool).await?;
    let mut out = vec![];
    if with_all {
        out.push(SelectOption { value: String::new(), label: "所有群組".into(), selected: current.is_empty() });
    }
    if s.all_devices() {
        out.push(SelectOption { value: "none".into(), label: "未分組".into(), selected: current == "none" });
    }
    out.extend(rows.into_iter().map(|(id, name)| SelectOption {
        selected: current == id.to_string(), value: id.to_string(), label: name,
    }));
    Ok(out)
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)] q: String,
    #[serde(default)] status: String,
    #[serde(default)] group: String,
    #[serde(default)] software: String,
    #[serde(default)] version: String,
    #[serde(default)] page: i64,
}

pub struct DeviceRow {
    pub id: Uuid,
    pub hostname: String,
    pub group: String,
    pub domain: String,
    pub os: String,
    pub user: String,
    pub ip: String,
    pub last_seen: String,
    pub badge: &'static str,
    pub badge_label: &'static str,
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesPage {
    nav: Nav,
    q: String,
    software: String,
    version: String,
    statuses: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<DeviceRow>,
    page: i64,
    has_next: bool,
    prev_url: String,
    next_url: String,
}

type ListRow = (Uuid, String, Option<String>, String, String, String, String, Option<DateTime<Utc>>, String);

fn page_url(q: &ListQuery, page: i64) -> String {
    format!(
        "/devices?q={}&status={}&group={}&software={}&version={}&page={page}",
        enc(&q.q), enc(&q.status), enc(&q.group), enc(&q.software), enc(&q.version)
    )
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let cutoff = online_cutoff(&st).await?;
    let page = q.page.max(0);
    let group_filter: Option<i64> = q.group.parse().ok();
    let mut rows: Vec<ListRow> = sqlx::query_as(
        "SELECT d.id, d.hostname, g.name, coalesce(d.domain, ''), coalesce(d.os_caption, ''), \
                coalesce(d.logged_on_user, ''), coalesce(d.last_ip, ''), d.last_seen_at, d.status \
         FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
           AND ($3 = '' OR d.hostname ILIKE $4 OR d.logged_on_user ILIKE $4 OR d.last_ip ILIKE $4) \
           AND (CASE WHEN $5 = '' THEN d.status <> 'retired' WHEN $5 = 'all' THEN true ELSE d.status = $5 END) \
           AND (CASE WHEN $6 = '' THEN true WHEN $6 = 'none' THEN d.group_id IS NULL ELSE d.group_id = $7 END) \
           AND ($8 = '' OR EXISTS (SELECT 1 FROM device_software sw WHERE sw.device_id = d.id \
                                   AND sw.name = $8 AND ($9 = '' OR coalesce(sw.version, '') = $9))) \
         ORDER BY d.hostname, d.id LIMIT $10 OFFSET $11",
    )
    .bind(s.all_devices()).bind(&s.groups)
    .bind(&q.q).bind(escape_like(&q.q))
    .bind(&q.status)
    .bind(&q.group).bind(group_filter)
    .bind(&q.software).bind(&q.version)
    .bind(PAGE_SIZE + 1).bind(page * PAGE_SIZE)
    .fetch_all(&st.pool).await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rows = rows.into_iter().map(|(id, hostname, group, domain, os, user, ip, last_seen, status)| {
        let (badge, badge_label) = status_label(&status, last_seen.is_some_and(|t| t > cutoff));
        DeviceRow {
            id, hostname, group: group.unwrap_or_else(|| "未分組".into()), domain, os, user, ip,
            last_seen: fmt_time(&st, last_seen), badge, badge_label,
        }
    }).collect();
    let statuses = [("", "使用中"), ("pending_approval", "待核准"), ("duplicate_suspect", "疑似重複"), ("retired", "已除役"), ("all", "全部")]
        .into_iter()
        .map(|(v, l)| SelectOption { value: v.into(), label: l.into(), selected: q.status == v })
        .collect();
    Ok(render(&DevicesPage {
        groups: group_options(&st, &s, &q.group, true).await?,
        nav: Nav::from(&s),
        prev_url: page_url(&q, page - 1),
        next_url: page_url(&q, page + 1),
        q: q.q, software: q.software, version: q.version,
        statuses, rows, page, has_next,
    }))
}

/// 取裝置的群組；不存在或不在範圍內回 None。
pub async fn device_group_in_scope(st: &AppState, s: &Session, id: Uuid) -> Result<Option<Option<i64>>, sqlx::Error> {
    let g: Option<Option<i64>> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(id).fetch_optional(&st.pool).await?;
    Ok(g.filter(|g| s.in_scope(*g)))
}

fn action_error(e: anyhow::Error) -> Response {
    (axum::http::StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

fn db_error(e: sqlx::Error) -> Response {
    AppError::from(e).into_response()
}

/// 可管理（非檢視者）且新、舊裝置都在範圍內。
async fn check_pending(st: &AppState, s: &Session, id: Uuid) -> Result<(), Response> {
    if !s.can_manage() {
        return Err(forbidden());
    }
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT d.group_id, o.group_id FROM devices d LEFT JOIN devices o ON o.id = d.reenroll_of WHERE d.id = $1",
    )
    .bind(id).fetch_optional(&st.pool).await.map_err(db_error)?;
    match row {
        Some((new_g, old_g)) if s.in_scope(new_g) && s.in_scope(old_g) => Ok(()),
        _ => Err(not_found()),
    }
}

pub async fn approve(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<Uuid>, Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    check_pending(&st, &s, id).await?;
    crate::devices::approve(&st.pool, id, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}

pub async fn reject(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<Uuid>, Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    check_pending(&st, &s, id).await?;
    crate::devices::reject(&st.pool, id, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to("/").into_response())
}

pub async fn approve_all(
    State(st): State<AppState>, AdminSession(s): AdminSession, Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT d.id FROM devices d JOIN devices o ON o.id = d.reenroll_of \
         WHERE d.status = 'pending_approval' \
           AND ($1::bool OR (d.group_id = ANY($2::bigint[]) AND o.group_id = ANY($2::bigint[]))) \
         ORDER BY d.enrolled_at",
    )
    .bind(s.all_devices()).bind(&s.groups).fetch_all(&st.pool).await.map_err(db_error)?;
    let mut tx = st.pool.begin().await.map_err(db_error)?;
    for id in ids {
        crate::devices::approve_in(&mut tx, id, &s.username).await.map_err(action_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(Redirect::to("/").into_response())
}
```

`web/mod.rs`：`pub mod devices;`，router 加：

```rust
        .route("/devices", get(devices::list))
        .route("/devices/approve-all", post(devices::approve_all))
        .route("/devices/{id}/approve", post(devices::approve))
        .route("/devices/{id}/reject", post(devices::reject))
```

- [ ] **Step 7: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat(server): 儀表板、裝置列表與核准（依群組範圍）"
```

---

### Task 7: 裝置詳細頁、除役、移動群組

**Files:**
- Create: `templates/device.html`、`templates/table.html`
- Modify: `src/web/devices.rs`、`src/web/mod.rs`
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /devices/{id}`、`GET /devices/{id}/tab/{tab}`（`software|patches|services|changes`，HTML 片段）、`POST /devices/{id}/retire`（需 `can_manage`）、`POST /devices/{id}/group`（欄位 `csrf, group`；平台管理員限定；`group` 為群組 id 或空字串＝未分組）

- [ ] **Step 1: 寫失敗測試**

```rust
async fn upload_software(s: &TestServer, a: &common::TestAgent, name: &str, ver: &str) {
    let up = protocol::InventoryUpload {
        schema_version: protocol::SCHEMA_VERSION,
        payload: protocol::InventoryPayload::Software(vec![protocol::SoftwareItem {
            name: name.into(), version: Some(ver.into()), publisher: None, install_date: None, arch: protocol::Arch::X64,
        }]),
    };
    let r = s.client(Some(a)).put(s.url("/v1/inventory/software")).json(&up).send().await.unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn device_detail_and_tabs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    upload_software(&s, &a, "<b>7-Zip</b>", "23.01").await;
    let c = s.admin_client().await;
    let (status, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert_eq!(status, 200);
    assert!(html.contains("PC-001"));
    assert!(html.contains(&format!("/devices/{}/tab/software", a.device_id)));
    let (status, frag) = s.page(&c, &format!("/devices/{}/tab/software", a.device_id)).await;
    assert_eq!(status, 200);
    assert!(frag.contains("&lt;b&gt;7-Zip&lt;/b&gt;"), "{frag}");
    assert!(!frag.contains("<html"));
    assert_eq!(s.page(&c, &format!("/devices/{}/tab/nope", a.device_id)).await.0, 404);
    assert_eq!(s.page(&c, &format!("/devices/{}", uuid::Uuid::new_v4())).await.0, 404);
}

#[sqlx::test(migrations = false)]
async fn group_admin_cannot_open_other_group_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    let other = s.enroll_ok(&kh, None, None).await;
    let c = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    assert_eq!(s.page(&c, &format!("/devices/{}", other.device_id)).await.0, 404);
    assert_eq!(s.page(&c, &format!("/devices/{}/tab/software", other.device_id)).await.0, 404);
    let (_, html) = s.page(&c, "/").await;
    let r = c.post(s.web_url(&format!("/devices/{}/retire", other.device_id)))
        .form(&[("csrf", csrf_from(&html).as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 404);
}

#[sqlx::test(migrations = false)]
async fn retire_requires_csrf_role_and_revokes(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let path = format!("/devices/{}/retire", a.device_id);

    let viewer = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&viewer, &format!("/devices/{}", a.device_id)).await;
    assert!(!html.contains("除役（"), "檢視者看不到除役按鈕");
    let r = viewer.post(s.web_url(&path)).form(&[("csrf", csrf_from(&html).as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 403);

    let c = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let r = c.post(s.web_url(&path)).form(&[("csrf", "forged")]).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    let r = c.post(s.web_url(&path)).form(&[("csrf", csrf_from(&html).as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(status, "retired");
}

#[sqlx::test(migrations = false)]
async fn only_platform_admin_moves_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let kh = s.group_id("高雄廠").await;
    let path = format!("/devices/{}/group", a.device_id);

    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部", "高雄廠"]).await;
    let (_, html) = s.page(&gary, "/").await;
    let r = gary.post(s.web_url(&path)).form(&[("csrf", csrf_from(&html).as_str()), ("group", &kh.to_string())]).send().await.unwrap();
    assert_eq!(r.status(), 403);

    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    let r = c.post(s.web_url(&path)).form(&[("csrf", csrf_from(&html).as_str()), ("group", &kh.to_string())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let kaohsiung_admin = s.login_as("kate", Role::GroupAdmin, &["高雄廠"]).await;
    assert_eq!(s.page(&kaohsiung_admin, &format!("/devices/{}", a.device_id)).await.0, 200);
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web`
Expected: 新測試 FAIL（404）。

- [ ] **Step 3: 樣板**

`templates/device.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>{{ d.hostname }} <span class="badge {{ d.badge }}">{{ d.badge_label }}</span></h1>
<table>
  <tr><th>裝置 ID</th><td>{{ d.id }}</td><th>群組</th><td>{{ d.group }}</td></tr>
  <tr><th>網域</th><td>{{ d.domain }}</td><th>作業系統</th><td>{{ d.os }}（{{ d.build }}）</td></tr>
  <tr><th>使用者</th><td>{{ d.user }}</td><th>IP</th><td>{{ d.ip }}</td></tr>
  <tr><th>廠牌／型號</th><td>{{ d.model }}</td><th>CPU</th><td>{{ d.cpu }}</td></tr>
  <tr><th>記憶體</th><td>{{ d.ram }}</td><th>BIOS 序號</th><td>{{ d.serial }}</td></tr>
  <tr><th>最後報到</th><td>{{ d.last_seen }}</td><th>開機時間</th><td>{{ d.boot }}</td></tr>
  <tr><th>註冊時間</th><td>{{ d.enrolled }}</td><th>Agent 版本</th><td>{{ d.agent }}</td></tr>
</table>
{% if !d.errors.is_empty() %}
<h2>收集錯誤</h2>
<table>{% for e in d.errors %}<tr><th>{{ e.0 }}</th><td class="error">{{ e.1 }}</td></tr>{% endfor %}</table>
{% endif %}
{% if nav.platform %}
<form method="post" action="/devices/{{ d.id }}/group">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <label>移到群組 <select name="group">{% for o in groups %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}</select></label>
  <button>移動</button>
</form>
{% endif %}
{% if nav.manage && d.can_retire %}
<form method="post" action="/devices/{{ d.id }}/retire">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <button class="danger">除役（撤銷憑證，Agent 將停止報到）</button>
</form>
{% endif %}
<div class="tabs">
  {% for t in tabs %}<button hx-get="/devices/{{ d.id }}/tab/{{ t.0 }}" hx-target="#tab">{{ t.1 }}</button>{% endfor %}
</div>
<div id="tab" hx-get="/devices/{{ d.id }}/tab/software" hx-trigger="load"></div>
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
    pub group: String,
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
    nav: Nav,
    d: DeviceView,
    groups: Vec<SelectOption>,
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
    String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>,
    Option<DateTime<Utc>>, Option<DateTime<Utc>>, DateTime<Utc>, Option<String>, String, String,
    Option<i64>, Option<String>,
);

pub async fn detail(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<Uuid>,
) -> Result<Response, AppError> {
    let row: Option<DetailRow> = sqlx::query_as(
        "SELECT d.hostname, d.domain, d.os_caption, d.os_build, d.logged_on_user, d.last_ip, d.bios_serial, \
                d.last_seen_at, d.boot_time, d.enrolled_at, d.agent_version, d.status, d.section_errors::text, \
                d.group_id, g.name \
         FROM devices d LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE d.id = $1 AND ($2::bool OR d.group_id = ANY($3::bigint[]))",
    )
    .bind(id).bind(s.all_devices()).bind(&s.groups)
    .fetch_optional(&st.pool).await?;
    let Some((hostname, domain, os, build, user, ip, serial, last_seen, boot, enrolled, agent, status, errors, group_id, group)) = row
    else {
        return Ok(not_found());
    };
    let hw: Option<(Option<String>, Option<String>, Option<String>, i64)> =
        sqlx::query_as("SELECT manufacturer, model, cpu, ram_mb FROM device_hardware WHERE device_id = $1")
            .bind(id).fetch_optional(&st.pool).await?;
    let cutoff = online_cutoff(&st).await?;
    let (badge, badge_label) = status_label(&status, last_seen.is_some_and(|t| t > cutoff));
    let errors: std::collections::BTreeMap<String, String> = serde_json::from_str(&errors).unwrap_or_default();
    let o = |v: Option<String>| v.unwrap_or_default();
    let (model, cpu, ram) = match hw {
        Some((mf, model, cpu, ram)) => (
            format!("{} {}", o(mf), o(model)).trim().to_string(),
            o(cpu),
            format!("{:.1} GB", ram as f64 / 1024.0),
        ),
        None => Default::default(),
    };
    let current_group = group_id.map(|g| g.to_string()).unwrap_or_else(|| "none".into());
    Ok(render(&DevicePage {
        groups: if s.all_devices() { group_options(&st, &s, &current_group, false).await? } else { vec![] },
        nav: Nav::from(&s),
        d: DeviceView {
            id, hostname,
            group: group.unwrap_or_else(|| "未分組".into()),
            domain: o(domain), os: o(os), build: o(build), user: o(user), ip: o(ip),
            model, cpu, ram, serial: o(serial),
            last_seen: fmt_time(&st, last_seen), boot: fmt_time(&st, boot), enrolled: fmt_time(&st, Some(enrolled)),
            agent: o(agent),
            errors: errors.into_iter().collect(),
            badge, badge_label,
            can_retire: status != "retired",
        },
        tabs: vec![("software", "軟體"), ("patches", "修補（KB）"), ("services", "服務"), ("changes", "變更歷史")],
    }))
}

const TAB_LIMIT: i64 = 5000;

pub async fn tab(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path((id, tab)): Path<(Uuid, String)>,
) -> Result<Response, AppError> {
    if device_group_in_scope(&st, &s, id).await?.is_none() {
        return Ok(not_found());
    }
    let (headers, sql): (Vec<&'static str>, &'static str) = match tab.as_str() {
        "software" => (vec!["名稱", "版本", "發行者", "架構", "安裝日期"],
            "SELECT name, coalesce(version, ''), coalesce(publisher, ''), arch, coalesce(install_date, '') \
             FROM device_software WHERE device_id = $1 ORDER BY lower(name) LIMIT $2"),
        "patches" => (vec!["KB", "安裝日期"],
            "SELECT kb, coalesce(installed_on, '') FROM device_patches WHERE device_id = $1 ORDER BY kb LIMIT $2"),
        "services" => (vec!["名稱", "顯示名稱", "啟動類型", "狀態", "執行檔"],
            "SELECT name, coalesce(display_name, ''), start_mode, state, coalesce(binary_path, '') \
             FROM device_services WHERE device_id = $1 ORDER BY lower(name) LIMIT $2"),
        "changes" => (vec!["時間（UTC）", "區段", "變更", "項目", "舊值", "新值"],
            "SELECT to_char(detected_at, 'YYYY-MM-DD HH24:MI'), section, change, item_key, \
                    coalesce(old_value, ''), coalesce(new_value, '') \
             FROM inventory_changes WHERE device_id = $1 ORDER BY detected_at DESC LIMIT $2"),
        _ => return Ok(not_found()),
    };
    use sqlx::Row;
    let rows = sqlx::query(sql).bind(id).bind(TAB_LIMIT + 1).fetch_all(&st.pool).await?;
    let truncated = rows.len() as i64 > TAB_LIMIT;
    let rows = rows.iter().take(TAB_LIMIT as usize)
        .map(|r| (0..headers.len()).map(|i| r.get::<String, _>(i)).collect())
        .collect();
    Ok(render(&TableFragment { headers, rows, truncated }))
}

pub async fn retire(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<Uuid>, Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    if device_group_in_scope(&st, &s, id).await.map_err(db_error)?.is_none() {
        return Err(not_found());
    }
    crate::devices::retire(&st.pool, id, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}

#[derive(Deserialize)]
pub struct MoveForm {
    csrf: String,
    #[serde(default)]
    group: String,
}

pub async fn move_group(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<Uuid>, Form(f): Form<MoveForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let group = match f.group.as_str() {
        "" | "none" => None,
        g => Some(g.parse::<i64>().map_err(|_| (axum::http::StatusCode::BAD_REQUEST, "bad group").into_response())?),
    };
    crate::groups::move_device(&st.pool, id, group, &s.username).await.map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}
```

router：

```rust
        .route("/devices/{id}", get(devices::detail))
        .route("/devices/{id}/tab/{tab}", get(devices::tab))
        .route("/devices/{id}/retire", post(devices::retire))
        .route("/devices/{id}/group", post(devices::move_group))
```

- [ ] **Step 5: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(server): 裝置詳細頁、除役與移動群組"
```

---

### Task 8: 全公司軟體搜尋（依範圍統計）

**Files:**
- Create: `templates/software.html`、`src/web/software.rs`；Modify: `src/web/mod.rs`
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /software?q=`：範圍內、未除役裝置的「名稱／版本／安裝台數」，連到 `/devices?software=&version=`；最多 500 列。

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn software_search_is_scoped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 2).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    let a = s.enroll_ok(&tp, None, None).await;
    let b = s.enroll_ok(&tp, None, None).await;
    let k = s.enroll_ok(&kh, None, None).await;
    upload_software(&s, &a, "Google Chrome", "120").await;
    upload_software(&s, &b, "Google Chrome", "121").await;
    upload_software(&s, &k, "Google Chrome", "121").await;

    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/software?q=chrome").await;
    assert!(html.contains("/devices?software=Google%20Chrome&amp;version=121\">2<"), "{html}");

    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&gary, "/software?q=chrome").await;
    assert!(html.contains("/devices?software=Google%20Chrome&amp;version=121\">1<"), "只算自己群組：{html}");
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
  {% for r in rows %}<tr><td>{{ r.name }}</td><td>{{ r.version }}</td><td><a href="{{ r.url }}">{{ r.count }}</a></td></tr>{% endfor %}
</table>
{% if truncated %}<p class="muted">結果過多，只顯示前 500 筆，請縮小搜尋範圍。</p>{% endif %}
{% endif %}
{% endblock %}
```

`web/software.rs`：

```rust
//! 全公司軟體搜尋：範圍內依名稱與版本統計安裝台數。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use super::auth::{AdminSession, Nav};
use super::{enc, escape_like, render};
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
    nav: Nav,
    q: String,
    rows: Vec<SoftwareRow>,
    truncated: bool,
}

pub async fn search(
    State(st): State<AppState>, AdminSession(s): AdminSession, Query(q): Query<SearchQuery>,
) -> Result<Response, AppError> {
    let mut rows: Vec<(String, String, i64)> = if q.q.trim().is_empty() {
        vec![]
    } else {
        sqlx::query_as(
            "SELECT sw.name, coalesce(sw.version, ''), count(DISTINCT sw.device_id) \
             FROM device_software sw JOIN devices d ON d.id = sw.device_id AND d.status <> 'retired' \
             WHERE sw.name ILIKE $1 AND ($2::bool OR d.group_id = ANY($3::bigint[])) \
             GROUP BY 1, 2 ORDER BY lower(sw.name), 2 LIMIT $4",
        )
        .bind(escape_like(q.q.trim())).bind(s.all_devices()).bind(&s.groups).bind(LIMIT + 1)
        .fetch_all(&st.pool).await?
    };
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    Ok(render(&SoftwarePage {
        nav: Nav::from(&s),
        q: q.q,
        rows: rows.into_iter().map(|(name, version, count)| SoftwareRow {
            url: format!("/devices?software={}&version={}", enc(&name), enc(&version)),
            name, version, count,
        }).collect(),
        truncated,
    }))
}
```

router `.route("/software", get(software::search))`、`pub mod software;`。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(server): 全公司軟體搜尋（依範圍統計）"
```

---

### Task 9: 註冊金鑰管理（依範圍）

**Files:**
- Create: `templates/tokens.html`、`src/web/tokens.rs`；Modify: `src/web/mod.rs`
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /tokens`（檢視者 403；群組管理員只列自己群組的金鑰）；`POST /tokens`（`csrf, name, max_uses, group, valid_days`；群組管理員必須選自己的群組，平台管理員可選「未分組」）→ 200 並顯示一次明碼；`POST /tokens/{id}/revoke`（範圍外 404）→ 303。建立寫 audit `token_create`（不含明碼）。

- [ ] **Step 1: 寫失敗測試**

```rust
fn new_token_from(html: &str) -> String {
    let marker = r#"<code id="new-token">"#;
    let start = html.find(marker).expect("token shown once") + marker.len();
    html[start..start + 64].to_string()
}

#[sqlx::test(migrations = false)]
async fn token_created_in_web_can_enroll_and_be_revoked(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北總部").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c.post(s.web_url("/tokens"))
        .form(&[("csrf", csrf_from(&html).as_str()), ("name", "IT pilot"), ("max_uses", "2"), ("group", &tp.to_string()), ("valid_days", "7")])
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    let token = new_token_from(&r.text().await.unwrap());
    let a = s.enroll_ok(&token, None, None).await;
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(g, Some(tp));

    let detail: String = sqlx::query_scalar("SELECT detail::text FROM audit_log WHERE action = 'token_create'")
        .fetch_one(&s.pool).await.unwrap();
    assert!(!detail.contains(&token), "明碼不可寫進稽核記錄");

    let id: i64 = sqlx::query_scalar("SELECT id FROM enroll_tokens WHERE name = 'IT pilot'").fetch_one(&s.pool).await.unwrap();
    let (_, html) = s.page(&c, "/tokens").await;
    assert!(!html.contains(&token), "列表不顯示明碼");
    let r = c.post(s.web_url(&format!("/tokens/{id}/revoke")))
        .form(&[("csrf", csrf_from(&html).as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(s.enroll(&token, None, None).await.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn group_admin_tokens_are_scoped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let kh = s.group_id("高雄廠").await;
    let _ = s.create_group_token("高雄廠", 1).await;
    let kh_token_id: i64 = sqlx::query_scalar("SELECT id FROM enroll_tokens").fetch_one(&s.pool).await.unwrap();
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (status, html) = s.page(&gary, "/tokens").await;
    assert_eq!(status, 200);
    assert!(!html.contains("高雄廠 token"), "看不到別的群組的金鑰");
    let csrf = csrf_from(&html);

    let r = gary.post(s.web_url("/tokens"))
        .form(&[("csrf", csrf.as_str()), ("name", "x"), ("max_uses", "1"), ("group", &kh.to_string()), ("valid_days", "")])
        .send().await.unwrap();
    assert_eq!(r.status(), 403, "不能替別的群組建立金鑰");
    let r = gary.post(s.web_url("/tokens"))
        .form(&[("csrf", csrf.as_str()), ("name", "x"), ("max_uses", "1"), ("group", ""), ("valid_days", "")])
        .send().await.unwrap();
    assert_eq!(r.status(), 403, "不能建立未分組的金鑰");
    let r = gary.post(s.web_url(&format!("/tokens/{kh_token_id}/revoke"))).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 404);

    let viewer = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    assert_eq!(s.page(&viewer, "/tokens").await.0, 403);
}

#[sqlx::test(migrations = false)]
async fn token_form_validates_input(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c.post(s.web_url("/tokens"))
        .form(&[("csrf", csrf_from(&html).as_str()), ("name", ""), ("max_uses", "0"), ("group", ""), ("valid_days", "")])
        .send().await.unwrap();
    assert_eq!(r.status(), 400);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_tokens").fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 0);
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web token`
Expected: FAIL（404）。

- [ ] **Step 3: 樣板**

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
<fieldset><legend>建立金鑰</legend>
<form method="post" action="/tokens">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <label>名稱 <input name="name" required maxlength="100"></label>
  <label>可使用次數 <input name="max_uses" type="number" min="1" value="100" required></label>
  <label>群組 <select name="group">{% for o in groups %}<option value="{{ o.value }}">{{ o.label }}</option>{% endfor %}</select></label>
  <label>有效天數 <input name="valid_days" type="number" min="1" placeholder="不限"></label>
  <button>建立</button>
</form>
</fieldset>
<table>
  <tr><th>名稱</th><th>群組</th><th>已用／上限</th><th>到期</th><th>建立者</th><th>建立時間</th><th>狀態</th></tr>
  {% for t in rows %}
  <tr>
    <td>{{ t.name }}</td><td>{{ t.group }}</td><td>{{ t.used }} / {{ t.max }}</td><td>{{ t.expires }}</td>
    <td>{{ t.created_by }}</td><td>{{ t.created_at }}</td>
    <td>{% if t.active %}
      <form class="inline" method="post" action="/tokens/{{ t.id }}/revoke"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button class="danger">作廢</button></form>
    {% else %}<span class="muted">{{ t.state }}</span>{% endif %}</td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
```

- [ ] **Step 4: `web/tokens.rs`**

```rust
//! 註冊金鑰：建立（明碼只顯示一次）、列表、作廢；群組管理員限自己的群組。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, group_options};
use super::login::CsrfForm;
use super::{fmt_time, forbidden, not_found, render};
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
    nav: Nav,
    new_token: Option<String>,
    groups: Vec<SelectOption>,
    rows: Vec<TokenRow>,
}

type Row = (i64, String, Option<String>, i32, i32, Option<DateTime<Utc>>, Option<DateTime<Utc>>, String, DateTime<Utc>);

fn db(e: sqlx::Error) -> Response {
    AppError::from(e).into_response()
}

async fn page_for(st: &AppState, s: &Session, new_token: Option<String>) -> Result<Response, Response> {
    if !s.can_manage() {
        return Err(forbidden());
    }
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT t.id, t.name, g.name, t.used_count, t.max_uses, t.expires_at, t.revoked_at, t.created_by, t.created_at \
         FROM enroll_tokens t LEFT JOIN device_groups g ON g.id = t.group_id \
         WHERE ($1::bool OR t.group_id = ANY($2::bigint[])) ORDER BY t.id DESC",
    )
    .bind(s.all_devices()).bind(&s.groups).fetch_all(&st.pool).await.map_err(db)?;
    let now = Utc::now();
    let rows = rows.into_iter().map(|(id, name, group, used, max, expires, revoked, created_by, created_at)| {
        let state = if revoked.is_some() { "已作廢" }
            else if expires.is_some_and(|e| e <= now) { "已過期" }
            else if used >= max { "已用完" }
            else { "" };
        TokenRow {
            id, name, group: group.unwrap_or_else(|| "未分組".into()), used, max,
            expires: expires.map(|e| fmt_time(st, Some(e))).unwrap_or_else(|| "不限".into()),
            created_by, created_at: fmt_time(st, Some(created_at)),
            active: state.is_empty(), state,
        }
    }).collect();
    Ok(render(&TokensPage {
        nav: Nav::from(s),
        new_token,
        groups: group_options(st, s, "", false).await.map_err(db)?,
        rows,
    }))
}

pub async fn list(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, Response> {
    page_for(&st, &s, None).await
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
    max_uses: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    valid_days: String,
}

pub async fn create(
    State(st): State<AppState>, AdminSession(s): AdminSession, Form(f): Form<CreateForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string()).into_response();
    let group: Option<i64> = match f.group.as_str() {
        "" | "none" => None,
        g => Some(g.parse().map_err(|_| bad("群組不正確"))?),
    };
    if !s.in_scope(group) {
        return Err(forbidden());
    }
    let name = f.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(bad("名稱必填，最多 100 字"));
    }
    let max_uses: i32 = f.max_uses.trim().parse().ok().filter(|n| *n >= 1).ok_or_else(|| bad("可使用次數需為正整數"))?;
    let valid_days: Option<i64> = match f.valid_days.trim() {
        "" => None,
        d => Some(d.parse().ok().filter(|n: &i64| (1..=3650).contains(n)).ok_or_else(|| bad("有效天數需為 1～3650"))?),
    };
    let (id, token) = create_token(&st.pool, &NewToken {
        name: name.into(),
        group_id: group,
        expires_at: valid_days.map(|d| Utc::now() + Duration::days(d)),
        max_uses,
        created_by: s.username.clone(),
    }).await.map_err(db)?;
    let mut c = st.pool.acquire().await.map_err(db)?;
    crate::audit::record(&mut c, &s.username, "token_create", Some(&id.to_string()),
        serde_json::json!({ "name": name, "max_uses": max_uses, "group_id": group, "valid_days": valid_days }))
        .await.map_err(db)?;
    page_for(&st, &s, Some(token)).await
}

pub async fn revoke(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.can_manage() {
        return Err(forbidden());
    }
    let group: Option<Option<i64>> = sqlx::query_scalar("SELECT group_id FROM enroll_tokens WHERE id = $1")
        .bind(id).fetch_optional(&st.pool).await.map_err(db)?;
    match group {
        Some(g) if s.in_scope(g) => {}
        _ => return Err(not_found()),
    }
    revoke_token(&st.pool, id, &s.username).await
        .map_err(|e| (StatusCode::CONFLICT, format!("{e:#}")).into_response())?;
    Ok(Redirect::to("/tokens").into_response())
}
```

router：`.route("/tokens", get(tokens::list).post(tokens::create))`、`.route("/tokens/{id}/revoke", post(tokens::revoke))`；`pub mod tokens;`（web 內模組，與 crate 的 `tokens` 以路徑區分）。

- [ ] **Step 5: 測試**

Run: `cargo test -p endpoint-server --test web`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(server): 註冊金鑰管理（依群組範圍）"
```

---

### Task 10: 群組管理、帳號管理、修改自己的密碼

**Files:**
- Modify: `src/groups.rs`（`create`、`delete`）
- Create: `templates/groups.html`、`templates/accounts.html`、`templates/account.html`、`templates/password.html`
- Create: `src/web/groups.rs`、`src/web/accounts.rs`、`src/web/password.rs`；Modify: `src/web/mod.rs`
- Modify: `tests/web.rs`

**Interfaces:**
- Produces:
  - `groups::create(pool, name, actor) -> anyhow::Result<i64>`（名稱 1～100 字、不可重複；audit `group_create`）
  - `groups::delete(pool, id, actor) -> anyhow::Result<()>`（有裝置或金鑰時拒絕；audit `group_delete`）
  - 頁面（平台管理員限定，其他角色 403）：`GET/POST /groups`、`POST /groups/{id}/delete`、`GET/POST /accounts`（列表＋建立）、`GET /accounts/{id}`、`POST /accounts/{id}`（角色＋群組）、`POST /accounts/{id}/disable`、`/enable`、`/unlock`、`/password`（重設）
  - 所有人：`GET/POST /password`（目前密碼、新密碼、確認）
  - 表單的群組多選以多個 `groups` 欄位傳送（`application/x-www-form-urlencoded` 重複 key），handler 用 `axum::extract::RawForm` 手動解析（`serde_urlencoded` 不支援重複 key 對 Vec）

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn non_platform_cannot_open_admin_pages(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    for path in ["/groups", "/accounts", "/audit"] {
        assert_eq!(s.page(&gary, path).await.0, 403, "{path}");
    }
}

#[sqlx::test(migrations = false)]
async fn platform_admin_manages_groups(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/groups").await;
    let csrf = csrf_from(&html);
    let r = c.post(s.web_url("/groups")).form(&[("csrf", csrf.as_str()), ("name", "新竹辦公室")]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let id: i64 = sqlx::query_scalar("SELECT id FROM device_groups WHERE name = '新竹辦公室'").fetch_one(&s.pool).await.unwrap();

    let _ = s.create_group_token("台北總部", 1).await;
    let busy = s.group_id("台北總部").await;
    let r = c.post(s.web_url(&format!("/groups/{busy}/delete"))).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 409, "有金鑰的群組不能刪");
    let r = c.post(s.web_url(&format!("/groups/{id}/delete"))).form(&[("csrf", csrf.as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
}

#[sqlx::test(migrations = false)]
async fn platform_admin_creates_group_admin_who_can_log_in(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北總部").await;
    let kh = s.group_id("高雄廠").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/accounts").await;
    let body = format!(
        "csrf={}&username=henry&role=group_admin&groups={tp}&groups={kh}&password=henry-long-password",
        csrf_from(&html)
    );
    let r = c.post(s.web_url("/accounts"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let groups: Vec<i64> = sqlx::query_scalar(
        "SELECT group_id FROM admin_groups JOIN admins a ON a.id = admin_id WHERE a.username = 'henry' ORDER BY group_id",
    ).fetch_all(&s.pool).await.unwrap();
    assert_eq!(groups, { let mut v = vec![tp, kh]; v.sort(); v });

    let h = s.web_client();
    let r = h.post(s.web_url("/login"))
        .form(&[("username", "henry"), ("password", "henry-long-password")]).send().await.unwrap();
    assert_eq!(r.status(), 303);
}

#[sqlx::test(migrations = false)]
async fn disable_kills_sessions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    assert_eq!(s.page(&gary, "/").await.0, 200);
    let id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = 'gary'").fetch_one(&s.pool).await.unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/accounts/{id}")).await;
    let r = c.post(s.web_url(&format!("/accounts/{id}/disable")))
        .form(&[("csrf", csrf_from(&html).as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(s.page(&gary, "/").await.0, 303, "被停用後立即登出");
}

#[sqlx::test(migrations = false)]
async fn platform_admin_cannot_disable_self(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = 'admin'").fetch_one(&s.pool).await.unwrap();
    let (_, html) = s.page(&c, &format!("/accounts/{id}")).await;
    let r = c.post(s.web_url(&format!("/accounts/{id}/disable")))
        .form(&[("csrf", csrf_from(&html).as_str())]).send().await.unwrap();
    assert_eq!(r.status(), 409);
}

#[sqlx::test(migrations = false)]
async fn reset_password_unlocks_and_user_changes_own(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    sqlx::query("UPDATE admins SET locked_until = now() + interval '10 minutes' WHERE username = 'gary'")
        .execute(&s.pool).await.unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = 'gary'").fetch_one(&s.pool).await.unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/accounts/{id}")).await;
    let r = c.post(s.web_url(&format!("/accounts/{id}/password")))
        .form(&[("csrf", csrf_from(&html).as_str()), ("password", "temporary-password-1")]).send().await.unwrap();
    assert_eq!(r.status(), 303);

    let g = s.web_client();
    let r = g.post(s.web_url("/login")).form(&[("username", "gary"), ("password", "temporary-password-1")]).send().await.unwrap();
    assert_eq!(r.status(), 303, "重設後可登入（鎖定已解除）");
    let (_, html) = s.page(&g, "/password").await;
    let csrf = csrf_from(&html);
    let r = g.post(s.web_url("/password"))
        .form(&[("csrf", csrf.as_str()), ("current", "wrong-password-xx"), ("new", "gary-new-password"), ("confirm", "gary-new-password")])
        .send().await.unwrap();
    assert_eq!(r.status(), 400);
    let r = g.post(s.web_url("/password"))
        .form(&[("csrf", csrf.as_str()), ("current", "temporary-password-1"), ("new", "gary-new-password"), ("confirm", "gary-new-password")])
        .send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(s.page(&g, "/").await.0, 200, "改自己的密碼不會登出目前的工作階段");
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web`
Expected: 新測試 FAIL（404）。

- [ ] **Step 3: `groups.rs` 追加**

```rust
pub async fn create(pool: &PgPool, name: &str, actor: &str) -> anyhow::Result<i64> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty() && name.chars().count() <= 100, "群組名稱必填，最多 100 字");
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar("INSERT INTO device_groups (name) VALUES ($1) RETURNING id")
        .bind(name).fetch_one(&mut *tx).await
        .map_err(|_| anyhow::anyhow!("群組名稱已存在"))?;
    crate::audit::record(&mut tx, actor, "group_create", Some(name), serde_json::json!({ "id": id })).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn delete(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let (devices, tokens): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM devices WHERE group_id = $1), (SELECT count(*) FROM enroll_tokens WHERE group_id = $1)",
    ).bind(id).fetch_one(&mut *tx).await?;
    anyhow::ensure!(devices == 0 && tokens == 0, "群組內還有 {devices} 台裝置、{tokens} 把金鑰，無法刪除");
    let name: Option<String> = sqlx::query_scalar("DELETE FROM device_groups WHERE id = $1 RETURNING name")
        .bind(id).fetch_optional(&mut *tx).await?;
    let name = name.ok_or_else(|| anyhow::anyhow!("群組不存在"))?;
    crate::audit::record(&mut tx, actor, "group_delete", Some(&name), serde_json::json!({ "id": id })).await?;
    tx.commit().await?;
    Ok(())
}
```

- [ ] **Step 4: 樣板**

`templates/groups.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>群組</h1>
<form method="post" action="/groups">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <input name="name" required maxlength="100" placeholder="新群組名稱"> <button>建立</button>
</form>
<table>
  <tr><th>名稱</th><th>裝置</th><th>金鑰</th><th>管理員</th><th></th></tr>
  {% for g in rows %}
  <tr><td><a href="/devices?group={{ g.id }}">{{ g.name }}</a></td><td>{{ g.devices }}</td><td>{{ g.tokens }}</td><td>{{ g.admins }}</td>
    <td>{% if g.devices == 0 && g.tokens == 0 %}
      <form class="inline" method="post" action="/groups/{{ g.id }}/delete"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button class="danger">刪除</button></form>
    {% endif %}</td></tr>
  {% endfor %}
</table>
{% endblock %}
```

`templates/accounts.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>帳號</h1>
<fieldset><legend>建立帳號</legend>
<form method="post" action="/accounts">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <p><label>帳號 <input name="username" required maxlength="64" autocomplete="off"></label>
  <label>初始密碼（至少 12 字元） <input name="password" type="password" required minlength="12" autocomplete="new-password"></label></p>
  <p>角色：{% for r in roles %}<label><input type="radio" name="role" value="{{ r.value }}" {% if r.selected %}checked{% endif %}> {{ r.label }}</label> {% endfor %}</p>
  <p>群組（群組管理員／檢視者必選）：{% for g in groups %}<label><input type="checkbox" name="groups" value="{{ g.value }}"> {{ g.label }}</label> {% endfor %}</p>
  <button>建立</button>
</form>
</fieldset>
<table>
  <tr><th>帳號</th><th>角色</th><th>群組</th><th>狀態</th><th>建立時間</th></tr>
  {% for a in rows %}
  <tr><td><a href="/accounts/{{ a.id }}">{{ a.username }}</a></td><td>{{ a.role }}</td><td>{{ a.groups }}</td>
    <td><span class="{{ a.state_class }}">{{ a.state }}</span></td><td>{{ a.created_at }}</td></tr>
  {% endfor %}
</table>
{% endblock %}
```

`templates/account.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>帳號：{{ a.username }} <span class="badge {{ a.state_class }}">{{ a.state }}</span></h1>
<fieldset><legend>角色與群組</legend>
<form method="post" action="/accounts/{{ a.id }}">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <p>{% for r in roles %}<label><input type="radio" name="role" value="{{ r.value }}" {% if r.selected %}checked{% endif %}> {{ r.label }}</label> {% endfor %}</p>
  <p>{% for g in groups %}<label><input type="checkbox" name="groups" value="{{ g.value }}" {% if g.selected %}checked{% endif %}> {{ g.label }}</label> {% endfor %}</p>
  <button>儲存</button>
</form>
</fieldset>
<fieldset><legend>重設密碼</legend>
<form method="post" action="/accounts/{{ a.id }}/password">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <input name="password" type="password" required minlength="12" autocomplete="new-password"> <button>重設（同時解除鎖定、登出對方）</button>
</form>
</fieldset>
<p>
{% if a.locked %}<form class="inline" method="post" action="/accounts/{{ a.id }}/unlock"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button>解除鎖定</button></form>{% endif %}
{% if a.disabled %}
<form class="inline" method="post" action="/accounts/{{ a.id }}/enable"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button>啟用</button></form>
{% else %}
<form class="inline" method="post" action="/accounts/{{ a.id }}/disable"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button class="danger">停用</button></form>
{% endif %}
</p>
{% endblock %}
```

`templates/password.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>修改密碼</h1>
{% if let Some(m) = message %}<p class="notice">{{ m }}</p>{% endif %}
{% if let Some(e) = error %}<p class="error">{{ e }}</p>{% endif %}
<form method="post" action="/password">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <p><label>目前密碼<br><input name="current" type="password" required autocomplete="current-password"></label></p>
  <p><label>新密碼（至少 12 字元）<br><input name="new" type="password" required minlength="12" autocomplete="new-password"></label></p>
  <p><label>確認新密碼<br><input name="confirm" type="password" required minlength="12" autocomplete="new-password"></label></p>
  <button>修改</button>
</form>
{% endblock %}
```

- [ ] **Step 5: handler**

`web/groups.rs`：

```rust
//! 群組管理（平台管理員）。

use askama::Template;
use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf};
use super::login::CsrfForm;
use super::{forbidden, render};
use crate::AppState;
use crate::error::AppError;

pub struct GroupRow {
    pub id: i64,
    pub name: String,
    pub devices: i64,
    pub tokens: i64,
    pub admins: i64,
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsPage {
    nav: Nav,
    rows: Vec<GroupRow>,
}

pub async fn list(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, AppError> {
    if !s.all_devices() {
        return Ok(forbidden());
    }
    let rows: Vec<(i64, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, \
                (SELECT count(*) FROM devices d WHERE d.group_id = g.id AND d.status <> 'retired'), \
                (SELECT count(*) FROM enroll_tokens t WHERE t.group_id = g.id), \
                (SELECT count(*) FROM admin_groups a WHERE a.group_id = g.id) \
         FROM device_groups g ORDER BY g.name",
    ).fetch_all(&st.pool).await?;
    Ok(render(&GroupsPage {
        nav: Nav::from(&s),
        rows: rows.into_iter().map(|(id, name, devices, tokens, admins)| GroupRow { id, name, devices, tokens, admins }).collect(),
    }))
}

#[derive(Deserialize)]
pub struct CreateForm {
    csrf: String,
    name: String,
}

fn conflict(e: anyhow::Error) -> Response {
    (StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

pub async fn create(State(st): State<AppState>, AdminSession(s): AdminSession, Form(f): Form<CreateForm>) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    crate::groups::create(&st.pool, &f.name, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to("/groups").into_response())
}

pub async fn delete(
    State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    crate::groups::delete(&st.pool, id, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to("/groups").into_response())
}
```

`web/accounts.rs`：

```rust
//! 帳號管理（平台管理員）。

use askama::Template;
use axum::extract::{Form, Path, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Role, Session, check_csrf};
use super::devices::SelectOption;
use super::login::CsrfForm;
use super::{fmt_time, forbidden, not_found, render};
use crate::AppState;
use crate::accounts::{self, NewAdmin};
use crate::error::AppError;

pub struct AccountRow {
    pub id: i64,
    pub username: String,
    pub role: &'static str,
    pub groups: String,
    pub state: &'static str,
    pub state_class: &'static str,
    pub created_at: String,
    pub locked: bool,
    pub disabled: bool,
}

#[derive(Template)]
#[template(path = "accounts.html")]
struct AccountsPage {
    nav: Nav,
    roles: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<AccountRow>,
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    nav: Nav,
    a: AccountRow,
    roles: Vec<SelectOption>,
    groups: Vec<SelectOption>,
}

type Row = (i64, String, String, Option<String>, Option<DateTime<Utc>>, Option<DateTime<Utc>>, DateTime<Utc>, Vec<i64>);

const SELECT: &str = "SELECT a.id, a.username, a.role, \
       (SELECT string_agg(g.name, '、' ORDER BY g.name) FROM admin_groups ag JOIN device_groups g ON g.id = ag.group_id WHERE ag.admin_id = a.id), \
       a.locked_until, a.disabled_at, a.created_at, \
       ARRAY(SELECT group_id FROM admin_groups WHERE admin_id = a.id) \
     FROM admins a";

fn to_row(st: &AppState, r: Row) -> (AccountRow, Vec<i64>) {
    let (id, username, role, groups, locked_until, disabled_at, created_at, group_ids) = r;
    let locked = locked_until.is_some_and(|t| t > Utc::now());
    let (state, state_class) = if disabled_at.is_some() { ("已停用", "disabled") }
        else if locked { ("已鎖定", "locked") }
        else { ("啟用中", "online") };
    (AccountRow {
        id, username,
        role: Role::parse(&role).map(Role::label).unwrap_or("?"),
        groups: groups.unwrap_or_default(),
        state, state_class,
        created_at: fmt_time(st, Some(created_at)),
        locked, disabled: disabled_at.is_some(),
    }, group_ids)
}

async fn all_groups(st: &AppState, selected: &[i64]) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM device_groups ORDER BY name").fetch_all(&st.pool).await?;
    Ok(rows.into_iter().map(|(id, name)| SelectOption { selected: selected.contains(&id), value: id.to_string(), label: name }).collect())
}

fn roles(current: &str) -> Vec<SelectOption> {
    Role::ALL.into_iter().map(|r| SelectOption { value: r.as_str().into(), label: r.label().into(), selected: r.as_str() == current }).collect()
}

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() { Ok(()) } else { Err(forbidden()) }
}

fn db(e: sqlx::Error) -> Response {
    AppError::from(e).into_response()
}

fn conflict(e: anyhow::Error) -> Response {
    (StatusCode::CONFLICT, format!("{e:#}")).into_response()
}

pub async fn list(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, Response> {
    platform(&s)?;
    let rows: Vec<Row> = sqlx::query_as(&format!("{SELECT} ORDER BY a.username")).fetch_all(&st.pool).await.map_err(db)?;
    Ok(render(&AccountsPage {
        nav: Nav::from(&s),
        roles: roles("group_admin"),
        groups: all_groups(&st, &[]).await.map_err(db)?,
        rows: rows.into_iter().map(|r| to_row(&st, r).0).collect(),
    }))
}

pub async fn detail(State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<Row> = sqlx::query_as(&format!("{SELECT} WHERE a.id = $1")).bind(id).fetch_optional(&st.pool).await.map_err(db)?;
    let Some(row) = row else { return Err(not_found()) };
    let role = row.2.clone();
    let (a, group_ids) = to_row(&st, row);
    Ok(render(&AccountPage { nav: Nav::from(&s), roles: roles(&role), groups: all_groups(&st, &group_ids).await.map_err(db)?, a }))
}

/// 解析含重複 `groups` 欄位的表單。
struct AccountForm {
    csrf: String,
    username: String,
    password: String,
    role: Option<Role>,
    groups: Vec<i64>,
}

fn parse_form(raw: &[u8]) -> AccountForm {
    let mut f = AccountForm { csrf: String::new(), username: String::new(), password: String::new(), role: None, groups: vec![] };
    for (k, v) in form_urlencoded::parse(raw) {
        match k.as_ref() {
            "csrf" => f.csrf = v.into_owned(),
            "username" => f.username = v.into_owned(),
            "password" => f.password = v.into_owned(),
            "role" => f.role = Role::parse(&v),
            "groups" => f.groups.extend(v.parse::<i64>().ok()),
            _ => {}
        }
    }
    f
}

pub async fn create(State(st): State<AppState>, AdminSession(s): AdminSession, RawForm(raw): RawForm) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let role = f.role.ok_or_else(|| (StatusCode::BAD_REQUEST, "角色不正確").into_response())?;
    accounts::create(&st.pool, &NewAdmin { username: f.username, password: f.password, role, groups: f.groups }, &s.username)
        .await.map_err(conflict)?;
    Ok(Redirect::to("/accounts").into_response())
}

pub async fn update(State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, RawForm(raw): RawForm) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let role = f.role.ok_or_else(|| (StatusCode::BAD_REQUEST, "角色不正確").into_response())?;
    accounts::update(&st.pool, id, role, &f.groups, s.admin_id, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

pub async fn disable(State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::set_disabled(&st.pool, id, true, s.admin_id, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

pub async fn enable(State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::set_disabled(&st.pool, id, false, s.admin_id, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

pub async fn unlock(State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, Form(f): Form<CsrfForm>) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::unlock(&st.pool, id, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}

#[derive(Deserialize)]
pub struct ResetForm {
    csrf: String,
    password: String,
}

pub async fn reset_password(State(st): State<AppState>, AdminSession(s): AdminSession, Path(id): Path<i64>, Form(f): Form<ResetForm>) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    accounts::reset_password(&st.pool, id, &f.password, &s.username).await.map_err(conflict)?;
    Ok(Redirect::to(&format!("/accounts/{id}")).into_response())
}
```

`crates/server/Cargo.toml` 加 `form_urlencoded = "1"`（axum 已間接依賴，不增加編譯量）。

`web/password.rs`：

```rust
//! 修改自己的密碼（所有角色）。

use askama::Template;
use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, check_csrf};
use super::render;
use crate::AppState;

#[derive(Template)]
#[template(path = "password.html")]
struct PasswordPage {
    nav: Nav,
    message: Option<&'static str>,
    error: Option<String>,
}

pub async fn form(AdminSession(s): AdminSession) -> Response {
    render(&PasswordPage { nav: Nav::from(&s), message: None, error: None })
}

#[derive(Deserialize)]
pub struct ChangeForm {
    csrf: String,
    current: String,
    new: String,
    confirm: String,
}

pub async fn submit(State(st): State<AppState>, AdminSession(s): AdminSession, Form(f): Form<ChangeForm>) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    let fail = |e: String| (StatusCode::BAD_REQUEST, render(&PasswordPage { nav: Nav::from(&s), message: None, error: Some(e) })).into_response();
    if f.new != f.confirm {
        return Err(fail("兩次輸入的新密碼不一致".into()));
    }
    crate::accounts::change_own_password(&st.pool, s.admin_id, &f.current, &f.new, &s.token_hash)
        .await.map_err(|e| fail(format!("{e:#}")))?;
    Ok(render(&PasswordPage { nav: Nav::from(&s), message: Some("密碼已更新"), error: None }))
}
```

router 加：

```rust
        .route("/groups", get(groups::list).post(groups::create))
        .route("/groups/{id}/delete", post(groups::delete))
        .route("/accounts", get(accounts::list).post(accounts::create))
        .route("/accounts/{id}", get(accounts::detail).post(accounts::update))
        .route("/accounts/{id}/disable", post(accounts::disable))
        .route("/accounts/{id}/enable", post(accounts::enable))
        .route("/accounts/{id}/unlock", post(accounts::unlock))
        .route("/accounts/{id}/password", post(accounts::reset_password))
        .route("/password", get(password::form).post(password::submit))
```

以及 `pub mod accounts; pub mod groups; pub mod password;`。

- [ ] **Step 6: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(server): 群組管理、帳號管理與修改密碼"
```

---

### Task 11: 稽核記錄頁

**Files:**
- Create: `templates/audit.html`、`src/web/audit.rs`；Modify: `src/web/mod.rs`（移除 Task 5 的暫時 fallback）
- Modify: `tests/web.rs`

**Interfaces:**
- Produces: `GET /audit?page=`（平台管理員限定）：最新在前、每頁 50 筆；動作顯示中文標籤。

- [ ] **Step 1: 寫失敗測試**

```rust
#[sqlx::test(migrations = false)]
async fn audit_page_lists_logins_and_failures(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.web_client().post(s.web_url("/login"))
        .form(&[("username", "ghost"), ("password", "<script>x</script>")]).send().await.unwrap();
    let c = s.admin_client().await;
    let (status, html) = s.page(&c, "/audit").await;
    assert_eq!(status, 200);
    assert!(html.contains("登入成功") && html.contains("登入失敗") && html.contains("ghost"));
    assert!(!html.contains("<script>x"), "密碼不應出現在稽核記錄");
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test web audit_page`
Expected: FAIL。

- [ ] **Step 3: 樣板與 handler**

`templates/audit.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>稽核記錄</h1>
<table>
  <tr><th>時間</th><th>操作者</th><th>動作</th><th>對象</th><th>細節</th></tr>
  {% for r in rows %}<tr><td>{{ r.at }}</td><td>{{ r.actor }}</td><td>{{ r.action }}</td><td>{{ r.target }}</td><td class="muted">{{ r.detail }}</td></tr>{% endfor %}
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
//! 稽核記錄頁（平台管理員）。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav};
use super::{fmt_time, forbidden, render};
use crate::AppState;
use crate::error::AppError;

const PAGE_SIZE: i64 = 50;

fn label(action: &str) -> &str {
    match action {
        "login" => "登入成功",
        "login_failed" => "登入失敗",
        "logout" => "登出",
        "password_change" => "修改自己的密碼",
        "token_create" => "建立註冊金鑰",
        "token_revoke" => "作廢註冊金鑰",
        "device_retire" => "除役裝置",
        "device_approve" => "核准重新註冊",
        "device_reject" => "拒絕重新註冊",
        "device_move" => "移動裝置群組",
        "group_create" => "建立群組",
        "group_delete" => "刪除群組",
        "admin_create" => "建立帳號",
        "admin_update" => "變更帳號角色／群組",
        "admin_disable" => "停用帳號",
        "admin_enable" => "啟用帳號",
        "admin_password_reset" => "重設帳號密碼",
        "admin_unlock" => "解除帳號鎖定",
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
    nav: Nav,
    rows: Vec<AuditRow>,
    page: i64,
    has_next: bool,
}

pub async fn page(State(st): State<AppState>, AdminSession(s): AdminSession, Query(q): Query<PageQuery>) -> Result<Response, AppError> {
    if !s.all_devices() {
        return Ok(forbidden());
    }
    let page = q.page.max(0);
    let mut rows: Vec<(DateTime<Utc>, String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT at, actor, action, target, detail::text FROM audit_log ORDER BY id DESC LIMIT $1 OFFSET $2",
    ).bind(PAGE_SIZE + 1).bind(page * PAGE_SIZE).fetch_all(&st.pool).await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    Ok(render(&AuditPage {
        nav: Nav::from(&s),
        rows: rows.into_iter().map(|(at, actor, action, target, detail)| AuditRow {
            at: fmt_time(&st, Some(at)), actor, action: label(&action).to_string(),
            target: target.unwrap_or_default(),
            detail: if detail == "{}" { String::new() } else { detail },
        }).collect(),
        page,
        has_next,
    }))
}
```

router `.route("/audit", get(audit::page))`、`pub mod audit;`，並移除 Task 5 暫時加的 fallback。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS（`pages_require_login` 對所有路徑仍回 303）。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(server): 稽核記錄頁"
```

---

### Task 12: serve 開兩個監聽埠、設定、README、實機檢查、PR

**Files:**
- Modify: `crates/server/src/config.rs`、`crates/server/src/lib.rs`（`serve`）、`README.md`

**Interfaces:**
- Produces: `Config.web_listen`（`EM_WEB_LISTEN`，預設 `0.0.0.0:443`）、`Config.display_utc_offset: i32`（`EM_DISPLAY_UTC_OFFSET`，預設 8，範圍 -12～14）

- [ ] **Step 1: 寫失敗測試**（`config.rs`）

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
            web_listen: get("EM_WEB_LISTEN").unwrap_or_else(|| "0.0.0.0:443".into()).parse().context("EM_WEB_LISTEN")?,
            display_utc_offset: {
                let h: i32 = get("EM_DISPLAY_UTC_OFFSET").unwrap_or_else(|| "8".into()).parse().context("EM_DISPLAY_UTC_OFFSET")?;
                anyhow::ensure!((-12..=14).contains(&h), "EM_DISPLAY_UTC_OFFSET out of range");
                h
            },
```

`serve`：`AppState::new(...).with_display_offset(cfg.display_utc_offset)`；並：

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

伺服器同時在 `EM_WEB_LISTEN`（預設 `0.0.0.0:443`）提供 HTTPS 管理網頁，使用 `ca-init` 產生的伺服器憑證；瀏覽器需信任 `pki/root.pem`（或改用公司 CA 簽發的伺服器憑證）。

建立第一個平台管理員（密碼從標準輸入讀取，至少 12 字元）：

```bash
echo '<密碼>' | cargo run -p endpoint-server -- admin-create admin
```

### 角色與群組

- **平台管理員**：全部電腦、帳號、群組、稽核記錄。
- **群組管理員**：只看得到、只管理被指派群組的電腦（除役、核准重新註冊、建立該群組的註冊金鑰）。
- **唯讀檢視者**：只能檢視被指派群組的電腦。

電腦的群組由註冊時使用的金鑰決定；平台管理員可在裝置頁把電腦移到別的群組。

同一台電腦重灌後重新註冊，會列在儀表板「待核准」，需管理員核准後才會接手原裝置記錄。時間以 `EM_DISPLAY_UTC_OFFSET`（小時，預設 8）顯示。
````

- [ ] **Step 5: 全部檢查**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: 全部通過。

- [ ] **Step 6: 實機檢查**

用開發資料庫啟動 `serve`（`EM_WEB_LISTEN=127.0.0.1:18444`），`admin-create` 建平台管理員，再以網頁建立一個群組管理員；用瀏覽器（Playwright／Chrome DevTools MCP，忽略自簽憑證或匯入 root.pem）分別以兩種身分登入，截圖：儀表板、裝置列表、裝置詳細（htmx 分頁）、軟體搜尋、金鑰建立、群組、帳號、稽核記錄；確認主控台沒有 CSP 錯誤、群組管理員看不到範圍外資料。截圖存 `$CLAUDE_JOB_DIR/tmp/`，重點頁面回報使用者。

- [ ] **Step 7: 最終審查、PR、合併**（依 executing-plans 與使用者的 PR 流程）
