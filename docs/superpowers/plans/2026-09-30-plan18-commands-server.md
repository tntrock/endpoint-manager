# 計畫 18：遠端指令（伺服器＋協定）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 伺服器端的遠端指令：
- 腳本管理（含雙人核准設定）。
- 指令建立（單台或群組展開）與取消。
- 報到時下發指令。
- `POST /v1/commands/{id}/result` 回報結果。
- 過期處理的背景工作。

網頁在計畫 20，Agent 在計畫 19。

**Architecture:**
- 協定型別放在新模組 `protocol::command`。
- 伺服器新增模組 `crates/server/src/commands/`：
  - `scripts.rs`：腳本的新增、修改、核准、停用、刪除，以及核准設定。
  - `runs.rs`：建立與取消指令、權限範圍。
  - `api.rs`：報到下發與結果回報。
  - `worker.rs`：過期處理。
- 權限用一個小型的 `Actor { username, platform: bool, groups: Vec<i64> }` 傳入。網頁端（計畫 20）從 `Session` 轉換過來，管理邏輯不依賴網頁模組。

**Tech Stack:** Rust、axum、sqlx、sha2（已有）。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-09-30-remote-commands-design.md`

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 協定新欄位一律 `#[serde(default)]`；未知的列舉值解析成 `Unknown`。
- 腳本限制：
  - 名稱 1–100 字、不能有控制字元。
  - 說明最多 1,000 字。
  - 內容 1 位元組–64 KiB（`MAX_SCRIPT_BYTES = 65536`），不能有 NUL。
  - 逾時 1–120 分鐘。
- 指令限制：
  - 重開機／關機延遲 0–60 分鐘，預設 10。
  - 過期 1 小時–30 天，預設 7 天。
  - 報到每次最多下發 10 筆（`MAX_COMMANDS_PER_CHECKIN`）。
  - 輸出最多 64 KiB（`MAX_OUTPUT_BYTES = 65536`）。
- 所有管理動作都寫稽核紀錄。
- 測試指令：`cargo test -p protocol`、`cargo test -p endpoint-server`；最後跑 clippy 和 fmt。

## Review Focus
1. 群組管理員不能對範圍外的裝置或群組建立指令，也不能建立 `script` 指令；未分組的裝置也算範圍外。
2. 雙人核准模式下，最後修改內容的人不能核准；別人核准後，原作者再改內容，要回到待核准。
3. 取消或過期後，Agent 回報的結果不能覆寫狀態；已經成功或失敗的指令也不能被再次回報覆寫。
4. 指令建立時複製的腳本內容，不受之後修改腳本的影響。下發的一定是建立當時的內容與雜湊。
5. 報到下發不能拖慢沒有指令的裝置。查詢要走部分索引，而且只在有指令時才做寫入。

---

### Task 1：協定型別 `protocol::command`

**Files:**
- Create：`crates/protocol/src/command.rs`
- Modify：`crates/protocol/src/lib.rs`（加 `pub mod command;`；`CheckinResponse` 加 `commands`）。這個檔案含 NUL 字元，要用 Python 編輯。
- Modify：`crates/server/src/checkin.rs`（暫時填 `commands: vec![]`）

**Produces:**
```rust
pub const MAX_SCRIPT_BYTES: usize = 65536;
pub const MAX_OUTPUT_BYTES: usize = 65536;
pub const MAX_COMMANDS_PER_CHECKIN: i64 = 10;
#[serde(rename_all = "snake_case")]
pub enum CommandAction { Collect, Apply, Reboot, Shutdown, Script, #[serde(other)] Unknown }
impl CommandAction { pub fn as_str(self) -> &'static str; pub fn parse(s: &str) -> CommandAction }
pub struct ScriptSpec { pub sha256: String, pub content: String, pub timeout_minutes: u32 }
pub struct Command { pub id: i64, pub action: CommandAction,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub delay_minutes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")] pub script: Option<ScriptSpec> }
#[serde(rename_all = "snake_case")]
pub enum CommandStatus { Succeeded, Failed, #[serde(other)] Unknown }
pub struct CommandResult { pub status: CommandStatus, #[serde(default)] pub exit_code: Option<i32>, #[serde(default)] pub output: String }
impl CommandResult { pub fn validate(&self) -> Result<(), &'static str> } // 狀態不能是 Unknown；output ≤ 64 KiB（位元組）、不能有 NUL
/// 取字串最後 max 個位元組（落在 UTF-8 字元邊界）：Agent 截斷輸出時用
pub fn tail_utf8(s: &str, max: usize) -> &str
// CheckinResponse：
#[serde(default)] pub commands: Vec<command::Command>,
```

- [ ] **Step 1：寫失敗測試**（`command.rs` 內）
  - 舊格式的 `CheckinResponse` JSON 能解析，`commands` 是空的。
  - `{"id":1,"action":"format_disk"}` 解析成 `Unknown`；`reboot` 帶 `delay_minutes` 能往返。
  - `validate`：65,536 位元組通過；65,537 位元組失敗；含 NUL 失敗；`Unknown` 狀態失敗。
  - `tail_utf8("中文abc", 4)` 回傳 `"abc"`，不能切在字元中間；長度未超過時原樣回傳。
- [ ] **Step 2：** 執行 `cargo test -p protocol command`，預期 FAIL。
- [ ] **Step 3：** 實作，並修改 checkin 讓它能編譯。
- [ ] **Step 4：** 執行 `cargo test -p protocol` 和 `cargo build --workspace`，預期 PASS。
- [ ] **Step 5：** Commit「協定：遠端指令型別」。

### Task 2：資料表與腳本管理（`commands::scripts`）

**Files:**
- Create：`crates/server/migrations/0014_commands.sql`
- Create：`crates/server/src/commands/mod.rs`（`pub mod scripts;`；另定義 `Actor`）、`crates/server/src/commands/scripts.rs`
- Modify：`crates/server/src/lib.rs`（加 `pub mod commands;`）
- Test：`crates/server/tests/commands.rs`（新檔）

**Migration：**
```sql
CREATE TABLE scripts (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    description      TEXT NOT NULL DEFAULT '',
    content          TEXT NOT NULL,
    sha256           TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    timeout_minutes  INT NOT NULL CHECK (timeout_minutes BETWEEN 1 AND 120),
    status           TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'disabled')),
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by       TEXT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by      TEXT,
    approved_at      TIMESTAMPTZ
);
CREATE TABLE command_runs (
    id                     BIGSERIAL PRIMARY KEY,
    action                 TEXT NOT NULL CHECK (action IN ('collect', 'apply', 'reboot', 'shutdown', 'script')),
    delay_minutes          INT CHECK (delay_minutes BETWEEN 0 AND 60),
    script_id              BIGINT REFERENCES scripts(id) ON DELETE RESTRICT,
    script_sha256          TEXT,
    script_content         TEXT,
    script_timeout_minutes INT,
    target_label           TEXT NOT NULL,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at             TIMESTAMPTZ NOT NULL,
    canceled_at            TIMESTAMPTZ,
    canceled_by            TEXT,
    CHECK ((action = 'script') = (script_id IS NOT NULL))
);
CREATE INDEX command_runs_created_idx ON command_runs (created_at DESC);
CREATE TABLE command_targets (
    id           BIGSERIAL PRIMARY KEY,
    run_id       BIGINT NOT NULL REFERENCES command_runs(id) ON DELETE CASCADE,
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'sent', 'succeeded', 'failed', 'expired', 'canceled')),
    exit_code    INT,
    output       TEXT NOT NULL DEFAULT '',
    sent_at      TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    UNIQUE (run_id, device_id)
);
CREATE INDEX command_targets_open_idx ON command_targets (device_id, id) WHERE status IN ('pending', 'sent');
CREATE INDEX command_targets_run_idx ON command_targets (run_id, status);
INSERT INTO settings (key, value) VALUES ('scripts_require_second_approver', 'true')
ON CONFLICT (key) DO NOTHING;
```

**Produces:**
```rust
// commands/mod.rs
#[derive(Debug, Clone)]
pub struct Actor { pub username: String, pub platform: bool, pub groups: Vec<i64> }
// commands/scripts.rs
pub struct ScriptInput { pub name: String, pub description: String, pub content: String, pub timeout_minutes: i32 }
pub async fn require_second_approver(pool: &PgPool) -> Result<bool, sqlx::Error>;  // 讀不到或壞掉時回 true（安全預設）
pub async fn set_require_second_approver(pool: &PgPool, on: bool, actor: &Actor) -> anyhow::Result<()>;
pub async fn create_script(pool: &PgPool, i: &ScriptInput, actor: &Actor) -> anyhow::Result<i64>;
pub async fn update_script(pool: &PgPool, id: i64, i: &ScriptInput, actor: &Actor) -> anyhow::Result<()>;
pub async fn approve_script(pool: &PgPool, id: i64, actor: &Actor) -> anyhow::Result<()>;
pub async fn set_disabled(pool: &PgPool, id: i64, disabled: bool, actor: &Actor) -> anyhow::Result<()>;
pub async fn delete_script(pool: &PgPool, id: i64, actor: &Actor) -> anyhow::Result<()>;
```

**規則：**
- 所有函式都要求 `actor.platform`，否則回「只有平台管理員能管理腳本」。
- **新增或修改內容：**
  - 驗證欄位，計算 `sha256`。
  - 需要雙人核准時，狀態設為 `pending`，並清掉 `approved_by`／`approved_at`。
  - 不需要時，狀態設為 `approved`，`approved_by` 設為 actor 本人。
- **修改：**
  - `content` 或 `timeout_minutes` 有變：同上處理核准狀態，並更新 `updated_by`。
  - 只改名稱或說明：狀態不變，`updated_by` 也不變（`updated_by` 代表「最後修改內容的人」）。
  - 已停用的腳本不能修改內容：回「腳本已停用，請先啟用」。
- **核准：**
  - 只有 `pending` 狀態可以核准。
  - 需要雙人核准時，`actor.username` 不能等於 `updated_by`，否則回「不能核准自己修改的腳本」。
- **停用、啟用：**
  - 停用：狀態改成 `disabled`。
  - 啟用：需要雙人核准時改成 `pending`；不需要時改成 `approved`，`approved_by` 設為 actor。
- **刪除：**
  - 被 `command_runs` 引用時回「腳本已被指令使用，只能停用」。外鍵 RESTRICT 也要擋。
- 名稱重複（unique violation）時回「腳本名稱已存在」。
- 稽核動作名稱：`script_create`、`script_update`、`script_approve`、`script_disable`、`script_enable`、`script_delete`、`setting_scripts_second_approver`。稽核內容放 id、sha256、status。

- [ ] **Step 1：寫失敗測試**（`tests/commands.rs`，`#[sqlx::test(migrations = false)]`，比照 `tests/updates.rs` 的 `TestServer`）
  - 群組管理員呼叫 `create_script` 會失敗。
  - 驗證：名稱空白、內容空的、內容有 NUL、65,537 位元組、逾時 0 和 121 都失敗；名稱重複失敗。
  - **雙人核准（預設）：**
    1. alice 建立後狀態是 `pending`，`sha256` 正確。
    2. alice 核准失敗，錯誤訊息含「自己」；bob 核准成功。
    3. alice 只改說明，狀態仍是 `approved`。
    4. alice 改內容，狀態變回 `pending`，`approved_by` 清空。
    5. bob 改內容，狀態也是 `pending`；這時 alice 可以核准，因為最後修改的是 bob。
  - **單人模式：**
    1. `set_require_second_approver(false)` 會寫稽核。
    2. 之後 carol 建立的腳本直接是 `approved`，`approved_by` 是 carol。
  - 設定值被改壞（`'"x"'`）時，`require_second_approver` 回 true。
  - **停用與啟用：** 停用後改內容失敗；啟用後在雙人模式下是 `pending`。
  - **刪除：** 沒被引用的可以刪除。「被引用不能刪」在 Task 3 測試，那時才建得出指令。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands`，預期 FAIL（編譯錯誤）。
- [ ] **Step 3：** 實作 migration、mod、scripts。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「遠端指令：資料表與腳本管理」。

### Task 3：建立與取消指令（`commands::runs`）

**Files:**
- Create：`crates/server/src/commands/runs.rs`
- Test：`crates/server/tests/commands.rs`

**Produces:**
```rust
pub enum Target { Device(uuid::Uuid), Group(i64) }
pub struct RunInput { pub action: String, pub target: Target, pub delay_minutes: Option<i32>,
                      pub script_id: Option<i64>, pub expires_hours: i64 }
pub const DEFAULT_DELAY_MINUTES: i32 = 10;
pub const DEFAULT_EXPIRES_HOURS: i64 = 24 * 7;
/// 回傳 (run id, 台數)
pub async fn create_run(pool: &PgPool, i: &RunInput, actor: &Actor) -> anyhow::Result<(i64, i64)>;
pub async fn cancel_run(pool: &PgPool, id: i64, actor: &Actor) -> anyhow::Result<()>;
```

**規則：**
- **動作與參數：**
  - 動作必須是 5 種之一。
  - `reboot`／`shutdown` 的延遲沒填時用 10，範圍 0–60；其他動作的延遲存 NULL。
  - `expires_hours` 範圍 1–720。
- **權限：**
  - 檢視者不會呼叫到這裡，網頁端會先擋；這裡只檢查 `platform` 和群組。
  - 非平台管理員：`script` 回「只有平台管理員能執行腳本」。
  - 非平台管理員：`Device` 的 `group_id` 必須在 `actor.groups` 內（未分組不行）；`Group` 的 id 必須在 `actor.groups` 內。否則回「不在你的管理範圍」。
- **`script`：**
  - `SELECT … FOR SHARE` 讀取腳本，狀態必須是 `approved`，否則回「腳本尚未核准或已停用」。
  - 把 `sha256`、`content`、`timeout_minutes` 複製到 run。
- **`target_label`：**
  - Device：「裝置 <hostname>」。
  - Group：「群組 <name>」。
- **對象不存在：**
  - Device：裝置不存在或不是使用中時，回「裝置不存在或未啟用」。
  - Group：群組不存在時回「群組不存在」。
- **展開**（同一個交易）：
  - `INSERT INTO command_targets (run_id, device_id) SELECT $1, id FROM devices WHERE status = 'active' AND group_id = $2`（Device 則只插入一筆）。
  - 台數為 0 時回「群組內沒有使用中的裝置」，整筆 rollback。
- **稽核：** `command_create`，內容是 `{id, action, target, count, script_id, script_sha256, delay_minutes, expires_at}`。
- **取消：**
  - 平台管理員或建立者本人才能取消。
  - 已經取消過，回「指令已取消」。
  - 設定 `canceled_at`／`canceled_by`，並把 `pending`／`sent` 的指令改成 `canceled`，同時設 `finished_at`。
  - 稽核：`command_cancel`。

- [ ] **Step 1：寫失敗測試**
  - 用有群組的 token 註冊 3 台「台北」、1 台「高雄」（比照 `tests/updates_web.rs`）。
  - **平台管理員：**
    - 對台北下 `collect`，回傳 3 台，`command_targets` 3 筆都是 `pending`。
    - 對單台高雄下 `reboot`，沒填延遲時存 10。
    - 延遲 61 失敗；過期 0 小時和 721 小時都失敗；動作 `format` 失敗。
  - **群組管理員（只管台北）：**
    - 對高雄群組或高雄的裝置下指令，錯誤訊息含「管理範圍」。
    - `script` 錯誤訊息含「平台管理員」。
    - 對台北的 `collect` 成功。
  - **腳本：**
    - `pending` 的腳本不能下指令。
    - 核准後下指令，run 的 `script_content` 等於當時的內容。
    - 之後修改腳本內容，run 的內容不變。
    - 腳本被引用後 `delete_script` 失敗，錯誤訊息含「只能停用」。
  - 對沒有使用中裝置的群組下指令失敗，也沒有留下 run。
  - **取消：**
    - 其他群組管理員（不是建立者）取消失敗。
    - 建立者取消成功，`pending` 全部變 `canceled`；再取消一次失敗。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands`，預期新測試 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「遠端指令：建立與取消」。

### Task 4：報到下發、結果回報、過期處理

**Files:**
- Create：`crates/server/src/commands/api.rs`、`crates/server/src/commands/worker.rs`
- Modify：`crates/server/src/checkin.rs`：只對使用中的裝置呼叫 `commands::api::pending_for(&st.pool, device_id)`。
- Modify：`crates/server/src/lib.rs`：
  - `agent_router` 加 `.route("/v1/commands/{id}/result", post(commands::api::result))`。
  - serve 時 `commands::worker::spawn(pool.clone())`，放在 `compliance::worker::spawn` 旁邊。
- Test：`crates/server/tests/commands.rs`

**Produces:**
```rust
pub async fn pending_for(pool: &PgPool, device: Uuid) -> Result<Vec<protocol::command::Command>, sqlx::Error>;
pub async fn result(State(st): State<AppState>, device: AuthedDevice, Path(id): Path<i64>, Json(r): Json<CommandResult>) -> Result<StatusCode, AppError>;
pub async fn expire(pool: &PgPool) -> Result<u64, sqlx::Error>;  // 回傳標成過期的筆數
pub fn spawn(pool: PgPool);  // 每 5 分鐘呼叫 expire
```

**`pending_for`：**
- 先查（走部分索引）：
  ```sql
  SELECT t.id, r.action, r.delay_minutes, r.script_sha256, r.script_content, r.script_timeout_minutes, t.status
  FROM command_targets t JOIN command_runs r ON r.id = t.run_id
  WHERE t.device_id = $1 AND t.status IN ('pending','sent')
    AND r.canceled_at IS NULL AND r.expires_at > now()
  ORDER BY t.id LIMIT 10
  ```
  沒有結果時直接回空，不做寫入。
- 其中 `pending` 的指令：`UPDATE command_targets SET status = 'sent', sent_at = now() WHERE id = ANY($1) AND status = 'pending'`。
- 組出 `Command`：只有 `script` 動作帶 `ScriptSpec`；timeout 超出 u32 範圍時用 30。

**`result`：**
- 呼叫 `validate`，失敗回 400。
- 輸出移除控制字元，保留 `\n`、`\r`、`\t`。
- 寫入：
  ```sql
  UPDATE command_targets SET status = $3, exit_code = $4, output = $5, finished_at = now()
  WHERE id = $1 AND device_id = $2 AND status IN ('pending','sent')
  ```
- 影響 0 列時：再查 `id` 是否屬於這台裝置。屬於的話回 204（已是終結狀態、已取消或已過期，忽略）；不屬於就回 404。
- 成功回 204。

**`expire`：**
```sql
UPDATE command_targets t SET status = 'expired', finished_at = now()
FROM command_runs r
WHERE r.id = t.run_id AND t.status IN ('pending','sent') AND r.expires_at <= now()
```

- [ ] **Step 1：寫失敗測試**
  - **下發：**
    - 對一台建立 12 個 `collect`，報到回傳 10 筆，id 由小到大；資料庫中那 10 筆變成 `sent`、另 2 筆仍是 `pending`。
    - 再報到一次，仍回傳同樣 10 筆（重送）。
  - `script` 指令的 `Command.script.content` 等於建立時的內容。
  - **不下發的情況：**
    - 取消的不下發。
    - `UPDATE command_runs SET expires_at = now() - interval '1 minute'` 後不下發；`expire()` 回傳筆數，狀態變 `expired`。
    - 已停用（retired）的裝置報到時 `commands` 為空。
  - **結果回報：**
    - 回報 succeeded 後回 204，資料庫寫入 exit_code 與輸出；控制字元 `\u{7}` 被移除、`\n` 保留。
    - 再回報 failed 回 204，但狀態仍是 succeeded。
    - 回報別台裝置的 id 回 404。
    - 65,537 位元組的輸出回 400。
    - 取消後才回報：204，狀態仍是 canceled。
  - 沒有任何指令的裝置報到時，`commands` 為空。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands`，預期新測試 FAIL。
- [ ] **Step 3：** 實作 api、worker 與串接。
- [ ] **Step 4：** 執行 `cargo test --workspace`、clippy、fmt，全部 PASS。
- [ ] **Step 5：** Commit「遠端指令：報到下發、結果回報與過期」。
