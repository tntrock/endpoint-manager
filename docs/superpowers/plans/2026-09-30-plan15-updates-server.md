# 計畫 15：Windows Update 控制（伺服器＋協定）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 伺服器端的更新原則：資料表、管理 CRUD（含暫停／恢復）、報到下發 `update_policy`、Agent 狀態回報 `PUT /v1/update-status`。網頁與合規規則在計畫 17，Agent 在計畫 16。

**Architecture:**
- 協定型別放在新模組 `protocol::update`，兩端共用值名稱白名單。
- 伺服器新模組 `crates/server/src/updates/`，分成四個檔案：
  - `policy.rs`：表單設定 `PolicySettings` 的驗證，以及轉成登錄檔值清單（純函式）。
  - `admin.rs`：CRUD、暫停、稽核。
  - `assign.rs`：「群組 → 原則」快取，比照 `deploy::assign::DeployCache`。
  - `api.rs`：Agent 狀態回報。

**Tech Stack:** Rust、axum、sqlx、chrono（`NaiveDate`）。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-09-30-windows-update-design.md`

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 協定新欄位一律 `#[serde(default)]`（Option 欄位另加 `skip_serializing_if`），舊 Agent 和舊伺服器互相相容。
- 一個群組最多屬於一個原則；每個原則至少一個群組。
- 名稱 1–100 字，不能有控制字元。
- 設定範圍：
  - 品質更新延後 0–30、功能更新延後 0–365（天）
  - 期限 0–30、寬限 0–7（天）
  - 使用中時段 0–23 點，長度 1–18 小時
- 所有管理動作寫稽核紀錄，並讓 `update_state.generation` 加 1。修改設定、暫停、恢復都讓 `revision` 加 1。
- 測試指令：`cargo test -p protocol`、`cargo test -p endpoint-server`；最後跑 `cargo clippy --workspace --all-targets -- -D warnings` 和 `cargo fmt --all -- --check`。

## Review Focus
1. 下列裝置報到時，`update_policy` 都是 None，但 `update_policy_hash` 一定有值：沒有群組、群組沒有原則、裝置不是使用中。
2. 把已屬於其他原則的群組加進原則時，錯誤訊息要寫出那個原則的名稱，而且整筆不寫入（交易）。
3. 刪除原則後，該群組的裝置下次報到時變成 None；被原則使用的群組不能刪除。
4. `PUT /v1/update-status` 遇到以下內容回 400：未來日期、`detail` 過長、未知 state。裝置只能寫自己的那一列。
5. 暫停後 revision 會變。報到回應的值清單包含 `PauseQualityUpdatesStartTime`，並自動帶上 `DeferQualityUpdates`=1（沒設延後時天數為 0）。

---

### Task 1：協定型別 `protocol::update`

**Files:**
- Create：`crates/protocol/src/update.rs`
- Modify：`crates/protocol/src/lib.rs`
  - 加 `pub mod update;`
  - `CheckinResponse` 加兩個欄位
  - 這個檔案含 NUL 字元，要用 Python 編輯
- Modify：`crates/server/src/checkin.rs`：暫時填 `update_policy: None`、`update_policy_hash: Some(update_policy_hash(None))`；Task 4 再換成實際值。

**Produces:**
```rust
pub const VALUE_NAMES: [&str; 17] = [ "DeferQualityUpdates", "DeferQualityUpdatesPeriodInDays",
  "PauseQualityUpdatesStartTime", "DeferFeatureUpdates", "DeferFeatureUpdatesPeriodInDays",
  "PauseFeatureUpdatesStartTime", "SetComplianceDeadline", "ConfigureDeadlineForQualityUpdates",
  "ConfigureDeadlineGracePeriod", "SetComplianceDeadlineForFU", "ConfigureDeadlineForFeatureUpdates",
  "ConfigureDeadlineGracePeriodForFeatureUpdates", "ConfigureDeadlineNoAutoReboot",
  "ConfigureDeadlineNoAutoRebootForFeatureUpdates", "SetActiveHours", "ActiveHoursStart",
  "ActiveHoursEnd" ];
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PolicyData { Dword(u32), String(String), #[serde(other)] Unknown }
pub struct PolicyValue { pub name: String, pub data: PolicyData }
pub struct UpdatePolicy { pub id: i64, pub revision: i32, pub values: Vec<PolicyValue> }
pub fn update_policy_hash(p: Option<&UpdatePolicy>) -> String  // values 依 name 排序後的 JSON 做 SHA-256
#[serde(rename_all = "snake_case")]
pub enum ApplyState { Unmanaged, Applied, Conflict, Error, #[serde(other)] Unknown }
pub struct UpdateStatus {
    pub policy_id: Option<i64>, pub revision: Option<i32>, pub state: ApplyState,
    #[serde(default)] pub detail: String, pub reboot_pending: bool,
    pub reboot_pending_since: Option<DateTime<Utc>>, pub last_patch_date: Option<NaiveDate>,
}
pub const MAX_DETAIL_LEN: usize = 500;
impl UpdateStatus { pub fn validate(&self, now: DateTime<Utc>) -> Result<(), &'static str> }
// CheckinResponse：
#[serde(default, skip_serializing_if = "Option::is_none")] pub update_policy: Option<update::UpdatePolicy>,
#[serde(default, skip_serializing_if = "Option::is_none")] pub update_policy_hash: Option<String>,
```
`VALUE_NAMES` 就是規格 §2 表格裡的全部值名稱（17 個）。重複由單元測試檢查。

**`validate` 的規則：**
- `detail` 最多 500 字、不能有 NUL。
- `state` 不能是 `Unknown`。
- `reboot_pending_since` 不能晚於 now + 1 天。
- `last_patch_date` 不能晚於 (now + 1 天) 的日期。

- [ ] **Step 1：寫失敗測試**（`update.rs` 內的 `#[cfg(test)]`）
  - 舊格式的 `CheckinResponse` JSON（沒有新欄位）能解析，新欄位是 None。
  - `{"name":"X","data":{"type":"qword","value":1}}` 解析成 `PolicyData::Unknown`。
  - `update_policy_hash` 與 values 的順序無關；None 和「空 values」的雜湊不同。
  - `ApplyState` 的未知字串解析成 `Unknown`。
  - `validate` 的邊界：500 字通過、501 字失敗、明天通過、後天失敗、`Unknown` 失敗。
  - `VALUE_NAMES` 沒有重複。
- [ ] **Step 2：** 執行 `cargo test -p protocol update`，預期 FAIL（模組還不存在）。
- [ ] **Step 3：** 實作型別與函式，並修改 server checkin 讓它能編譯。
- [ ] **Step 4：** 執行 `cargo test -p protocol` 和 `cargo build --workspace`，預期 PASS。
- [ ] **Step 5：** Commit「協定：Windows Update 原則與狀態型別」。

### Task 2：表單設定與值清單（`updates::policy`）

**Files:**
- Create：`crates/server/src/updates/mod.rs`（`pub mod policy;`；Task 3–5 再加其他模組）、`crates/server/src/updates/policy.rs`
- Modify：`crates/server/src/lib.rs` 加 `pub mod updates;`

**Produces:**
```rust
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Deadline { pub days: u32, pub grace: u32 }
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ActiveHours { pub start: u32, pub end: u32 }
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicySettings {
    pub quality_defer_days: Option<u32>,
    pub feature_defer_days: Option<u32>,
    pub quality_pause_start: Option<NaiveDate>,
    pub feature_pause_start: Option<NaiveDate>,
    pub quality_deadline: Option<Deadline>,
    pub feature_deadline: Option<Deadline>,
    pub no_auto_reboot: bool,
    pub active_hours: Option<ActiveHours>,
}
impl PolicySettings {
    pub fn validate(&self) -> anyhow::Result<()>;
    pub fn values(&self) -> Vec<PolicyValue>;   // 依 name 排序
}
pub const PAUSE_DAYS: i64 = 35;
```

**`values()` 的規則：**
- 品質更新：`quality_defer_days` 或 `quality_pause_start` 任一有值時，寫入：
  - `DeferQualityUpdates`=1
  - `DeferQualityUpdatesPeriodInDays`=`quality_defer_days.unwrap_or(0)`
  - 有暫停日時，再寫 `PauseQualityUpdatesStartTime`=`YYYY-MM-DD`（String）
- 功能更新：規則同上。
- `quality_deadline`：寫入 `SetComplianceDeadline`=1、`ConfigureDeadlineForQualityUpdates`、`ConfigureDeadlineGracePeriod`。若 `no_auto_reboot`，再寫 `ConfigureDeadlineNoAutoReboot`=1。
- `feature_deadline`：寫入 `SetComplianceDeadlineForFU`=1、`ConfigureDeadlineForFeatureUpdates`、`ConfigureDeadlineGracePeriodForFeatureUpdates`。若 `no_auto_reboot`，再寫 `ConfigureDeadlineNoAutoRebootForFeatureUpdates`=1。
- `active_hours`：寫入 `SetActiveHours`=1、`ActiveHoursStart`、`ActiveHoursEnd`。

**`validate()` 的錯誤訊息：**
- 範圍錯誤：「品質更新延後必須是 0–30 天」等。
- 使用中時段長度 `(end + 24 - start) % 24` 必須是 1–18，否則「使用中時段必須是 1–18 小時」。
- `no_auto_reboot` 但沒有任何期限：「「期限前不自動重開機」需要設定期限」。

- [ ] **Step 1：寫失敗測試**（`policy.rs` 內）
  - 空設定的 values 是空的。
  - 只有暫停時帶 `DeferQualityUpdates=1` 與天數 0。
  - 延後＋暫停同時設定。
  - 兩種期限＋不自動重開機時，兩個 NoAutoReboot 都寫入。
  - 使用中時段跨午夜（22→6，8 小時）通過；0→19（19 小時）失敗；5→5 失敗。
  - 各範圍的邊界：30 通過、31 失敗、365 通過、366 失敗、寬限 8 失敗。
  - 所有 values 的名稱都在 `protocol::update::VALUE_NAMES` 裡。
  - JSON 往返：`serde_json` 序列化再解析得到相同結果；`{}` 解析成 Default。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --lib updates::policy`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「更新原則：設定驗證與登錄檔值轉換」。

### Task 3：資料表與管理 CRUD（`updates::admin`）

**Files:**
- Create：`crates/server/migrations/0012_update_policies.sql`
- Create：`crates/server/src/updates/admin.rs`
- Modify：`crates/server/src/groups.rs`：群組使用量加上 `update_policy_groups`；刪除群組的錯誤訊息要提到「更新原則」。
- Test：`crates/server/tests/updates.rs`（新檔，`mod common;`）

**Migration：**
```sql
CREATE TABLE update_policies (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    revision    INT NOT NULL DEFAULT 1,
    settings    JSONB NOT NULL DEFAULT '{}',
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- 一台裝置只屬一個群組：一個群組最多屬於一個原則，裝置就最多對應一個原則
CREATE TABLE update_policy_groups (
    group_id   BIGINT PRIMARY KEY REFERENCES device_groups(id) ON DELETE RESTRICT,
    policy_id  BIGINT NOT NULL REFERENCES update_policies(id) ON DELETE CASCADE
);
CREATE INDEX update_policy_groups_policy_idx ON update_policy_groups (policy_id);
CREATE TABLE update_policy_status (
    device_id            UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    policy_id            BIGINT,
    revision             INT,
    state                TEXT NOT NULL CHECK (state IN ('unmanaged', 'applied', 'conflict', 'error')),
    detail               TEXT NOT NULL DEFAULT '',
    reboot_pending       BOOLEAN NOT NULL,
    reboot_pending_since TIMESTAMPTZ,
    last_patch_date      DATE,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX update_policy_status_policy_idx ON update_policy_status (policy_id, state);
CREATE TABLE update_state (generation BIGINT NOT NULL);
INSERT INTO update_state VALUES (0);
```
（寫之前先確認 `device_groups` 的實際表名與 id 型別，依 0001／0002 migration 為準。）

**Produces:**
```rust
pub struct PolicyInput { pub name: String, pub settings: PolicySettings, pub groups: Vec<i64> }
#[derive(Debug, Clone, Copy)] pub enum PauseKind { Quality, Feature }
pub async fn create_policy(pool: &PgPool, i: &PolicyInput, actor: &str) -> anyhow::Result<i64>;
pub async fn update_policy(pool: &PgPool, id: i64, i: &PolicyInput, actor: &str) -> anyhow::Result<()>;
/// start = None 表示恢復
pub async fn set_pause(pool: &PgPool, id: i64, kind: PauseKind, start: Option<NaiveDate>, actor: &str) -> anyhow::Result<()>;
pub async fn delete_policy(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()>;
```

**實作要點：**
- 驗證名稱與 `settings.validate()`；`groups` 去重後不能為空。
- 在交易內 `SELECT id FROM update_policies WHERE id = $1 FOR UPDATE`，不存在時回「原則不存在」。
- **更新：**
  - 保留原本的暫停日：表單不含暫停，所以 `settings` 的兩個 pause 欄位沿用資料庫的值。
  - `revision + 1`。
  - 刪掉舊群組再寫新群組。
- **群組衝突：**
  - 寫入前先查 `SELECT g.name, p.name FROM update_policy_groups x JOIN … WHERE x.group_id = ANY($1) AND x.policy_id <> $2`。有結果時回「群組「A」已屬於原則「B」」。
  - 萬一並行時撞到 PK 衝突，也回同樣的錯誤。
  - 群組不存在（外鍵錯誤）時回「群組不存在」。
- **名稱重複**（unique violation）：回「原則名稱已存在」。
- **暫停／恢復：** `settings = jsonb_set(...)`，或讀出來改完再寫回；`revision + 1`。
  - 稽核動作名稱：`update_policy_pause`／`update_policy_resume`。
  - 稽核內容：`{"id", "kind": "quality"|"feature", "start"}`。
- **其他稽核動作名稱：** `update_policy_create`、`update_policy_update`、`update_policy_delete`。稽核內容放 id、settings、groups。
- 每個異動都執行 `UPDATE update_state SET generation = generation + 1`。

- [ ] **Step 1：寫失敗測試**（`tests/updates.rs`，`#[sqlx::test(migrations = false)]`，比照 `tests/deploy.rs`）
  - 建立成功；稽核有 `update_policy_create`；generation 加 1。
  - 驗證錯誤：
    - 名稱空白、名稱有 `\t`
    - 沒有群組
    - 延後 31 天
    - 群組 id 9999
    - 名稱重複
  - 群組衝突：原則 A 用了「台北」後，建立原則 B 用「台北」失敗，錯誤訊息含「A」；B 完全沒有寫入。
  - 更新：revision 變 2；群組換成「高雄」後，「台北」可以給別的原則用；暫停日保留。
  - `set_pause(Quality, Some(2026-09-30))`：revision 加 1；設定裡有暫停日；再 `set_pause(Quality, None)` 就清掉。
  - 刪除：群組連結消失，群組可以刪除；原則使用中時，`groups::delete` 失敗且訊息含「更新原則」。
  - 更新或刪除不存在的 id：錯誤訊息含「原則不存在」。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test updates`，預期 FAIL（編譯錯誤：模組不存在）。
- [ ] **Step 3：** 實作 migration、admin，並修改 groups。
- [ ] **Step 4：** 同一指令預期 PASS；另跑 `cargo test -p endpoint-server --test deploy`，確認群組相關測試不受影響。
- [ ] **Step 5：** Commit「更新原則：資料表與管理」。

### Task 4：快取與報到下發（`updates::assign`）

**Files:**
- Create：`crates/server/src/updates/assign.rs`
- Modify：`crates/server/src/lib.rs`：`AppState` 加 `pub updates: Arc<updates::assign::UpdatePolicyCache>`，在 `new` 裡初始化。
- Modify：`crates/server/src/checkin.rs`
- Test：`crates/server/tests/updates.rs`

**Produces:**
```rust
pub struct PolicySet { pub generation: i64, pub by_group: HashMap<i64, Arc<UpdatePolicy>> }
impl PolicySet { pub fn policy_for(&self, group: Option<i64>) -> Option<UpdatePolicy> }
#[derive(Default)] pub struct UpdatePolicyCache { /* 同 DeployCache */ }
impl UpdatePolicyCache {
    pub async fn get(&self, pool: &PgPool) -> Result<Arc<PolicySet>, sqlx::Error>;
    pub async fn get_throttled(&self, pool: &PgPool) -> Result<Arc<PolicySet>, sqlx::Error>;
    pub fn invalidate(&self);
}
```

**實作要點：**
- `load` 在一個交易內讀取 generation、`update_policies`（id、revision、settings）和 `update_policy_groups`。
  - `settings` 解析成 `PolicySettings`；解析失敗時記 `tracing::error!` 並跳過該原則，不讓報到失敗。
  - 用 `settings.values()` 產生 `UpdatePolicy`。
- 報到時：
  - `update_policy = if status == "active" { set.policy_for(group_id) } else { None }`
  - `update_policy_hash = Some(update_policy_hash(update_policy.as_ref()))`

- [ ] **Step 1：寫失敗測試**
  - 三台裝置分別屬於台北、高雄和沒有原則的群組。原則 A 套用台北。
    - 台北那台報到拿到 A，values 和 `settings.values()` 相同。
    - 另外兩台是 None，但 `update_policy_hash` 是 Some。
  - 修改 A 之後（`s.state.updates.invalidate()`）revision 變 2，雜湊也改變。
  - 刪除 A 之後變 None。
  - 停用裝置（`UPDATE devices SET status = 'disabled'`，依既有測試的做法）拿到 None。
  - `PolicySet::policy_for(None)` 回傳 None（放在 `assign.rs` 的單元測試）。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test updates checkin`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-server --test updates`，預期 PASS。
- [ ] **Step 5：** Commit「更新原則：報到下發」。

### Task 5：狀態回報 `PUT /v1/update-status`（`updates::api`）

**Files:**
- Create：`crates/server/src/updates/api.rs`
- Modify：`crates/server/src/lib.rs`：在 `agent_router` 加 `.route("/v1/update-status", put(updates::api::status))`
- Test：`crates/server/tests/updates.rs`

**Produces:**
```rust
pub async fn status(State(st): State<AppState>, device: AuthedDevice, Json(s): Json<UpdateStatus>) -> Result<StatusCode, AppError>
```

**實作要點：**
- 呼叫 `s.validate(Utc::now())`，失敗時回 `AppError::BadRequest`。
- 以 `device.device_id` upsert 到 `update_policy_status`，每個欄位都更新，`updated_at` 設為 `now()`。
- `state` 用 `serde_json` 的標籤字串存。
- 成功回 204。
- `detail` 移除控制字元（保留換行以外的全部移除），比照 `deploy::api::result`。

- [ ] **Step 1：寫失敗測試**
  - 送出 applied 狀態後回 204，資料庫那一列正確；再送 conflict 覆蓋。
  - 以下各自回 400：明天之後的 `last_patch_date`、501 字的 `detail`、`"state":"weird"`。
  - 沒有用戶端憑證的請求被拒絕（比照既有 agent 端點測試的寫法）。
  - 兩台裝置各自只寫到自己的那一列。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test updates status`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test --workspace`、clippy、fmt，全部 PASS。
- [ ] **Step 5：** Commit「更新原則：Agent 狀態回報」。
