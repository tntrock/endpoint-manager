# 計畫 16：Windows Update 控制（Agent）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agent 端的更新原則處理：
- 依報到收到的 `update_policy` 寫入或刪除 WUfB 登錄檔值。
- 偵測衝突。
- 收集待重開機與最後裝更新日期。
- 以 `PUT /v1/update-status` 回報。

**Architecture:** 新模組 `crates/agent/src/updates/`，四個檔案：
- `logic.rs`：純函式 `decide`，決定要寫什麼、刪什麼、狀態是什麼；另有 `last_patch_date`。
- `state.rs`：`update_policy.json`。
- `host.rs`：`WuHost` trait，負責登錄檔讀寫與待重開機偵測。
- `worker.rs`：`UpdateWorker`、`run_update_worker`，比照 `deploy::worker`，並用 `watch` 通道從報到迴圈接收工作。

Windows 實作是 `windows/wupolicy.rs`（winreg）。e2e 測試用記憶體中的假 host，跨平台執行。

**Tech Stack:** Rust、tokio、winreg、chrono。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-09-30-windows-update-design.md`（§2、§4）

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 只寫 `protocol::update::VALUE_NAMES` 內的值。遇到白名單外的名稱或 `PolicyData::Unknown` 時，整份原則不套用，狀態記為 `error`。
- 報到回應沒有 `update_policy_hash`（舊伺服器）時，Agent 完全不動 WU 設定，也不回報狀態。
- 只刪「自己寫過、而且目前值仍等於當初寫入內容」的值。`WindowsUpdate` 機碼本身不刪。
- 正式路徑：`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`（64 位元檢視）。
- 狀態回報時機：內容改變時，或距上次成功送出滿 24 小時時。
- 檢查週期：每小時一次，原則改變時立即執行。
- 測試指令：
  - `cargo test -p endpoint-agent`
  - Windows 實機：`cargo test -p endpoint-agent --test windows`
  - e2e 需要 Postgres：`cargo test -p endpoint-agent --test e2e`
  - 最後跑 clippy 和 fmt。

## Review Focus
1. 原則改版時，舊版有、新版沒有的值被管理員（或 GPO）改過的話不能刪；沒被改過的要刪。
2. 衝突後 revision 沒變就不能再寫入；值被改回和當初寫入相同時，要回到 `applied`。
3. 刪除或寫入失敗時記為 `error`、保留 `written`，下次 pass 重試，不會「忘記」自己寫過的值。
4. 伺服器從新版換回舊版（回應沒有 hash）時，worker 停止運作，不刪任何值。
5. 狀態內容沒變時 24 小時內不重送；回報失敗（網路錯誤）時下次 pass 再送。

---

### Task 1：核對 ADMX 值名稱

**Files:**
- Test：`crates/agent/tests/windows.rs`（加一個測試）

- [ ] **Step 1：寫測試 `admx_declares_every_policy_value`**
  - 讀 `%SystemRoot%\PolicyDefinitions\WindowsUpdate.admx`，對 `protocol::update::VALUE_NAMES` 的每個名稱斷言檔案中出現 `valueName="<名稱>"`。
  - 檔案不存在時：若環境變數 `CI` 有設定就 panic（CI 必須檢查到），否則印出訊息後略過（本機 Windows Home 沒有這個檔案）。
  - 同時斷言 `PauseQualityUpdatesStartTime` 所在的元素是 `<text`（REG_SZ），而 `DeferQualityUpdatesPeriodInDays` 是 `<decimal`：找出 `valueName="X"` 所在那一行，檢查它前面的標籤名稱。
- [ ] **Step 2：** 推到分支，看 CI `agent-windows` job 的結果。
  - 全部通過：繼續下一個工作。
  - 有名稱不存在：CI runner 是 Server 2022，它的 ADMX 可能比 Windows 11 22H2 舊，例如缺少 `SetComplianceDeadlineForFU`。
    - 查 Microsoft Learn 的 Policy CSP - Update（ADMX 對應段落），確認正確名稱。
    - 名稱錯了：修改 `VALUE_NAMES`、伺服器的 `policy.rs` 與規格 §2。
    - 只是 runner 的 ADMX 太舊：把該名稱列在測試的「舊版 ADMX 可能沒有」清單，並在 ledger 記 ruling。
- [ ] **Step 3：** Commit「Agent：核對 WU 原則值名稱與 ADMX 一致」。

### Task 2：純邏輯 `updates::logic`

**Files:**
- Create：`crates/agent/src/updates/mod.rs`（`pub mod logic;`，之後再加其他模組）、`crates/agent/src/updates/logic.rs`
- Modify：`crates/agent/src/lib.rs` 加 `pub mod updates;`

**Produces:**
```rust
use protocol::update::{ApplyState, PolicyData, UpdatePolicy};
use std::collections::BTreeMap;

/// 目前套用的結果（state.rs 會存這個）
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Applied {
    pub policy_id: Option<i64>,
    pub revision: Option<i32>,
    /// 值名稱 → 自己寫入的內容
    pub written: BTreeMap<String, PolicyData>,
    pub state: Option<ApplyState>,   // None = 從未處理
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    /// 什麼都不做，狀態改成 (state, detail)
    Report { state: ApplyState, detail: String },
    /// 寫入 writes、刪除 deletes，完成後讀回確認
    Apply { writes: Vec<(String, PolicyData)>, deletes: Vec<String> },
    /// 移出範圍：刪除 deletes，清空 written
    Release { deletes: Vec<String> },
}

/// `current(name)` 讀目前的值（不存在 → None）
pub fn decide(desired: Option<&UpdatePolicy>, applied: &Applied,
              current: &dyn Fn(&str) -> Option<PolicyData>) -> Decision;

/// 從 patches 清單（WMI InstalledOn）取最新日期；支援 M/D/YYYY 與 16 位 hex FILETIME
pub fn last_patch_date(items: &[protocol::PatchItem]) -> Option<chrono::NaiveDate>;
```

**`decide` 的規則：**
1. `desired` 有原則、但有值不在白名單，或 data 是 `Unknown`：回 `Report { Error, "不支援的值：<名稱>" }`。
2. `desired` 有原則，且屬於以下任一情況：`(id, revision)` 和 `applied` 不同、`applied.state` 是 `Error`、或 `applied.state` 是 `None`。回 `Apply`：
   - `writes` 是全部值。
   - `deletes` 是 `applied.written` 裡新原則沒有、而且 `current == written` 的名稱。
3. `desired` 有原則，`(id, revision)` 相同，狀態是 applied 或 conflict：
   - `applied.written` 裡任一值的 `current` 和寫入內容不同：回 `Report { Conflict, "<名稱>, <名稱>" }`，名稱依字母排序。
   - 否則回 `Report { Applied, "" }`。
4. `desired` 是 None：
   - `written` 不空：回 `Release`，`deletes` 是 `current == written` 的名稱。
   - 否則回 `Report { Unmanaged, "" }`。

- [ ] **Step 1：寫失敗測試**（`logic.rs` 內）
  - 首次套用：`Apply`，writes 是全部值、沒有 deletes。
  - 改版：舊版有 A、B，新版只有 A。B 的目前值等於寫入內容時刪除；B 被改過時不刪。
  - 同版且值相符：`Applied`。
  - 同版而 B 被改：`Conflict`，detail 是「B」。
  - 衝突後值被改回：`Applied`。
  - 上次是 Error：再次 `Apply`。
  - 白名單外的名稱，或 `PolicyData::Unknown`：`Error`，detail 含名稱。
  - None 且有 written：`Release`，只刪相符的值。
  - None 且沒有 written：`Unmanaged`。
  - `last_patch_date`：
    - `["9/10/2026","12/1/2025"]` → 2026-09-10。
    - FILETIME `"01d9e4c2a1b2c3d4"` → 解析出的日期（寫測試時以 `chrono` 計算期望值並寫死）。
    - 空字串或 None → None。
    - 格式錯誤的項目略過。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --lib updates::logic`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「Agent：WU 原則套用邏輯」。

### Task 3：狀態檔與登錄檔存取

**Files:**
- Create：`crates/agent/src/updates/state.rs`、`crates/agent/src/updates/host.rs`
- Create：`crates/agent/src/windows/wupolicy.rs`（`windows/mod.rs` 加 `pub mod wupolicy;`）
- Test：`crates/agent/tests/windows.rs`

**Produces:**
```rust
// state.rs
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateState {
    pub applied: Applied,
    pub reboot_pending_since: Option<DateTime<Utc>>,
    /// 上次成功送出的狀態雜湊與時間
    pub sent_hash: Option<String>,
    pub sent_at: Option<DateTime<Utc>>,
}
impl UpdateState {
    pub fn load(dir: &Path) -> UpdateState;               // 檔案不存在或壞掉 → Default（壞掉時記 warn）
    pub fn save(&self, dir: &Path) -> std::io::Result<()>; // 先寫暫存檔再 rename，比照 deploy::state
}
pub const FILE: &str = "update_policy.json";

// host.rs
pub trait WuHost: Send + Sync + 'static {
    fn read(&self, name: &str) -> std::io::Result<Option<PolicyData>>;
    fn write(&self, name: &str, data: &PolicyData) -> std::io::Result<()>;
    /// 值不存在也算成功
    fn delete(&self, name: &str) -> std::io::Result<()>;
    fn reboot_pending(&self) -> bool;
}
/// 測試用：記憶體中的登錄檔
#[derive(Default)] pub struct MemoryHost { pub values: Mutex<BTreeMap<String, PolicyData>>, pub reboot: AtomicBool, pub fail_writes: AtomicBool }

// windows/wupolicy.rs
pub const POLICY_PATH: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
pub struct RegistryHost { root: winreg::HKEY, path: String }
impl RegistryHost {
    pub fn machine() -> Self;                     // HKLM + POLICY_PATH
    pub fn at(root: winreg::HKEY, path: &str) -> Self; // 測試用
}
impl WuHost for RegistryHost { ... }
```

**RegistryHost 的實作要點：**
- 讀：REG_DWORD → `Dword`、REG_SZ → `String`、其他型別 → `Unknown`；值不存在 → `Ok(None)`；機碼不存在 → `Ok(None)`。
- 寫：`create_subkey_with_flags(path, KEY_WRITE | KEY_WOW64_64KEY)` 後用 `set_value`。`Unknown` 回 `InvalidInput` 錯誤（`decide` 已先擋掉）。
- 刪：`delete_value`，遇到 NotFound 視為成功。
- 待重開機：以下任一機碼存在即為真：
  - HKLM `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
  - HKLM `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`

  讀取時使用 KEY_WOW64_64KEY。

- [ ] **Step 1：寫失敗測試**
  - `state.rs` 單元測試：
    - save 後 load 得到相同內容。
    - 壞掉的 JSON 讀成 Default。
    - 缺欄位的舊檔也能讀。
  - `host.rs` 單元測試：`MemoryHost` 的讀、寫、刪。
  - `tests/windows.rs`：`registry_host_round_trip`（不需系統管理員）
    - 在 `HKCU\Software\endpoint-manager-test\<uuid>` 寫 Dword 和 String，讀回相同；刪除後讀到 None；刪除不存在的值成功。
    - 用 `reg query` 或 winreg 確認 String 的型別是 REG_SZ。
    - 最後刪掉整個測試機碼。
    - `reboot_pending()` 能呼叫、不 panic（值依機器而定，不斷言）。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --lib updates` 和 `cargo test -p endpoint-agent --test windows registry_host`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同樣兩個指令，預期 PASS。
- [ ] **Step 5：** Commit「Agent：WU 狀態檔與登錄檔存取」。

### Task 4：worker、報到串接、回報

**Files:**
- Create：`crates/agent/src/updates/worker.rs`
- Modify：`crates/agent/src/client.rs`：新增 `pub async fn update_status(&self, s: &UpdateStatus) -> Result<(), ClientError>`（PUT `/v1/update-status`）。
- Modify：`crates/agent/src/agent.rs`：新增 `with_updates(tx: watch::Sender<Option<UpdateWork>>)`。報到後比照 deploy 用 `send_if_modified`；只有 `update_policy` 內容改變時才喚醒 worker，連線資訊則每次都更新。
- Modify：`crates/agent/src/windows/mod.rs`：spawn `run_update_worker(UpdateWorker::new(dir, Arc::new(WindowsCollector), RegistryHost::machine()), rx, shutdown)`。
- Test：`crates/agent/tests/e2e.rs` 新增 `mod updates`（使用真實伺服器與 `MemoryHost`）。

**Produces:**
```rust
#[derive(Debug, Clone)]
pub struct UpdateWork { pub policy: Option<UpdatePolicy>, pub server_url: String, pub root_pem: String, pub identity_pem: Option<String> }
pub const RECHECK: Duration = Duration::from_secs(60 * 60);
pub const RESEND: chrono::Duration = chrono::Duration::hours(24);
pub struct UpdateWorker<C: Collector, H: WuHost> { dir, collector: Arc<C>, host: Arc<H>, state: UpdateState }
impl UpdateWorker {
    pub fn new(dir: &Path, collector: Arc<C>, host: Arc<H>) -> Self;
    pub async fn pass(&mut self, w: &UpdateWork);
    pub async fn pass_at(&mut self, w: &UpdateWork, now: DateTime<Utc>);
    pub fn state(&self) -> &UpdateState;
}
pub async fn run_update_worker<C, H>(worker, rx: watch::Receiver<Option<UpdateWork>>, shutdown: watch::Receiver<bool>);
```

**`pass_at` 的流程**（登錄檔操作在 `spawn_blocking` 裡執行，比照 deploy 收集軟體清單的做法）：
1. 呼叫 `decide`，`current` 用 `host.read`。讀取失敗時當成 None，並記 warn。
2. 依 decision 處理：
   - **`Report`**：更新 `applied.state` 與 `detail`。
   - **`Apply`**：
     1. 依序寫入與刪除，遇到第一個錯誤就停止，記為 `Error`，detail 寫「寫入 <名稱> 失敗：<錯誤>」。已寫入的值要加進 `written`，這樣下次改版時仍能清除。
     2. 全部成功後讀回確認：不同就記為 `Error`「讀回不符：<名稱>」；相符就把 `written` 設為新原則的值，並更新 id、revision，記為 `Applied`。
   - **`Release`**：依序刪除。成功刪除的值從 `written` 移除；全部成功後 id 和 revision 設為 None，記為 `Unmanaged`。有任何失敗就記為 `Error`，保留剩下的 `written`。
3. **待重開機**：`host.reboot_pending()` 從 false 變 true 時，`reboot_pending_since = now`；變成 false 時清除。
4. **最後裝更新日期**：透過 `spawn_blocking` 呼叫 `collector.collect(Section::Patches)` 並套用 `last_patch_date`；收集失敗時為 None。
5. 組出 `UpdateStatus`：
   - `policy_id` 與 `revision` 取 `applied`。
   - `state` 取 `applied.state`，還沒有時用 `Unmanaged`。
   - `detail` 截到 `MAX_DETAIL_LEN`。
6. 對 `UpdateStatus` 的 JSON 做 SHA-256。雜湊和 `sent_hash` 不同、或 `sent_at` 早於 now − RESEND 時才送出；成功後更新 `sent_hash` 與 `sent_at`。
7. 狀態有變就呼叫 `save`，失敗時記 error。

**`run_update_worker`：** 比照 `deploy::worker::run_worker`。收到 `Some(work)` 時立刻 pass，之後每 RECHECK 再做一次；`None`（舊伺服器）時什麼都不做。

- [ ] **Step 1：寫失敗測試**（`tests/e2e.rs` 的 `mod updates`）
  - `policy_applied_conflict_and_released`：
    1. 在伺服器建立原則（群組為測試 Agent 報到時的群組；若 Env 預設沒有群組，就用有群組的 token 註冊）。
    2. 呼叫 `Agent::run_cycle`，從 watch 通道取出 `UpdateWork`，交給使用 `MemoryHost` 的 `UpdateWorker::pass`。
    3. MemoryHost 的值等於原則的值，伺服器的 `update_policy_status` 是 applied、revision 1。
    4. 手動改 MemoryHost 的一個值後 pass：伺服器顯示 conflict，detail 含該名稱，而且那個值沒被寫回。
    5. 伺服器端修改原則（revision 2）後 run_cycle 再 pass：重新寫入，狀態回到 applied。
    6. 刪除原則後 run_cycle 再 pass：MemoryHost 清空，狀態是 unmanaged。
  - `write_failure_is_error_and_retried`：設定 `fail_writes` 後 pass，狀態是 error；清除後再 pass，狀態是 applied。
  - `status_not_resent_when_unchanged`：連續 pass 兩次，第二次不送。檢查方式：`sent_at` 沒變；也可以看伺服器 `update_policy_status.updated_at` 沒變。改 `pass_at` 的 now 為 25 小時後就會重送。
  - `old_server_means_no_work`：回應沒有 `update_policy_hash` 時 watch 值為 None。這個情況 e2e 很難製造，所以把「hash 為 None → None」寫成 `agent.rs` 裡可測的小函式 `update_work(resp, ...)`，並用單元測試驗證。
  - `reboot_pending_since`：`MemoryHost.reboot` 設為 true 後 pass，回報的 since 等於 now；再 pass 時 since 不變；設為 false 後 pass，since 變成 None。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --test e2e updates`，預期 FAIL（編譯錯誤）。
- [ ] **Step 3：** 實作 worker、client、agent 與 windows 串接。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-agent`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all -- --check`，預期全部通過。
- [ ] **Step 5：** Commit「Agent：WU 原則 worker 與狀態回報」。
