# 計畫 19：遠端指令（Agent）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agent 收到報到下發的指令後，依序執行並回報結果。要做到：
- 去重：同一個指令不執行兩次。
- 執行中斷時回報失敗。
- 重開機或關機前先回報結果。
- 腳本先驗證雜湊再執行，並收回輸出。

**Architecture:**
- 新模組 `crates/agent/src/commands/`：
  - `logic.rs`：純函式。決定每個指令「該做什麼」；產生 `shutdown.exe` 參數與通知訊息。
  - `state.rs`：`commands.json`。
  - `worker.rs`：`CommandWorker`、`CommandHost` trait、`run_command_worker`。
- 程序執行沿用派送的 `ProcessRunner`，抽出 `run_process(cmd, timeout, capture)`，並加上輸出收集。
- 「立即套用」用 `tokio::sync::Notify` 喚醒派送與更新原則的背景工作。
- 「重新收集」沿用報到迴圈既有的 `mpsc::Sender<Section>` 觸發通道。

**Tech Stack:** Rust、tokio、sha2。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-09-30-remote-commands-design.md`（§5）

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 報到回應沒有 `commands`（舊伺服器）時，就是空清單，worker 什麼都不做。
- 執行前先在 `commands.json` 寫入 `started_at` 並存檔；狀態檔保留 30 天。
- 輸出最多 `protocol::command::MAX_OUTPUT_BYTES`（64 KiB）：只保留最後的部分，用 `tail_utf8` 截斷。
- 腳本：
  - 雜湊不符就回報失敗，不執行。
  - 寫成 `<資料目錄>\scripts\<id>.ps1`（UTF-8 含 BOM），執行完刪除。
  - 執行方式：`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "<路徑>"`。
  - 結束碼 0 算成功；逾時算失敗，訊息「逾時（N 分鐘）」。
- 重開機／關機：
  - 指令：`%SystemRoot%\System32\shutdown.exe /r|/s /t <秒> /c "<訊息>" /d p:0:0`。
  - 一律先回報成功（輸出為要執行的指令），再執行。回報失敗時仍然執行，結果留在狀態檔補送。
- 測試指令：
  - `cargo test -p endpoint-agent`
  - Windows 實機：`cargo test -p endpoint-agent --test windows`
  - e2e 需要 Postgres：`cargo test -p endpoint-agent --test e2e`
  - 完整測試：`cargo test --workspace -j 4`（減少記憶體用量）
  - 最後跑 clippy 和 fmt。

## Review Focus
1. 同一個指令每次報到都會重送：已有結果的只補送；已開始但沒有結果的回報「執行中斷」；絕不重跑腳本或重複關機。
2. 腳本逾時或被結束時，仍然要回報已收到的部分輸出，而且不能卡住 worker。
3. 重開機指令在回報失敗（網路斷）時仍要執行，開機後補送結果；但不能因為補送又再重開一次。
4. 輸出含非 UTF-8 位元組（PowerShell 預設 OEM 編碼）時不能 panic；用 lossy 轉換。
5. 狀態檔遺失時，伺服器重送的指令會被當成新指令再執行一次。這是已知限制：腳本應設計成可以重複執行。要寫在 README（計畫 20）。

---

### Task 1：程序執行加上輸出收集（`deploy::worker::run_process`）

**Files:**
- Modify：`crates/agent/src/deploy/worker.rs`
- Test：同檔案的 `#[cfg(all(test, windows))]` 測試

**Produces:**
```rust
pub struct RunOutput { pub result: RunResult, pub output: String }
/// capture = false 時 stdout／stderr 丟棄（派送用），true 時各保留最後 MAX_OUTPUT_BYTES，
/// 結束後以 stdout、stderr 的順序合併（lossy UTF-8），再用 tail_utf8 截到 MAX_OUTPUT_BYTES
pub async fn run_process(cmd: &Cmd, timeout: Duration, capture: bool) -> std::io::Result<RunOutput>;
```
`ProcessRunner::run` 改成呼叫 `run_process(cmd, timeout, false)` 並回傳 `.result`，派送行為不變。

**實作要點：**
- `capture` 時把 stdout 和 stderr 設成 `Stdio::piped()`。各自 spawn 一個讀取 task，讀到的資料放進 `VecDeque<u8>` 或 `Vec<u8>`，超過上限就從前面丟掉。
- 逾時處理：
  1. 用 Job 結束整個程序樹，再 `child.kill()`。
  2. 等讀取 task 最多 5 秒，避免孫程序繼承了 handle 讓 pipe 一直不關。
  3. 逾時就 abort 讀取 task，用已讀到的部分。
- stdout、stderr 都有內容時，兩段之間加 `\n`。

- [ ] **Step 1：寫失敗測試**
  - `run_process_captures_output_and_exit_code`：`cmd /c "echo hello & echo oops 1>&2 & exit 3"` 得到 `Exited(3)`，輸出含 `hello` 和 `oops`。
  - `run_process_keeps_tail`：`cmd /c "for /l %i in (1,1,20000) do @echo line%i"` 的輸出不超過 65,536 位元組，而且以 `line20000` 結尾（去掉結尾換行後）。
  - `run_process_timeout_returns_partial_output`：`cmd /c "echo started & ping -n 30 127.0.0.1 >nul"`，1 秒逾時，得到 `TimedOut`，輸出含 `started`，總耗時 < 10 秒。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --lib deploy::worker`，預期 FAIL（`run_process` 不存在）。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令預期 PASS；原本的 `process_runner_reports_exit_code_and_timeout` 與 `timeout_kills_the_whole_process_tree` 仍要通過。
- [ ] **Step 5：** Commit「Agent：程序執行可收集輸出」。

### Task 2：純邏輯與狀態檔（`commands::logic`、`commands::state`）

**Files:**
- Create：`crates/agent/src/commands/mod.rs`、`logic.rs`、`state.rs`
- Modify：`crates/agent/src/lib.rs`（加 `pub mod commands;`）

**Produces:**
```rust
// state.rs
pub const FILE: &str = "commands.json";
pub const FORGET_AFTER_DAYS: i64 = 30;
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry { pub started_at: Option<DateTime<Utc>>, pub result: Option<CommandResult>, pub reported: bool }
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CommandsState { pub entries: BTreeMap<i64, Entry> }
impl CommandsState {
    pub fn load(dir: &Path) -> Self;          // 讀不到或壞掉 → Default（記 warn）
    pub fn save(&self, dir: &Path) -> std::io::Result<()>;  // crate::state::write_atomic
    pub fn prune(&mut self, now: DateTime<Utc>);  // started_at 早於 30 天前且已回報的刪掉
}
// logic.rs
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// 第一次看到：執行
    Run,
    /// 已有結果、還沒回報成功：只補送
    Report(CommandResult),
    /// 已開始但沒有結果（執行中斷）：回報失敗，不再執行
    Interrupted,
    /// 已回報：什麼都不做（伺服器可能還沒處理到，下一輪就不會再送）
    Done,
}
pub fn step(entry: Option<&Entry>) -> Step;
pub const INTERRUPTED: &str = "執行中斷（Agent 停止或電腦重新開機）";
/// shutdown.exe 的參數（不含程式路徑）
pub fn shutdown_args(reboot: bool, delay_minutes: u32) -> String;
pub fn verify_script(spec: &ScriptSpec) -> bool;   // SHA-256(content) 與 spec.sha256 相同（不分大小寫）
```

**`shutdown_args` 的規則：**
- 開頭是 `/r` 或 `/s`，接著 `/t <delay*60>`、`/c "<訊息>"`，最後是 `/d p:0:0`。
- 訊息：
  - 延遲 > 0：「IT 部門排定在 N 分鐘後重新開機，請儲存您的工作。」（關機時把「重新開機」換成「關機」）
  - 延遲 = 0：「IT 部門即將重新開機。」（同上）
- 延遲超過 60 分鐘時用 60（伺服器已經檢查過範圍，這裡是保險）。

- [ ] **Step 1：寫失敗測試**
  - `step` 的四種情況：沒有 entry、有結果但還沒回報、有 `started_at` 但沒有結果、已回報。
  - `shutdown_args(true, 10)` 等於 `/r /t 600 /c "IT 部門排定在 10 分鐘後重新開機，請儲存您的工作。" /d p:0:0`；`(false, 0)` 是 `/s /t 0 /c "IT 部門即將關機。" /d p:0:0`；`(true, 999)` 的 `/t` 是 3600。
  - `verify_script`：雜湊正確時是 true；大寫雜湊也是 true；內容被改過時是 false。
  - state：
    - save 後 load 得到相同內容。
    - 壞掉的 JSON 讀成 Default。
    - `prune` 刪掉 31 天前已回報的，保留未回報的和 29 天前的。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --lib commands`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「Agent：遠端指令邏輯與狀態檔」。

### Task 3：worker、主機介面、報到串接

**Files:**
- Create：`crates/agent/src/commands/worker.rs`
- Modify：`crates/agent/src/client.rs`：新增 `pub async fn command_result(&self, id: i64, r: &CommandResult) -> Result<(), ClientError>`（POST `/v1/commands/{id}/result`）。
- Modify：`crates/agent/src/agent.rs`：
  - 新增 `with_commands(tx: watch::Sender<Option<CommandWork>>)`。
  - 報到後用 `send_if_modified` 傳出指令，只在指令 id 清單改變時喚醒 worker。
- Modify：`crates/agent/src/deploy/worker.rs` 的 `run_worker`、`crates/agent/src/updates/worker.rs` 的 `run_update_worker`：
  - 新增參數 `nudge: Arc<tokio::sync::Notify>`。
  - 等待的 `select!` 加上 `_ = nudge.notified() => {}`，被喚醒時立刻再跑一輪。
- Modify：`crates/agent/src/windows/mod.rs`：建立兩個 `Notify` 和 `WindowsHost`，spawn `run_command_worker`。
- Create：`crates/agent/src/windows/commands.rs`：`WindowsHost`，實作 `CommandHost`。
- Test：`crates/agent/tests/e2e.rs` 新增 `mod commands`；呼叫 `run_worker`／`run_update_worker` 的既有測試也要補上 `nudge` 參數。

**Produces:**
```rust
#[derive(Debug, Clone)]
pub struct CommandWork { pub commands: Vec<Command>, pub server_url: String, pub root_pem: String, pub identity_pem: Option<String> }
pub trait CommandHost: Send + Sync + 'static {
    /// 要求報到迴圈下一輪重新收集所有區段
    fn collect_all(&self);
    /// 喚醒派送與更新原則的背景工作
    fn apply_now(&self);
    /// 執行 shutdown.exe（參數由 logic::shutdown_args 產生）
    fn shutdown(&self, args: &str) -> impl Future<Output = std::io::Result<()>> + Send;
    /// 執行腳本檔，回傳結果與輸出
    fn run_script(&self, path: &Path, timeout: Duration) -> impl Future<Output = std::io::Result<RunOutput>> + Send;
}
pub struct CommandWorker<H: CommandHost> { dir: PathBuf, host: Arc<H>, state: CommandsState }
impl<H: CommandHost> CommandWorker<H> {
    pub fn new(dir: &Path, host: Arc<H>) -> Self;
    pub fn state(&self) -> &CommandsState;
    pub async fn pass(&mut self, w: &CommandWork);
}
pub async fn run_command_worker<H: CommandHost>(worker: CommandWorker<H>, rx: watch::Receiver<Option<CommandWork>>, shutdown: watch::Receiver<bool>);
```

**`pass` 的流程**（對每個 command 依序處理）：
1. 依 `step(state.entries.get(&id))` 決定：
   - `Done`：跳過。
   - `Report(r)`：送出 r。
   - `Interrupted`：結果記為 `failed` + `INTERRUPTED`，存檔後送出。
   - `Run`：見下一步。
2. **`Run`**：
   1. 寫入 `started_at = now` 並存檔。
   2. 依動作執行：
      - **`Collect`**：`host.collect_all()`，結果為成功，輸出「已要求重新收集盤點」。
      - **`Apply`**：`host.apply_now()`，結果為成功，輸出「已要求立即套用派送與更新原則」。
      - **`Reboot` / `Shutdown`**：
        1. 產生參數，結果為成功（輸出是 `shutdown.exe <參數>`），存檔。
        2. 送出結果。
        3. 不論送出是否成功，都呼叫 `host.shutdown(args)`。
        4. shutdown 本身失敗時，把結果改成失敗（附錯誤）、`reported = false`、存檔，下一輪再送。
      - **`Script`**：
        1. `verify_script` 不符：結果為失敗「腳本雜湊不符」。
        2. 寫檔，路徑 `dir/scripts/<id>.ps1`，內容是 BOM（`\u{feff}`）加上腳本內容。
        3. 呼叫 `host.run_script(path, timeout_minutes*60 秒)`；`Exited(0)` 為成功，`Exited(n)` 為失敗（exit_code n），`TimedOut` 為失敗，輸出前面加上「逾時（N 分鐘）\n」。
        4. 刪除檔案（失敗時記 warn）。
      - **`Unknown`**：結果為失敗「不支援的指令」。
   3. 把結果寫進 entry、存檔，然後送出。
3. **送出**：`client.command_result(id, &r)`。
   - 成功，或伺服器回 404（指令已不存在）：`reported = true`，存檔。
   - 其他錯誤：記 warn，下一輪重送。
4. 每輪結束呼叫 `prune(now)`，有變更才存檔。

**`run_command_worker`：** 收到新工作就做一次 pass；之後每 5 分鐘再做一次，用來補送結果。`None` 時不動作。

- [ ] **Step 1：寫失敗測試**（`tests/e2e.rs` 的 `mod commands`，真實伺服器搭配 `FakeHost`，FakeHost 記錄所有呼叫）
  - `collect_and_apply_reach_the_host_and_server`：
    1. 用 `endpoint_server::commands::runs::create_run` 對這台下 `collect` 和 `apply`。
    2. `Agent::run_cycle` 後，從 watch 取出工作交給 `pass`。
    3. FakeHost 收到 collect_all 和 apply_now 各一次。
    4. 伺服器的 `command_targets` 兩筆都是 succeeded。
    5. 再 run_cycle 一次加 pass：不會再呼叫 host。
  - `reboot_reports_before_shutdown`：
    1. FakeHost 的 `shutdown` 會查伺服器資料庫，確認這筆已經是 succeeded，代表先回報後執行。
    2. 參數含 `/r /t 600`。
  - `reboot_runs_even_if_report_fails`：
    1. 用指向關閉中 port 的 server_url 建立 `CommandWork`，模擬網路斷。
    2. `pass` 後 shutdown 被呼叫一次，狀態檔的 entry `reported == false`。
    3. 換回正確的 work 再 `pass`：補送成功，而且 shutdown 沒有再被呼叫。
  - `script_hash_mismatch_is_not_run`：
    1. 用平台管理員建立並核准腳本，再下指令。
    2. 把 work 裡 `script.content` 改掉。
    3. `pass` 後 run_script 沒被呼叫，伺服器是 failed，輸出含「雜湊不符」。
  - `script_runs_and_file_is_removed`：
    1. FakeHost 的 run_script 讀取檔案內容，確認開頭是 BOM 加原內容，再回傳 `Exited(3)` 與輸出 "hi"。
    2. 伺服器得到 failed、exit_code 3、輸出 "hi"。
    3. 檔案已刪除。
  - `interrupted_command_is_reported_not_rerun`：
    1. 先寫一個只有 `started_at` 的狀態檔，模擬執行中斷。
    2. `pass` 後 host 沒被呼叫，伺服器是 failed，輸出是 INTERRUPTED。
  - 補上 `nudge` 參數後，`agent_hands_assignments_to_worker` 等既有測試仍要通過。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --test e2e commands`，預期 FAIL（編譯錯誤）。
- [ ] **Step 3：** 實作 worker、client、agent 串接、nudge、WindowsHost 與 windows spawn。
  - `WindowsHost::shutdown` 執行 `%SystemRoot%\System32\shutdown.exe`，參數用 `raw_arg`。
  - `run_script` 執行 PowerShell 並呼叫 `run_process(…, true)`。
  - `collect_all` 透過既有的 `mpsc::Sender<Section>` 用 `try_send` 送出每個區段。
  - `apply_now` 對兩個 Notify 各呼叫 `notify_one`。
- [ ] **Step 4：Windows 實機測試**（`tests/windows.rs`）
  - `windows_host_runs_powershell_script`：在暫存目錄寫一個 `.ps1`，內容 `Write-Output hi; exit 3`，用 `WindowsHost::run_script` 執行，得到 `Exited(3)` 而且輸出含 `hi`。
  - 不測 shutdown。
- [ ] **Step 5：** 執行 `cargo test -p endpoint-agent`、`cargo test --workspace -j 4`、clippy、fmt，全部 PASS。
- [ ] **Step 6：** Commit「Agent：遠端指令 worker 與回報」。
