# 計畫 24：收尾——遠端指令 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修正規格 §3 的 19 項遠端指令延後問題（24-1～24-19）。

**Architecture:**
- 伺服器：`commands::CmdError`（Forbidden／Invalid／NotFound／Conflict）取代只區分權限的 `Forbidden`；網頁依型別決定狀態碼，其他錯誤記錄後回 500。權限檢查一律先於輸入驗證與存在檢查。
- 網頁：指令詳情加「等待中」篩選；清單顯示已取消；沒有未完成對象時不能取消；平台管理員看得到對象裝置都被刪除的指令。
- Agent：同一批重新開機／關機最後執行；延遲 0 加 `/f`；逾時前綴不被截掉；啟動時清除殘留腳本；重新收集不丟觸發；超過 31 天的紀錄（含未回報）清除。

**Tech Stack:** 既有依賴。

**Spec:** `docs/superpowers/specs/2026-10-03-deferred-fixes-design.md`（§3）

## Global Constraints
- 使用者可見文字與註解用繁體中文，風格同既有程式碼。
- 每項修正都有先失敗再通過的測試；文件與無法測試的項目在 ledger 寫 Ruling。
- 規格 24-13 的描述有誤（已回報的紀錄本來就會在 30 天後清除）：實際問題是**未回報**的紀錄永不清除。修正為「開始超過 31 天的紀錄一律清除（指令最長 30 天過期，伺服器之後不再接受結果）」，並同步修改規格。
- 測試指令：`cargo test -p endpoint-server --test commands --test commands_web`、`cargo test -p endpoint-agent`、`cargo test -p loadsim`；完整：`cargo test --workspace -j 4`、clippy、fmt。

## Review Focus
1. 改成 500 的錯誤不能吞掉原本應該給使用者看的輸入錯誤（每個 `ensure!`／`context` 都要改成有型別的錯誤）。
2. 群組管理員對任何不在範圍內或不存在的群組、裝置、腳本動作，都得到同樣的 403，訊息不洩漏是否存在。
3. Agent 同一批有「延遲 0 重新開機」與腳本時，腳本先跑完並回報，重新開機最後。
4. 新增的 CHECK 對既有資料成立（已刪除的腳本 `script_id` 已是 RESTRICT，快照欄位一定有值）。
5. 過濾格式字元後，換行、Tab 與一般中文、emoji 不受影響。

---

### Task 1：伺服器錯誤型別、權限順序、資料完整性

**Files:**
- Modify：`crates/server/src/commands/mod.rs`、`runs.rs`、`scripts.rs`、`api.rs`
- Modify：`crates/protocol/src/command.rs`（`strip_format_chars`）
- Create：`crates/server/migrations/0018_command_checks.sql`
- Test：`crates/server/tests/commands.rs`、`crates/protocol/src/command.rs` 單元測試

**Interfaces（Produces）：**
```rust
// commands/mod.rs
#[derive(Debug, thiserror::Error)]
pub enum CmdError {
    #[error("{0}")] Forbidden(String),  // 403
    #[error("{0}")] Invalid(String),    // 422
    #[error("{0}")] NotFound(String),   // 404
    #[error("{0}")] Conflict(String),   // 409
}
pub fn cmd_error_kind(e: &anyhow::Error) -> Option<&CmdError>;
// protocol::command
/// 移除 Unicode 格式字元（Cf，例如 U+202E），保留換行與 Tab
pub fn strip_format_chars(s: &str) -> String;
```

**規則：**
- `runs.rs`、`scripts.rs` 裡所有 `ensure!`、`bail!`、`.context(...)` 產生的使用者錯誤改成 `CmdError`：輸入問題 `Invalid`、找不到 `NotFound`、狀態不允許 `Conflict`。資料庫錯誤維持原樣（之後成為 500）。
- `create_run` 順序：
  1. 腳本動作的「只有平台管理員」檢查最先（群組管理員送腳本 → 403，不論其他欄位）。
  2. 範圍：群組管理員的群組 id 不在自己的群組清單 → 403（不查群組是否存在）；裝置不存在或不在範圍 → 403（訊息「這台裝置不在你的管理範圍」）。平台管理員才會看到 404「群組不存在」／「裝置不存在或未啟用」。
  3. 之後才是延遲、過期等輸入驗證（422）。
- 裝置範圍檢查查詢加 `FOR SHARE`，在同一交易內鎖住裝置列（24-15）。
- `cancel_run`：沒有 `pending`／`sent` 的對象時回 `Conflict("指令都已完成，沒有可取消的裝置")`（24-6）。
- 稽核（24-16）：`update_script` 的 detail 加 `old_sha256`；`set_require_second_approver` 加 `old`。
- `api.rs` 存結果時，輸出先 `strip_format_chars`；`scripts.rs` 的說明與名稱同樣過濾（24-17）。
- Migration 0018：
  ```sql
  ALTER TABLE command_runs
    ADD CONSTRAINT command_runs_script_snapshot CHECK
      ((action = 'script') = (script_sha256 IS NOT NULL AND script_content IS NOT NULL
                               AND script_timeout_minutes IS NOT NULL)),
    ADD CONSTRAINT command_runs_delay_action CHECK
      (delay_minutes IS NULL OR action IN ('reboot', 'shutdown'));
  ```

- [ ] **Step 1：寫失敗測試**
  - `strip_format_chars`：移除 U+202E、U+200B、U+FEFF、U+2066；保留 `"第一行\n\t中文 😀"` 原樣。
  - `tests/commands.rs`：
    - 群組管理員送腳本（腳本 id 不存在、過期 0 小時）→ 錯誤是 `CmdError::Forbidden`。
    - 群組管理員對不存在的群組 id 99999 與範圍外的群組 → 都是 `Forbidden`，訊息相同；對不存在的裝置 → `Forbidden`。平台管理員對不存在的群組 → `NotFound`。
    - 延遲 61 → `Invalid`。
    - 全部完成的指令取消 → `Conflict`。
    - 直接 INSERT 一筆 `action = 'collect'` 但有 `delay_minutes` 的 command_runs → 違反 CHECK。
    - 更新腳本後稽核 detail 有 `old_sha256`；切換雙人核准的稽核有 `old`。
    - Agent 回報含 U+202E 的輸出 → 資料庫存的輸出沒有 U+202E。
- [ ] **Step 2：** 執行 `cargo test -p protocol` 與 `cargo test -p endpoint-server --test commands`，預期 FAIL。
- [ ] **Step 3：** 實作。`web/commands.rs`、`web/scripts.rs` 的 `is_forbidden` 呼叫暫時改成 `cmd_error_kind(&e)` 判斷 Forbidden（Task 2 再完整處理）。
- [ ] **Step 4：** 同上指令 PASS；`cargo test -p endpoint-server` PASS。
- [ ] **Step 5：** Commit「收尾：遠端指令錯誤型別與資料完整性」。

---

### Task 2：網頁

**Files:**
- Modify：`crates/server/src/web/commands.rs`、`web/scripts.rs`、`templates/commands.html`、`command_detail.html`、`script_form.html`
- Test：`crates/server/tests/commands_web.rs`

**規則：**
- `command_error(e)`（取代 `command_error(e, status)`）：`CmdError` 依種類回 403／422／404／409 與訊息；其他錯誤 `tracing::error!` 後回 500「伺服器錯誤，請稍後再試」（24-1）。`create` 失敗時 422／409 重新顯示表單，其他依上面的對應。
- 延遲欄位：有填但不是整數 → 422「延遲必須是 0–60 分鐘的整數」（24-2）；空白才用預設。
- 詳情篩選加「等待中」（`waiting` → `t.status IN ('pending', 'sent')`）（24-4）。
- 清單：
  - 查詢改為 `command_runs r LEFT JOIN (command_targets t JOIN devices v ON v.id = t.device_id) ON t.run_id = r.id`，條件 `$1::bool OR v.group_id = ANY($2)`：平台管理員看得到對象裝置都已刪除的指令（台數 0），群組管理員維持只看有範圍內裝置的（24-5）。
  - 已取消的指令在狀態欄顯示「已取消」。
- 詳情的「取消」按鈕只在等待中台數 > 0 時顯示（24-6）。
- `script_form.html`：`<textarea ...>` 與 `{{ f.content }}`、`{{ f.description }}` 之間加一個換行（HTML 會忽略 `<textarea>` 後的第一個換行，內容開頭的換行因此保留）（24-7）。

- [ ] **Step 1：寫失敗測試**（`tests/commands_web.rs`）
  - 讓資料庫錯誤發生（測試中把 `command_runs` 改名後送出）→ 500，回應不含 SQL 字樣。
  - 延遲 `abc` → 422。
  - 詳情 `?status=waiting` 只列等待中的裝置。
  - 對象裝置被刪除的指令：平台管理員清單看得到、詳情 200；群組管理員 404。
  - 已取消的指令在清單顯示「已取消」；全部完成的指令詳情沒有取消按鈕，POST 取消 → 409。
  - 腳本內容以換行開頭時，編輯頁送出原內容後 sha256 不變（不需要重新核准）。
  - 混合範圍（24-19）：指令對象橫跨兩個群組，群組管理員在清單與詳情只看到自己群組的台數與主機名稱。
  - 詳情頁的輸出含 `<script>` 時被跳脫（24-19）。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands_web`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** `cargo test -p endpoint-server` PASS。
- [ ] **Step 5：** Commit「收尾：遠端指令網頁」。

---

### Task 3：Agent

**Files:**
- Modify：`crates/agent/src/commands/logic.rs`、`worker.rs`、`state.rs`、`crates/agent/src/windows/commands.rs`
- Test：`logic.rs`／`state.rs` 單元測試、`crates/agent/tests/e2e.rs`（指令的 worker 測試，使用既有的假 host）

**規則：**
- `shutdown_args(reboot, 0)` 加上 ` /f`（24-11）。
- 逾時輸出：前綴 `逾時（N 分鐘）\n` 加上 `tail_utf8(output, MAX_OUTPUT_BYTES - 前綴長度)`，前綴一定保留（24-8）。抽成 `logic::timeout_output(minutes, output) -> String`。
- `CommandWorker::new` 清除 `scripts\` 內所有檔案（24-9）。
- `pass` 依序處理：先處理非重新開機／關機的指令，最後才處理重新開機／關機（保持各自原本的順序）（24-10）。抽成 `logic::order(commands) -> Vec<&Command>`。
- `CommandHost::collect_all` 改為 `async`，Windows 實作用 `send().await`（通道關閉時略過）（24-12）。
- `CommandsState::prune`：開始超過 31 天的紀錄一律刪除；沒有 `started_at` 的紀錄維持保留邏輯（24-13）。

- [ ] **Step 1：寫失敗測試**
  - `shutdown_args(true, 0)` 含 `/f`；`shutdown_args(true, 10)` 不含。
  - `timeout_output(5, "x".repeat(70_000))`：以「逾時（5 分鐘）」開頭，長度 ≤ `MAX_OUTPUT_BYTES`。
  - `order`：`[reboot(1), script(2), collect(3)]` → `[2, 3, 1]`。
  - `prune`：未回報、開始 32 天前的紀錄被刪；未回報、10 天前的保留。
  - worker（假 host）：`scripts\` 有殘留檔，建立 worker 後被清除；一批 `[reboot 延遲 0, script]` → 假 host 記錄的呼叫順序是 script 再 shutdown。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** `cargo test -p endpoint-agent` PASS（Windows 專屬的 `collect_all` 由 CI 的 Windows 工作驗證編譯）。
- [ ] **Step 5：** Commit「收尾：遠端指令 Agent」。

---

### Task 4：loadsim 與規格同步

**Files:**
- Modify：`tools/loadsim/src/main.rs`（`commands` 子命令加 `--expect N`，回報成功台數不等於 N 時失敗）、`tools/loadsim/commands_setup.sql`（結尾註解：如何把裝置移回原群組）、`docs/superpowers/specs/2026-10-03-deferred-fixes-design.md`（24-13 描述）
- Test：`tools/loadsim/tests/sim.rs`（既有的 commands 情境加上預期台數檢查）

- [ ] **Step 1：** 測試改為檢查 `commands` 回傳的成功台數等於指令對象台數；先用錯誤的預期值確認會失敗。
- [ ] **Step 2：** 實作 `--expect` 與 SQL 註解、修改規格。
- [ ] **Step 3：** `cargo test --workspace -j 4`、clippy、fmt 全部 PASS。
- [ ] **Step 4：** Commit「收尾：loadsim 指令檢查與規格同步」。
