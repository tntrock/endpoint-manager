# 計畫 20：遠端指令（網頁、負載測試、README）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成第六期的使用者可見部分：
- 腳本管理頁 `/scripts`（含雙人核准設定）。
- 指令頁 `/commands`（清單、對群組下指令、詳情、取消）。
- 裝置頁的「遠端指令」分頁。
- 權限錯誤回 403。
- loadsim `commands` 情境與負載測試。
- README。

**Architecture:**
- 新增 `crates/server/src/web/scripts.rs`、`crates/server/src/web/commands.rs`，比照 `web/updates.rs`：askama 模板、`AdminSession`、`check_csrf`。
- 管理邏輯（`commands::scripts`／`runs`）的權限錯誤改用型別 `commands::Forbidden`，網頁用 `downcast_ref` 判斷：權限錯誤回 403，其他錯誤回 422（表單）或 409（動作）。
- `Session` 轉成 `Actor` 由網頁端的小函式負責。

**Tech Stack:** Rust、axum、askama、sqlx。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-09-30-remote-commands-design.md`（§1.1、§6、§8）

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 所有 POST 都要檢查 CSRF。
- 檢視者（`!s.can_manage()`）看不到任何下指令的表單；直接 POST 回 403。
- 群組管理員：
  - 只看得到「至少有一台範圍內裝置」的指令；台數、裝置與輸出只含範圍內的裝置。
  - 不能用 `/scripts`（GET 也回 403），也不能執行腳本。
- 核准表單必須帶上頁面顯示的 sha256（`approve_script` 的 `expected_sha256`）。
- 指令輸出在模板裡顯示（askama 自動跳脫），放在 `<pre>` 裡。
- 測試指令：`cargo test -p endpoint-server`、`cargo test -p loadsim`；完整測試用 `cargo test --workspace -j 4`；最後跑 clippy 和 fmt。

## Review Focus
1. 群組管理員打開一個同時含範圍內外裝置的指令詳情：只看到範圍內裝置的輸出與台數，看不到範圍外裝置的主機名稱與輸出。
2. 群組管理員直接 POST `/commands`，帶範圍外的群組或 `script` 動作：回 403，不是 422。
3. 核准者打開腳本詳情後內容被改掉，再按核准：回 409，訊息含「內容已變更」，不會核准新內容。
4. 腳本內容或輸出含 `<script>`：頁面顯示的是跳脫後的文字。
5. 對裝置下指令後重新整理（PRG）不會重複建立：POST 回 303 導向。

---

### Task 1：權限錯誤型別（`commands::Forbidden`）

**Files:**
- Modify：`crates/server/src/commands/mod.rs`、`scripts.rs`、`runs.rs`
- Test：`crates/server/tests/commands.rs`

**Produces:**
```rust
/// 權限不足（網頁回 403）；其他錯誤是輸入或狀態問題
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Forbidden(pub String);
pub fn is_forbidden(e: &anyhow::Error) -> bool;   // e.downcast_ref::<Forbidden>().is_some()
```

**改成 `Forbidden` 的錯誤：**
- `scripts.rs` 的 `platform()`（只有平台管理員能管理腳本）。
- `approve_script` 的「不能核准自己修改的腳本」。
- `runs.rs` 的：
  - 「只有平台管理員能執行腳本」
  - 「不在你的管理範圍」（裝置與群組）
  - 「只有建立者或平台管理員能取消」

訊息文字不變。用 `return Err(Forbidden(...).into())`，不要用 `ensure!`，因為 `ensure!` 產生的是一般字串錯誤。

先確認 server crate 有沒有 `thiserror`；沒有就手寫 `impl std::fmt::Display` 和 `impl std::error::Error`，不加新依賴。

- [ ] **Step 1：寫失敗測試**：在既有測試加斷言 `is_forbidden(&err)`。
  - 群組管理員建立腳本：true。
  - 自己核准：true。
  - 範圍外的群組：true。
  - 群組管理員執行腳本：true。
  - 別人取消：true。
  - 延遲 61（輸入錯誤）：false。
  - 腳本內容已變更：false。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands`，預期 FAIL（`is_forbidden` 不存在）。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「遠端指令：權限錯誤型別」。

### Task 2：腳本管理頁（`web/scripts.rs`）

**Files:**
- Create：`crates/server/src/web/scripts.rs`
- Create：模板 `scripts.html`（清單與設定）、`script_form.html`（新增／編輯）、`script_detail.html`（詳情）
- Modify：`crates/server/src/web/mod.rs`（`pub mod scripts;` 和路由）、`templates/base.html`（平台管理員導覽列加上「腳本」）
- Test：`crates/server/tests/commands_web.rs`（新檔）

**路由：**
```
.route("/scripts", get(scripts::list).post(scripts::create))
.route("/scripts/new", get(scripts::new_form))
.route("/scripts/settings", post(scripts::settings))
.route("/scripts/{id}", get(scripts::detail))
.route("/scripts/{id}/edit", get(scripts::edit_form).post(scripts::update))
.route("/scripts/{id}/{action}", post(scripts::act))   // approve、disable、enable、delete
```

**共用：**
```rust
pub(super) fn actor(s: &Session) -> crate::commands::Actor {
    Actor { username: s.username.clone(), platform: s.all_devices(), groups: s.groups.clone() }
}
/// Forbidden → 403；其他 → 給定的狀態碼與訊息
pub(super) fn command_error(e: anyhow::Error, status: StatusCode) -> Response
```
這兩個函式放在 `web/commands.rs`，Task 2 先建立這個檔案，只放這兩個函式。

**頁面內容：**
- **清單**：名稱、狀態（待核准／已核准／已停用）、sha256 前 12 碼、最後修改者、核准者，以及「建立腳本」連結。
  - 上方是設定：「腳本需要第二位平台管理員核准」的核取方塊加儲存按鈕，POST 到 `/scripts/settings`，欄位 `require=1` 或不送。
- **表單**：名稱、說明（textarea）、內容（textarea，等寬字型，rows=20）、逾時（分鐘，預設 30）。
  - 驗證錯誤時回 422，保留輸入。
  - 成功時 303 導向詳情頁。
- **詳情**：
  - 顯示名稱、狀態、說明、完整 sha256、逾時、建立者、最後修改者、核准者與時間、被指令使用的次數（`SELECT count(*) FROM command_runs WHERE script_id = $1`），以及 `<pre>{{ content }}</pre>`。
  - 動作按鈕：
    - 核准：hidden `sha256` = 頁面上的 sha256。狀態是 pending，或「已核准但需要另一位重新核准」時才顯示；目前使用者在 `editors` 裡時不顯示，改顯示說明「需由另一位平台管理員核准」。
    - 停用或啟用。
    - 編輯。
    - 刪除：有 `confirm`；被使用過時不顯示，改顯示說明「已被指令使用，只能停用」。
- **act**：
  - `approve` 讀表單的 `sha256` 呼叫 `approve_script`。
  - 錯誤用 `command_error(e, 409)`。
  - 成功時 303 導向詳情；`delete` 導向 `/scripts`。
- 每個 handler 一開始先檢查 `s.all_devices()`，不是平台管理員就回 403。

- [ ] **Step 1：寫失敗測試**（`tests/commands_web.rs`，比照 `tests/updates_web.rs`，用 `s.login_as(...)` 建立 alice、bob 兩位平台管理員）
  - alice 建立腳本（內容含 `<script>alert(1)</script>`）：
    - 303 導向詳情。
    - 詳情頁顯示 `&lt;script&gt;`，沒有原始的 `<script>alert(1)`。
    - 詳情頁沒有核准按鈕，有「需由另一位平台管理員核准」。
  - bob 打開詳情，取得頁面的 sha256。alice 改內容後，bob 用舊 sha256 POST 核准：409，訊息含「內容已變更」。
  - bob 重新打開詳情後核准：303，狀態變成已核准。
  - 設定：
    - 取消勾選後 `require_second_approver` 是 false，稽核有一筆。
    - 群組管理員 POST `/scripts/settings` 回 403。
  - 群組管理員 GET `/scripts` 和 `/scripts/new` 都是 403。
  - 建立時名稱空白：422，頁面保留內容。
  - 沒有 CSRF 的 POST 被拒絕。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands_web scripts`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「網頁：腳本管理」。

### Task 3：指令頁與裝置分頁（`web/commands.rs`）

**Files:**
- Modify：`crates/server/src/web/commands.rs`
- Create：模板 `commands.html`（清單與群組表單）、`command_detail.html`、`commands_tab.html`（裝置分頁）
- Modify：`web/mod.rs`（路由）、`web/devices.rs`（分頁列表在「更新」之後加 `("commands", "遠端指令")`，`tab` 轉交 `super::commands::device_tab`）、`templates/base.html`（可管理的人導覽列加上「遠端指令」）
- Test：`crates/server/tests/commands_web.rs`

**路由：**
```
.route("/commands", get(commands::list).post(commands::create))
.route("/commands/{id}", get(commands::detail))
.route("/commands/{id}/cancel", post(commands::cancel))
.route("/devices/{id}/commands", post(commands::create_for_device))
```

**範圍 SQL**（`$1` 全部、`$2` 群組）：
```sql
-- 指令清單：至少有一台範圍內裝置的 run，各狀態台數只算範圍內
SELECT r.id, r.action, r.target_label, r.created_by, r.created_at, r.expires_at, r.canceled_at IS NOT NULL,
       count(t.id), count(*) FILTER (WHERE t.status = 'pending'), … 'sent', 'succeeded', 'failed', 'expired', 'canceled'
FROM command_runs r JOIN command_targets t ON t.run_id = r.id JOIN devices v ON v.id = t.device_id
WHERE $1::bool OR v.group_id = ANY($2::bigint[])
GROUP BY r.id ORDER BY r.id DESC LIMIT 51 OFFSET $3
```
`target_label` 對群組管理員也照樣顯示，因為只會顯示含範圍內裝置的 run。

**頁面內容：**
- **清單**：
  - 每頁 50 筆。
  - 欄位：動作（中文）、對象、建立者、建立時間、過期、各狀態台數（等待中＝pending＋sent）。
  - 可管理的人看得到「對群組下指令」表單：
    - 動作：重新收集、立即套用、重新開機、關機；平台管理員另有「執行腳本」。
    - 群組：只列範圍內的群組。
    - 延遲（重開機／關機用，預設 10）。
    - 腳本（只列已核准的，平台管理員才有）。
    - 過期：1 小時、1 天、7 天、30 天。
- **create**：
  - 檢視者回 403。
  - 用 `runs::create_run`。Forbidden 回 403；其他錯誤回 422，重新顯示清單頁與錯誤訊息。
  - 成功時 303 導向 `/commands/{id}`。
- **詳情**：
  - 依狀態篩選（`?status=`），每頁 100 台。
  - 欄位：主機名稱（範圍內，連到裝置頁）、狀態、結束碼、完成時間、輸出（`<details><summary>輸出</summary><pre>…</pre></details>`）。
  - 腳本指令另外顯示腳本名稱與當時的 sha256。
  - 取消按鈕：建立者或平台管理員，而且還沒取消時才顯示。
  - 範圍內完全沒有裝置的 run 回 404。
- **cancel**：用 `runs::cancel_run`；Forbidden 回 403，其他錯誤回 409；成功時 303 導向詳情。
- **裝置分頁**：
  - 範圍外的裝置回 404。
  - 可管理的人看到按鈕：
    - 重新收集、立即套用。
    - 重新開機、關機：有 `confirm`，可選延遲。
    - 執行腳本：只有平台管理員，下拉選單只列已核准的腳本。
  - 下方列出這台最近 20 筆：動作、建立者、狀態、結束碼、時間、輸出。
- **create_for_device**：
  - POST 欄位：`action`、`delay`、`script_id`、`csrf`。
  - 用 `Target::Device`，過期固定 7 天。
  - Forbidden 回 403，其他錯誤回 409。
  - 成功時 303 導向 `/devices/{id}`（PRG）。

**標籤：**
- 動作：collect 重新收集、apply 立即套用、reboot 重新開機、shutdown 關機、script 執行腳本。
- 狀態：pending 等待中、sent 已送出、succeeded 成功、failed 失敗、expired 已過期、canceled 已取消。

- [ ] **Step 1：寫失敗測試**
  - 環境：用群組 token 註冊台北 2 台、高雄 1 台；平台管理員 admin，群組管理員 gary（台北），檢視者 vera（台北）。
  - admin 對台北下 `collect`：303；清單顯示「群組 台北」，等待中 2。
  - **gary：**
    - POST `/commands` 對高雄：403。
    - `action=script`：403。
    - 對台北下 `reboot`：303。
  - **詳情的範圍：**
    - admin 對單台高雄下 `apply`。gary 的清單看不到這個 run；gary GET 它的詳情是 404。
    - 為了測試同一個 run 同時含範圍內外裝置，直接在資料庫建一個 run：一筆 `command_runs`，`command_targets` 含台北 1 台與高雄 1 台。gary 打開詳情只看到台北那台，頁面不含高雄裝置的 id。
  - **輸出跳脫：**
    1. 高雄那台的 Agent 回報（`POST /v1/commands/{id}/result`）輸出 `<b>hi</b>`。
    2. admin 的詳情頁顯示 `&lt;b&gt;hi&lt;/b&gt;`。
  - **裝置分頁：**
    - admin 看得到「執行腳本」；gary 只看得到四個固定動作；vera 沒有任何按鈕。
    - vera POST `/devices/{id}/commands`：403。
  - **create_for_device：** admin 對台北第 1 台下 collect，303 導向 `/devices/{id}`；分頁列出這筆。
  - **取消：** 建立者取消成功；gary 取消 admin 建立的指令回 403。
  - 沒有 CSRF 的 POST 被拒絕。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test commands_web commands`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-server --test commands_web`，預期 PASS。
- [ ] **Step 5：** Commit「網頁：遠端指令清單、詳情與裝置分頁」。

### Task 4：loadsim、負載測試、README

**Files:**
- Modify：`tools/loadsim/src/lib.rs`：新增 `pub async fn commands(t: &Target, devices: &[Device], concurrency: usize) -> (Report, usize)`。每台報到後，對每個 `commands` 回報 succeeded（輸出 "ok"）；回傳報告與沒有收到指令的台數。
- Modify：`tools/loadsim/src/main.rs`：新增 `"commands"` 指令，參數 `--concurrency`（預設 60）和 `--max-secs`（預設 900）；USAGE 也要更新。
- Create：`tools/loadsim/commands_setup.sql`：
  1. 建立群組「load cmd」，把前 5,000 台裝置（`ORDER BY id LIMIT 5000`）放進去。
  2. `\timing` 量下面這段 SQL：`INSERT INTO command_runs (action, target_label, created_by, expires_at) VALUES ('collect', '群組 load cmd', 'loadsim', now() + interval '7 days') RETURNING id`，接著用 `INSERT … SELECT` 展開 5,000 筆，與 `runs::create_run` 相同。
  3. 用 psql 執行，不經過 `raw_sql`，所以檔案裡可以用 `\timing`。
- Modify：`tools/loadsim/tests/sim.rs`：
  - 在既有測試最後，用 `endpoint_server::commands::runs::create_run` 對 5 台下 collect。
  - `loadsim::commands` 的結果是 ok 5、errors 0、沒收到指令 0。
  - `command_targets` 5 筆都是 succeeded。
- Modify：`docs/loadtest.md`：新增「遠端指令（第六期）」一節，量測三件事：
  1. 展開 5,000 筆的時間（psql `\timing`，目標 ≤ 5 秒）。
  2. 有 5,000 筆待下發時，心跳 500 次／秒、120 秒的 p99（目標 < 100ms）。
  3. `loadsim commands` 讓 30,000 台報到，其中 5,000 台回報（目標 0 錯誤，資料庫 5,000 筆 succeeded）。

  照實記錄結果，重跑方法也要寫進文件。
- Modify：`README.md`：新增「遠端指令」一節，內容如下：
  - 固定動作與腳本，以及誰可以用。
  - 雙人核准：怎麼設定；修改後要重新核准；核准時以畫面上的內容為準。
  - 送達方式：隨報到送達（預設 60 秒），過期時間。
  - 重開機、關機：延遲與通知、先回報後執行。
  - 腳本：
    - 以 SYSTEM 用 Windows PowerShell 5.1 執行，輸出最後 64 KiB。
    - 逾時時結束整個程序樹。
    - 取消只對還沒開始的有效。
    - **Agent 狀態檔遺失時，伺服器重送的指令可能再執行一次，腳本應設計成可重複執行。**
  - 需要 Agent 0.6.0 以上；升級順序：先升級伺服器，再升級 Agent。

- [ ] **Step 1：寫失敗測試**：在 `tools/loadsim/tests/sim.rs` 加上 commands 的部分。
- [ ] **Step 2：** 執行 `cargo test -p loadsim`，預期 FAIL。
- [ ] **Step 3：** 實作 lib、main、SQL。
- [ ] **Step 4：** 執行 `cargo test -p loadsim`，預期 PASS。
- [ ] **Step 5：** 實際跑負載測試。環境比照 `docs/loadtest.md` 的重跑方法，並沿用第五期的驅動腳本做法：release build、三萬台。結果寫進文件。
- [ ] **Step 6：** 更新 README；跑 `cargo test --workspace -j 4`、clippy、fmt。
- [ ] **Step 7：** Commit「loadsim：遠端指令情境；負載測試與 README」。
