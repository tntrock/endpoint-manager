# 計畫 25：軟體派送與 Windows Update 延後問題 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal：** 修正規格 25-1～25-21（派送、Windows Update 原則、相關合規與 loadsim）。

**Architecture：**
- 伺服器端改用 plan 24 的 `CmdError`（`crate::commands::CmdError`），讓「不存在」回 404、「過期的表單」回 409、輸入錯誤回 422。
- Agent 端在既有的狀態檔加 `#[serde(default)]` 欄位，不改協定欄位的意義。
- 合規「太久沒更新」改用管理網頁時區的「今天」。

**Tech Stack：** Rust、axum、sqlx（Postgres）、askama；Agent 用 windows-sys。

**Spec：** `docs/superpowers/specs/2026-10-03-deferred-fixes-design.md`（§4）

## Global Constraints

- 不新增依賴（windows-sys 加 feature 不算新依賴）。協定新增欄位一律 `#[serde(default)]`。
- 標為「修」的每一項都有先失敗再通過的測試。無法測試的項目在任務中註明：25-5 只有 Windows CI 編譯驗證，25-13 是字串排版，25-14 是測試本身。
- `cargo fmt --all`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace -j 4` 全綠。
- 所有使用者看到的文字用繁體中文。

## Review Focus

1. 「重試失敗」後，已成功的裝置在重新回報前顯示為「等待中（上一輪：成功）」，不能被算成失敗，也不能消失。
2. 24 小時內被移除 3 次後不再重裝。過了 24 小時，或管理員按「重試失敗」（revision 改變）時，要恢復嘗試。
3. 回報結果時遇到 404 視為完成，但 401、5xx、連不上仍要保留重送。
4. 原則表單的 revision 檢查只擋「別人改過」：自己剛暫停／恢復後重新開表單，要能正常儲存。
5. 讀登錄檔失敗時回報「錯誤」，但不能因此刪除或覆寫任何值。

---

### Task 1：派送清單與詳情只計目前 revision（25-1）

**Files：**
- Modify: `crates/server/src/web/deployments.rs`（`counts_sql`、`detail` 的 failures／裝置查詢、`DeviceRow` 狀態文字）
- Test: `crates/server/tests/deploy_web.rs`

**Interfaces：** 無跨任務介面。

- [ ] **Step 1：寫失敗的測試** `retry_counts_only_current_revision`
  - 建立 2 台裝置與派送 d（`server_package`、`admin::create_deployment`）。兩台都以 revision 1 回報 failed（用 `fail_result`）。
  - 呼叫 `dadmin::retry_failed(&s.pool, d, "admin")`，revision 變成 2。
  - 第一台以 revision 2 回報 failed：直接 POST `/v1/deployments/{d}/result`，`revision: 2`。
  - 斷言：
    - 詳情頁含「失敗：1」「等待中：1」。
    - 清單頁那一列失敗數是 1。
    - `?status=pending` 列出第二台，狀態文字含「上一輪」。
    - 「主要失敗原因」只算 1 台。
- [ ] **Step 2：執行。** `cargo test -p endpoint-server --test deploy_web retry_counts` 預期 FAIL（失敗：2）。
- [ ] **Step 3：實作**
  - `counts_sql`：`LEFT JOIN deployment_status ds ON ds.deployment_id = d.id AND ds.device_id = v.id AND ds.revision = d.revision`。舊 revision 的列因此算成等待中。
  - failures 查詢加上 `AND ds.revision = d.revision`。
  - 裝置查詢多選 `ds.revision < d.revision`（`old`）。條件改為：
    - `pending`：`ds.device_id IS NULL OR ds.revision < d.revision`
    - 其他狀態：`ds.status = $4 AND ds.revision = d.revision`
  - `DeviceRow.status` 在 `old` 時顯示「等待中（上一輪：{原狀態}）」。
- [ ] **Step 4：執行。** 同 Step 2，預期 PASS。再跑 `cargo test -p endpoint-server --test deploy_web`，全綠。
- [ ] **Step 5：Commit** 「派送：清單與詳情只計目前 revision」

### Task 2：Agent 派送（25-2～25-7）

**Files：**
- Modify:
  - `crates/agent/src/deploy/state.rs`（`Entry.installs`）
  - `crates/agent/src/deploy/logic.rs`（`Plan::Removed`、`decide`、`msiexec`）
  - `crates/agent/src/deploy/worker.rs`（`pass_at` 的 now、`succeed`、`Removed` 回報、`new()` 清 log）
  - `crates/agent/src/client.rs`（`report` 遇 404 視為完成）
  - `crates/agent/Cargo.toml`（windows-sys 加 `Win32_System_SystemInformation`）
- Test: `crates/agent/src/deploy/logic.rs` tests、`crates/agent/tests/e2e.rs`（`mod deploy`、`client_maps_status_codes`）

**Interfaces：**
- `Entry { #[serde(default)] pub installs: Vec<DateTime<Utc>> }`：同一 revision 內每次安裝成功的時間。
- `Plan::Removed`：24 小時內已成功安裝 3 次、又被移除，回報失敗一次。
- `pub const MAX_REINSTALLS: usize = 3;`

- [ ] **Step 1：寫失敗的測試**
  - logic `reinstall_limit`：
    - `Entry { installs: 3 筆 1 小時內 }`、未安裝 → `Plan::Removed`。
    - 同樣的 entry 加上 `reported: Some(Failed)` → `Plan::Nothing`。
    - 3 筆都是 25 小時前 → `Plan::Execute`。
    - revision 不同 → `Plan::Execute`。
  - e2e `reinstalls_stop_after_three_removals`：
    - `setup(&e, 0, true)`，迴圈 3 次：`pass` 之後清空 `runner.software`。
    - 第 4 次 `pass`：`runs == 3`，狀態為 failed，訊息含「一再被移除」。
  - e2e `client_maps_status_codes` 加一段：對不存在的派送 `c.report(999_999, &r)` 回 `Ok(())`。
  - e2e `each_assignment_uses_its_own_time`：
    - 兩個派送，runner 結束碼 1603。
    - `pass_at(&w, t0)`，t0 取 1 小時前。
    - 第二個派送的 `last_attempt` 大於第一個。
    - Worker 需要 `pub fn state(&self) -> &DeployState`，沒有就加。
  - e2e `old_install_logs_are_removed`：
    - `packages/old.log` 用 `File::set_modified` 設成 31 天前，另有一個 `new.log`。
    - `Worker::new` 之後 old 不在、new 還在。
  - e2e `worker_uninstalls_and_reports`：
    - 新 helper `deployment_with(e, data, action, uninstall_args)`，`deployment()` 改呼叫它。
    - FakeRunner 加 `uninstall: bool`，執行時從清單移除「Fake App」。
    - 已安裝、動作是 uninstall、uninstall_args 為 `/uninstall /S`。
    - `pass` 之後：狀態 succeeded、軟體不在清單、runner 的參數是 `/uninstall /S`。
- [ ] **Step 2：執行。** `cargo test -p endpoint-agent -j 4 --lib reinstall_limit` 與各 e2e 測試。預期都 FAIL；uninstall 測試預期本來就 PASS，那就是補測試（25-7），在 ledger 註明。
- [ ] **Step 3：實作**
  - `decide`：在 `MAX_ATTEMPTS` 檢查前，若 `a.action == Install` 且 24 小時內 `installs` 達 `MAX_REINSTALLS`：
    - `e.reported == Some(Failed)` → `Nothing`
    - 否則 → `Removed`
  - `succeed(…, now)`：安裝動作時 `installs.push(now)`，並刪掉 24 小時前的。
  - worker 處理 `Plan::Removed`：`report(Failed, None, "安裝後一再被移除（24 小時內已安裝 3 次），24 小時後再試", attempts)`。
  - `pass_at`：迴圈開始前 `let started = Utc::now();`，每個指派用 `let now = now + (Utc::now() - started);`。
  - `client.report`：比照 `command_result`，`status.is_success() || status == NOT_FOUND` 時回 `Ok`。兩者共用私有 helper `post_result(url, body)`。
  - `msiexec()`：
    - `#[cfg(windows)]` 用 `GetSystemDirectoryW` 取系統目錄。
    - 非 Windows 與失敗時用 `C:\Windows\System32`。
    - Windows 專屬，CI 編譯驗證；沒有 RED 測試，ledger 註明。
  - `Worker::new`：`.log` 修改時間超過 30 天就刪（`LOG_KEEP_DAYS = 30`）。
- [ ] **Step 4：執行。** Step 2 的測試全部 PASS；`cargo test -p endpoint-agent -j 4` 全綠。
- [ ] **Step 5：Commit** 「Agent 派送：重裝上限、404 視為完成、逐一計時、清 log、移除測試」

### Task 3：更新原則伺服器端與網頁（25-8～25-11、25-17～25-21）

**Files：**
- Modify:
  - `crates/server/src/updates/admin.rs`
  - `crates/server/src/web/updates.rs`
  - `crates/protocol/src/update.rs`（`last_patch_date` 下限）
  - `crates/server/templates/update_form.html`、`updates_tab.html`、`groups.html`
- Test: `crates/server/tests/updates.rs`、`updates_web.rs`、`web/updates.rs` 單元測試、protocol 單元測試

**Interfaces：**
- `admin::update_policy(pool, id, &PolicyInput, expected_revision: Option<i32>, actor)`：多一個參數，`None` 不檢查。
- `admin::set_pause`：`start` 不在 `[今天−35, 今天+1]`（UTC）時回 `CmdError::Invalid`。
- `lock_policy` 不存在時回 `CmdError::NotFound`，回傳 `(name, Option<PolicySettings>, revision)`。

- [ ] **Step 1：寫失敗的測試**
  - updates_web `classification_checks_policy_and_revision`（25-8）：
    - 原則 revision 2。
    - 一台回報 `conflict` 但 revision 1 → 尚未回報。
    - 一台回報 `error` 且 `policy_id` 是別的原則 → 尚未回報。
    - 一台回報 `error` 且 `policy_id` 為 None → 錯誤。
  - updates_web `missing_policy_is_404`（25-9）：對 `/updates/999999/edit`（POST 合法表單）、`/pause-quality`、`/delete` 都回 404。
  - web 單元測試 `grace_without_deadline_is_rejected`（25-10）：只填 `quality_grace` → Err，訊息含「寬限期需要先填期限」。
  - updates_web `disabled_device_tab_says_disabled`（25-11）：裝置停用後，更新分頁含「已停用」、不含「不受管」。
  - updates_web `unparseable_settings_are_shown`（25-17）：
    - `UPDATE update_policies SET settings = '{"quality_defer_days":"x"}'`。
    - 詳情頁含「設定無法解析」。
    - 編輯後儲存成功，設定恢復可解析。
  - updates `pause_date_must_be_recent`（25-18）：`set_pause(…, Some(2000-01-01))` 回 Err。
  - protocol `ancient_patch_date_is_rejected`（25-18）：`last_patch_date = 1900-01-01` 時 `validate` 回 Err。
  - updates `audit_keeps_old_settings_and_groups`（25-19）：
    - `update_policy_update` 的 detail 有 `old.settings` 與 `old.groups`。
    - `update_policy_delete` 有 `settings` 與 `groups`。
  - updates_web `stale_form_is_409`（25-20）：
    - 開編輯頁取得 `revision`，然後 `set_pause`（revision +1）。
    - 用舊 revision 送出 → 409，訊息含「重新整理」，設定未變。
    - 重新開表單再送 → 303。
  - web `groups_column_label`（25-21）：群組頁含「規則、派送與原則」。
- [ ] **Step 2：執行。** `cargo test -p endpoint-server --test updates_web --test updates`、`cargo test -p protocol --lib`，預期上述都 FAIL。
- [ ] **Step 3：實作**
  - `CONFLICT` 改為 `(s.state = 'conflict' AND s.policy_id = p.id AND s.revision = p.revision)`。
  - `ERROR` 改為 `(s.state = 'error' AND (s.policy_id IS NULL OR s.policy_id = p.id))`。
  - `classify` 同步修改。
  - `lock_policy`：
    - 不存在時回 `CmdError::NotFound("原則不存在")`。
    - 設定無法解析時回 None：`update_policy` 用預設值，`set_pause` 回 `Invalid("原則設定無法解析，請先編輯原則重新儲存")`。
  - web `update`／`act` 的錯誤分流：
    - NotFound → `not_found()`
    - Conflict → 表單 409
    - Invalid → 表單 422（`act` 回 422 文字）
    - 其他 → `action_error`
  - `to_input` 的 deadline 閉包：期限空白但寬限有值時回錯。
  - `Tab` 加 `disabled: bool`。範本在停用時顯示「已停用：Agent 不會收到更新原則。」
  - `parse_settings` 回 `Option`：
    - `describe` 在 None 時只顯示「設定無法解析（請編輯原則重新儲存）」。
    - 清單的暫停文字用預設值。
  - `set_pause`：`start` 不在 `[UTC 今天−35, UTC 今天+1]` 時回 `Invalid("暫停日期必須是最近 35 天內")`。
  - protocol `validate`：`last_patch_date < 2000-01-01` → `Err("last_patch_date is too old")`。
  - 稽核：
    - update 時記 `old: {name, settings, groups}`（groups 在 `set_groups` 前讀）。
    - delete 時記 `settings`、`groups`。
    - pause 時記 `old_start`。
  - `FormFields.revision`（表單隱藏欄位）傳給 `update_policy(…, Some(rev))`。不符時回 `Conflict("原則已被其他人修改，請重新整理後再編輯")`。
  - `groups.html` 欄名改為「規則、派送與原則」。Ruling：計數也包含派送，比規格的「規則與原則」更準確。
- [ ] **Step 4：執行。** 同 Step 2，全部 PASS。另外確認既有呼叫 `update_policy` 的地方都補上 `None`：`tests/updates.rs`、`agent/tests/e2e.rs`。
- [ ] **Step 5：Commit** 「更新原則：分類、404、寬限、停用、無法解析、暫停日期、稽核、同時編輯、欄名」

### Task 4：Agent 更新原則（25-15、25-16）

**Files：**
- Modify: `crates/agent/src/updates/worker.rs`（`apply`）、`crates/agent/src/updates/host.rs`（`MemoryHost.fail_reads`）
- Test: `crates/agent/tests/e2e.rs`（`mod updates`）

- [ ] **Step 1：寫失敗的測試**
  - `release_failure_keeps_written_and_retries`：加上斷言，釋放失敗時回報的 revision 是 None（`row()` 的第 3 欄）。
  - 新增 `read_failure_is_error_not_conflict`：
    - 套用原則（applied）後設定 `host.fail_reads`。
    - `pass` → 伺服器上的狀態是 `error`，detail 含「讀取」。
    - 登錄檔的值未被刪除。
- [ ] **Step 2：執行。** `cargo test -p endpoint-agent --test e2e updates::`，預期 2 項 FAIL。
- [ ] **Step 3：實作**
  - `MemoryHost` 加 `fail_reads: AtomicBool`，`read` 在設定時回 `Err(PermissionDenied)`。
  - `apply`：
    - `current` 閉包把第一個讀取錯誤記在 `RefCell<Option<(String, io::Error)>>`。
    - 處理完之後若有讀取錯誤，狀態改為 `(Error, "讀取 {name} 失敗：{e}")`。
  - `Decision::Release`：進迴圈前就把 `policy_id`／`revision` 設成 None。
- [ ] **Step 4：執行。** 同 Step 2，PASS；`cargo test -p endpoint-agent -j 4` 全綠。
- [ ] **Step 5：Commit** 「Agent 更新原則：釋放後回報 None、讀取失敗回報錯誤」

### Task 5：合規時區、SQL 排版、loadsim 等待（25-12～25-14）

**Files：**
- Modify:
  - `crates/server/src/compliance/evaluate.rs`（`DeviceFacts.today`、`PatchAge`）
  - `crates/server/src/compliance/store.rs`（兩處建構、25-13 的 SQL）
  - `crates/server/src/compliance/mod.rs`（`set_display_offset`／`today()`）
  - `crates/server/src/lib.rs`（啟動時設定）
  - `tools/loadsim/tests/sim.rs`
- Test: `evaluate.rs` 單元測試

**Interfaces：**
- `DeviceFacts { pub today: NaiveDate }`：管理網頁時區的今天，`patch_age` 用它。
- `compliance::set_display_offset(FixedOffset)`、`compliance::today(now) -> NaiveDate`。
  - 實作是 `OnceLock`，預設 +8，與 `AppState` 的預設相同。
  - 加 `ponytail:` 註解：同一個程序只有一個時區；要支援多個 AppState 時改成由呼叫端傳入。

- [ ] **Step 1：寫失敗的測試** `patch_age_uses_display_date`
  - `now` = 2026-10-02T20:00Z，`today` = 2026-10-03。
  - last = 2026-09-02，max 30。
  - 結果應為違規（31 天）；用 UTC 日期只有 30 天。
- [ ] **Step 2：執行。** `cargo test -p endpoint-server --lib patch_age` 預期 FAIL（編譯錯誤：沒有 `today` 欄位，接著是斷言失敗）。
- [ ] **Step 3：實作**
  - `PatchAge` 改用 `f.today`。
  - 兩處建構 `DeviceFacts` 時用 `today: super::today(now)`。
  - 測試的 `facts()` 補上 `today`。
  - `lib.rs` 在設定 `display_offset` 的地方呼叫 `compliance::set_display_offset`。
  - 25-13：`store.rs:129` 的 SQL 改用 `\` 續行，去掉多餘空白（排版，沒有測試）。
  - 25-14：`sim.rs` 三處 `sleep(5500)` 改成讓對應快取失效：
    - 規則：沒有 `invalidate` 就加一個，與 `deploy`／`updates` 相同。
    - 派送：`deploy.invalidate()`。
    - 更新原則：`updates.invalidate()`。
    - loadsim 測試若拿不到 `AppState`，就保留等待，在 ledger 寫 Ruling。
- [ ] **Step 4：執行。** `cargo test -p endpoint-server --lib`、`cargo test -p loadsim -j 4`，全綠。
- [ ] **Step 5：Commit** 「合規用顯示時區的日期、SQL 排版、loadsim 不再固定等待」
