# 計畫 26：分點快取與第一～三期延後問題 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal：** 修正規格 26-1～26-27（Agent 與快取的連線、快取程式、中央的快取管理、合規、雜項）。

**Architecture：** 每項都在原本的模組內修，不搬動結構。資料庫變更放在兩個新 migration：
- 0019：快取名稱的唯一性只限非 rejected。
- 0020：違規列記錄「轉入未知時是否寫過歷程」。

不存在回 404 的地方沿用 `crate::commands::CmdError`。

**Tech Stack：** Rust、axum、sqlx（Postgres）、askama、reqwest、rcgen、x509-parser。

**Spec：** `docs/superpowers/specs/2026-10-03-deferred-fixes-design.md`（§5）

## Global Constraints

- 不新增依賴；協定新增欄位一律 `#[serde(default)]`。
- 標為「修」的每一項都有先失敗再通過的測試。下列項目在任務中註明原因，不寫 RED 測試：
  - 文件：26-15、26-26。
  - 只有 Windows 能驗證：26-6。
  - 測試本身：26-21、26-25、26-27。
  - 只能在每天部分時段重現：26-16 的趨勢查詢。
- `cargo fmt --all`、clippy `-D warnings`、`cargo test --workspace -j 4` 全綠。
- 使用者看到的文字用繁體中文。

## Review Focus

1. 快取換發金鑰後回應遺失，再停用、重新啟用：快取要換上與新憑證相符的金鑰，不能卡在 TLS 失敗。
2. 中央卡住時，快取對每個下載請求最多等 10 秒，之後 30 秒內直接回 503；中央恢復後立刻恢復授權。
3. 「違規 → 未知 → 符合」的歷程最後一筆是「→ 符合」。但規則剛上線時的「無 → 未知 → 符合」不寫歷程，避免歷程暴增。
4. 名稱以 `*-500` 這類 SID 樣式比對的允許清單，不能讓名稱剛好像 SID 的帳號誤符合。
5. 「全部核准」的結果只在送出 POST 後顯示；帶參數的連結不會顯示任何核准訊息。

---

### Task 1：Agent 連線與派送（26-1、26-2、26-3、26-27）

**Files：** `crates/agent/src/client.rs`、`crates/agent/src/deploy/worker.rs`、`crates/agent/src/agent.rs`、`crates/agent/tests/e2e.rs`

- [ ] **Step 1：寫失敗的測試**
  - e2e `connect_timeout_is_short`：
    - 連到不會回應的位址（`10.255.255.1:443`，封包會被丟棄），`checkin` 要在 15 秒內回 `Err`。
    - 這個位址如果在 CI 上立刻被拒絕，測試照樣會通過，但無法證明逾時有作用，在 ledger 註明。
  - e2e `cache_pause_uses_current_time`：
    - `pass_at(w, t0)`，t0 取 2 小時前。
    - 快取連不上時，`cache_paused_until` 應約為「現在 + 5 分鐘」，不是「t0 + 5 分鐘」。
    - Worker 需要 `pub fn cache_paused_until()` 讀取。
  - e2e `package_source_change_wakes_worker`：
    - 報到一次後 `rx.borrow_and_update()`。
    - 把裝置所在據點的快取改掉，再報到一次。
    - `rx.has_changed()` 應為 true。
  - 26-27：`interrupted_install_counts_as_attempt` 改為輪詢 `deploy.json` 出現 `in_progress: true` 後才中斷，不用固定 500 毫秒。這是測試本身的修正，沒有 RED。
- [ ] **Step 2：執行。** 預期前三個 FAIL。
- [ ] **Step 3：實作**
  - `ServerClient::new` 加 `.connect_timeout(CONNECT_TIMEOUT)`，`CONNECT_TIMEOUT = 10 秒`。中央與快取都用這個 client。
  - `download()` 的快取暫停改用 `Utc::now()` 設定與判斷。
  - `agent.rs` 的 `send_if_modified`：指派或 `package_source` 任一改變就喚醒。
- [ ] **Step 4：執行。** 全部 PASS；`cargo test -p endpoint-agent -j 4` 全綠。
- [ ] **Step 5：Commit** 「Agent：連線逾時、快取暫停用當下時間、快取改變時喚醒」

### Task 2：快取程式（26-4、26-5、26-6、26-7、26-11、26-12）

**Files：**
- `crates/cache/src/identity.rs`、`run.rs`、`server.rs`、`auth.rs`、`fetch.rs`、`config.rs`
- 測試：同檔案的單元測試，以及 `crates/server/tests/branch.rs`

**Interfaces：**
- `identity::save_renew_key` / `load_renew_key` / `remove_renew_key`：檔名 `renew.key`。
- `identity::key_matches(key_pem, chain_pem) -> bool`：用 rcgen 的公鑰 DER 比對 x509 的 SPKI。
- `AuthCache::{fail, failing}`：記住 30 秒的失敗。

- [ ] **Step 1：寫失敗的測試**
  - identity `key_matches_certificate`：用自簽憑證測試，相符的金鑰回 true，另一把回 false。
  - branch 整合測試 `renew_lost_response_then_reenable_uses_new_key`：
    - 快取 renew：中央已記下新的 CSR，但模擬回應遺失，不安裝新憑證。
    - 停用再啟用（中央用新 CSR 簽發）。
    - `recover()` 之後，安裝的金鑰與憑證相符。
    - 先找既有的快取整合測試作為樣板。
  - auth `failure_is_remembered`：`fail()` 之後 `failing()` 為 true；過了設定的時間為 false。
  - server `authorize_failure_is_fast_and_remembered`：
    - 用 stub 中央，授權永遠不回應。
    - 第一個請求在 10 秒左右回 503，第二個請求立即回 503。
  - fetch `bad_sha_is_filtered`：`replace()` 收到 sha256 格式不對的套件時略過，其他照常。
  - 26-12：`run.rs` 改由獨立的每分鐘迴圈呼叫 `prune`，用 `prune_loop` 的單元測試（paused time）驗證。
- [ ] **Step 2：執行。** 預期都 FAIL。
- [ ] **Step 3：實作**
  - renew：
    - 送出 CSR 前先 `save_renew_key`，安裝新憑證後 `remove_renew_key`。
    - `recover()`：在目前的金鑰與 `renew.key` 中，選與新憑證相符的那把安裝。都不符時回錯。
  - `server.rs`：
    - 授權前先查 `failing()`，是就直接 503。
    - `tokio::time::timeout(AUTHORIZE_TIMEOUT = 10 秒, authorize)`，失敗或逾時就 `fail()`，記住 30 秒。
  - `secure_data_dir`：先 `icacls <dir> /reset /T /Q`，再設定授權。只有 Windows 驗證，CI 編譯，在 ledger 註明。
  - `Catalog::replace`：sha256 不是 64 位 hex 的略過，並 `tracing::warn!`。
  - 刪除 `FetchError::NotListed` 與它的 match 分支。
  - prune 改為每分鐘獨立執行（`tokio::spawn`），報到成功時不再呼叫。
- [ ] **Step 4：執行。** `cargo test -p endpoint-cache -j 4` 與 `--test branch` 全綠。
- [ ] **Step 5：Commit** 「快取：換發金鑰保存、授權逾時與失敗記憶、icacls 重設、過濾 sha、移除 NotListed、獨立清理」

### Task 3：中央的快取管理（26-8、26-9、26-10、26-13、26-14、26-15）

**Files：**
- `crates/server/src/branch/api.rs`、`branch/sites.rs`
- `crates/server/src/web/sites.rs`、`templates/device.html`
- `crates/server/migrations/0019_cache_name_unique.sql`
- `crates/cache/cache_setup.sql`（或實際檔名）、`README.md`
- 測試：`crates/server/tests/branch.rs`、`branch_web.rs`

- [ ] **Step 1：寫失敗的測試**
  - `poll_is_rate_limited`：同一 IP 連續 poll 超過 enroll 的上限 → 429。
  - `enroll_rejects_unsignable_names`：
    - 先找出一個能通過 `validate`、但核准時簽不出來的名稱，用它註冊 → 400。
    - 如果找不到這種名稱，這項改成「註冊時試簽一次」的程式碼審查項目，在 ledger 註明沒有 RED。
  - `rejected_name_can_be_reused`：註冊 A，拒絕，再註冊同名 A → 成功。
  - `device_page_explains_site_and_disabled_cache`：
    - 據點的快取停用。
    - 裝置頁含「依最後回報的 IP」與「已停用，向中央下載」。
  - `site_delete_db_error_is_500`：用 trigger 讓刪除失敗 → 500；不存在的據點 → 404。
- [ ] **Step 2：執行。** 預期都 FAIL。
- [ ] **Step 3：實作**
  - `poll` 開頭加 `enroll_limiter.check`，要加 `ConnectInfo`。
  - `enroll`：用 `st.ca.sign_cache_csr(&req.csr_pem, 0, &req.dns_names, now)` 試簽一次，結果不保存，失敗回 400。
  - migration 0019：
    - `ALTER TABLE caches DROP CONSTRAINT caches_name_key;`
    - `CREATE UNIQUE INDEX caches_name_active ON caches (name) WHERE status <> 'rejected';`
  - `site_of`：
    - 快取不是使用中時顯示「{名稱}（{狀態}，向中央下載）」。
    - device.html 的欄名改為「據點（依最後回報的 IP）」。
  - `delete_site`：不存在時回 `CmdError::NotFound`。web 端 NotFound → 404，其他記錄錯誤後回 500。
  - 文件（26-15）：
    - 修正 `cache_setup.sql` 指向不存在的 `cache_approve.sql`。
    - README 的 Linux 步驟改為先把 `root.pem` 複製到可讀的位置。
- [ ] **Step 4：執行。** `--test branch --test branch_web` 全綠。
- [ ] **Step 5：Commit** 「中央快取管理：poll 速率限制、註冊時試簽、名稱可重用、裝置頁說明、刪除據點錯誤、文件」

### Task 4：合規與第一～三期（26-16、26-20～26-25）

**Files：**
- `crates/server/src/compliance/worker.rs`、`compliance/store.rs`、`compliance/evaluate.rs`、`compliance/admin.rs`、`compliance/templates.rs`、`compliance/baseline.json`
- `crates/server/src/web/compliance.rs`、`crates/server/src/inventory.rs`
- `crates/server/migrations/0020_violation_logged.sql`
- 測試：`tests/compliance.rs`、`tests/config_rules.rs`、`tests/config_web.rs`、單元測試

- [ ] **Step 1：寫失敗的測試**
  - `cleanup_uses_display_date`：
    - `cleanup_history(pool, today)` 多一個參數。
    - `today` = 現在 + 200 天、保留 30 天時，日期為「現在 + 100 天」的快照應被刪除。
  - 26-16 的趨勢查詢：改為綁定顯示時區的今天，只能在部分時段重現，沒有 RED。
  - `unchanged_registry_rows_are_not_locked`：
    - 另一個交易對該裝置的 `device_registry` 取 `FOR SHARE`。
    - 上傳完全相同的值，應在 2 秒內完成。目前會被鎖住等待。
  - 26-21 `duplicate_registry_first_wins`：
    - 同一次上傳中同一個值出現兩次，先 `"z"` 後 `"a"`。
    - 存下來的應是 `"z"`。這是測試補強。
  - `history_returns_to_compliant`：
    - 規則先違規，然後資料缺失變未知，最後符合。
    - 最後一筆歷程是「unknown → none」。
    - 另外驗證「無 → 未知 → 符合」不寫任何歷程。
  - `local_admins_matches_builtin_sid`：
    - 允許 `*-500`。名稱改過的內建帳號（SID 以 `-500` 結尾）符合。
    - 名稱叫 `x-500` 但 SID 不同的帳號不符合。
  - `template_exists_is_typed`：用同一個 `template_key` 建第二條規則，錯誤能 downcast 成 `admin::TemplateExists`。
  - 26-25：在既有的表單往返測試加上 Defender 防竄改與密碼最長使用期限。這是測試補強。
- [ ] **Step 2：執行。** 預期 RED 的項目都 FAIL。
- [ ] **Step 3：實作**
  - `cleanup_history(pool, today)`：`compliance_daily` 用 `day < $today - days`。worker 傳入顯示時區的今天。趨勢查詢改綁定 `today`。
  - 登錄檔 upsert：外層 `WHERE NOT EXISTS`，相同的值不進 `ON CONFLICT`。保持先 `DISTINCT ON` 取先出現的，再過濾。
  - migration 0020：`device_violations` 加 `logged boolean NOT NULL DEFAULT true`。`apply` 的規則：
    - 「無 → 未知」寫入的列 `logged = false`。
    - 其他轉入未知的情況 `logged = true`。
    - 刪除未知列時，`logged` 為 true 才寫「→ none」歷程。
  - `LocalAdmins`：樣式以 `S-1-` 或 `*-` 開頭時比對 `sid`，否則比對名稱。baseline.json 的範本改用 `["*-500"]`。
  - `admin::TemplateExists` 改為錯誤型別，`templates::create` 用 `downcast_ref` 判斷。
- [ ] **Step 4：執行。** `cargo test -p endpoint-server -j 4` 全綠。
- [ ] **Step 5：Commit** 「合規：顯示時區清理、未變更登錄檔不鎖、歷程回到符合、SID 允許清單、範本型別判斷」

### Task 5：雜項（26-17、26-18、26-19、26-26）

**Files：**
- `crates/server/src/notify/send.rs`
- `crates/server/src/web/devices.rs`、`web/dashboard.rs`、`templates/approve_result.html`（新）
- `crates/server/src/tokens.rs`、`groups.rs`、`main.rs`
- `docs/loadtest.md`
- 測試：單元測試、`tests/followups.rs`、`tests/web.rs`

- [ ] **Step 1：寫失敗的測試**
  - send `causes_are_not_repeated`：`join_causes("A（B）", ["B", "B", "C"])` 的結果裡，`B` 只出現一次。
  - `approve_all_shows_result_page`：
    - POST 後回 200，頁面含「已核准 N 台」。
    - `GET /?approved=99` 不含「已核准」。
  - `cli_token_audits_group_and_token`：
    - 呼叫 `tokens::create_token_cli(pool, name, max_uses, Some("新群組"), Some(7))`。
    - 有一筆 `group_create` 稽核。
    - `token_create` 的 detail 有 `valid_days`，沒有 `expires_at`，與網頁格式相同。
    - 群組已存在時不寫 `group_create`。
- [ ] **Step 2：執行。** 預期都 FAIL。
- [ ] **Step 3：實作**
  - `describe()` 抽出純函式 `join_causes`：跳過已出現在前面文字裡的原因。
  - `approve_all`：直接 render `approve_result.html`，含結果與回儀表板的連結。dashboard 刪除 `approved`／`skipped` 參數。
  - `tokens::create_token_cli`：
    - 同一個交易裡建立群組；新建的群組才寫 `group_create`。
    - token 稽核的格式與網頁相同（`installer: false`、`server_url: null`）。
    - main.rs 改呼叫它，刪除 `create_token_audited`。
  - `docs/loadtest.md`：說明 `--max-secs 3600` 是全量重算的上限，留出 5 分鐘目標的餘裕。
- [ ] **Step 4：執行。** 相關測試 PASS。
- [ ] **Step 5：Commit** 「雜項：webhook 原因去重、全部核准結果頁、指令列稽核、負載測試文件」
