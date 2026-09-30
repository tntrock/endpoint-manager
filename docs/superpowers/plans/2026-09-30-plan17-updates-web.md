# 計畫 17：Windows Update 控制（合規規則、網頁、負載測試）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成第五期的使用者可見部分：
- 三種合規規則：`patch_age`、`reboot_pending`、`update_policy`。
- 更新原則網頁：清單、表單、詳情、暫停／恢復、概況、裝置「更新」分頁。
- loadsim `updates` 情境與負載測試文件。
- README。

**Architecture:**
- 合規規則沿用 `compliance::rules`（Params／Check）與 `compliance::evaluate`（`DeviceFacts` 加 `update_status`）。狀態由 `store::load_config` 從 `update_policy_status` 載入；`PUT /v1/update-status` 成功後呼叫 `refresh_after_upload`。
- 網頁新增 `crates/server/src/web/updates.rs`，比照 `web/deployments.rs`：askama 模板、`AdminSession`、`check_csrf`，寫入動作只限平台管理員。

**Tech Stack:** Rust、axum、askama、sqlx、htmx（既有）。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-09-30-windows-update-design.md`（§1.1、§5、§6、§8）

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 所有 POST 都要檢查 CSRF。寫入動作只限平台管理員，其他人回 403。
- 群組管理員的台數與裝置清單只包含自己範圍內的裝置。
- 暫停的開始日一律由伺服器以顯示時區（`st.display_offset`）的「今天」決定，不接受表單傳入的日期（處理計畫 15 延後的小問題）。
- 規則參數範圍：`patch_age.max_days` 1–365、`reboot_pending.max_days` 1–90；`update_policy` 沒有參數。
- 測試指令：`cargo test -p endpoint-server`、`cargo test -p loadsim`；最後跑 clippy 和 fmt。

## Review Focus
1. 裝置第一次套用就失敗時，Agent 回報的是 `policy_id = None, state = error`（計畫 16 的語意）。原則詳情仍要把這台算在「錯誤」，不能算成「尚未回報」。
2. 群組管理員看原則清單與詳情時，看不到範圍外的裝置與群組名稱；也不能從 URL 直接執行暫停或刪除（回 403）。
3. 超過 N 天沒更新的規則：沒有 `update_status`，或 `last_patch_date` 為 None 時判為「未知」，不是違規。
4. 原則已刪除但裝置還沒回報時，裝置分頁顯示「已刪除的原則」，不能出錯。
5. 暫停已過 35 天時，清單顯示「暫停已過期」。

---

### Task 1：三種合規規則

**Files:**
- Create：`crates/server/migrations/0013_update_rules.sql`：先 DROP 再 ADD `compliance_rules_kind_check`，在 0008 的清單後面加上 `'patch_age', 'reboot_pending', 'update_policy'`。
- Modify：`crates/server/src/compliance/rules.rs`
  - `KINDS` 加三個（陣列長度 15）；`kind_label` 分別是「太久沒更新」「待重開機太久」「更新原則衝突」。
  - `Params`／`Check` 加上 `PatchAge { max_days: u32 }`、`RebootPending { max_days: u32 }`、`UpdatePolicy`。
  - 補上 `parse`、`to_json`、`kind`、`compile`。
- Modify：`crates/server/src/compliance/evaluate.rs`
  - `DeviceFacts` 加 `pub update_status: Option<UpdateFact>`。
  - `pub struct UpdateFact { state: String, detail: String, reboot_pending: bool, reboot_pending_since: Option<DateTime<Utc>>, last_patch_date: Option<NaiveDate> }`。
  - `check_one` 加三個分支；`summarize` 加文字。
- Modify：`crates/server/src/compliance/store.rs`：`load_config` 讀 `update_policy_status`，兩個建立 `DeviceFacts` 的地方都要補 `update_status`。
- Modify：`crates/server/src/updates/api.rs`：寫入成功後呼叫 `crate::compliance::refresh_after_upload(&st, device.device_id)`，失敗只記 error、不影響回應，比照 `inventory::upload`。
- Modify：`crates/server/src/web/rules.rs` 與 `templates/rule_form.html`：
  - `patch_age`／`reboot_pending` 使用欄位 `p_max_days`，對應 JSON `{"max_days": n}`。
  - `update_policy` 不用填參數，JSON 是 `{}`。
  - 編輯時從 JSON 讀回 `max_days`。
- Test：`evaluate.rs` 單元測試、`rules.rs` 單元測試、`web/rules.rs` 的 `form_to_params_by_kind`、`tests/updates.rs`

**判定規則**（`now` 取 `DeviceFacts.now`）：
- **`patch_age`**：
  - 沒有 `update_status`，或 `last_patch_date` 為 None：回 Unknown，reason 為 `no_data`；日期為 None 時 reason 為 `no_patch_date`。
  - 否則 `last_patch_date < now.date_naive() - max_days` 時違規，detail 是 `{"last_patch_date": "YYYY-MM-DD", "days": n}`。
- **`reboot_pending`**：
  - 沒有 `update_status`：Unknown `no_data`。
  - `reboot_pending` 為真，且 `since` 早於 `now - max_days`：違規，detail 是 `{"reboot_pending_since": RFC3339, "days": n}`。
  - `since` 為 None 但 `reboot_pending` 為真：不算違規，因為沒有起始時間無法判斷天數。
- **`update_policy`**：
  - 沒有 `update_status`：Unknown `no_data`。
  - state 是 `conflict` 或 `error`：違規，detail 是 `{"update_state": state, "update_detail": detail}`。
  - 其他（applied、unmanaged）：符合。
- **`summarize` 的文字**：
  - `no_patch_date`：「沒有可判讀的更新安裝日期」
  - 有 `last_patch_date`：「最後裝更新：{date}（{days} 天前）」
  - 有 `reboot_pending_since`：「待重開機已 {days} 天」
  - 有 `update_state`：衝突是「原則被改動：{update_detail}」，錯誤是「原則套用失敗：{update_detail}」

**關於重算時機：** 這三種規則會隨時間變化。狀態上傳時會評估；Agent 至少每 24 小時會重送一次（計畫 16 的 RESEND），所以違規最晚在跨過門檻後約一天出現。這個延遲記在 README。

- [ ] **Step 1：寫失敗測試**
  - `evaluate.rs`：每種 kind 的違規、符合、未知三種情況各一個，包括 `since` 為 None 和 unmanaged 的情況。
  - `rules.rs`：
    - `parse` 的邊界：`patch_age` 0 失敗、1 通過、365 通過、366 失敗；`reboot_pending` 91 失敗；`update_policy` 帶 `{}` 通過。
    - `to_json` 與 `parse` 往返後相同。
  - `web/rules.rs` 的 `form_to_params_by_kind`：加入三種 kind 的案例。
  - `tests/updates.rs`：`status_upload_drives_compliance`
    1. 建立 `update_policy` 與 `patch_age(max_days 30)` 兩條規則（`compliance::admin::create_rule`，看 `tests/config_rules.rs` 的用法）。
    2. PUT 狀態：conflict，`last_patch_date` 是 60 天前。
    3. 在 `compliance_status`（實際表名依 0004 migration）看到兩條規則都違規。
    4. 再 PUT：applied，今天的日期。兩條都恢復符合。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --lib compliance` 和 `cargo test -p endpoint-server --test updates status_upload`，預期 FAIL。
- [ ] **Step 3：** 實作（含 migration 0013）。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-server`，預期全部 PASS。既有的 `KINDS` 相關測試要一起更新。
- [ ] **Step 5：** Commit「合規：太久沒更新、待重開機太久、更新原則衝突三種規則」。

### Task 2：原則清單、表單、詳情、動作（`web/updates.rs`）

**Files:**
- Create：`crates/server/src/web/updates.rs`
- Create：模板 `updates.html`（清單）、`update_form.html`（新增／編輯）、`update_detail.html`（詳情）
- Modify：`crates/server/src/web/mod.rs`，加入以下路由：
  ```
  .route("/updates", get(updates::list).post(updates::create))
  .route("/updates/new", get(updates::new_form))
  .route("/updates/{id}", get(updates::detail))
  .route("/updates/{id}/edit", get(updates::edit_form).post(updates::update))
  .route("/updates/{id}/{action}", post(updates::act))   // pause-quality、resume-quality、pause-feature、resume-feature、delete
  ```
  寫在 `/updates/overview`（Task 3）之前，避免路由衝突。axum 的固定路徑優先，但仍要用測試確認。
- Modify：`templates/base.html`：「派送」後面加上 `<a href="/updates">更新原則</a>`。
- Test：`crates/server/tests/updates_web.rs`（新檔，比照 `tests/deploy_web.rs`）

**狀態分類的 SQL**（`$1` 全部、`$2` 群組，比照 deployments 的 TARGET）：
```sql
-- 原則 p 的對象：使用中、在管理範圍內、群組屬於此原則
v.status = 'active' AND ($1::bool OR v.group_id = ANY($2::bigint[]))
  AND EXISTS (SELECT 1 FROM update_policy_groups g WHERE g.policy_id = p.id AND g.group_id = v.group_id)
-- LEFT JOIN update_policy_status s ON s.device_id = v.id，分類：
applied  : s.state = 'applied'  AND s.policy_id = p.id AND s.revision = p.revision
conflict : s.state = 'conflict' AND s.policy_id = p.id
error    : s.state = 'error'    -- 第一次套用就失敗時 policy_id 是 None，所以不看 policy_id
pending  : 其餘（包括沒有狀態、舊 revision、unmanaged）
```

**清單：**
- 欄位：名稱、群組、暫停狀態、對象、已套用、衝突、錯誤、尚未回報。
- 群組名稱只顯示管理範圍內的群組。平台管理員看得到全部群組。
- 暫停狀態由 `settings.quality_pause_start`／`feature_pause_start` 計算：
  - 「品質更新暫停中，至 M/D」（開始日 + `PAUSE_DAYS`）
  - 超過結束日時顯示「品質更新暫停已過期」
  - 功能更新同理

**表單：**
- 欄位：
  - 名稱
  - 群組（核取方塊，沿用 `super::rules::group_checks`，只列出群組）
  - 品質更新延後天數、功能更新延後天數
  - 品質更新期限、寬限；功能更新期限、寬限
  - 期限前不自動重開機（核取方塊）
  - 使用中時段開始、結束（`<select>` 0–23，另有「不設定」）
- 空白欄位就是 None。期限欄位有填、寬限沒填時，寬限用 2（Windows 預設），並在說明文字寫出來。
- 驗證錯誤時回 422，重新顯示表單並保留輸入，比照 deployments::create。
- 編輯時從 `settings` 帶入目前的值。

**詳情：**
- 原則設定的摘要（每項一行，例如「品質更新延後 7 天」）。
- 各狀態台數的篩選連結（`?state=&page=`）與裝置列表，每頁 100 台，比照 deployments。欄位：主機名稱、狀態、說明（detail）、回報時間。
- 平台管理員會看到按鈕：暫停／恢復品質更新、暫停／恢復功能更新、編輯、刪除（刪除有 `confirm`）。

**`act`：**
- `pause-*` 呼叫 `admin::set_pause(pool, id, kind, Some(today), user)`，其中 `today = Utc::now().with_timezone(&st.display_offset).date_naive()`；`resume-*` 傳 None。
- `delete` 完成後導向 `/updates`；其他動作完成後導向 `/updates/{id}`。
- 錯誤用 `action_error` 處理。

- [ ] **Step 1：寫失敗測試**（`tests/updates_web.rs`）
  - 平台管理員：
    - 新增後 303 導向詳情；錯誤輸入回 422，頁面保留名稱，並顯示「品質更新延後必須是 0–30 天」。
    - 編輯後 revision 變 2。
    - 暫停品質更新後，資料庫的 `quality_pause_start` 是顯示時區的今天，清單顯示「品質更新暫停中」。
    - 恢復後清掉。
    - 刪除後導向 `/updates`。
  - 暫停開始日設為 40 天前（直接改資料庫）時，清單顯示「暫停已過期」。
  - 狀態分類：四台裝置分別是 applied（revision 相符）、舊 revision 的 applied、`policy_id NULL` 的 error、沒有狀態。詳情頁台數依序是：已套用 1、錯誤 1、尚未回報 2。
  - 群組管理員（只管「台北」）：
    - 清單只計台北的裝置，看不到「高雄」這個群組名稱。
    - POST `/updates/new`、`/updates/{id}/pause-quality`、`/updates/{id}/delete` 都回 403。
    - GET `/updates/new` 回 403。
  - 沒有 CSRF 的 POST 被拒絕，狀態碼比照既有 web 測試。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test updates_web`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同一指令，預期 PASS。
- [ ] **Step 5：** Commit「網頁：更新原則清單、表單、詳情與暫停」。

### Task 3：更新概況與裝置「更新」分頁

**Files:**
- Modify：`crates/server/src/web/updates.rs`（加 `overview`、`device_tab`）
- Create：`templates/updates_overview.html`、`templates/updates_tab.html`
- Modify：`web/mod.rs`：`.route("/updates/overview", get(updates::overview))`
- Modify：`web/devices.rs`：分頁列表在「派送」之後加上 `("updates", "更新")`，`tab` 函式對 `"updates"` 轉交給 `super::updates::device_tab`。
- Test：`tests/updates_web.rs`

**概況：**
- **UBR 分布**：`SELECT os_build, os_ubr, count(*) FROM devices WHERE status = 'active' AND (範圍) GROUP BY 1, 2 ORDER BY 1 DESC, 2 DESC`。
- **待重開機最久的 50 台**：`update_policy_status.reboot_pending AND reboot_pending_since IS NOT NULL`（範圍內），依 since 由舊到新排序。欄位：主機名稱（連到裝置頁）、待重開機起始時間、天數。

**裝置分頁：**
- 範圍外的裝置回 404。
- **目前指派的原則**：用 `st.updates.get(&st.pool)` 取出 `PolicySet.policy_for(group)`，連同原則名稱，名稱從資料庫讀。沒有時顯示「不受管」。
- **期望值**：該原則的 `values`，列出名稱＝值。
- **Agent 回報**：
  - 狀態（套用中文標籤：已套用／衝突／錯誤／不受管）
  - 說明
  - 回報的原則：用 policy_id 查名稱；查不到時顯示「已刪除的原則」
  - revision、待重開機（起始時間）、最後裝更新日期、回報時間
- Agent 沒有回報實際寫入的值，所以不顯示逐值的「實際」欄。衝突時說明裡會列出被改的值名稱。

- [ ] **Step 1：寫失敗測試**
  - 概況頁：兩台組建 19045／UBR 5000、一台 22631／4000 時，頁面列出兩列、台數正確。一台待重開機 3 天時，出現在清單。
  - 群組管理員看概況時，不含範圍外的裝置。
  - 裝置分頁：
    - 有原則：列出期望值 `DeferQualityUpdatesPeriodInDays = 7`。
    - 狀態是 conflict 時，說明含值名稱。
    - 原則刪除後，狀態仍顯示，回報的原則顯示「已刪除的原則」。
    - 範圍外的裝置回 404。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test updates_web overview`、`... tab`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-server`，預期 PASS。
- [ ] **Step 5：** Commit「網頁：更新概況與裝置更新分頁」。

### Task 4：loadsim、負載測試、README

**Files:**
- Modify：`tools/loadsim/src/lib.rs`，新增 `pub async fn updates(t: &Target, devices: &[Device], concurrency: usize) -> (Report, usize)`：每台報到；有 `update_policy` 就 PUT 一次 applied 狀態（policy_id、revision 取回應值，`last_patch_date` 為今天）；沒有原則的台數計入第二個回傳值。
- Modify：`tools/loadsim/src/main.rs`：加 `"updates"` 指令，參數 `--concurrency`，比照 `deploy`；USAGE 也要更新。
- Create：`tools/loadsim/updates_setup.sql`：
  1. 建立 5 個群組（`load wu 1..5`）。
  2. 把 `devices` 依 `abs(hashtext(id::text)) % 5` 分到這 5 個群組。
  3. 每個群組建一個原則（settings：品質延後 7 天、品質期限 3／寬限 2、使用中時段 8–18）。
  4. `UPDATE update_state SET generation = generation + 1`。
- Modify：`tools/loadsim/tests/sim.rs`：加 `updates` 的小規模測試。3 台，其中 2 台在有原則的群組；回報錯誤數為 0，`update_policy_status` 有 2 筆。
- Modify：`docs/loadtest.md`：新增「Windows Update 控制（第五期）」一節。
  - 條件：三萬台、5 個原則、並行 60。
  - 量測：
    1. `heartbeat` 情境：報到 500 次／秒，量 p99（目標 < 100ms）。
    2. `updates` 情境：三萬台各報到並上傳一次狀態（目標 0 個 5xx、`update_policy_status` 三萬筆）。
    3. 合規重算：加入 `patch_age`、`reboot_pending`、`update_policy` 三條規則前後，各跑一次全量重算（`rules.sql` 的既有方法），比較時間（目標增加不超過 10%）。
  - 照實記錄結果；未達標時寫出原因，不調整目標。重跑方法也寫進「重跑方法」一節。
- Modify：`README.md`：新增「Windows Update 控制」一節。
  - 一個群組只屬於一個原則，受管群組不要再有管 WU 的 GPO（否則回報衝突）。
  - 暫停 35 天後由 Windows 自動恢復。
  - 期限值新舊名稱並存，請在 22H2／23H2 確認「已設定的更新原則」有生效。
  - 三種合規規則約每 24 小時更新一次。
  - 升級順序：先升級伺服器，再升級 Agent。

- [ ] **Step 1：寫失敗測試**：`tools/loadsim/tests/sim.rs` 的 `updates` 測試。
- [ ] **Step 2：** 執行 `cargo test -p loadsim`，預期 FAIL。
- [ ] **Step 3：** 實作 lib、main、SQL。
- [ ] **Step 4：** 執行 `cargo test -p loadsim`，預期 PASS。
- [ ] **Step 5：** 實際跑負載測試。環境比照 `docs/loadtest.md` 的重跑方法：Docker Postgres 加 release build。結果寫進文件。
- [ ] **Step 6：** 更新 README；跑 `cargo test --workspace`、clippy、fmt。
- [ ] **Step 7：** Commit「loadsim：更新原則情境；負載測試與 README」。
