# 計畫 23：分點快取（Agent、管理網頁、負載測試、文件）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 完成第七期分點快取：
- Agent 依報到的 `package_source` 向快取下載；快取有問題時依據點設定決定是否改向中央，並回報下載來源。
- 管理網頁 `/sites`、`/caches`（含快取註冊金鑰），裝置頁顯示據點與快取，派送詳情顯示來源。
- loadsim「透過快取下載」情境與負載測試（規格 §1.1），README 部署說明。

**Architecture:**
- Agent：`client::DownloadError` 拆出「忙碌」「連不上」「被拒」；派送 worker 依 `Work.package_source` 選來源，「快取暫停期」放在 worker 記憶體。
- 網頁：新模組 `web/sites.rs`、`web/caches.rs`，只限平台管理員；表單錯誤以 422 重新顯示表單（比照 `web/updates.rs` 的 `invalid`）。
- Migration 0017：`try_inet(text)`，讓 `devices.last_ip`（文字）可以安全地和網段比對。
- loadsim 新增 `cache-deploy` 子命令。

**Tech Stack:** 既有依賴。Agent 的 dev-dependency 加上 `endpoint-cache`（只供 e2e 測試）。

**Spec:** `docs/superpowers/specs/2026-10-02-branch-cache-design.md`（§1.1、§4、§5、§6、§7）

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 據點、快取、快取註冊金鑰只限平台管理員（檢視與管理都是）；所有變更寫稽核紀錄（沿用計畫 21 的函式）。
- 網頁的 POST 都檢查 CSRF；表單驗證錯誤回 422 並顯示在表單上（規格 §6）。
- Agent 下載規則（規格 §4）：
  - 快取回 503／429：照 `Retry-After` 稍後再試，**不**改向中央，不算嘗試。
  - 快取連不上、逾時、回 503 以外的 5xx：`fallback_to_central` 為 true 時這次改向中央，並進入 5 分鐘快取暫停期；為 false 時稍後重試快取（不算嘗試）。
  - 快取回 403／404：照下載失敗處理，不改向中央。
  - 快取給的檔案雜湊或大小不符：允許改向中央時改向中央重試一次；否則照下載失敗處理。
  - 結果回報 `source`：這次實際下載的來源；沿用本機已驗證的檔案時不帶。
- 測試指令：
  - `cargo test -p endpoint-agent`、`cargo test -p endpoint-server`、`cargo test -p loadsim`
  - 完整測試：`cargo test --workspace -j 4`
  - 最後跑 clippy 和 fmt。

## Review Focus
1. 快取停機而且不允許改向中央時，端點不會累積失敗次數（不算嘗試），快取恢復後自然完成；也不會在每次重試時改去中央。
2. 快取暫停期內，所有派送都直接向中央下載，不會每個派送都先等快取逾時一次。
3. 停用中的快取、已刪除的據點：網頁顯示一致，裝置頁不會顯示已停用的快取為「使用中」。
4. `devices.last_ip` 是任意文字（例如空字串、`fe80::1%12` 這種帶介面編號的位址）時，據點頁與裝置頁不會出錯。
5. 群組管理員、檢視者打開或送出 `/sites`、`/caches` 的任何網址都得到 403；`/tokens` 不會列出或作廢快取金鑰。

以上各點的測試：1、2 在 Task 1；3、4 在 Task 3；5 在 Task 3、4。

---

### Task 1：Agent 依來源下載與改向中央

**Files:**
- Modify：`crates/agent/src/client.rs`、`crates/agent/src/deploy/worker.rs`、`crates/agent/src/agent.rs`
- Modify：`tools/loadsim/src/lib.rs`（`DownloadError` 拆分後的對應）
- Test：`crates/agent/tests/e2e.rs`（`mod deploy` 內）

**Interfaces（Produces）：**
```rust
// client.rs
pub enum DownloadError {
    /// 伺服器忙碌（503／429）：依 Retry-After 稍後再試
    Retry(Option<Duration>),
    /// 連不上、逾時、503 以外的 5xx
    Unreachable,
    Unauthorized,
    /// 403：不允許下載（快取的授權被拒）
    Forbidden,
    NotFound,
    Mismatch,
    Io(std::io::Error),
}
// deploy/worker.rs
pub struct Work { /* 既有欄位 */ pub package_source: Option<protocol::branch::PackageSource> }
pub const CACHE_PAUSE: Duration = Duration::from_secs(5 * 60);
```

**實作要點：**
- `client.rs`：`fetch` 的狀態對應改為 200 → 繼續；404 → `NotFound`；401 → `Unauthorized`；403 → `Forbidden`；503／429 → `Retry(retry_after)`；其他狀態與送出失敗、閒置逾時、串流中斷 → `Unreachable`。
- `worker.rs`：
  - `Worker` 新增 `cache_paused_until: Option<DateTime<Utc>>`、`source: Option<DownloadSource>`（每次 `execute` 開頭清成 None，`report` 建 `DeployResult` 時帶入）。
  - `execute` 的下載改成 `self.download(w, spec, &file, now)`，回傳 `Result<(), DownloadError>` 並設定 `self.source`：
    1. 有 `package_source` 且 `now >= cache_paused_until`：用 `ServerClient::new(&src.url, &w.root_pem, w.identity_pem.clone())` 下載。
       - `Ok` → source = Cache。
       - `Retry(after)` → 原樣回傳（不改向）。
       - `Unreachable`／`Unauthorized` → `fallback_to_central` 為 true：`cache_paused_until = now + CACHE_PAUSE`，記錄 warn，改向中央；否則回 `Retry(None)`（不算嘗試，DOWNLOAD_RETRY 後再試）。
       - `Mismatch` → 允許改向時改向中央一次；否則回 `Mismatch`。
       - `Forbidden`／`NotFound`／`Io` → 原樣回傳（下載失敗）。
    2. 其他情況向中央下載，成功時 source = Central。
  - `execute` 對錯誤的處理：`Retry` 照舊排程；中央的 `Unreachable` 視同 `Retry(None)`；`Unauthorized`（中央）照舊停止；其他（含 `Forbidden`）`fail_before_run`。
  - `pass` 需要 `Work`：`execute` 已經拿得到 `w`（目前由 `pass_at` 傳 client），把 `&Work` 一路傳下去。
- `agent.rs`：建立 `Work` 時帶 `package_source: resp.package_source.clone()`。`send_if_modified` 的比較維持只看指派；但來源改變也要更新內容（比照連線資訊每次都更新的寫法）。
- `loadsim/src/lib.rs`：`deploy` 的重試條件改為 `Retry(_) | Unreachable`。

- [ ] **Step 1：寫失敗測試**（`crates/agent/tests/e2e.rs` 的 `mod deploy`，真實中央）
  - 測試用的假快取：`stub(e, kind)` 用中央的 `tls::serve_mtls` + `tls::server_config(pki)`（憑證含 127.0.0.1）啟動一個 HTTPS 伺服器，回傳網址。`kind`：
    - `Ok(bytes)`：200 回傳內容
    - `Status(503, Some(60))`、`Status(500, None)`、`Status(403, None)`、`Status(404, None)`
    - `Corrupt`：200 回傳等長但不同的內容
    - 另有 `dead_url()`：已關閉的埠
  - 每個情境用 `setup` 建立派送與 `Work`，`Work.package_source = Some(PackageSource { cache_id: 1, url, fallback_to_central })`，執行 `worker.pass(&w)`：
    - 假快取 200：安裝成功；`deployment_status.source = 'cache'`；中央的下載沒被呼叫（中央套件檔先改名，下載中央會失敗）。
    - 假快取 503（Retry-After 60）+ fallback true：`pass` 回傳約 60 秒後再檢查；沒有執行安裝、沒有記一次嘗試、沒有向中央下載。
    - 連不上 + fallback true：改向中央成功，`source = 'central'`；同一個 worker 立刻再處理第二個派送（另一個套件）時直接向中央下載，不再連快取（第二個派送的 `package_source` 指向一個會計算請求數的假快取，計數為 0）（Review Focus 2）。
    - 連不上 + fallback false：`pass` 回傳下次檢查時間；嘗試次數為 0、沒有回報失敗；把 `package_source` 換成假快取 200 後再 `pass` → 成功、`source = 'cache'`（Review Focus 1）。
    - 假快取 500 + fallback true：改向中央。
    - 假快取 403、404：回報 failed，嘗試次數 1，沒有向中央下載。
    - 假快取 Corrupt + fallback true：改向中央成功；fallback false：回報 failed（大小或 SHA-256 不符）。
    - 沒有 `package_source`：向中央下載，`source = 'central'`。
  - Agent 報到的接線：建立據點 `10.0.0.0/8`、直接在資料庫插入 active 快取並推進 `branch_state.generation`、`invalidate`；`Fake` 的心跳 IP 設為 `10.1.1.1`，`run_cycle` 後 `Work.package_source` 有值且 url 正確。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --test e2e deploy`，預期新測試 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-agent` 與 `cargo test -p loadsim`，預期 PASS。
- [ ] **Step 5：** Commit「分點快取：Agent 依來源下載與改向中央」。

---

### Task 2：Agent 透過真實快取下載（e2e）

**Files:**
- Modify：`crates/agent/Cargo.toml`（dev-dependency `endpoint-cache = { path = "../cache" }`）
- Test：`crates/agent/tests/cache_e2e.rs`

**內容：** 真實中央 + 真實 `endpoint-cache`（同一行程）+ 真實派送 worker：
- 快取：`endpoint_cache::run::enroll`（url `https://127.0.0.1:<port>`，先綁定監聽埠取得埠號）→ `caches::approve` → `Cache::start_with` → `server::serve`。
- 據點 `127.0.0.0/8`、fallback true；`Fake` 心跳 IP `127.0.0.5`。

- [ ] **Step 1：寫失敗測試**
  - Agent `run_cycle` → worker `pass`：安裝成功、`deployment_status.source = 'cache'`、快取的 `central.downloads_started() == 1`；第二台裝置也成功，下載次數仍是 1。
  - 停止快取（abort serve task）後第三台裝置：改向中央成功、`source = 'central'`。
  - 未被指派的裝置直接向快取要這個套件（用 Agent 的 `ServerClient` 連快取網址）→ `DownloadError::Forbidden`。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-agent --test cache_e2e`，預期 FAIL（Task 1 已完成時也可能直接 PASS；那時至少確認測試會在快取回錯誤內容時失敗：暫時把 `source` 斷言改成 `central` 看它失敗，再改回）。
- [ ] **Step 3：** 視需要修正。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-agent`，預期 PASS。
- [ ] **Step 5：** Commit「分點快取：Agent 與快取的端對端測試」。

---

### Task 3：網頁 `/sites`、裝置頁的據點與快取

**Files:**
- Create：`crates/server/migrations/0017_try_inet.sql`、`crates/server/src/web/sites.rs`、`templates/sites.html`、`templates/site_form.html`
- Modify：`crates/server/src/web/mod.rs`（路由）、`templates/base.html`（平台管理員看到「據點」「快取」）、`crates/server/src/web/devices.rs` 與 `templates/device.html`（據點、快取兩列）
- Test：`crates/server/tests/branch_web.rs`

**Migration 0017：**
```sql
-- devices.last_ip 是 Agent 回報的文字：無法解析時回 NULL，不讓查詢出錯
CREATE FUNCTION try_inet(t TEXT) RETURNS INET LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
    RETURN t::inet;
EXCEPTION WHEN others THEN
    RETURN NULL;
END $$;
```

**路由：**
- `GET /sites`：清單（名稱、網段、快取名稱與狀態、改向中央、頻寬、磁碟、對應裝置數）。
  - 裝置數：`count(DISTINCT d.id)`，條件 `d.status = 'active' AND try_inet(d.last_ip) <<= ANY(s.cidrs)`；頁面註明「依最後回報的 IP；網段重疊時兩個據點都會計入」。
- `GET /sites/new`、`POST /sites`：表單欄位 name、cidrs（多行文字，每行一個網段）、fallback（checkbox）、bandwidth（空白＝不限）、disk_gb。
- `GET /sites/{id}/edit`、`POST /sites/{id}`：編輯。
- `POST /sites/{id}/delete`：刪除後回清單。
- 錯誤：`sites::*` 的 Err → 422 重新顯示表單並保留輸入；數字欄位解析失敗同樣 422。不存在的 id → 404。
- 裝置頁基本資料加一列：「據點」顯示依 `last_ip` 對應的據點（最長前綴、相同時 id 小的；用 `try_inet`），「快取」顯示該據點的快取名稱與狀態（`使用中`／`已停用`／`待核准`；沒有快取顯示「無（向中央下載）」）。沒有對應據點時顯示「—」。

- [ ] **Step 1：寫失敗測試**（`tests/branch_web.rs`）
  - 平台管理員：新增據點（兩個網段，一行一個）→ 302 到清單；清單顯示名稱與正規化後的網段。
  - 重複網段 → 422，頁面含另一個據點的名稱，且保留輸入的名稱；`10.0.0.0/33` → 422；頻寬 `abc` → 422。
  - 編輯、刪除；刪除被快取使用的據點後，快取仍在（`site_id` 為 NULL）。
  - 裝置數：一台裝置 `last_ip = '10.1.2.3'` 計入 `10.1.0.0/16`；`last_ip` 為 `''`、`'fe80::1%12'`、`'garbage'` 的裝置不讓頁面出錯（Review Focus 4）。
  - 群組管理員與檢視者：`GET /sites`、`GET /sites/new`、`POST /sites`、`POST /sites/{id}/delete` 都是 403（Review Focus 5）；沒有 CSRF 的 POST 被拒。
  - 裝置頁：有據點、快取使用中 → 顯示據點名稱與「使用中」；快取停用 → 顯示「已停用」（Review Focus 3）；沒有對應 → 「—」。
  - 稽核：`site_create`、`site_update`、`site_delete` 各一筆，actor 是登入的帳號。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test branch_web`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同上指令，預期 PASS；`cargo test -p endpoint-server --test web` 仍 PASS。
- [ ] **Step 5：** Commit「分點快取：據點網頁與裝置頁」。

---

### Task 4：網頁 `/caches`、快取註冊金鑰、派送來源

**Files:**
- Create：`crates/server/src/web/caches.rs`、`templates/caches.html`
- Modify：`crates/server/src/web/mod.rs`、`crates/server/src/web/tokens.rs`（只列裝置金鑰；作廢時只接受裝置金鑰）、`crates/server/src/web/deployments.rs` 與 `templates/deployment_detail.html`（來源欄）
- Test：`crates/server/tests/branch_web.rs`

**路由：**
- `GET /caches`：
  - 快取清單：名稱、據點、網址、狀態、最後回報（`fmt_time`，從未回報顯示「—」）、版本、磁碟用量（GB，一位小數）、預先下載進度「已存 N／應有 M」（N = `cache_packages` 中屬於應有清單的筆數；M = 未停止派送用到的套件數）。
  - 待核准：據點下拉選單（只列沒有快取的據點）＋「核准」、「拒絕」。
  - 使用中／停用：「停用」或「啟用」、改據點（下拉選單含「不指定」）。
  - 每台都有「刪除」（確認對話框文字：刪除後快取需要重新註冊）。
  - 快取註冊金鑰：建立表單（名稱、可使用次數、有效天數）與清單（作廢按鈕）；建立後在頁面上方顯示一次明碼與 `endpoint-cache enroll` 的指令範例（`--server` 用 `agent_public_url`）。
- `POST /caches/{id}/approve`（欄位 site）、`/reject`、`/disable`、`/enable`、`/site`（欄位 site，空白＝不指定）、`/delete`。
- `POST /caches/tokens`、`POST /caches/tokens/{id}/revoke`：`kind = 'cache'`、`group_id = NULL`；稽核 `token_create`／`token_revoke`（detail 含 `"kind": "cache"`）。
- 動作錯誤（例如據點已有快取）→ 409 顯示錯誤文字（沿用 `action_error`）；不存在 → 404。
- `/tokens`：查詢加 `t.kind = 'device'`；作廢路由先確認是裝置金鑰，否則 404。
- 派送詳情的裝置表加「來源」欄：`cache` → 快取、`central` → 中央、NULL → —。

- [ ] **Step 1：寫失敗測試**（`tests/branch_web.rs`）
  - 建立快取金鑰：頁面顯示明碼一次；資料庫 `kind = 'cache'`；`/tokens` 看不到這把金鑰；`POST /tokens/{id}/revoke` 這把金鑰 → 404；`POST /caches/tokens/{id}/revoke` → 作廢成功。
  - 用這把金鑰呼叫 `/v1/cache/enroll` 建立待核准快取 → `/caches` 顯示「待核准」與只含空據點的下拉選單；核准（選據點）→ 狀態「使用中」；稽核 `cache_approve` 的 actor 是登入帳號。
  - 核准到已有快取的據點 → 409；拒絕使用中的快取 → 409。
  - 停用 → 「已停用」，報到不再下發（呼叫 `/v1/checkin` 驗證）；啟用 → 「使用中」。
  - 改據點為「不指定」→ 清單的據點欄為「—」。
  - 進度：一個未停止派送的套件、`cache_packages` 有這筆 → 「已存 1／應有 1」。
  - 刪除 → 清單沒有這台。
  - 群組管理員與檢視者：`/caches` 的 GET 與每個 POST 都是 403（Review Focus 5）；沒有 CSRF 的 POST 被拒。
  - 派送詳情：`deployment_status.source = 'cache'` 的裝置列顯示「快取」，NULL 顯示「—」。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test branch_web`，預期新測試 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-server`，預期 PASS。
- [ ] **Step 5：** Commit「分點快取：快取網頁、金鑰與派送來源」。

---

### Task 5：loadsim、負載測試與文件

**Files:**
- Modify：`tools/loadsim/src/lib.rs`、`tools/loadsim/src/main.rs`、`tools/loadsim/tests/sim.rs`
- Create：`tools/loadsim/cache_setup.sql`
- Modify：`docs/loadtest.md`、`README.md`、`deploy/endpoint-cache.service`（檔頭步驟）

**loadsim：**
- `ip_addresses` 改成可設定：`Target` 新增 `ip: String`（預設 `10.0.0.1`，`--ip` 指定）。
- 新函式 `pub async fn cache_deploy(t: &Target, devices: &[Device], concurrency: usize) -> CacheReport`：
  - 每台：報到 → 必須有 `package_source`（沒有時計入 `no_source`）→ 用 `package_source.url` 建 `ServerClient`（裝置身分）→ `verify_package`；`Retry` 依 Retry-After 重試（計入 `busy`）；`Unreachable` 計入 `unreachable` 後改向中央（計入 `fallback`）→ 回報第一個指派 `source` 為實際來源。
  - `CacheReport { report: Report, busy: usize, unreachable: usize, fallback: usize, no_source: usize }`。
- 子命令 `cache-deploy --server URL --root root.pem --devices devices.json [--count N] [--concurrency 300] [--ip 10.0.0.1]`：只用前 N 台（預設 5,000；`--devices` 已是裝置清單檔，所以台數用 `--count`）；失敗條件：errors > 0、no_source > 0。
- `cache_setup.sql`：建立據點 `10.0.0.0/8`（fallback true）並推進 `branch_state`（快取用 `endpoint-cache enroll` 註冊後在網頁或 SQL 核准）。
- `tests/sim.rs`：用真實中央 + 真實快取跑 `cache_deploy` 3 台：全部成功、`busy == 0`、`no_source == 0`。

**負載測試（照 `docs/loadtest.md` 的重跑方法，結果寫進新的「分點快取（第七期）」段落）：**
- 條件：同一台電腦跑中央、一台快取（`endpoint-cache run`）、loadsim；30,000 台模擬裝置；10 MB 套件。
- 量測：
  1. `loadsim cache-deploy --count 5000 --concurrency 300`：全部成功；快取記錄的「package downloaded from central」只有 1 筆；除了 503 之外沒有 5xx。
  2. 同時在另一個視窗跑 `loadsim heartbeat --rate 500 --secs 60`：報到 p99（標準 < 100ms）。
  3. 停止快取後再跑 `cache-deploy --count 500`：全部改向中央成功（`fallback == 500`）。
  4. 據點改為不允許改向中央、快取停止：`cache-deploy --count 100` 全部回報 `unreachable`、沒有回報失敗；重新啟動快取後再跑一次全部成功。
  5. 未被指派與撤銷：已由 Task 2 的 e2e 與計畫 22 的整合測試涵蓋，文件註明。
- 未達標照實記錄，不調整目標。

**README：** 新增「分點快取」章節：
- 架構一段話；防火牆：端點 → 快取 TCP 8443（可設定）、快取 → 中央的 Agent 埠。
- Windows：複製 `endpoint-cache.exe`、`enroll` 範例（以系統管理員執行）、`sc.exe create EndpointManagerCache binPath= "... service" start= auto`、`sc.exe failure ... actions= restart/60000`、`sc.exe failureflag EndpointManagerCache 1`。
- Linux systemd：`useradd --system endpoint-cache`、`install -d -o endpoint-cache -m 0700 /var/lib/endpoint-cache`、以該使用者執行 `enroll`、安裝 unit；自訂儲存目錄要加 `ReadWritePaths=`。
- Docker：`docker build -f deploy/cache.Dockerfile`；具名 volume；綁定主機目錄時先 `chown 65532:65532`；`enroll` 用 `docker run --rm -v ... enroll ...`。
- 管理網頁：建立快取金鑰 → 註冊 → 核准並指定據點；據點網段以 Agent 回報的本機 IP 判斷。
- `deploy/endpoint-cache.service` 檔頭改成上述正確步驟。

- [ ] **Step 1：寫失敗測試**：`tests/sim.rs` 的 `cache_deploy` 測試，執行 `cargo test -p loadsim`，預期 FAIL。
- [ ] **Step 2：** 實作 loadsim，執行 `cargo test -p loadsim`，預期 PASS。
- [ ] **Step 3：** 跑負載測試（release 版），把結果寫進 `docs/loadtest.md`。
- [ ] **Step 4：** 寫 README 與 systemd 檔頭。
- [ ] **Step 5：** `cargo test --workspace -j 4`、clippy、fmt 全部 PASS；Commit「分點快取：負載測試與部署文件」。
