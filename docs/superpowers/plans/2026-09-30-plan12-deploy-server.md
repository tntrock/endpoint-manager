# 計畫 12：軟體派送（伺服器）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 伺服器端的套件儲存、派送模型、報到指派、下載與回報 API、發布狀態與自動暫停。網頁在計畫 14，Agent 在計畫 13。

**Architecture:** 新模組 `crates/server/src/deploy/`：`store.rs`（套件檔案與中繼資料）、`admin.rs`（套件與派送的 CRUD、狀態切換、稽核）、`assign.rs`（快取與指派計算）、`api.rs`（Agent 端的下載與回報）。比對程式 `Glob`／`cmp_version` 從 `compliance::matcher` 搬到 `protocol::matcher`，兩端共用。

**Tech Stack:** Rust、axum、sqlx、msi crate；不加新 crate，只在 workspace 的 tokio 加上 `fs`、`io-util` feature。

**Spec:** `docs/superpowers/specs/2026-09-30-software-deployment-design.md`

## Global Constraints
- 使用者可見文字用繁體中文；程式註解用繁體中文，風格同既有程式碼。
- 協定新欄位一律 `#[serde(default)]`，舊 Agent／舊伺服器互相相容。
- 單檔上限 2 GiB（`MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024`）。參數字串最多 1000 字、不能含控制字元。
- 所有管理動作寫稽核記錄。
- 測試：`cargo test -p endpoint-server`、`cargo test -p protocol`，最後 clippy 與 fmt。

## Review Focus
1. 未被指派的裝置不能下載套件，也不能回報結果（回 404）。
2. 暫停或停止的派送不會出現在報到回應裡；試點階段只下發給試點群組。
3. 自動暫停只看目前 revision、有實際嘗試過的裝置（不含 compliant），樣本數不足時不暫停。
4. 被引用的套件不能刪除；刪除套件時只有在沒有其他套件共用同一檔案時才刪檔。
5. 同時下載超過上限時回 503 與 `Retry-After`，許可在串流結束或中斷時都會歸還。

---

### Task 1：比對程式搬到 protocol
- Move：`crates/server/src/compliance/matcher.rs` → `crates/protocol/src/matcher.rs`（`pub mod matcher;`），伺服器改為 `pub use protocol::matcher;`（保持 `crate::compliance::matcher::*` 路徑可用）。
- 既有 matcher 單元測試跟著搬。
- Run：`cargo test -p protocol matcher`、`cargo test -p endpoint-server` → PASS。

### Task 2：協定型別
- `protocol`：
  - `DeployAction { Install, Uninstall }`、`PackageKind { Msi, Exe }`（serde snake_case）
  - `Detect { name, publisher: Option<String>, min_version: Option<String> }`
  - `PackageSpec { id: i64, kind, sha256, size: u64, file_name, install_args, uninstall_args, msi_product_code: Option<String>, success_codes: Vec<i32>, detect }`
  - `Assignment { deployment_id: i64, revision: i32, action, package: PackageSpec }`
  - `DeployStatus { Compliant, Succeeded, RebootRequired, Failed }`
  - `DeployResult { revision: i32, status, exit_code: Option<i32>, message: String, attempts: i32 }`，`validate()`：message ≤ 1000 字元、attempts 0–100。
  - `CheckinResponse.deployments: Vec<Assignment>`（`#[serde(default)]`）、`deployments_hash: Option<String>`（`#[serde(default, skip_serializing_if = "Option::is_none")]`）
  - `pub fn assignments_hash(a: &[Assignment]) -> String`（SHA-256 of canonical JSON，依 deployment_id 排序）
- 測試：舊格式（沒有新欄位）的回應能解析；hash 與順序無關；`DeployResult::validate` 邊界。
- 修補 `CheckinResponse` 的所有建構處（server checkin、agent 測試假伺服器）。

### Task 3：資料表與套件儲存、管理 API
- migration `0010_deploy.sql`：`packages`、`deployments`、`deployment_groups`、`deployment_status`、`deploy_state`（見規格 §2；CHECK 限制 kind／action／stage／status；`deployment_status` 以 `(deployment_id, device_id)` 為主鍵，外鍵 ON DELETE CASCADE；`deployments.package_id` 外鍵 ON DELETE RESTRICT）。
- `deploy::store`：
  - `package_dir()`：`EM_PACKAGE_DIR`（`Config.package_dir`，預設 `packages`）。
  - `save_upload(dir, stream) -> (sha256, size)`：寫暫存檔、邊寫邊算雜湊、超過上限回錯誤並刪暫存檔，完成後 rename 成 `<sha256>`（已存在就刪暫存檔）。
  - `msi_info(path) -> Option<MsiInfo { name, version, product_code, manufacturer }>`（讀 Property 表）。
- `deploy::admin`：
  - `PackageInput`（name、version、kind、install_args、uninstall_args、success_codes、detect_*）與 `validate`。
  - `create_package(pool, sha256, size, file_name, &PackageInput, msi_product_code, actor)`、`update_package`、`delete_package(pool, dir, id, actor)`（被引用回錯誤「套件仍被派送使用」）。
  - `DeploymentInput`（name、package_id、action、include、exclude、pilot_group_id、max_failure_pct 1–100、min_samples 1–10000）；`create_deployment`（有試點 → pilot，否則 all；移除動作時 EXE 套件必須有 uninstall_args，MSI 必須有 product code）。
  - `set_stage(pool, id, Transition::{Expand, Pause, Resume, Stop}, actor)`，不合法的切換回錯誤；`retry_failed`（revision + 1）；`delete_deployment`（只限 stopped）。
  - 每個異動 bump `deploy_state.generation` 並寫稽核。
- 測試（`tests/deploy.rs`）：儲存與去重、超過上限、MSI 資訊（用 repo 內 `crates/server/tests/data/*.msi`，若無則以 `installer` 測試用的範本 MSI；找不到就在 ledger 記 ruling 改測非 MSI 回 None）、狀態切換表、驗證錯誤、被引用的套件不能刪、稽核記錄。

### Task 4：指派快取與報到
- `deploy::assign::DeployCache`（同 `RuleCache`：`get_throttled`，每 5 秒最多查一次 generation）：載入 stage 為 pilot／all 的派送與其套件、範圍群組。
- `fn assignments_for(cache, group_id: Option<i64>) -> Vec<Assignment>`：範圍（include 空＝全部；exclude 優先）＋ stage 條件（pilot 只給試點群組）。
- `checkin`：讀裝置 `group_id`、`status`（非 active 不指派）；回應加上 `deployments` 與 `deployments_hash`。
- 測試：範圍、試點、暫停後消失、擴大後出現、停用裝置不指派、hash 隨內容變動。

### Task 5：下載與回報 API
- `GET /v1/packages/{id}/content`：`AuthedDevice`；裝置目前的指派中有這個 package id 才允許（404）；`tokio::sync::Semaphore`（`EM_DOWNLOAD_CONCURRENCY`，預設 50）`try_acquire_owned` 失敗 → 503 + `Retry-After: 60`；以 `futures_util::stream::unfold` 讀檔串流（64 KiB），許可隨串流 drop 歸還；`Content-Length`；檔案不存在 → 404。
- `POST /v1/deployments/{id}/result`：驗證 `DeployResult`；目前指派中沒有這個派送 → 404；upsert `deployment_status`；狀態為 failed 時在同一交易內檢查自動暫停（`SELECT … FOR UPDATE` 派送列，計算目前 revision 下 succeeded／reboot_required／failed 的數量）。
- 測試：未指派 404、下載內容與雜湊正確、上限 503 與許可歸還、回報 upsert、自動暫停（含樣本不足不暫停、compliant 不計入、舊 revision 不計入）、暫停後的派送回報仍接受（已在執行的安裝）→ 規則：派送為 paused 且裝置原本在範圍內時接受回報。
