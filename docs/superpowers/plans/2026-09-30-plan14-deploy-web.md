# 計畫 14：軟體派送（網頁、負載測試、文件）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 平台管理員能在網頁上傳套件、建立與控制派送；所有管理員能看自己範圍內的派送狀態；以三萬台驗證報到與下載；補齊文件。

**Architecture:** `web/packages.rs`、`web/deployments.rs`、`static/upload.js`；裝置頁新增「派送」分頁；`loadsim deploy`。

**Spec:** `docs/superpowers/specs/2026-09-30-software-deployment-design.md` §1.1、§6、§7

## Global Constraints
- CSP `default-src 'self'`：只能用外部 JS 檔（`/static/upload.js`），不能 inline。
- 套件、派送的建立與控制只限平台管理員（其他人 403）；派送清單與詳情所有管理員可看，但群組管理員的台數與裝置清單只含範圍內的裝置；範圍外裝置的分頁回 404。
- 上傳：PUT 原始檔案串流（不經表單解析），CSRF 以 `X-CSRF-Token` 標頭驗證；只接受 `.msi`／`.exe`；MSI 必須能讀出 ProductCode，否則 400；超過 2 GiB 回 413。上傳成功即建立套件（名稱、版本、偵測規則以 MSI 資訊或檔名預填），再進入編輯頁補參數。
- 使用者可見文字用繁體中文。
- 負載測試未達標時照實記錄。

## Review Focus
1. 群組管理員看得到派送清單，但台數只算範圍內的裝置；看不到範圍外裝置的名稱。
2. 上傳路由不受 5 MB body 限制，但自己以 2 GiB 上限；非平台管理員、CSRF 錯誤、副檔名錯誤都不能留下檔案。
3. 派送詳情的「等待中」台數＝範圍內使用中裝置減去已有狀態的裝置（試點階段只算試點群組）。
4. 自動暫停後頁面提示「建議先重試失敗再繼續」。
5. `loadsim deploy` 驗證下載內容的雜湊，並在 503 時依 Retry-After 重試。

---

### Task 1：套件頁面與上傳
- 路由：`GET /packages`（清單）、`GET /packages/upload`（上傳頁）、`PUT /packages/upload`（原始檔案；`X-File-Name` 為 URL 編碼的檔名）、`GET /packages/{id}`（編輯）、`POST /packages/{id}`（更新）、`POST /packages/{id}/delete`。
- `static/upload.js`：以 XMLHttpRequest 送出（顯示進度），成功後導向 `/packages/{id}`。
- 測試（`tests/deploy_web.rs`）：平台管理員上傳 MSI（`installer::template_with`）→ 預填名稱／版本／偵測；上傳 EXE；群組管理員 403；CSRF 錯誤 403；`.zip` 400；非 MSI 內容的 .msi 400；以上錯誤都不留檔；編輯、刪除（被引用時顯示錯誤）。

### Task 2：派送頁面與裝置分頁
- 路由：`GET /deployments`、`GET /deployments/new`、`POST /deployments`、`GET /deployments/{id}`（`?status=pending|compliant|succeeded|reboot_required|failed&page=`）、`POST /deployments/{id}/{expand|pause|resume|stop|retry|delete}`；裝置分頁 `deployments`；導覽列「派送」。
- 台數 SQL：範圍內使用中裝置（依派送的有效階段、包含／排除、試點；群組管理員再加上自己的群組）；狀態台數 JOIN devices 後同樣限制範圍。
- 測試：建立派送、各動作與權限、群組管理員只看範圍內台數與裝置、等待中計算、裝置分頁（範圍外 404）、自動暫停提示。

### Task 3：負載測試與文件
- `loadsim deploy --devices devices.json [--concurrency 100]`：每台報到 → 下載第一個指派的套件（驗證雜湊，503 依 Retry-After 重試）→ 對每個指派回報（第一個 succeeded，其餘 compliant）。
- `tools/loadsim/deploy_setup.sql`：以 psql 變數 `sha`、`size` 建立 1 個 10MB 套件與 10 個派送（全部裝置）；套件檔由 loadsim 產生（`loadsim make-package --out file --size-mb 10` 印出 sha 與大小），複製到伺服器的套件目錄。
- 依 §1.1 執行並記錄於 `docs/loadtest.md`；README 新增「軟體派送」一節（上傳、派送、試點、自動暫停、Agent 行為與重試、`EM_PACKAGE_DIR`、`EM_DOWNLOAD_CONCURRENCY`、Docker volume）。
- docker-compose：新增 packages volume 與環境變數。
