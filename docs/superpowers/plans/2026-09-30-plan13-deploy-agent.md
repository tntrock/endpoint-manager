# 計畫 13：軟體派送（Agent）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agent 依報到回應的指派（期望狀態）偵測、下載驗證、以 SYSTEM 執行安裝／移除、回報結果，並有重試上限。

**Architecture:** 新模組 `crates/agent/src/deploy/`：
- `logic.rs`（純函式：偵測、決策、指令組成、結束碼對應）
- `state.rs`（`deploy.json` 狀態檔）
- `worker.rs`（背景工作：一次一個、下載、執行、回報）
- 主迴圈每次報到後把「指派＋連線資訊」送進 `watch` channel；伺服器沒有 `deployments_hash` 時送 `None`，worker 停止接新工作。

**Tech Stack:** Rust、tokio（workspace 加 `process` feature）、reqwest（`chunk()` 串流，不加 feature）、sha2（workspace 已有）。

**Spec:** `docs/superpowers/specs/2026-09-30-software-deployment-design.md` §3、§4

## Global Constraints
- 只執行 SHA-256 與大小都相符的檔案；檔名由 Agent 決定：`<資料目錄>\packages\<sha256>.msi|.exe`。
- msiexec 用 `%SystemRoot%\System32\msiexec.exe` 完整路徑，避免 PATH 劫持。
- 參數在 Windows 以 `raw_arg` 原樣傳入（管理員填的引號不被重新跳脫）。
- 逾時 60 分鐘；3010／1641 → reboot_required；1618 → 不算嘗試；失敗 24 小時後重試，同一 revision 最多 3 次。
- 503／網路錯誤不算嘗試；下載 404（檔案不在或已不指派）回報失敗。
- 所有新行為都有測試；Windows 專屬的執行測試以 `cfg(windows)`。

## Review Focus
1. 雜湊或大小不符時一定不執行，且刪除檔案。
2. 同一 revision 失敗不超過 3 次；已回報的狀態不重複回報；revision 改變時重設。
3. 伺服器降版（沒有 deployments_hash）時停止派送。
4. 安裝後偵測不到算失敗（避免無限重裝）。
5. worker 不阻塞報到迴圈；服務停止時能結束。

---

### Task 1：決策與指令（純函式）
- `deploy/logic.rs`：
  - `is_installed(detect: &Detect, items: &[SoftwareItem]) -> bool`（`protocol::matcher::Glob`、`cmp_version`）
  - `enum Plan { Nothing, ReportCompliant, Execute, Wait(DateTime<Utc>) }`；`decide(a: &Assignment, installed: bool, e: &Entry, now) -> Plan`
  - `enum Outcome { Status(DeployStatus), Busy }`；`outcome(code: i32, spec: &PackageSpec) -> Outcome`
  - `struct Cmd { program: PathBuf, args: String }`；`install_cmd(spec, file, log) -> Cmd`、`uninstall_cmd(spec, file) -> Option<Cmd>`
- `deploy/state.rs`：`Entry { revision, attempts, last_attempt: Option<DateTime>, last_failed: bool, reported: Option<DeployStatus> }`、`DeployState { entries: BTreeMap<i64, Entry> }`、`load(dir)`／`save(dir)`（壞檔當空的，記錄一次錯誤）、`entry_for(a)`（revision 不同時重設）、`prune(active_ids)`。
- 測試：偵測（名稱／發行者／版本）、決策表（已符合且已回報 → Nothing；未回報 → ReportCompliant；失敗 < 24h → Wait；≥ 3 次 → Nothing；revision 變更重設）、結束碼、指令字串。

### Task 2：下載與回報的 client 方法
- `ServerClient::download(&self, pkg: &PackageSpec, dest: &Path) -> Result<(), DownloadError>`：`/v1/packages/{id}/content`、每次請求逾時 30 分鐘、`chunk()` 寫入暫存檔並算雜湊、大小超過 `pkg.size` 立即中止；不符 → 刪檔 `DownloadError::Mismatch`；404 → `NotFound`；503／網路 → `Retry(Option<Duration>)`。
- `ServerClient::report(&self, deployment_id, &DeployResult) -> Result<(), ClientError>`。
- 測試：e2e（真實伺服器）下載內容與雜湊、雜湊不符（改資料庫的 sha256）→ Mismatch 且不留檔、未指派 → NotFound、回報成功寫入 `deployment_status`。

### Task 3：worker 與主迴圈接線
- `deploy/worker.rs`：`pub struct Work { assignments, server_url, root_pem, identity_pem }`；`run_worker(dir, collector, rx: watch::Receiver<Option<Work>>, shutdown, runner)`：清單變動或每 15 分鐘評估一次；逐一處理；`Runner` trait（真實實作用 `tokio::process`，`kill_on_drop` 與逾時）。
- `Agent`：新增 `deploy_tx: Option<watch::Sender<Option<Work>>>`（`with_deploy(tx)`）；報到成功後依 `deployments_hash` 送 `Some(Work)` 或 `None`。
- `run_agent`／服務：啟動 worker（Windows 服務與 `run` 模式都啟用）。
- 測試：
  - 單元（假 Runner、假 collector）：安裝成功 → 回報 succeeded；成功但偵測不到 → failed；1618 → 不計次；失敗 3 次後停止；移除流程。
  - Windows e2e：真實伺服器 + EXE 套件（`cmd.exe` 的複本，參數 `/c exit 0`）；假 collector 在執行後回報已安裝 → deployment_status = succeeded。
