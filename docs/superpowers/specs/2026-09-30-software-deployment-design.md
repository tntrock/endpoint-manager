# 第四期：軟體派送 設計

日期：2026-09-30。狀態：已與使用者確認範圍與方案 A（期望狀態隨報到下發）。使用者授權在不在場時依本規格直接實作。

## 1. 範圍

**做：**
- 平台管理員上傳 MSI／EXE 套件，設定「這些群組要安裝 X」或「必須移除 Y」（期望狀態）。
- 新加入範圍的電腦自動補裝。
- 分階段發布：先試點群組，管理員確認後擴大到全部。
- 失敗率超過門檻時自動暫停。

**不做（之後的子專案）：** 分點快取、Windows Update 控制、PowerShell 腳本、維護時段、使用者通知、自動重新開機。

**權限：**
- 套件與派送只有平台管理員能建立或修改。
- 群組管理員只能看自己範圍內裝置的派送狀態。

### 1.1 成功標準

條件：i5-12400、三萬台模擬裝置、10 個進行中的派送。
- 報到 500 次／秒時，p99 < 100ms（與前幾期相同）。
- 三萬台各下載一個 10MB 套件並回報：
  - 超過同時下載上限的請求收到 503，不能有其他 5xx。
  - 最後全部回報成功，沒有遺失。
  - 同時記錄總耗時。
- 未達標時照實記錄，不調整目標。

## 2. 資料模型（migration 0010）

### `packages`

| 欄位 | 說明 |
|---|---|
| `id` | 主鍵 |
| `name`, `version` | 顯示用；MSI 上傳時自動填入 ProductName／ProductVersion |
| `kind` | `msi` 或 `exe` |
| `file_name` | 原始檔名（只用於顯示與下載時的副檔名） |
| `size`, `sha256` | 檔案內容；以 sha256 命名存在 `EM_PACKAGE_DIR`（預設 `packages`），同內容只存一份 |
| `msi_product_code` | MSI 移除用，上傳時讀出 |
| `install_args` | MSI：附加的屬性（例如 `ALLUSERS=1`）；EXE：靜默安裝參數 |
| `uninstall_args` | 只用於 EXE：以套件本身執行移除時的參數；空白表示不能用來移除 |
| `success_codes` | 額外視為成功的結束碼（`0` 永遠成功；`3010`、`1641` 為成功但需要重新開機） |
| `detect_name`, `detect_publisher`, `detect_min_version` | 偵測規則：沿用合規引擎的萬用字元與版本比較；名稱必填 |
| `created_by`, `created_at`, `updated_at` | |

- 被派送引用的套件不能刪除。
- 套件刪除後，若沒有其他套件使用同一個 sha256，就刪除檔案。
- 單檔上限 2 GiB。

### `deployments`

| 欄位 | 說明 |
|---|---|
| `id`, `name` | |
| `package_id` | |
| `action` | `install` 或 `uninstall` |
| `stage` | `pilot`、`all`、`paused`、`stopped` |
| `paused_from` | 暫停前的階段，「繼續」時還原 |
| `pilot_group_id` | 試點群組。沒有設定時建立後直接是 `all` |
| `max_failure_pct`, `min_samples` | 自動暫停門檻，預設 10%、20 台 |
| `revision` | 按「重試失敗」時加一，Agent 看到新 revision 會重設嘗試次數 |
| `created_by`, `created_at`, `updated_at` | |

範圍用 `deployment_groups(deployment_id, group_id, mode)`，mode 為 include 或 exclude，規則與合規規則相同：都不選代表全部裝置，排除優先。

### `deployment_status`

| 欄位 | 說明 |
|---|---|
| `(deployment_id, device_id)` | 主鍵 |
| `status` | `compliant`（本來就符合）、`succeeded`、`reboot_required`、`failed` |
| `exit_code`, `message` | message 最多 1000 字 |
| `attempts`, `revision` | |
| `updated_at` | |

沒有列的範圍內裝置算「等待中」。

### 其他

- `deploy_state(generation)`：任何派送或套件異動都加一，報到端的快取依它判斷是否過期。
- 所有管理動作都寫稽核記錄。

## 3. 協定

- **`CheckinResponse.deployments: Vec<Assignment>`**（serde 預設空）與 **`deployments_hash: Option<String>`**。
  - 沒有 `deployments_hash` 代表伺服器不支援派送，Agent 不做任何派送。
- **`Assignment`** 包含：
  - `deployment_id`、`revision`、`action`。
  - `package`：`id`、`kind`、`sha256`、`size`、`file_name`、`install_args`、`uninstall_args`、`msi_product_code`、`success_codes`、`detect`（name／publisher／min_version）。
- **指派條件：**
  - 裝置是 active 且在派送範圍內。
  - stage 是 `all`，或 stage 是 `pilot` 且裝置屬於試點群組。
  - `paused` 與 `stopped` 的派送不下發；已經在執行的安裝會跑完並回報。
- **`GET /v1/packages/{id}/content`**：
  - 需要 mTLS，而且這台裝置目前必須被指派到使用這個套件的派送，否則回 404。
  - 同時下載數受 `EM_DOWNLOAD_CONCURRENCY` 限制（預設 50）；超過時回 503，並附 `Retry-After: 60`。
  - 以串流方式回傳檔案。
- **`POST /v1/deployments/{id}/result`**，內容為 `{ revision, status, exit_code, message, attempts }`：
  - 只接受目前指派給這台裝置的派送，否則回 404。
  - 以 upsert 寫入 `deployment_status`。
  - 回報失敗時檢查自動暫停。
- **報到效能：**
  - 進行中的派送以快取保存，依 generation 每 5 秒最多確認一次，做法同規則快取。
  - 每次報到只在記憶體中依裝置群組篩選，不額外查資料庫。

## 4. Agent 流程

- **何時評估：** 每次報到後，若有指派，在背景工作中依 `deployment_id` 順序逐一處理，一次只跑一個安裝，報到不受影響。
  - 清單雜湊沒變、也沒有待重試的項目時，最多每 15 分鐘評估一次。
- **偵測：** 當下讀取本機軟體清單，沿用盤點的登錄檔讀法。
  - 萬用字元與版本比較改放在 `protocol` crate，伺服器和 Agent 共用同一份實作。
  - 已安裝的判斷：名稱與發行者相符，且版本 ≥ 最低版本（有設定時）。
- **安裝：**
  - 已安裝 → 回報 `compliant`。每個（派送, revision）只回報一次，記在本機狀態檔。
  - 未安裝 →
    1. 下載到 `資料目錄\packages\<sha256>.<副檔名>`（目錄已由 secdir 限制為 SYSTEM／Administrators），邊寫邊算 SHA-256；大小或雜湊不符就刪除並回報失敗。
    2. 執行安裝：
       - MSI：`msiexec.exe /i "<檔案>" /qn /norestart /L*v "<log>" <install_args>`
       - EXE：`"<檔案>" <install_args>`
    3. 逾時 60 分鐘就結束程序，算失敗。
    4. 刪除安裝檔。
    5. 成功後再偵測一次；偵測不到就算失敗（「安裝程式回報成功，但偵測不到軟體」），避免同一台一直重裝。
- **移除：**
  - 偵測不到 → 回報 `compliant`。
  - 偵測到 →
    - MSI：`msiexec.exe /x <ProductCode> /qn /norestart`
    - EXE：先下載，再用 `uninstall_args` 執行。
    - 完成後再偵測一次，還偵測得到就算失敗。
- **結束碼：**
  - `0` 與 `success_codes` → `succeeded`。
  - `3010`、`1641` → `reboot_required`。
  - `1618`（另一個安裝進行中）→ 不算嘗試，下次再試。
  - 其他 → `failed`，訊息附上結束碼。
- **重試：**
  - 失敗後 24 小時再試，同一 revision 最多 3 次。
  - 管理員按「重試失敗」讓 revision 加一，嘗試次數重新計算。
  - 下載遇到 503 或網路錯誤時不算嘗試，依 `Retry-After` 稍後再試。
- **安全：**
  - 只執行雜湊符合的檔案；檔案名稱由 Agent 自行決定，不採用伺服器給的路徑。
  - 參數由伺服器驗證，不能含控制字元，最多 1000 字。
  - 不做 Authenticode 檢查。信任來源是經 mTLS 取得的雜湊；伺服器被入侵的風險在第一期已接受，因為伺服器本來就能下發設定。

## 5. 發布與自動暫停

- **建立派送：** 有設試點群組時 stage 為 `pilot`，否則為 `all`。
- **狀態切換：**
  - 「擴大到全部」：`pilot` → `all`。
  - 「暫停」：記錄 `paused_from`。
  - 「繼續」：還原到 `paused_from`。
  - 「停止」：終態，之後可以刪除。
- **自動暫停：**
  - 收到失敗回報時，統計目前 revision 下有嘗試過的裝置（`succeeded`、`reboot_required`、`failed`；`compliant` 不算）。
  - 樣本數 ≥ `min_samples`，且失敗率 > `max_failure_pct` 時，改為 `paused`。
  - 寫入 `deployment_auto_pause` 稽核記錄（操作者為 system）。
  - 試點階段也適用。

## 6. 管理網頁

| 頁面 | 內容 |
|---|---|
| **套件**（`/packages`，平台管理員） | 清單。上傳頁用靜態 `upload.js` 以 PUT 串流原始檔案，符合 CSP、不需 multipart。上傳完成後進入編輯頁，MSI 會預先填入名稱、版本、ProductCode 與偵測規則。 |
| **派送**（`/deployments`） | 清單顯示各狀態台數。所有管理員都能看，群組管理員只計算範圍內的裝置。 |
| **派送詳情** | 各狀態台數、失敗原因前幾名、依狀態篩選的裝置清單（分頁）；平台管理員可以擴大、暫停、繼續、停止、重試失敗、刪除（僅限已停止的）。 |
| **裝置頁「派送」分頁** | 這台的各派送狀態。 |
| 導覽列 | 新增「派送」。 |

## 7. 錯誤處理

- 上傳中斷時刪除暫存檔；檔案超過 2 GiB 回 413。
- 套件檔案遺失（被人手動刪除）時，下載回 404；Agent 回報失敗，訊息寫「伺服器上找不到套件檔案」。
- 伺服器降版時，舊伺服器的報到回應沒有 `deployments_hash`，Agent 停止派送；已在進行中的安裝會跑完，但不回報。

## 8. 測試

- **伺服器：**
  - 指派條件：範圍、試點、暫停。
  - 下載權限與同時下載上限。
  - 回報的 upsert 與自動暫停。
  - 各狀態切換。
  - 網頁權限與上傳。
- **Agent：**
  - 偵測與結束碼對應。
  - 重試策略與狀態檔。
  - 下載時的雜湊驗證。
  - 在 Windows 上以 `cmd.exe /c exit N` 驗證 EXE 執行、逾時與結束碼。
  - 對真實伺服器做端對端測試：下載、執行、回報。
- **負載測試：** 新增 `loadsim deploy` 指令：報到取得指派、下載、回報。

## 9. 實作分期

- **計畫 12**：共用比對程式搬到 `protocol` crate；伺服器的資料表、套件儲存與上傳 API、派送模型、指派與快取、下載與回報 API、發布狀態與自動暫停。
- **計畫 13**：Agent 端的偵測、下載驗證、執行、重試狀態、回報。
- **計畫 14**：管理網頁、`loadsim deploy` 與負載測試、文件。
