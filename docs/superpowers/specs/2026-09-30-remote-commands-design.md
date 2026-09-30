# 第六期：遠端指令 設計

日期：2026-09-30。狀態：以下都已與使用者確認：
- 範圍：固定動作＋核准過的腳本。
- 送達方式：隨報到送達，不做長連線。
- 腳本核准：可以設定，預設雙人。
- 權限：固定動作群組管理員也可以用。
- 方案 A：每台一筆的指令佇列，報到時下發。
- 兩段設計都已確認。

## 1. 範圍

**做：**
- 固定動作：
  - `collect`：重新收集全部盤點。
  - `apply`：立即套用派送與更新原則。
  - `reboot`：重新開機，可以延遲並通知使用者。
  - `shutdown`：關機，可以延遲並通知使用者。
- 腳本：平台管理員上傳 PowerShell 腳本，經過核准後，對單台或整個群組執行，收回結束碼與輸出。

**不做：**
- 長連線、即時互動 Shell。
- 排程或重複執行的指令。
- 腳本參數。
- 檔案傳輸。
- 以登入使用者身分執行。
- 自動化工作流程。

**權限：**
- 固定動作：平台管理員可以對全部裝置執行；群組管理員只能對自己群組的裝置執行；檢視者不行。
- 腳本：上傳、修改、核准、停用、執行都只限平台管理員。
- 群組管理員只看得到自己範圍內裝置的指令與結果。
- 所有建立、取消、核准與設定變更都寫稽核紀錄。

**送達延遲：** 指令在裝置下次報到時送達。預設報到間隔 60 秒。

### 1.1 成功標準

條件：i5-12400、三萬台模擬裝置。
- 對一個 5,000 台的群組下 `collect`：展開（建立 5,000 筆）不超過 5 秒；同時報到 500 次／秒時 p99 < 100ms；結果全部回報，沒有 5xx。
- 沒有待下發的指令時，報到 p99 < 100ms，和前幾期相同。
- 未達標時照實記錄，不調整目標。

## 2. 腳本

資料表 `scripts`：

| 欄位 | 說明 |
|---|---|
| `id`、`name` | 名稱唯一，1–100 字，不能有控制字元 |
| `description` | 最多 1,000 字 |
| `content` | PowerShell 文字，UTF-8，1 位元組–64 KiB，不能有 NUL |
| `sha256` | `content` 的 SHA-256（小寫 hex） |
| `timeout_minutes` | 1–120，預設 30 |
| `status` | `pending`（待核准）／`approved`（已核准）／`disabled`（已停用） |
| `created_by`、`created_at`、`updated_by`、`updated_at` | |
| `approved_by`、`approved_at` | |

**規則：**
- **系統設定 `scripts_require_second_approver`**（預設 true）：
  - **true**：新增或修改內容後狀態是 `pending`，必須由**另一位**平台管理員核准。核准者不能是 `updated_by`（最後修改內容的人）。
  - **false**：新增或修改後直接是 `approved`，`approved_by` 設為修改者本人，稽核紀錄照寫。
- 修改內容或逾時時，重算 sha256，並依上一條決定狀態。只改名稱或說明時，狀態不變。
- 停用後不能再建立新的執行；已建立的指令不受影響，因為它綁定的是當時的內容。可以再「啟用」回 `pending`，或在單人模式下回到 `approved`。
- 被指令引用過的腳本不能刪除，只能停用。

## 3. 指令

**`command_runs`**（一次操作）：
- 欄位：
  - `id`
  - `action`：`collect`、`apply`、`reboot`、`shutdown`、`script`
  - `delay_minutes`：重開機或關機的延遲 0–60，預設 10；其他動作為 NULL
  - `script_id`、`script_sha256`、`script_content`、`script_timeout_minutes`：建立時複製一份，之後修改腳本不影響
  - `target_label`：對象描述，例如「裝置 PC-001」或「群組 台北」
  - `created_by`、`created_at`
  - `expires_at`：預設 7 天，可選 1 小時到 30 天
  - `canceled_at`、`canceled_by`

**`command_targets`**（每台一筆）：
- 欄位：
  - `id`（BIGSERIAL）、`run_id`、`device_id`
  - `status`：`pending`／`sent`／`succeeded`／`failed`／`expired`／`canceled`
  - `exit_code`
  - `output`：最後 64 KiB
  - `sent_at`：第一次送出的時間
  - `finished_at`
- 索引 `(device_id) WHERE status IN ('pending','sent')`，讓報到時的查詢走部分索引。

**建立指令：**
- 對象是單台裝置、或一個群組的所有使用中裝置。群組在同一個交易內以 `INSERT … SELECT` 展開。
- 權限檢查：
  - 群組管理員只能選自己範圍內的裝置或群組，動作不能是 `script`。
  - `script` 的腳本必須是 `approved`。
- 展開後是 0 台時回錯誤「群組內沒有使用中的裝置」。

**取消：**
- 建立者或平台管理員可以取消整次操作。
- 把還是 `pending`／`sent` 的指令標成 `canceled`。已經在執行中的無法中止，之後回報的結果會被忽略。

**過期：** 背景工作每 5 分鐘把 `expires_at < now()` 而且還是 `pending`／`sent` 的指令標成 `expired`。

## 4. 協定

- `CheckinResponse.commands: Vec<Command>`（`#[serde(default)]`）。
- `Command { id: i64 /* target id */, action: CommandAction, delay_minutes: Option<u32>, script: Option<ScriptSpec> }`。
  - `ScriptSpec { sha256, content, timeout_minutes }`。
  - `CommandAction` 未知值解析為 `Unknown`；Agent 對 `Unknown` 回報失敗「不支援的指令」。
- **下發：**
  - 報到時查這台還沒完成、沒過期、沒取消的指令（`pending`／`sent`，而且 run 沒被取消、沒過期），由舊到新最多 10 筆。
  - 同一個交易把 `pending` 改成 `sent`，並記下 `sent_at`。
  - 只下發給使用中的裝置。
- **結果回報：**
  - 端點：`POST /v1/commands/{id}/result`，內容 `CommandResult { status: succeeded|failed, exit_code: Option<i32>, output: String }`。
  - 驗證：`output` 最多 64 KiB，不能有 NUL；超過時回 400，Agent 端要先截斷。
  - 指令不屬於這台裝置時回 404。
  - 指令已經是終結狀態（succeeded／failed／expired／canceled）時回 204，但不覆寫。
  - 伺服器在寫入前移除控制字元，保留 `\n`、`\r` 和 `\t`。

## 5. Agent

- **傳遞**：報到後把 `commands` 交給背景工作，用 `watch`，比照派送。背景工作依序一筆一筆處理，不阻塞報到。
- **本機狀態檔 `commands.json`**：記錄 `id → { started_at, result: Option<CommandResult>, reported: bool }`，保留 30 天。
  - 已有 `result` 但還沒成功回報：只補送結果。
  - 已有 `started_at` 但沒有 `result`（執行中斷，例如重開機）：回報 `failed`，輸出「執行中斷（Agent 停止或電腦重新開機）」，不再執行。
  - 執行前先寫入 `started_at` 並存檔。
- **各動作：**
  - **`collect`**：通知報到迴圈把所有區段標成需要收集，下一輪重新上傳。回報 `succeeded`。
  - **`apply`**：喚醒派送與更新原則的背景工作。回報 `succeeded`。
  - **`reboot` / `shutdown`**：
    1. 先回報 `succeeded`，輸出為要執行的指令，確保關機前伺服器已經有結果。
    2. 再執行 `%SystemRoot%\System32\shutdown.exe /r（或 /s） /t <秒數> /c "<訊息>" /d p:0:0`。
    3. 訊息是「IT 部門排定在 N 分鐘後重新開機（或關機），請儲存您的工作。」，延遲 0 分鐘時是「IT 部門即將重新開機（或關機）」。
    4. 回報失敗時仍然執行，並把結果留在狀態檔，開機後補送。
  - **`script`**：
    1. 驗證內容的 SHA-256，不符就回報 `failed`「腳本雜湊不符」，不執行。
    2. 寫到 `<Agent 資料目錄>\scripts\<id>.ps1`，UTF-8 含 BOM。
    3. 以 `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <路徑>` 執行，重用派送的 `Runner`（沒有視窗、Job Object 逾時結束整個程序樹）。
    4. 收集輸出：`Runner` 回傳 stdout 與 stderr 合併後的內容，保留最後 64 KiB。
    5. 結束碼 0 算 `succeeded`，否則 `failed`；逾時是 `failed`「逾時（N 分鐘）」。
    6. 執行完刪除腳本檔。
- `Unknown`：回報 `failed`「不支援的指令」。

## 6. 管理網頁

- **裝置頁「遠端指令」分頁**：
  - 按鈕（可管理這台的人才看得到）：重新收集、立即套用、重開機、關機、執行腳本（平台管理員才有，下拉選單只列已核准的腳本）。
  - 重開機和關機需要確認，可以選延遲。
  - 下方列出這台最近 20 筆指令：動作、建立者、狀態、結束碼、輸出（可以展開）、時間。
- **`/commands`**：
  - 清單：動作、對象、建立者、建立與過期時間、各狀態台數；每頁 50 筆，由新到舊。
  - 「對群組下指令」表單：動作、群組、延遲、腳本、過期時間。
  - 詳情頁：依狀態列出裝置（每頁 100 台）、輸出、取消按鈕。
  - 群組管理員只看得到含自己範圍內裝置的操作，台數也只算範圍內的裝置。
- **`/scripts`**（只限平台管理員）：
  - 清單：名稱、狀態、sha256 前 12 碼、最後修改者、核准者。
  - 新增、編輯、核准、停用和啟用。
  - 詳情頁：內容、完整 sha256、核准資訊、被使用的次數。
  - 需要雙人核准時，最後修改者本人看不到核准按鈕；直接 POST 會回 403 並說明原因。
- **設定**：放在既有的設定頁；沒有設定頁就放在 `/scripts` 頁上方。內容是「腳本需要第二位平台管理員核准」的切換，只限平台管理員，變更寫稽核。
- 所有 POST 都檢查 CSRF。

## 7. 錯誤處理

- 建立指令時的驗證錯誤，顯示在表單上：權限、腳本沒有核准、延遲範圍、過期範圍、群組內沒有裝置。
- Agent 執行失敗只影響那一筆指令，不影響報到、盤點與其他指令。
- 伺服器重送不會讓 Agent 重複執行（見 §5 的去重）。
- 背景工作在過期處理失敗時記錄 error，下一輪再試。

## 8. 測試

- **protocol**：舊版回應（沒有 `commands`）可以解析；未知動作解析為 `Unknown`；`CommandResult` 驗證的邊界。
- **伺服器**：
  - 腳本：新增、修改、sha256；雙人核准時自己不能核准；改內容後回到 `pending`；單人模式直接核准；設定變更寫稽核；被引用的腳本不能刪除。
  - 建立指令：群組展開；群組管理員的範圍與 `script` 限制（403）；只接受已核准的腳本；過期與延遲的範圍。
  - 下發：上限 10 筆；由舊到新；重送；過期、取消的不下發；非使用中裝置不下發。
  - 結果回報：只能回報自己的指令（404）；終結狀態不覆寫；過期處理。
  - 網頁：權限（群組管理員、檢視者）、CSRF、各狀態台數、輸出有經過跳脫。
- **Agent 單元測試**：去重；中斷後回報失敗；雜湊不符不執行；輸出截斷到 64 KiB；關機指令字串。
- **Windows 實機測試**：
  - 實際執行 `Write-Output hi; exit 3`：拿到輸出 `hi`，結果為 failed（3）。
  - 逾時會結束程序樹。
  - 不實際重開機。
- **e2e**：用真實伺服器與假的執行器，驗證「建立 → 報到 → 執行 → 回報 → 資料庫有結果」；也驗證重開機時先回報再執行。
- **loadsim**：新增 `commands` 情境，模擬三萬台報到並回報指令結果。

## 9. 實作分期

- **計畫 18**：
  - protocol。
  - migration 0014：`scripts`、`command_runs`、`command_targets`，以及設定 `scripts_require_second_approver`。
  - 腳本與指令的管理模組：新增、修改、核准、建立、取消、稽核。
  - 報到下發、結果回報、過期背景工作。
- **計畫 19**：Agent 的 commands 模組：
  - 狀態檔、執行器、各動作、報到串接。
  - Runner 補上輸出收集。
  - e2e。
- **計畫 20**：
  - 網頁：裝置分頁、`/commands`、`/scripts`、設定。
  - loadsim、負載測試。
  - README。
