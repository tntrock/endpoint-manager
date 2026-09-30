# 第五期：Windows Update 控制 設計

日期：2026-09-30。狀態：已與使用者確認：
- 範圍：設定原則＋稽核。
- GPO 衝突處理：依群組選擇是否接管。
- 原則項目：延後＋暫停、期限＋使用中時段。
- 稽核：輕量狀態。
- 方案 A：專用子系統，稽核接進合規引擎。

## 1. 範圍

**做：**
- 平台管理員在網頁建立「更新原則」，指定套用的群組。
- Agent 把原則寫進 Windows Update for Business（WUfB）的原則登錄檔。
- 回報每台的套用結果（已套用／衝突／錯誤）、是否待重開機、最後裝更新的日期。
- 三種新合規規則：太久沒裝更新、待重開機太久、原則衝突或錯誤。

**不做：**
- 核准或拒絕個別 KB。
- 呼叫 Windows Update API 搜尋待裝更新。
- 鎖定功能版本（TargetReleaseVersion）。
- 排除驅動程式。
- WSUS 伺服器設定。
- 自動重新開機。

**權限：**
- 原則只有平台管理員能建立、修改、刪除、暫停。
- 群組管理員只能看自己範圍內裝置的狀態。
- 每次變更都寫稽核紀錄。

**與 GPO 的關係：**
- 只有被原則涵蓋的裝置才會寫入，其他裝置 Agent 完全不碰 WU 設定。
- 被涵蓋的裝置不該再有管 WU 的 GPO。若有，Agent 會回報「衝突」並停止覆寫（見 §4.3），由管理員決定拿掉 GPO，或把該群組移出原則。

### 1.1 成功標準

條件：i5-12400、三萬台模擬裝置、5 個原則。
- 報到 500 次／秒時 p99 < 100ms（與前幾期相同）。
- 三萬台同時上傳 `update_status`：沒有 5xx，全部寫入。
- 加入三種新規則後，合規重新計算時間不比加入前多 10% 以上。
- 未達標時照實記錄，不調整目標。

## 2. 原則內容

所有值都寫在 `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`。

- 每個項目都選填。沒設定的項目，Agent 不寫入，也會刪除自己以前寫過的對應值（見 §4.3）。
- 值名稱依 `WindowsUpdate.admx`，實作前必須在 CI Windows runner 的 `C:\Windows\PolicyDefinitions\WindowsUpdate.admx` 逐一核對（計畫 16 第一個任務）。核對結果和下表不同時，以 ADMX 為準並更新本表。（2026-09-30 已核對：品質更新期限用新版 ADMX 的 `SetComplianceDeadlineForQU`／`ConfigureDeadlineNoAutoRebootForQualityUpdates`，舊版名稱 `SetComplianceDeadline`／`ConfigureDeadlineNoAutoReboot` 不再出現在新版 ADMX。24H2 以前的 Windows 只認舊名稱，所以有任一期限時也寫入 `SetComplianceDeadline`=1，勾選不自動重開機時也寫入 `ConfigureDeadlineNoAutoReboot`=1，新舊並存。）

| 項目 | 設定範圍 | 寫入的值 |
|---|---|---|
| 品質更新延後 | 0–30 天 | `DeferQualityUpdates`=1（DWORD）、`DeferQualityUpdatesPeriodInDays`（DWORD） |
| 功能更新延後 | 0–365 天 | `DeferFeatureUpdates`=1、`DeferFeatureUpdatesPeriodInDays` |
| 暫停品質更新 | 開始日期 | `PauseQualityUpdatesStartTime`（REG_SZ `yyyy-mm-dd`）；必須同時設定品質更新延後（ADMX 中是同一個原則）。沒設延後時，伺服器以 0 天寫入 `DeferQualityUpdates`=1 與 `DeferQualityUpdatesPeriodInDays`=0 |
| 暫停功能更新 | 開始日期 | `PauseFeatureUpdatesStartTime`（REG_SZ）；同上，綁定功能更新延後 |
| 品質更新期限 | 期限 0–30 天、寬限 0–7 天 | `SetComplianceDeadlineForQU`=1、`ConfigureDeadlineForQualityUpdates`、`ConfigureDeadlineGracePeriod` |
| 功能更新期限 | 期限 0–30 天、寬限 0–7 天 | `SetComplianceDeadlineForFU`=1、`ConfigureDeadlineForFeatureUpdates`、`ConfigureDeadlineGracePeriodForFeatureUpdates` |
| 寬限期結束前不自動重開機 | 是／否（需有任一期限） | `ConfigureDeadlineNoAutoRebootForQualityUpdates`（品質）、`ConfigureDeadlineNoAutoRebootForFeatureUpdates`（功能），兩者同值 |
| 使用中時段 | 開始、結束 0–23 點，時段長度 1–18 小時（可跨午夜） | `SetActiveHours`=1、`ActiveHoursStart`、`ActiveHoursEnd` |

**暫停：**
- 網頁按「暫停」時，把開始日設為今天（伺服器的顯示時區）。按「恢復」時清除。
- Windows 會在開始日後 35 天自動恢復。網頁顯示「暫停中，至 <開始日+35 天>」；過期後顯示「暫停已過期」，不自動清除。
- 暫停與恢復都會讓 revision 加 1，也都寫稽核紀錄。

**伺服器端的協定型別：**
- `UpdatePolicy { id, revision, values: Vec<PolicyValue> }`，其中 `PolicyValue { name, data: PolicyData }`。
- `PolicyData` 是 `Dword(u32)`／`String(String)`，另有 `#[serde(other)] Unknown`：新版伺服器加了新型別時，舊 Agent 仍能解析。
- 伺服器負責把表單設定轉成值清單。
- 白名單 `VALUE_NAMES` 放在 protocol，兩端共用。Agent 只接受白名單內的值名稱（§4.2）。

## 3. 伺服器

### 3.1 資料表（migration 0012）

**`update_policies`：**
- 基本欄位：
  - `id`
  - `name`：唯一，1–100 字，不能有控制字元。
  - `revision`：INT，從 1 開始。
  - `settings`：JSONB，就是表單的內容。
  - `created_at`、`updated_at`
- `settings` 的格式由 Rust 型別 `PolicySettings` 定義，包含：
  - `quality_defer_days`、`feature_defer_days`
  - `quality_pause_start`、`feature_pause_start`（DATE 字串）
  - `quality_deadline`、`feature_deadline`：`Option<Deadline { days, grace }>`
  - `no_auto_reboot`：bool
  - `active_hours`：`Option<ActiveHours { start, end }>`
  - 其餘都是 `Option`。

**`update_policy_groups`：**
- 欄位：`group_id`（PK，FK ON DELETE RESTRICT）、`policy_id`（FK ON DELETE CASCADE）。
- 一台裝置只屬於一個群組（`devices.group_id`），所以用「一個群組最多屬於一個原則」取代優先順序與排除群組。每台裝置最多對應一個原則，不需要比較優先順序。
- 原則至少要有一個群組。群組被原則使用時不能刪除，比照派送。

**`update_policy_status`**（由 `PUT /v1/update-status` 寫入，一台一列）：
- 欄位：
  - `device_id`（PK）
  - `policy_id`（可為 NULL），`revision`
  - `state`（`unmanaged`／`applied`／`conflict`／`error`）
  - `detail`（衝突的值名稱或錯誤原因，最長 500 字）
  - `reboot_pending`（bool），`reboot_pending_since`（timestamptz）
  - `last_patch_date`（date）
  - `updated_at`
- `policy_id` 不設 FK：原則刪除後，Agent 下次回報前舊資料仍保留，網頁顯示「已刪除的原則」。

**`update_state`：**
- 單列，欄位 `generation`。原則有任何變更時加 1，用來讓報到快取過期，比照 `deploy_state`。

### 3.2 指派

- **哪個原則**：裝置所屬群組對應的原則。沒有群組、群組沒有原則，或裝置不是使用中狀態時為 `None`。
- **快取**：`UpdatePolicyCache` 比照 `DeployCache`，每 5 秒檢查一次 `generation`，把「群組 → 原則」載入記憶體。報到時直接用裝置的群組查表，不額外查資料庫。
- **下發**：`CheckinResponse` 新增兩個欄位：
  - `update_policy: Option<UpdatePolicy>`
  - `update_policy_hash: Option<String>`：必定有值；原則為 None 時是 `null` 的雜湊（和「沒有任何值的原則」不同）。舊 Agent 會忽略這兩個欄位。

### 3.3 `PUT /v1/update-status`

- 用獨立的端點，不做成盤點區段。原因：
  - 盤點區段由 Agent 的收集排程處理，舊伺服器看到不認識的區段會讓報到失敗。
  - 這份狀態由更新 worker 產生，比照派送的結果回報比較單純。
- 內容：`UpdateStatus { policy_id, revision, state, detail, reboot_pending, reboot_pending_since, last_patch_date }`。
- Agent 何時送：
  - 內容改變時。
  - 距上次成功送出滿 24 小時時。
  - 只在報到回應帶有 `update_policy_hash` 時送（伺服器支援才送）。
- 伺服器驗證以下項目，不合法時回 400：
  - `detail` 最長 500 字，不能有 NUL。
  - `state` 不能是未知值。
  - 日期不能晚於伺服器現在時間加 1 天。
- 寫入方式：以 `device_id` upsert 到 `update_policy_status`。

## 4. Agent

### 4.1 狀態檔

`update_policy.json` 和 `deploy.json` 放在同一個目錄，內容：
- 目前套用的 `policy_id` 與 `revision`
- `written`：值名稱 → 寫入的內容
- `state` 與 `detail`
- `reboot_pending_since`

### 4.2 值名稱白名單

- 只允許 §2 表格中的值名稱，寫死在 Agent 裡。
- 收到白名單以外的名稱時整份原則不套用，狀態記為 `error`，detail 寫「不支援的值：<名稱>」。

### 4.3 套用流程

以下兩種情況會觸發一次 pass：
- 報到收到的 `update_policy_hash` 改變時。
- 每小時一次（每次 pass 本身已經會比對衝突，不另外監聽登錄檔）。

每次 pass 依序處理：

1. **收到新原則，或 revision 改變：**
   - 寫入新原則的每個值。
   - 刪除 `written` 裡、新原則沒有的值，但只刪目前值仍等於當初寫入內容的。
   - 讀回確認，全部相符就記為 `applied`。
   - 更新 `written`。
2. **revision 沒變：**
   - 讀取 `written` 的每個值；任何一個不存在或內容不同，就記為 `conflict`，detail 列出值名稱。
   - `conflict` 之後不再寫入，直到 revision 改變。
   - 值又和 `written` 相符時（例如 GPO 被拿掉後有人手動改回），回到 `applied`。
3. **原則變成 None：**
   - 刪除 `written` 裡目前值仍等於當初寫入內容的值，清空 `written`，記為 `unmanaged`。
   - `WindowsUpdate` 機碼本身不刪。
4. **寫入或刪除失敗：** 記為 `error`，detail 是失敗的值名稱與錯誤。下次 pass 重試。
5. **登錄檔路徑：** 可注入。正式環境用 `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`；測試用 `HKCU\Software\endpoint-manager-test\<隨機>`。

「決定要寫什麼、刪什麼、狀態是什麼」寫成純函式 `plan(current_registry, written, desired) -> Plan`，登錄檔讀寫則獨立成一個 trait。

### 4.4 狀態收集

- **待重開機**：以下任一機碼存在即是待重開機：
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`

  從無到有時記下 `reboot_pending_since` 為現在時間；從有到無時清除。
- **最後裝更新的日期**：從既有 patches 清單的 `installed_on` 解析，取最新的一天。支援兩種格式：
  - `M/D/YYYY`
  - 16 進位 FILETIME

  無法解析的略過；全部無法解析時為 None。

## 5. 合規規則

新增三種 kind（migration 0012 擴充 `rules.kind` 的 CHECK）。三種都支援群組範圍、豁免、違規歷史與 Webhook 通知。

| kind | 參數 | 違規 | 未知 |
|---|---|---|---|
| `patch_age` | `max_days` 1–365 | `last_patch_date` 早於今天減 max_days | 沒有 `update_status`，或 `last_patch_date` 為 None |
| `reboot_pending` | `max_days` 1–90 | `reboot_pending` 為真，且 `reboot_pending_since` 早於現在減 max_days | 沒有 `update_status` |
| `update_policy` | 無 | 狀態是 `conflict` 或 `error`；detail 顯示原因 | 沒有 `update_status` |

`update_policy` 規則對狀態為 `unmanaged` 的裝置判定為符合。

`DeviceFacts` 新增 `update_status: Option<UpdateStatus>`。

## 6. 管理網頁

**`/updates`：更新原則清單**
- 欄位：名稱、套用群組、暫停狀態。
- 各狀態台數：已套用、衝突、錯誤、尚未回報。「尚未回報」的定義是：該原則應套用、但 `update_policy_status` 的 policy_id 或 revision 不相符。
- 群組管理員只計算自己範圍內的裝置。

**原則表單（新增／編輯）**
- 只有平台管理員可用。
- 項目同 §2，另選套用群組。群組已屬於其他原則時顯示錯誤（寫出是哪個原則）。

**原則詳情**
- 設定內容。
- 依狀態列出裝置，每頁 50 台，比照派送詳情。
- 按鈕（平台管理員）：暫停／恢復品質更新、暫停／恢復功能更新、刪除。

**`/updates/overview`：更新概況**
- 各組建的 UBR 分布：組建、UBR、台數，依組建排序。
- 待重開機最久的 50 台。

**裝置頁「更新」分頁**
- 套用的原則。
- 每個值的期望與實際：實際值取 `written`，衝突的值會另外標示。
- 待重開機狀態、最後裝更新日期。

**權限與防護**
- 所有 POST 都要檢查 CSRF。
- 非平台管理員嘗試修改時回 403。

## 7. 錯誤處理

- 原則驗證失敗時，表單顯示錯誤並保留使用者輸入。
- 驗證項目：
  - 範圍
  - 使用中時段長度
  - 「不自動重開機」需要至少設定一種期限
  - 至少一個群組，且群組不能已屬於其他原則
- 原則已刪除但裝置尚未回報時，網頁顯示「已刪除的原則」。
- Agent 寫入失敗只影響該台的狀態，不影響報到或其他功能。

## 8. 測試

- **protocol**：`UpdatePolicy` 序列化；雜湊穩定性；未知欄位與未知 data 型別的相容性。
- **伺服器**：
  - 原則 CRUD 與驗證
  - 依群組指派；一個群組不能屬於兩個原則
  - 快取在變更後過期
  - `update_status` 上傳與驗證
  - 三種規則的違規與未知
  - 網頁權限（群組管理員 403、CSRF）與範圍計數
  - 刪除被原則使用的群組會失敗
- **Agent 單元測試**：`plan()` 的各種組合：
  - 首次套用
  - revision 改變時刪除多餘的值
  - 衝突
  - 衝突後恢復
  - 移出範圍時只刪自己寫的值
  - 白名單外的名稱
- **Agent 登錄檔**（Windows，HKCU 測試機碼）：實際寫入、讀回、刪除；REG_SZ／DWORD 型別正確。
- **e2e**：套用 → 讀回 → 手動改值 → 回報 `conflict` → 原則修改後重新套用 → 移出範圍後清除。
- **loadsim**：新增 `updates` 情境，5 個原則、三萬台報到並上傳 `update_status`。結果記錄到 `docs/loadtest.md`。

## 9. 實作分期

- **計畫 15**：protocol、migration 0012、原則 CRUD（admin 模組）、指派與快取、報到下發、`update_status` 上傳與儲存。
- **計畫 16**：ADMX 值名稱核對，以及 Agent 的白名單、`plan()`、登錄檔 trait、狀態檔、待重開機與最後裝更新日期、worker、e2e。
- **計畫 17**：三種合規規則、網頁（清單、表單、詳情、概況、裝置分頁）、loadsim、README、負載測試文件。
