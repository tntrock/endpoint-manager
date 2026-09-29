# Endpoint Manager 第三期設計：組態基準合規

- 日期：2026-09-29
- 狀態：待審閱
- 授權：GPLv3
- 前一期：[2026-09-29-compliance-design.md](2026-09-29-compliance-design.md)（合規引擎、網頁、Webhook 通知）

## 1. 背景與範圍

藍圖 ③：檢查端點的系統設定是否符合基準，包括登錄檔、服務、防火牆、BitLocker、Defender、密碼原則、本機管理員。沿用第二期的合規引擎，範圍、豁免、歷程、趨勢、CSV、Webhook 通知全部共用；本期新增資料收集與規則類型。

本期範圍：

- Agent 新增兩個盤點區段：`security`（固定項目）與 `registry`（伺服器指定的登錄檔值）。
- 七種新規則：登錄檔值、服務、防火牆、BitLocker、Defender、密碼原則、本機管理員。
- 內建精選基準範本，勾選後建立成一般規則。
- 裝置頁「安全設定」分頁；「登錄檔值」查詢頁。

本期刻意不做：

- 自動修正設定（只偵測）。
- HKCU（使用者層級）登錄檔。
- GPO 物件本身的分析。
- 需要 `secedit` 的本機原則項目（使用者權限指派、稽核原則）。

### 1.1 成功標準

以 i5-12400、30,000 台、每台 1,000 個登錄檔值加上 `security` 區段為基準：

- 上傳觸發的單台評估 p99 < 20ms（與第二期相同）。
- 查詢清單變動後三萬台重新上傳 `registry` 期間，報到 p99 < 100ms。
- 規則上線後全量重算 < 5 分鐘。

未達標時，把實測可承受的量寫進 `docs/loadtest.md`，不調整目標。

## 2. Agent 資料收集

### 2.1 `security` 區段

預設每小時收集一次，間隔設定 `security_interval_secs`（最小 300 秒）。

| 項目 | 收集方式 | 內容 |
|---|---|---|
| 防火牆 | `INetFwPolicy2`（COM） | 網域、私人、公用三個設定檔**實際生效**的啟用狀態（含 GPO） |
| BitLocker | WMI `root\CIMV2\Security\MicrosoftVolumeEncryption` 的 `Win32_EncryptableVolume` | 每個固定磁碟的代號、是否系統磁碟、`ProtectionStatus`、加密百分比 |
| Defender | WMI `root\Microsoft\Windows\Defender` 的 `MSFT_MpComputerStatus` | 是否為作用中防毒（`AMRunningMode`）、即時保護、防竄改、病毒碼最後更新時間 |
| 密碼原則 | `NetUserModalsGet` level 0 與 3 | 最短長度、最長使用天數（0＝永不過期）、鎖定門檻（0＝不鎖定） |
| 本機管理員 | 以 SID `S-1-5-32-544` 取得群組名稱後 `NetLocalGroupGetMembers` level 2 | 成員的「網域\名稱」與 SID |

- 每一項獨立收集。任一項失敗時，該項以錯誤字串代替，不影響其他項。
- 錯誤沿用 Agent 既有「同一錯誤只記一次」的 warning 記錄方式。

協定型別（`protocol` crate）：

```rust
pub struct SecurityInfo {
    pub firewall: Probe<FirewallInfo>,     // { domain: bool, private: bool, public: bool }
    pub bitlocker: Probe<Vec<VolumeInfo>>, // { drive, is_system, protected: bool, percent: u8 }
    pub defender: Probe<DefenderInfo>,     // { active, realtime, tamper, signature_updated: Option<DateTime<Utc>> }
    pub password: Probe<PasswordPolicy>,   // { min_length, max_age_days, lockout_threshold }
    pub admins: Probe<Vec<AccountInfo>>,   // { name, sid }
}
pub enum Probe<T> { Ok(T), Error(String) }
```

### 2.2 `registry` 區段

- **查詢清單**：報到回應新增 `registry_queries: Vec<RegistryQuery { path, name }>` 與 `registry_queries_hash`。兩個欄位都有 `#[serde(default)]`，舊版 Agent 會忽略。
- **收集時機**：Agent 記住上次收集時的清單雜湊；清單雜湊改變時當次就收集並上傳，另外每小時（`registry_interval_secs`）重收一次。
- **回報內容**：`RegistryValue { path, name, state, kind, data }`。
  - `state`：`present`、`absent` 或 `denied`。
  - `kind`：`dword`、`qword`、`string`、`expand_string`、`multi_string`、`binary`、`other`。
  - `data`：數字轉成十進位字串；多字串以換行連接；二進位以小寫 hex 表示；內容最多 1024 字元。

**Agent 端防護**（伺服器被入侵也無法繞過）：

1. 路徑正規化：`/` 換成 `\`，去掉重複的 `\` 與結尾的 `\`，不分大小寫；含 `..` 的路徑直接拒絕。
2. 只接受 `HKLM\`，或同義的 `HKEY_LOCAL_MACHINE\`。
3. 拒絕清單：`HKLM\SAM`、`HKLM\SECURITY` 整個子樹；`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` 底下的 `DefaultPassword`、`AltDefaultPassword`。
4. 最多處理 5,000 筆查詢（硬上限），超過的部分忽略並記錄一次。
5. 被拒絕的查詢回報 `state = denied`，不讀取。

### 2.3 相容性

- 舊版 Agent 沒有這兩個區段，相關規則為「未知」，細節 `reason = "agent_outdated"`。
- 升級順序是先伺服器、後 Agent。新版 Agent 上傳伺服器不認識的區段時（400 且訊息為 unknown section），記錄一次後不再上傳該區段，直到 Agent 重新啟動。

## 3. 規則

七種新 kind，全部支援群組範圍與豁免。

| kind | 參數 | 違規條件 |
|---|---|---|
| `registry_value` | `path`、`name`、`op`（`equals`／`not_equals`／`gte`／`lte`／`contains`／`exists`／`not_exists`）、`expected`（`exists`／`not_exists` 不需要）、`absent_ok: bool` | 比對不成立。`dword`／`qword` 以數值比較，其他以字串比較、不分大小寫；`gte`／`lte` 遇到非數字的值為「未知」。值不存在時：`absent_ok` 為 true 算符合，否則違規；`exists`／`not_exists` 不看 `absent_ok`。 |
| `service_state` | `name`（服務名稱，不分大小寫）、`require`（`disabled`／`running`） | `disabled`：服務存在且啟動類型不是 Disabled（未安裝算符合）。`running`：未安裝、狀態不是 Running，或啟動類型是 Disabled。 |
| `firewall` | `profiles`：`domain`／`private`／`public` 的子集，至少一個 | 任一指定的設定檔未啟用 |
| `bitlocker` | `scope`：`system`／`all_fixed` | 範圍內任一磁碟 `protected = false`；`system` 範圍卻找不到系統磁碟時為違規 |
| `defender` | `realtime: bool`、`max_signature_age_days: Option<u32>`、`tamper: bool`（至少一項） | 任一要求不成立。`active = false`（例如被第三方防毒取代）時為「未知」，`reason = "defender_inactive"` |
| `password_policy` | `min_length`、`max_age_days`、`max_lockout_threshold`（皆為選填，至少一項） | `min_length`：實際長度小於設定值。`max_age_days`：實際為 0（永不過期）或大於設定值。`max_lockout_threshold`：實際為 0（不鎖定）或大於設定值。 |
| `local_admins` | `allowed`：萬用字元樣式清單（比對「網域\名稱」，不分大小寫） | 有成員不符合任何樣式，細節列出這些成員（最多 50 個） |

- **未知結果**：該區段從未上傳（或 Agent 過舊）；該項 `Probe::Error`；登錄檔值 `denied`；查詢清單剛改變、Agent 尚未回報新值（該值不在 `device_registry` 裡）。
- **細節與摘要**：`summarize` 為每種類型產生一行中文摘要，例如「公用設定檔未啟用」「C: 未加密保護」「最短長度 8，需要 12」。
- **規則驗證**：
  - `path` 套用 §2.2 相同的正規化與拒絕清單（同一套程式碼放在 `protocol` crate，Agent 與伺服器共用）。
  - 建立或啟用規則時，所有啟用中的登錄檔規則彙總後的相異查詢數不能超過 `registry_max_values`（預設 1000，範圍 1–5000），超過時拒絕存檔並提示。
- **預覽命中台數**：新的登錄檔查詢在預覽時尚未收集，所以預覽結果為「未知」，網頁上會註明。

## 4. 伺服器

### 4.1 資料表（migration 0007）

- `device_security`：`device_id` 為主鍵，各項欄位存成 jsonb（`firewall`、`bitlocker`、`defender`、`password`、`admins`），每項為 `{"ok": ...}` 或 `{"error": "..."}`。
- `device_registry`：`device_id`、`path`、`name`、`state`、`kind`、`data`，主鍵 (`device_id`, `path`, `name`)，另建索引 (`path`, `name`)。
- 設定：`security_interval_secs`（3600）、`registry_interval_secs`（3600）、`registry_max_values`（1000）。

### 4.2 協定與上傳

- **區段**：`Section` 新增 `Security`、`Registry`。走 `/v1/inventory/{section}`，大小上限、NUL 檢查、gzip 處理與現有區段相同。
- **清單外的值**：伺服器只保存查詢清單內的值（以規則快取算出的集合比對），清單外的直接丟棄。上傳時若清單剛好變動，只丟棄不在新清單的值，不回錯誤。
- **變更歷史**：兩個區段都寫入 `inventory_changes`。`security` 以項目為單位記錄，例如 `firewall.public: true → false`；`registry` 以「路徑\名稱」為單位。
- **報到回應**：`registry_queries` 由規則快取（`RuleCache`）附帶計算，快取更新時一起重算，報到時不額外查資料庫。

### 4.3 評估

- `DeviceFacts` 新增 `security: Option<SecurityInfo>`、`registry: Option<HashMap<(path, name), RegistryValue>>`、`services: Option<Vec<ServiceFact>>`。
- 會觸發評估的區段加上 `security`、`registry`、`services`。
- 批次預覽（`load_facts_bulk`）一併載入。

### 4.4 內建範本

- 範本檔 `crates/server/src/compliance/baseline.json` 以 `include_str!` 內嵌，每條有 `key`（穩定識別字）、分類、名稱、說明、嚴重度、kind、params。
- 規則頁「從範本建立」列出全部範本，已用同一 `key` 建立過的會標示（`compliance_rules` 新增 `template_key` 欄位）。勾選後批次建立，寫 `rule_create` 稽核記錄並附 `template_key`。
- 範本不含公司特定內容。

初版範本（值在實作計畫中逐一核對 Microsoft 文件）：

| 分類 | 範本 | kind | 嚴重度 |
|---|---|---|---|
| 網路與防火牆 | 三個防火牆設定檔皆啟用 | firewall | 高 |
| | 停用 SMBv1 伺服器（`LanmanServer\Parameters\SMB1 = 0`，未設定視為符合） | registry_value | 中 |
| | 停用 SMBv1 用戶端驅動 `mrxsmb10` | service_state | 中 |
| | 要求 SMB 伺服器簽章（`RequireSecuritySignature = 1`） | registry_value | 中 |
| | 停用 LLMNR（`DNSClient\EnableMulticast = 0`） | registry_value | 低 |
| | 停用遠端登錄服務 `RemoteRegistry` | service_state | 中 |
| | 遠端桌面要求 NLA（`RDP-Tcp\UserAuthentication = 1`） | registry_value | 中 |
| 帳號與密碼 | 只允許 NTLMv2（`Lsa\LmCompatibilityLevel ≥ 5`） | registry_value | 高 |
| | 停用 WDigest 明文認證（`WDigest\UseLogonCredential = 0`，未設定視為符合） | registry_value | 高 |
| | 限制匿名列舉（`Lsa\RestrictAnonymous = 1`） | registry_value | 中 |
| | LSA 保護（`Lsa\RunAsPPL = 1`） | registry_value | 中 |
| | 密碼最短 12 碼 | password_policy | 中 |
| | 密碼最長 365 天 | password_policy | 低 |
| | 鎖定門檻 10 次以內 | password_policy | 中 |
| | 本機管理員只允許內建 Administrator（需自行補上網域群組） | local_admins | 高 |
| 防毒與加密 | Defender 即時保護 | defender | 高 |
| | Defender 病毒碼 7 天內更新 | defender | 中 |
| | Defender 防竄改 | defender | 中 |
| | BitLocker 保護系統磁碟 | bitlocker | 高 |
| 系統強化 | UAC 開啟（`EnableLUA = 1`） | registry_value | 高 |
| | UAC 管理員提示（`ConsentPromptBehaviorAdmin ≤ 2`） | registry_value | 低 |
| | 停用所有磁碟自動執行（`NoDriveTypeAutoRun = 255`） | registry_value | 中 |
| | 登入畫面不顯示上次帳號（`DontDisplayLastUserName = 1`） | registry_value | 低 |
| | PowerShell 指令碼區塊記錄（`ScriptBlockLogging\EnableScriptBlockLogging = 1`） | registry_value | 低 |

## 5. 管理網頁

- **規則表單**：新增七種類型的欄位。登錄檔路徑欄位即時標示「只能讀取 HKLM、不能讀取 SAM／SECURITY」。
- **從範本建立**（`/compliance/rules/templates`）：平台管理員專用，依分類列出範本並勾選。
- **裝置頁「安全設定」分頁**：顯示 `security` 區段各項的目前內容或錯誤，以及收集時間。
- **登錄檔值查詢**（`/registry`）：
  - 輸入路徑與值名稱，統計範圍內裝置各個值（含「不存在」）的台數，點選後列出裝置。
  - 只能查到有規則在收集的值，頁面上會註明。
- **權限**：沿用第二期。規則與範本只有平台管理員能改；資料依群組範圍顯示。

## 6. 錯誤處理

- **Agent 收集**：各項獨立失敗；登錄檔個別值讀不到時回報 `absent` 或 `denied`；超過硬上限只處理前 5,000 筆。
- **伺服器驗證**：
  - 查詢清單在建立或啟用規則時就受 `registry_max_values` 限制，所以下發的清單永遠在上限內。
  - 上傳內容格式錯誤、筆數超過 5,000，或超過字串長度上限時，回 400。
- **舊版 Agent**：相關規則為未知，網頁細節寫「Agent 版本過舊」。

## 7. 測試

- **純函式單元測試**：
  - 七種規則的比對（數字與字串、`absent_ok`、服務未安裝、Defender 非作用中、密碼原則的 0 值、管理員萬用字元、BitLocker 找不到系統磁碟）。
  - 路徑正規化與拒絕清單（大小寫、`/`、重複 `\`、`..`、`HKEY_LOCAL_MACHINE` 別名）。
  - 查詢清單彙總與雜湊。
  - 摘要文字。
  - 範本 JSON 每一條都能通過 `Params::parse`。
- **資料庫整合測試**：
  - 兩個新區段上傳後會觸發評估。
  - 查詢清單隨規則新增、停用變化，報到回應也跟著更新。
  - 清單外的值被丟棄；超過上限時拒絕存檔。
  - 從範本建立規則，以及稽核記錄。
  - 登錄檔查詢頁只顯示範圍內的裝置。
  - 變更歷史有記錄。
- **Agent（CI `agent-windows`）**：
  - 實際收集 `security`：防火牆、密碼原則、管理員三項必須成功（CI 機器可能沒有 BitLocker、Defender）。
  - 讀取已知的登錄檔值，例如 `CurrentVersion\ProductName`。
  - 讀 `HKLM\SAM\SAM` 的查詢必須回 `denied`。
- **負載**：loadsim 新增 `security` 與 `registry` 上傳（`--registry N`），以 1,000 個值驗證 §1.1，結果寫入 `docs/loadtest.md`。
