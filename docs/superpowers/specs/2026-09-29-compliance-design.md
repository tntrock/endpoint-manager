# Endpoint Manager 第二期設計：軟體與修補合規

- 日期：2026-09-29
- 狀態：待審閱
- 授權：GPLv3
- 前一期：[2026-09-27-endpoint-inventory-design.md](2026-09-27-endpoint-inventory-design.md)

## 1. 背景與範圍

第一期已收集每台端點的軟體清單、修補（KB）與作業系統資訊。第二期以這些資料做**偵測與稽核**：管理員定義規則，系統找出違規裝置，保留歷程並發出通知。

本期範圍（藍圖 ② 非法軟體偵測，加上修補合規）：

- 五種規則：禁止軟體、必要軟體、軟體白名單、最低組建號、必要 KB。
- 規則預設套用到全部裝置，可限定或排除群組。
- 個別裝置豁免（原因＋到期日）。
- 目前違規、違規歷程、每日趨勢、CSV 匯出。
- Email 與 Webhook 彙整通知。**（2026-09-29 更新：Email 延後。lettre 相依的 `quoted_printable` 為 0BSD 授權，不在允許清單內；本期只提供 Webhook。）**

本期刻意不做：軟體／修補派送（藍圖 ④）、第三方軟體 CVE 比對、組態基準（藍圖 ③）、群組管理員自訂規則。

### 1.1 成功標準

以 i5-12400、30,000 台、每台 150 套軟體、50 條規則為基準：

- 上傳時評估單台，增加的延遲 p99 < 20ms。
- 全部重算 < 5 分鐘，期間報到 p99 < 100ms。
- 新規則一次冒出三萬筆違規時，每個通知管道只送出一次彙整。

## 2. 規則

### 2.1 共同欄位

每條規則有：名稱、說明、類型（`kind`）、嚴重度（`high`／`medium`／`low`）、啟用開關、參數（jsonb，依類型驗證）、套用範圍。

### 2.2 類型與參數

| kind | 參數 | 違規條件 |
|---|---|---|
| `forbidden_software` | `name`（必填）、`publisher`、`below_version` | 有任何軟體符合 name（與 publisher）；有 `below_version` 時，只有版本低於它的才算 |
| `required_software` | `name`（必填）、`publisher`、`min_version` | 沒有符合的軟體；或有 `min_version` 而所有符合的軟體版本都低於它 |
| `software_allowlist` | `entries`：`[{name?, publisher?}]`，每筆至少一個欄位，至少一筆 | 有任何軟體不符合清單中任一筆 |
| `os_build` | 二擇一：`{min_build}` 或 `{build, min_ubr}` | `min_build`：組建主號低於它（作業系統已停止支援）。`build`＋`min_ubr`：組建主號等於 build 且 UBR 低於 min_ubr；其他組建不受影響 |
| `required_kb` | `kb`（`^KB\d{6,8}$`，存成大寫） | 修補清單沒有這個 KB |

違規細節（`detail` jsonb）記錄命中的內容：命中的軟體名稱與版本、目前組建號與 UBR、缺少的 KB。白名單違規最多列 50 筆軟體，另附總數。

### 2.3 比對方式

- **名稱與發行者**：`*` 萬用字元（任意長度），整串比對，不分大小寫（Unicode 小寫化）。沒有其他特殊字元。
- **版本**：以 `.`、`-`、`_`、`+`、空白切段。兩段都是數字時以數值（u64）比較；都是文字時不分大小寫以字串比較；一邊數字一邊文字時數字較大（所以 `1.0` > `1.0-beta`）。段數不足補 `0`。例：`10.0.9` < `10.0.10`、`1.2` = `1.2.0`。

### 2.4 未知結果

資料不足以判斷時，結果是「未知」（`unknown`），不算違規也不算通過，細節寫明原因：

- 有版本條件，但命中的軟體沒有版本，而且沒有其他命中項能確定結果。
- `os_build` 的 `build`＋`min_ubr` 形式，但裝置沒有 UBR（舊版 Agent）。
- 規則參數無法解析（例如資料庫被手動改壞）：該規則對所有裝置都是未知，總覽頁標示「規則錯誤」。

裝置從未上傳過某區段（例如沒有軟體清單）時，依賴該區段的規則也是未知。

### 2.5 套用範圍

- 只評估狀態為 `active` 的裝置；`retired` 與 `duplicate_suspect` 不評估。
- 規則可設「只套用群組」清單與「排除群組」清單。只套用清單為空代表全部裝置；排除優先。沒有群組的裝置只會命中「只套用清單為空」的規則。
- 群組被任何規則引用時不能刪除（沿用 `groups::usage` 檢查），否則「只套用」清單變空會讓規則默默變成套用到全部裝置。

### 2.6 豁免

- 以（裝置, 規則）為單位，必填原因與到期日（最長 365 天），寫入稽核記錄。
- 被豁免的裝置仍會評估，命中時狀態為 `exempt`，不計入違規，也不發通知。
- 到期的豁免由背景工作刪除並重算該裝置。

## 3. Agent 變更

基本資料新增 `os_ubr: Option<u32>`，從 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` 的 `UBR`（REG_DWORD）讀取；讀不到就是 `None`。協定欄位使用 `#[serde(default)]`，新舊版本互通。伺服器的 `devices` 表新增 `os_ubr INTEGER`。

## 4. 資料庫（migration 0004）

- `compliance_rules`：id、name、description、kind、severity、enabled、params jsonb、created_by、created_at、updated_at。
- `compliance_rule_groups`：rule_id（ON DELETE CASCADE）、group_id（REFERENCES device_groups，不 cascade）、mode（`include`／`exclude`），PK (rule_id, group_id)。
- `compliance_exemptions`：id、device_id、rule_id（ON DELETE CASCADE）、reason、expires_at、created_by、created_at，UNIQUE (device_id, rule_id)；索引 (expires_at)。
- `device_violations`：device_id（CASCADE）、rule_id（CASCADE）、status（`violating`／`unknown`／`exempt`）、detail jsonb、since、updated_at，PK (device_id, rule_id)；索引 (rule_id, status)。
- `violation_events`：id bigserial、device_id（CASCADE）、rule_id（ON DELETE SET NULL）、rule_name（快照）、severity（快照）、from_status、to_status（`none` 表示無違規）、detail、at；索引 (device_id, at)、(at)。
- `compliance_daily`：day、rule_id（CASCADE）、violating、unknown、exempt，PK (day, rule_id)。
- `compliance_state`：單列，`generation`（規則或豁免變更時 +1）、`done_generation`、`cursor`（重算進度的 device_id）、`started_at`。
- `notify_outbox`：id bigserial、event jsonb、created_at。
- `notify_channels`：channel（`email`／`webhook`）、last_sent_id、next_attempt、last_ok_at、last_error。

歷程由既有每日清理工作刪除，保留天數設定 `violation_history_days`（預設 365，範圍 30–3650）。

## 5. 評估流程

### 5.1 評估函式

`compliance::evaluate(device: &DeviceFacts, rules: &RuleSet, exemptions: &[RuleId]) -> Vec<Outcome>` 是純函式。`DeviceFacts` 含 group_id、os_build、os_ubr、軟體清單、KB 清單與「哪些區段有資料」；`Outcome` 是（rule_id, status, detail）。沒有命中的規則不產生 Outcome。

`RuleSet` 是已解析、已預先編譯萬用字元的規則集，放在記憶體快取，以 `compliance_state.generation` 判斷是否需重新載入。

### 5.2 套用結果

`apply_outcomes(tx, device_id, outcomes)`：

1. 取 `pg_advisory_xact_lock(裝置)`，序列化同一台裝置的評估。
2. 讀出該裝置的 `device_violations`，與新結果比對：
   - 新增：寫入違規，事件 `none → status`。
   - 狀態或細節改變：更新，事件 `old → new`。細節改變但狀態不變時，只更新違規列，不寫事件也不通知，避免版本號小幅變動造成大量歷程。
   - 消失：刪除，事件 `status → none`。
3. 狀態變成或離開 `violating`、且規則嚴重度達通知門檻的事件，寫入 `notify_outbox`。

### 5.3 觸發時機

1. **上傳**：軟體、修補、基本資料區段寫入後（僅盤點雜湊改變時才會走到），在同一個交易內重新讀取該裝置的事實並評估。評估出錯只記錄錯誤、不讓上傳失敗。
2. **規則或豁免變更**：同一交易內 `generation += 1`。背景重算工作看到 `generation > done_generation` 時，從頭依 device_id 順序每 1,000 台一批重算；每批後更新 `cursor`；批與批之間讓出執行權。重算期間 generation 又改變就從頭再來。完成後設 `done_generation`。重算只用一條資料庫連線。伺服器重啟後依 `cursor` 繼續。
3. **每 5 分鐘**：刪除到期豁免，重算那些裝置。
4. **裝置除役或刪除**：除役時刪除其違規並寫 `→ none` 事件；刪除裝置由 CASCADE 處理。

### 5.4 每日快照

既有每日工作寫入當天的 `compliance_daily`（依 `device_violations` 聚合）。

## 6. 通知

### 6.1 設定

存在 `settings`（平台管理員可改，寫入稽核記錄）：

- `notify_min_severity`：預設 `medium`。
- `notify_interval_minutes`：預設 10，範圍 1–1440。
- `notify_email`：SMTP 主機、埠、加密（`starttls`／`tls`）、帳號、寄件者、收件人清單；空值代表停用。
- `notify_webhook_url`：只接受 `https://`；空值代表停用。

機密放環境變數，不存資料庫：`EM_SMTP_PASSWORD`、`EM_WEBHOOK_SECRET`。

### 6.2 彙整送出

背景工作每個間隔對每個已啟用管道執行一次：讀出 `id > last_sent_id` 的事件，組成一份彙整送出，成功後推進 `last_sent_id`。所有已啟用管道都送過的事件才刪除。

- **Email**：主旨含新增與解除數量；內文依規則分組，每條規則最多列 20 台（主機名稱、細節摘要），附網頁連結。
- **Webhook**：`POST` JSON：`{generated_at, new: [...], resolved: [...], truncated, total_new, total_resolved}`，每筆含 rule、severity、device_id、hostname、detail；`new` 與 `resolved` 合計最多 500 筆，超過時 `truncated: true`。設了 `EM_WEBHOOK_SECRET` 時，加 `X-EM-Signature: sha256=<hex HMAC-SHA256(body)>` 與 `X-EM-Timestamp`（簽章涵蓋 `timestamp + "." + body`）。逾時 10 秒；使用系統信任的憑證（`rustls-native-certs`）；不跟隨重新導向。
- 設定頁「送出測試通知」立即送一則測試訊息，回報成功或錯誤。

### 6.3 失敗處理

- 送出失敗：記錄 `last_error`，下次嘗試時間倍增（1 分鐘起，最長 1 小時）。總覽頁顯示最後成功時間與錯誤。
- 佇列上限 100,000 筆；超過時刪除最舊的事件並記錄警告，下一份彙整註明「有 N 筆事件因佇列已滿而遺失」。
- 兩個管道各自追蹤進度，互不影響。

### 6.4 新相依套件

`lettre`（rustls、無預設功能）、`reqwest`（沿用 workspace 版本）、`rustls-native-certs`、`hmac`。全部通過 `cargo deny`。

## 7. 管理網頁

沿用 askama 樣板與既有樣式，不加前端框架或 JS 函式庫。

| 路徑 | 內容 |
|---|---|
| `/compliance` | 每條規則的違規／未知／豁免數；重算進度；通知管道狀態；近 30 天每日違規數（CSS 長條） |
| `/compliance/rules` | 規則清單、新增、編輯（依類型的表單）、啟用／停用、刪除；表單可「預覽命中台數」 |
| `/compliance/violations` | 依規則、嚴重度、狀態、群組、主機名稱篩選；分頁；CSV 匯出（相同篩選，串流輸出） |
| 裝置頁「合規」區塊 | 目前結果與細節、有效豁免、新增／撤銷豁免、最近 50 筆歷程 |
| 設定頁「通知」區塊 | 見 §6.1，含測試按鈕 |

- **預覽命中台數**：以同一個評估函式分批跑全部裝置，不寫入；同時只允許一個預覽，逾時 30 秒。
- **CSV**：UTF-8 含 BOM（Excel 可正確顯示中文）；以 `=`、`+`、`-`、`@`、Tab、CR 開頭的欄位前面加 `'`。
- 所有修改走既有的 CSRF 檢查並寫入稽核記錄。

### 7.1 權限

| 動作 | 平台管理員 | 群組管理員 | 檢視者 |
|---|---|---|---|
| 看規則 | ✓ | ✓ | ✓ |
| 建立／修改／刪除規則、通知設定 | ✓ | — | — |
| 看違規、歷程、趨勢、匯出 CSV | 全部 | 自己的群組 | 自己的群組 |
| 新增／撤銷豁免 | ✓ | — | — |

群組管理員與檢視者的總覽數字與趨勢只計算自己群組的裝置（趨勢由 `device_violations` 即時聚合時套用群組條件；`compliance_daily` 只給平台管理員）。

## 8. 錯誤處理

- 評估失敗不影響盤點上傳（§5.3）。
- 單條規則參數壞掉只影響該規則（§2.4）。
- 重算與通知的進度都存在資料庫，重啟後接續。
- 豁免到期、規則停用、規則刪除都會觸發重算，違規清單不會殘留過期結果。

## 9. 測試

- **評估函式單元測試**：五種規則；萬用字元、大小寫、Unicode；版本比較（補 0、文字段、數字對文字）；只套用／排除／排除優先／無群組裝置；豁免；各種未知情況；白名單細節截斷。
- **資料庫整合測試**：上傳觸發評估；雜湊未變不評估；歷程差異（新增、狀態改變、細節改變不寫事件、解除）；規則變更後全量重算與重算中再變更；重啟後依 cursor 接續；豁免到期；除役清除違規；被規則引用的群組不能刪除；群組權限（看不到別群組、不能豁免）；CSV 注入防護與 BOM。
- **通知測試**：Webhook 以本機測試伺服器驗證 JSON、簽章、500 筆截斷、失敗重試與倍增、不跟隨重新導向；佇列上限；兩管道互不影響；Email 以 lettre stub 傳輸層驗證分組與內容。
- **Agent**：UBR 收集在 CI `agent-windows` job 實際執行；舊協定（無 `os_ubr`）可正常解析。
- **負載**：`tools/loadsim` 新增 `--rules N`，驗證 §1.1 的數字並寫入 `docs/loadtest.md`。
