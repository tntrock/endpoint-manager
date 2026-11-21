# 監控指標與資料保留 第一版 設計

## 1. 目的

- **監控**：目前要知道「Agent 是不是大量離線」「報到是不是變慢」「快取是不是掛了」，只能打開管理網頁看。這一版提供 Prometheus 格式的 `/metrics`，讓既有的監控系統可以收集並設定告警。
- **資料保留**：遠端指令的結果（含每台的輸出）和稽核記錄只會一直增加。這一版加上定期清除，保留天數可以在管理網頁設定。

`inventory_changes`（12 個月分割區）與合規歷史（`violation_history_days`）本來就有清除，不在這次範圍。

## 2. `/metrics`

### 2.1 開啟與驗證

- 新環境變數 `EM_METRICS_TOKEN`。沒設定時 `/metrics` 回 404（預設關閉）。少於 32 字元時伺服器拒絕啟動，避免弱權杖。
- 掛在**管理網頁的連接埠**（`EM_WEB_LISTEN`，HTTPS）。Agent 連接埠需要用戶端憑證，Prometheus 不方便使用。
- 請求要帶 `Authorization: Bearer <權杖>`。比對兩邊的 SHA-256，錯誤或缺少都回 401。
- 不需要登入，也不受 MFA 影響：這是給機器用的唯讀端點，內容只有統計數字，沒有主機名稱、帳號等個別資料。

### 2.2 指標

都以 `em_` 開頭。

收集時向資料庫查詢（結果快取 15 秒，避免頻繁收集造成負擔）：

| 指標 | 類型 | 標籤 | 說明 |
|---|---|---|---|
| `em_devices` | gauge | `os_family`, `status` | 裝置數 |
| `em_devices_online` | gauge | `os_family` | 使用中且在線的裝置數（與管理網頁相同的判斷：最近 3 個報到週期內有報到） |
| `em_devices_violating` | gauge | | 有合規違規的使用中裝置數 |
| `em_command_targets_open` | gauge | `status` | 尚未完成的指令目標（`pending`、`sent`） |
| `em_deployments` | gauge | `stage` | 派送數 |
| `em_caches` | gauge | `status` | 快取數 |
| `em_caches_stale` | gauge | | 使用中、但超過 5 分鐘沒報到的快取數 |
| `em_table_rows_estimate` | gauge | `table` | 主要大表的估計列數（`pg_class.reltuples`，不掃表） |
| `em_database_size_bytes` | gauge | | 資料庫大小 |
| `em_metrics_db_up` | gauge | | 這次收集的資料庫查詢是否成功（失敗時上面的指標不輸出，程序內的指標照常輸出） |

程序內：

| 指標 | 類型 | 標籤 | 說明 |
|---|---|---|---|
| `em_build_info` | gauge | `version` | 固定為 1 |
| `em_http_requests_total` | counter | `listener`（`agent`/`web`）, `route`, `code`（`2xx`…`5xx`） | 請求數 |
| `em_http_request_duration_seconds` | histogram | `listener`, `route` | 處理時間 |
| `em_heartbeat_buffered` | gauge | | 尚未寫入資料庫的報到數 |
| `em_db_pool_connections` | gauge | `state`（`idle`/`used`） | 資料庫連線 |
| `em_retention_deleted_total` | counter | `kind`（`commands`/`audit`） | 資料保留清除的列數 |
| `em_retention_last_success_timestamp_seconds` | gauge | | 最近一次清除成功的時間 |

- `route` 用路由的樣板（例如 `/v1/commands/{id}/result`），不用實際網址，標籤數量固定。沒有對應路由的請求（404）不計入。
- 不新增依賴：文字格式自己輸出。

## 3. 資料保留

### 3.1 設定

存在 `settings`，平台管理員在「稽核記錄」頁的「資料保留」區塊修改，修改會寫稽核記錄（`setting_retention`，含新舊值）。

| 設定 | 預設 | 範圍 | 清除對象 |
|---|---|---|---|
| `command_history_days` | 180 | 0 或 30–3650 | 遠端指令（含每台的結果與輸出） |
| `audit_history_days` | 0 | 0 或 365–3650 | 稽核記錄 |

- 0 表示永久保留。
- 稽核記錄預設永久保留：升級後不會刪掉任何稽核記錄，要由管理者決定。
- 指令只清除**已經結束**的：建立時間超過保留天數、已過期，而且沒有尚未完成的目標。
- 讀不到或被改壞的值當成預設值。

### 3.2 排程

- 伺服器啟動 1 分鐘後執行一次，之後每小時一次。
- 每批刪 1,000 列，批次之間暫停 100 毫秒，每次執行最多 100 批（每類最多 10 萬列），剩下的下次再刪，避免長時間鎖表。
- 有刪除時寫一筆稽核記錄 `retention_purge`（操作者 `system`，細節是各類刪除的列數）。
- 更新上面的保留指標。

## 4. 測試

- 指標：沒設權杖時 404、缺少或錯誤權杖 401、正確權杖 200 且含主要指標；文字格式（標籤跳脫、histogram 累計）；路由標籤用樣板。
- 設定：權杖太短時拒絕啟動。
- 保留：只刪超過天數且已結束的指令（未完成的、未過期的都保留）、0 表示不刪、稽核記錄依設定刪除並留下 `retention_purge`、設定的範圍檢查與權限、壞值用預設。
