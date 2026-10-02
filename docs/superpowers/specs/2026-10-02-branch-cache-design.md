# 第七期：分點快取 設計

日期：2026-10-02。狀態：已與使用者確認以下內容：
- 範圍：只快取派送套件。據點內可能有網路微分割，端點之間無法互連，所以不做點對點分享。
- 形式：獨立的快取程式。
- 據點對應：依 IP 網段。
- 存取控管：裝置憑證加上中央授權。
- 取得時機：預先下載，加上按需補抓。
- 方案 A：中央在報到時告訴 Agent 套件來源。
- 兩段設計都已確認。

## 1. 範圍

**做：**
- 各據點放一台快取主機，執行新的程式 `endpoint-cache`。快取從中央取得派送套件，就近提供給該據點的端點。
- 中央依端點回報的本機 IP 對應據點，在報到時告訴 Agent 向哪台快取下載。
- 快取向中央確認每個下載請求的授權，權限和直接向中央下載一致。

**不做：**
- 點對點分享。
- Windows Update 內容的快取或代理。
- 報到與上傳經由快取轉送。
- 一個據點多台快取（負載平衡、互為備援）。
- 快取之間的階層（快取向上層快取取檔）。

**權限：**
- 據點、快取、快取註冊金鑰都只限平台管理員管理。
- 所有變更都寫稽核紀錄。

### 1.1 成功標準

條件：i5-12400、同一台電腦上跑中央、一台快取與模擬端點；三萬台模擬裝置；10 MB 套件。
- 5,000 台端點對應到同一個據點，各從快取下載一個套件：
  - 快取從中央只下載該套件 1 次。
  - 5,000 台全部下載並驗證成功。
  - 除了同時連線上限造成的 503 之外，沒有其他 5xx。
- 上述下載期間，中央報到 500 次／秒時 p99 < 100ms。
- 快取停機時：
  - 允許改向中央的據點，端點全部改向中央完成下載。
  - 不允許改向中央的據點，端點在快取恢復後完成下載。
- 未被指派的裝置向快取下載得到 403。被撤銷的裝置最晚 5 分鐘後失去存取權。
- 未達標時照實記錄，不調整目標。

## 2. 中央伺服器

### 2.1 資料表（migration 0016）

**`sites`：**
- `id`
- `name`：唯一，1–100 字，不能有控制字元。
- `cidrs`：`CIDR[]`，至少一個。
- `fallback_to_central`：bool，預設 true。
- `bandwidth_limit_mbps`：INT，可為 NULL（不限）。快取預先下載時使用。
- `disk_limit_gb`：INT，預設 100。
- `created_at`、`updated_at`

同一個 CIDR 不能出現在兩個據點，存檔時檢查。

**`caches`：**
- `id`
- `name`：唯一。
- `site_id`：可為 NULL（尚未指定）。UNIQUE（一個據點一台）。外鍵設 ON DELETE SET NULL。
- `url`：對端點提供服務的網址，`https://<主機>:<埠>`。
- `dns_names TEXT[]`：CSR 裡的主機名稱與 IP。
- `status`：`pending`／`active`／`disabled`。
- `cert_serial`、`cert_not_after`
- `last_seen`、`version`
- `disk_used_bytes`
- `created_at`

**`cache_packages`**（快取回報）：
- 欄位：`cache_id`、`package_id`、`size`、`updated_at`。
- 主鍵是 `(cache_id, package_id)`；兩個外鍵都設 ON DELETE CASCADE。

**`enroll_tokens`：** 新增 `kind TEXT NOT NULL DEFAULT 'device' CHECK (kind IN ('device','cache'))`。快取金鑰只能用來註冊快取，裝置金鑰也不能用來註冊快取。

**`deployment_status`：** 新增 `source TEXT`，值為 `cache`、`central` 或 NULL（舊版 Agent）。

### 2.2 據點對應

- 函式 `site_for(ips: &[IpAddr], sites) -> Option<SiteId>`：
  - 在所有據點的網段中，找最精確（前綴最長）而且包含任一回報 IP 的網段。
  - IPv4 與 IPv6 都支援。
  - 前綴長度相同時，以 site id 較小的優先。存檔時已擋住相同網段，所以這只發生在不同網段之間。
- 使用的 IP 是 Agent 報到時回報的 `ip_addresses`（本機位址），不使用伺服器看到的來源 IP，因為跨據點經過 NAT 後來源 IP 會失真。
- 據點與快取資料比照 `DeployCache`，載入記憶體並依 generation 失效（`branch_state` 單列）；報到時在記憶體中比對。

### 2.3 報到下發

- `CheckinResponse.package_source: Option<PackageSource>`（`#[serde(default)]`）。
- `PackageSource { cache_id: i64, url: String, fallback_to_central: bool }`。
- 只有在「對應到據點」而且「該據點的快取狀態是使用中」時才回傳。

### 2.4 快取註冊與憑證

- 平台管理員在網頁建立快取註冊金鑰（`kind = 'cache'`），可以設定使用次數與期限，比照裝置金鑰。
- 快取執行 `endpoint-cache enroll --server <中央網址> --root <root.pem> --token <金鑰> --name <名稱> --url https://cache-tp.corp:8443 --dns cache-tp.corp,10.1.2.3`：
  1. 在本機產生金鑰對，私鑰只存在快取的資料目錄。
  2. 送出 `POST /v1/cache/enroll`，內容是 CSR、名稱、url、dns_names。
  3. 中央驗證金鑰，建立狀態為 `pending` 的快取，回傳快取 id。
- 平台管理員在網頁核准並指定據點後，中央才簽發憑證：
  - 由現有 CA 簽發。
  - SAN 是 dns_names。
  - EKU 同時包含 serverAuth 與 clientAuth。
  - 有效期比照裝置憑證。
  - 憑證主體標示為快取，與裝置憑證區分。
- 快取以 `POST /v1/cache/enroll/status` 輪詢，核准後取得憑證鏈。
- 換發比照 Agent：剩 30 天時，中央在快取報到回應中要求換發。
- 停用的快取：
  - 中央拒絕它的所有請求。
  - 報到時不再把它指派給端點。

### 2.5 給快取的 API

快取以自己的憑證用 mTLS 連線；只接受狀態是 `active`、而且憑證序號與 `caches.cert_serial` 相符的快取。

- **`POST /v1/cache/checkin`**
  - 請求內容：`CacheCheckin { version, disk_used_bytes, stored: Vec<(package_id, size)> }`。
  - 回應內容：`CacheCheckinResponse { packages: Vec<CachePackage { id, sha256, size }>, bandwidth_limit_mbps, disk_limit_gb, renew_certificate }`。
  - `packages` 是所有未停止派送用到的套件。
  - 快取的報到會寫入 `last_seen`、`version`、`disk_used_bytes`，並以差異方式更新 `cache_packages`。
- **`GET /v1/cache/packages/{id}/content`**：
  - 下載套件。只允許下載出現在 `packages` 清單裡的套件，其他回 404。
  - 共用既有的下載同時上限 `EM_DOWNLOAD_CONCURRENCY`，額滿時回 503 並帶 `Retry-After`。
- **`POST /v1/cache/authorize`**：
  - 請求內容：`{ device_id, cert_serial, package_id }`。
  - 回應內容：`{ allowed: bool }`。允許的條件：
    - 裝置是使用中。
    - `cert_serial` 是裝置目前有效的憑證，而且沒被撤銷。
    - 這台裝置目前被指派這個套件。判斷與端點直接向中央下載共用同一個函式，包括暫停中的派送仍允許。

## 3. 快取程式 `endpoint-cache`

- 新 crate `crates/cache`，產出執行檔 `endpoint-cache`。
- 支援 Windows 服務與 Linux（systemd／Docker）。
- 子命令：`enroll`、`run`、`service`（Windows）。
- **設定檔** `cache.toml`，放在資料目錄：
  - 中央網址
  - 監聽位址：預設 `0.0.0.0:8443`
  - 儲存目錄：預設 `<資料目錄>/packages`
  - 同時下載上限：預設 200
- **資料目錄權限**：
  - Windows：只允許 SYSTEM 與 Administrators，比照 Agent 的做法。
  - Linux：0700。

### 3.1 對端點的 API

**`GET /v1/packages/{id}/content`**：路徑與中央相同，Agent 只換網址。處理順序如下：

1. **mTLS 驗證端點憑證**：
   - 信任錨是中央 CA。
   - 從憑證取出裝置 id 與序號，解析方式與中央的 `AuthedDevice` 相同，抽成共用函式。
   - 快取憑證不能當作裝置憑證使用。
2. **授權**：
   - 向中央 `authorize`，結果（允許或拒絕）以 `(device_id, cert_serial, package_id)` 為鍵快取 5 分鐘。
   - 中央連不上時：5 分鐘內曾允許的組合繼續允許；其他請求回 503，並帶 `Retry-After: 60`。
   - 拒絕回 403。
3. **同時連線上限**：額滿時回 503，並帶 `Retry-After: 60`。
4. **提供檔案**：
   - 套件已在本機就串流。
   - 套件不在本機：
     - 立即從中央下載。同一個套件同時只下載一次（single-flight），其他請求等它完成。
     - 下載完先驗 SHA-256 與大小，才改名放進儲存目錄。
     - 不符合就刪掉暫存檔，回 502。
   - 回應帶 `Content-Length`。

### 3.2 背景工作

- **報到**：每 60 秒向中央報到，回報已存的套件。
- **預先下載**：
  - 依清單依序下載缺少的套件，不並行，避免占滿 WAN。
  - 有 `bandwidth_limit_mbps` 時以權杖桶限速。
  - 與按需下載共用 single-flight：某個套件正在預先下載時，端點的請求會等它完成。
- **清除**：
  - 不在清單上的套件保留 7 天後刪除。用檔案的最後存取時間判斷，記錄在記憶體加上一個小狀態檔。
  - 用量超過 `disk_limit_gb` 時，從最久沒被下載的開始刪；清單上、正在使用的套件最後才刪。
- **換發憑證**：中央要求時重新產生金鑰與 CSR，換發後熱更新 TLS 設定，不需要重新啟動。
- **啟動時**：清掉上次留下的暫存檔。

## 4. Agent

- **儲存來源**：報到後把 `package_source` 交給派送 worker，放在 `Work` 新增的欄位。
- **下載時選擇來源**：
  - 有 `package_source`，而且不在「快取暫停期」內：向快取 url 下載。
  - 沒有 `package_source`：向中央下載。
- **快取回 503**：照 `Retry-After` 稍後再試，**不**改向中央。
- **快取連不上，或回 503 以外的 5xx**：
  - `fallback_to_central` 為 true：這次改向中央下載，並進入 5 分鐘的「快取暫停期」，期間都向中央下載。
  - `fallback_to_central` 為 false：照下載失敗處理，稍後重試快取。
- **快取回 403 或 404**：照下載失敗處理（伺服器端已不再指派），不改向中央。
- **下載驗證**：SHA-256 驗證不變。快取給的檔案不符時照下載失敗處理，並改向中央重試一次，前提是允許改向中央。
- **回報來源**：派送結果 `DeployResult` 新增 `source: Option<"cache"|"central">`。

## 5. 管理網頁

- **`/sites`**：
  - 據點清單：名稱、網段、快取、改向中央、目前對應的裝置數。
  - 裝置數依 `devices` 最後回報的 IP 計算，用 SQL 的 `inet <<= cidr`。
  - 新增、編輯、刪除。被快取使用的據點刪除時，快取的 site_id 會被設為 NULL。
- **`/caches`**：
  - 快取清單：名稱、據點、網址、狀態、最後回報、版本、磁碟用量、預先下載進度（已存 N／應有 M）。
  - 待核准的快取可以核准並選擇據點，也可以拒絕或刪除。
  - 使用中的快取可以停用或啟用、改據點。
  - 快取註冊金鑰：建立、作廢；明碼只顯示一次。
- **裝置頁**：基本資料加上「據點」與「快取」兩欄。
- **派送詳情**：裝置列表加上「來源」欄。

## 6. 錯誤處理

- 網段格式錯誤、重複網段、據點名稱重複：顯示在表單上，回 422。
- 快取註冊：金鑰無效、過期、用完，或金鑰種類不是快取，都回 401。重複名稱回 409。
- 快取與中央斷線時：
  - 已在本機的套件，對 5 分鐘內授權過的端點繼續提供。
  - 其他請求回 503。
  - 中央網頁顯示最後回報時間。
- 快取磁碟滿、寫入失敗：
  - 該次按需下載回 503。
  - 記錄 error，並在報到時回報 `disk_used_bytes`。

## 7. 測試

- **protocol**：舊版回應（沒有 `package_source`）可以解析；`DeployResult.source` 往返。
- **中央**：
  - `site_for`：最精確網段勝出、IPv6、沒有對應時的結果、相同前綴長度時的順序。
  - 據點 CRUD 與重複網段。
  - 快取註冊流程：金鑰種類、待核准、核准後簽發的憑證有正確的 SAN 與 EKU。
  - 報到下發 `package_source`：使用中與停用的快取、沒有對應的據點。
  - 快取 API：
    - 非使用中的快取被拒絕；序號不符被拒絕。
    - `packages` 清單內容。
    - 下載限制只能下載清單內的套件。
    - `authorize` 的各種情況：未指派、已撤銷、非使用中、暫停中的派送。
  - 網頁權限與 CSRF。
- **快取程式**（整合測試，在同一個行程啟動真實中央與快取）：
  - 預先下載後，從中央只下載 1 次。
  - 按需下載的 single-flight：10 個請求同時要同一個沒存的套件，中央只被下載 1 次。
  - 中央給的檔案雜湊不符時不存檔、回 502。
  - 授權拒絕回 403；授權結果快取，以及 5 分鐘後過期。
  - 中央斷線時，已授權的組合繼續服務，其他回 503。
  - 磁碟上限的清除順序。
- **Agent**：用真實中央加真實快取的 e2e 測試：
  - 從快取下載。
  - 快取停機時改向中央。
  - 不允許改向中央時重試快取。
  - 503 時不改向。
  - 回報 `source`。
- **loadsim**：新增「透過快取下載」情境，驗證 §1.1 的標準。

## 8. 實作分期

- **計畫 21**：
  - protocol：`PackageSource`、快取 API 型別、`DeployResult.source`。
  - migration 0016。
  - 據點、`site_for`、記憶體快取。
  - 快取註冊與核准、簽發憑證（CA 支援 SAN 與 EKU）。
  - 給快取的三個 API、報到下發。
- **計畫 22**：`endpoint-cache` 程式，包括設定、enroll、mTLS 伺服器、授權快取、single-flight、預先下載、清除、換發、Windows 服務，以及整合測試。
- **計畫 23**：
  - Agent 的來源選擇與改向中央、回報來源。
  - 網頁 `/sites`、`/caches`、裝置頁與派送詳情的欄位。
  - loadsim 情境與負載測試、README（部署快取的步驟、防火牆埠）。
