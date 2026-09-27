# Endpoint Manager 第一期設計：報到與資產盤點

- 日期：2026-09-27
- 狀態：待審閱
- 授權：GPLv3

## 1. 背景與目標

### 1.1 動機

企業內部需要集中控管大量 Windows 端點的系統設定、組態、軟體版本、非法元件與修補狀態。現有開源方案常被弱點掃描掃出漏洞且難以自行修補，因此自行開發一套**相依套件少、可自行維護、可客製化**的 Client-Server 管理工具，並以 GPLv3 開源於 GitHub。

### 1.2 整體藍圖（本文件只涵蓋 ①）

| 子系統 | 內容 |
|---|---|
| **① 報到＋資產盤點** | **本期範圍** |
| ② 非法軟體偵測 | 以 ① 的軟體清單與變更記錄為基礎做黑白名單規則 |
| ③ 組態基準合規 | 登錄檔、本機原則、防火牆、BitLocker 等檢查 |
| ④ 軟體／修補派送 | 管理伺服器只下發「裝什麼＋hash」，檔案由分點快取提供；Windows Update 交由 WSUS／WUfB，本系統負責控制與稽核 |
| ⑤ 遠端指令 | 需長連線（WebSocket），本期通訊層預留空間但不實作 |

### 1.3 規模與環境

- 端點數：25,000～30,000 台，AD 與非 AD 混合。
- 伺服器：Linux + Docker Compose（程式不綁 Linux 專屬功能，保留日後支援 Windows Server）。
- 管理介面：Web。

### 1.4 端點 OS 支援分期

| 期別 | 範圍 |
|---|---|
| 第一期（本文件） | Windows 10／11、Server 2016 以上，x86_64，Rust Agent |
| 第二期 | Windows 7／8.1、Server 2008 R2／2012，使用 `x86_64-win7-windows-msvc`（Tier 3，nightly + build-std）另出版本 |
| 第三期 | XP／2003：VBScript 以排程工作收集資料寫到網路分享資料夾，伺服器匯入器讀取；**唯讀盤點**，介面標示「舊系統／高風險」 |

無法安裝 Agent 的設備（印表機、交換器等）屬「網路探索」子系統，不在本系列範圍。

### 1.5 成功標準

1. Win10+ 端點透過 MSI（GPO 或手動）安裝後自動註冊並持續報到。
2. 管理網頁可查詢每台電腦的基本資訊、硬體、軟體、KB、服務，並可跨電腦搜尋（例：哪些電腦裝了某軟體某版本）。
3. 軟體安裝／移除在數秒到數分鐘內反映到伺服器並留下變更記錄。
4. 通過第 7 節的負載驗收標準（30,000 台模擬）。

## 2. 架構總覽

```
[Windows 端點: agent.exe (Windows Service, LocalSystem)]
        │  HTTPS + JSON, mTLS, Agent 主動輪詢
        ▼
[server (單一執行檔)]
   ├─ :8443  Agent API（強制 mTLS，/v1/enroll 例外）
   └─ :443   管理網頁（HTTPS + 帳密登入，askama + htmx）
        │
        ▼
[PostgreSQL]
```

- 全 Rust；管理網頁由伺服器端渲染，**不使用 npm**（htmx 以單一 vendored JS 檔隨程式發佈）。
- 兩個監聽埠分離，可用防火牆分別管控（例：管理網頁只開放 IT 網段）。

## 3. 專案結構

```
endpoint-manager/
├─ crates/
│  ├─ protocol/   Agent 與伺服器共用的訊息型別（serde），每則訊息帶 schema_version
│  ├─ agent/
│  │   ├─ service       Windows Service 生命週期與排程
│  │   ├─ collectors/   basic / hardware / software / patches / services，各自獨立
│  │   ├─ client        mTLS 連線、重試、退避、jitter
│  │   └─ state         憑證、device_id、各區段 hash；存於 C:\ProgramData\EndpointManager\，ACL 僅 SYSTEM 與 Administrators
│  └─ server/
│      ├─ agent_api     :8443
│      ├─ web           :443，askama 模板 + htmx
│      ├─ db            sqlx + migrations
│      └─ ca            中繼 CA，簽發／撤銷 Agent 憑證
├─ tools/loadsim/ 負載模擬器（模擬 N 台 Agent）
├─ installer/     WiX 設定，產生 MSI
├─ deploy/        docker-compose.yml、Dockerfile
├─ docs/
└─ LICENSE        GPLv3
```

TLS 一律使用 rustls（純 Rust，不依賴 Windows Schannel）。

## 4. 資料流程

### 4.1 註冊（每台一次）

1. Agent 首次啟動，於本機產生金鑰對（ECDSA P-256），私鑰不離開本機。
2. `POST /v1/enroll`，內容：註冊金鑰、CSR、hostname、SMBIOS UUID、BIOS 序號、MAC 清單。
3. 伺服器驗證金鑰（未過期、未作廢、未超過 max_uses），比對硬體識別決定新建或沿用裝置記錄，以中繼 CA 簽發憑證（CN = device_id，效期 1 年）。
4. 回傳 `{ device_id, certificate_chain }`；Agent 存入 state，**刪除本機的註冊金鑰**，之後一律以 mTLS 連線。

- **伺服器驗證**：MSI 內建根 CA 指紋，Agent 只信任此根 CA 簽出的伺服器憑證。
- **註冊金鑰**：安裝時以 `msiexec /i agent.msi ENROLL_TOKEN=... SERVER_URL=...` 帶入；帶對即自動核准。金鑰可設到期日、使用次數上限、隨時作廢，並帶 `group_label` 做簡單分組。
- **重灌**：SMBIOS UUID 與 BIOS 序號皆相符 → 沿用裝置記錄並撤銷舊憑證。
- **疑似重複**：僅 SMBIOS UUID 相符但序號不符（常見於複製的 VM）→ 新建記錄並標為 `duplicate_suspect`，由管理員處理。

### 4.2 心跳

```
POST /v1/checkin
  { schema_version, agent_version, boot_time, logged_on_user, ip_addresses,
    section_hashes: { basic, hardware, software, patches, services },
    section_errors: { <section>: <message> } }
→ { next_checkin_seconds, request_sections: [...], collection_intervals: {...}, renew_certificate: bool }
```

- 預設間隔 **60 秒**，加 ±20% 隨機延遲；由伺服器下發，可調整（尖峰時可自動拉長至 5 分鐘）。
- 伺服器將 last_seen 等熱欄位先存在記憶體，**每 30 秒批次寫入** DB。
- 超過 3 個報到週期未報到視為離線。

### 4.3 各區段收集策略

| 區段 | 來源 | 預設策略 |
|---|---|---|
| basic（登入者、IP、OS 版本等） | API／登錄檔 | 每次心跳 |
| software | 登錄檔 Uninstall 機碼（HKLM 64／32 位元、各使用者 HKU） | `RegNotifyChangeKeyValue` 事件觸發（去抖動 10 秒）＋每小時補收 |
| patches | WMI `Win32_QuickFixEngineering` | 每小時，Windows Update 完成事件時觸發 |
| services | WMI `Win32_Service` | 每小時 |
| hardware | WMI | 開機一次＋每 24 小時 |

間隔由伺服器 `settings` 下發。

### 4.4 差異上傳

- Agent 對每個區段計算 hash（對正規化並排序後的 JSON 做 SHA-256），心跳時只送 hash。
- 伺服器發現 hash 不符，於回應 `request_sections` 中要求上傳；Agent 以 `PUT /v1/inventory/{section}`（gzip）上傳**整個區段**。
- 伺服器處理：與舊資料比對算出差異 → 寫入 `inventory_changes` → 同一交易內刪除舊資料、寫入新資料、更新 hash。

### 4.5 憑證續期

剩餘效期 < 30 天時，伺服器於心跳回應設 `renew_certificate: true`；Agent 產生新 CSR 透過現有 mTLS 呼叫 `POST /v1/renew` 換發。

## 5. 資料庫（PostgreSQL）

### 5.1 裝置與身分

- `devices`：id (UUID PK)、hostname、domain、is_domain_joined、smbios_uuid、bios_serial、management_type（`agent` / `legacy_import`）、status（`active` / `retired` / `duplicate_suspect`）、last_seen_at、last_ip、logged_on_user、boot_time、agent_version、os_caption、os_build、enrolled_at、enroll_token_id
- `device_certs`：serial (PK)、device_id、not_after、revoked_at
- `enroll_tokens`：id、name、token_hash、group_label、expires_at、max_uses、used_count、revoked_at、created_by、created_at

### 5.2 盤點

- `device_hardware`：device_id (PK)、manufacturer、model、cpu、ram_mb、disks (jsonb)
- `device_software`：device_id、name、version、publisher、install_date、arch；索引 (name)、(device_id)
- `device_patches`：device_id、kb、installed_on；索引 (kb)
- `device_services`：device_id、name、display_name、start_mode、state、binary_path
- `inventory_sections`：(device_id, section) PK、hash、updated_at
- `inventory_changes`：id、device_id、section、change（`added` / `removed` / `updated`）、item_key、old_value、new_value、detected_at；**按月分割區**，預設保留 12 個月

估計總量約 2 千萬列、5～10GB。

### 5.3 管理

- `admins`：id、username、password_hash（argon2id）、role、disabled_at
- `sessions`：id、admin_id、expires_at
- `audit_log`：id、actor、action、target、detail (jsonb)、at
- `settings`：key、value (jsonb)

### 5.4 本期刻意不做

- 版本號語意比較（第 ② 期再加）。
- 部門／組織樹（本期以 `group_label` 分組）。
- AD／LDAP 登入（本期只有本機帳號）。

## 6. 錯誤處理與安全

### 6.1 Agent

| 情況 | 處理 |
|---|---|
| 伺服器連不上 | 指數退避 1→2→4…最長 30 分鐘＋jitter；持續收集，每區段只保留最新快照 |
| 伺服器回 503 | 遵守 `Retry-After` |
| WMI 卡住／損壞 | 每個 collector 逾時 60 秒、各自獨立；錯誤透過 `section_errors` 回報 |
| Agent panic | `panic = "abort"`，由 Windows Service 失敗復原自動重啟 |
| 憑證被撤銷 | 停止報到、寫事件檢視器；不自動重新註冊，須重新安裝 |
| 憑證過期（離線 > 1 年） | 同上 |
| 被停止／移除 | 服務 ACL 禁止一般使用者停止；伺服器標示長期離線 |

Agent 日誌寫入 Windows 事件檢視器。

### 6.2 伺服器

- device_id 一律取自 mTLS 憑證，**不信任 request body**。
- 請求大小上限 5MB（壓縮後）、解壓後上限 50MB；驗證 schema_version 與字串長度。
- `/v1/enroll` 依 IP 限速；金鑰只存 hash，constant-time 比較。
- DB 失效時 Agent API 回 503 + Retry-After；提供 `/healthz`。
- 管理網頁：Cookie HttpOnly / Secure / SameSite=Strict、CSRF token、登入失敗鎖定、所有管理操作寫入 `audit_log`。
- 日誌：`tracing` 結構化輸出至 stdout。

### 6.3 CA

- 兩層 CA：**根 CA 離線保存**，伺服器只持有中繼 CA。
- Agent 信任根 CA 指紋；中繼 CA 外洩時以根 CA 重新簽發中繼，無須重新安裝 Agent。

### 6.4 供應鏈

- CI 執行 `cargo audit` 與 `cargo deny`（漏洞、授權、禁用套件），有 CVE 即失敗。
- exe 與 MSI 以 Authenticode 簽章；開源文件說明自行簽章方式。

## 7. 測試策略

- **單元測試**：collector 拆成「取得資料（trait）」與「整理資料（純函式）」，以錄製樣本測試整理邏輯，涵蓋缺 DisplayVersion、`SystemComponent=1`、32／64 位元重複、中文名稱等；伺服器差異比對邏輯；protocol 各 schema 版本 JSON 樣本（`tests/fixtures/`）的相容性。
- **整合測試**：伺服器以 GitHub Actions PostgreSQL service container 測試註冊（成功／過期／作廢／超過次數）、撤銷憑證被拒、跨裝置寫入被拒、超大請求與 zip bomb 被擋、無憑證連不上 8443；Agent collectors 在 `windows-latest` 上實際執行。
- **端對端**：Docker 啟動伺服器，Agent 以主控台模式執行：註冊 → 心跳 → 上傳 → 網頁可查 → 安裝測試軟體 → 變更記錄出現。
- **負載測試**（`tools/loadsim`，30,000 台模擬、各自憑證）：
  - 500 次心跳／秒時 p99 < 200ms。
  - 30,000 台於 10 分鐘內各上傳完整軟體清單，無錯誤、無資料遺失。
- **導入**：IT 部門 10 台 → 100 → 1,000 → 全面，每階段觀察伺服器負載與端點 CPU／記憶體影響。
