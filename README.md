# Endpoint Manager

企業 Windows 端點管理工具：資產盤點、合規檢查、軟體派送、Windows Update 控制、遠端指令，並可在分點放快取主機節省 WAN 頻寬。

授權：GPL-3.0-only

- [整體架構](#整體架構)
- [網路連線與連接埠](#網路連線與連接埠)
- [憑證與信任](#憑證與信任)
- [部署](#部署)
- [功能說明](#功能說明)
- [開發](#開發)

## 整體架構

```mermaid
flowchart LR
    admin["IT 管理員<br/>瀏覽器"]
    hook["SIEM／Teams 等<br/>Webhook 接收端"]
    msu["Microsoft Update<br/>或 WSUS"]

    subgraph hq["總部／資料中心"]
        server["endpoint-server<br/>Agent API :8443<br/>管理網頁 :443"]
        db[("PostgreSQL 17<br/>:5432")]
    end

    subgraph site_a["一般據點"]
        agent1["Windows 端點<br/>endpoint-agent 服務"]
    end

    subgraph site_b["分點（有快取）"]
        cache["endpoint-cache<br/>:8443"]
        agent2["Windows 端點<br/>endpoint-agent 服務"]
    end

    admin -- "HTTPS 443" --> server
    server -- "TCP 5432" --> db
    agent1 -- "HTTPS 8443（mTLS）<br/>報到、盤點、下載套件" --> server
    agent2 -- "HTTPS 8443（mTLS）<br/>報到、盤點、回報結果" --> server
    agent2 -- "HTTPS 8443（mTLS）<br/>下載套件" --> cache
    cache -- "HTTPS 8443（mTLS）<br/>報到、授權查詢、下載套件" --> server
    server -- "HTTPS（選用）" --> hook
    agent1 -. "Windows 內建，不經本系統" .-> msu
    agent2 -.-> msu
```

| 元件 | 執行位置 | 說明 |
|---|---|---|
| `endpoint-server` | 總部的 Linux（Docker Compose）或 Windows 主機 | 中央伺服器。同一個程式提供兩個 HTTPS 服務：給 Agent 與快取的 **Agent API**，以及給 IT 人員的**管理網頁**。資料全部存在 PostgreSQL；派送套件存在本機目錄。 |
| PostgreSQL 17 | 與伺服器同機或獨立主機 | 唯一的資料庫。只有 `endpoint-server` 會連線。 |
| `endpoint-agent` | 每台受管的 Windows 電腦（Windows 服務，以 SYSTEM 執行） | 定期向中央報到、上傳盤點、取得要執行的派送／更新原則／遠端指令並回報結果。 |
| `endpoint-cache` | 分點的一台 Windows 或 Linux 主機（選用） | 向中央預先下載派送套件，提供給同據點的端點。端點仍直接向中央報到，只有**套件下載**改走快取。 |

設計重點：

- **所有連線都由端點往中央發起**（輪詢），中央不會主動連到端點。端點電腦不需要開任何對內的連接埠，也可以在 NAT 後面。
- 指令與派送在端點**下次報到時**送達，預設報到間隔 60 秒。
- Agent 與快取都用中央發的用戶端憑證做 mTLS 認證，不需要網域帳號。

## 網路連線與連接埠

### 連線清單

| # | 來源 | 目的 | 連接埠 | 協定 | 用途 | 必要 |
|---|---|---|---|---|---|---|
| 1 | IT 管理員的瀏覽器 | 中央伺服器 | **TCP 443**（`EM_WEB_LISTEN`） | HTTPS | 管理網頁 | 必要 |
| 2 | 所有 Windows 端點 | 中央伺服器 | **TCP 8443**（`EM_AGENT_LISTEN`） | HTTPS，註冊後為 mTLS | 註冊、報到、盤點、取得派送／原則／指令、回報結果、下載套件、憑證更新 | 必要 |
| 3 | 中央伺服器 | PostgreSQL | **TCP 5432** | PostgreSQL | 資料庫 | 必要 |
| 4 | 分點端點 | 該據點的快取 | **TCP 8443**（快取 `config.json` 的 `listen`） | HTTPS（mTLS） | 下載派送套件 | 有快取時 |
| 5 | 快取主機 | 中央伺服器 | **TCP 8443** | HTTPS（mTLS） | 快取註冊、報到、確認端點是否被指派、預先下載套件 | 有快取時 |
| 6 | 中央伺服器 | Webhook 接收端 | 接收端網址的埠（通常 443） | HTTPS | 合規違規通知 | 選用 |
| 7 | Windows 端點 | Microsoft Update 或 WSUS | 依 Windows 設定 | — | 實際下載 Windows 更新。本系統只寫入 Windows Update for Business 原則，不經手更新檔 | 依環境 |

### 防火牆建議

- **中央伺服器對內**：
  - 8443 開放給所有端點網段與快取主機。
  - 443 只開放給 IT 管理網段。
- **中央伺服器對外**：只有選用的 Webhook。
- **資料庫**：只允許中央伺服器連 5432。Docker Compose 部署時資料庫不對外發布連接埠，只在容器網路內可達。
- **端點**：不需要任何對內規則；只要能連到中央的 8443（以及有快取時，該據點快取的 8443）。
- **快取主機**：
  - 對內：8443 開放給該據點的端點。
  - 對外：中央的 8443。
- 中間有 TLS 檢查（SSL inspection）的 Proxy 或防火牆時，8443 必須設為**不解密**，否則 mTLS 會失敗。

### 伺服器 HTTP 端點一覽

這份清單供防火牆、WAF 與記錄分析參考。

| 服務 | 路徑 | 呼叫者 |
|---|---|---|
| Agent API（8443） | `GET /healthz` | 監控（不需憑證） |
| | `POST /v1/enroll` | 新端點，以註冊金鑰註冊（還沒有用戶端憑證） |
| | `POST /v1/renew` | Agent 更新裝置憑證 |
| | `POST /v1/checkin` | Agent 定期報到 |
| | `PUT /v1/inventory/{section}` | Agent 上傳盤點 |
| | `PUT /v1/update-status` | Agent 回報 Windows Update 狀態 |
| | `POST /v1/deployments/{id}/result`、`POST /v1/commands/{id}/result` | Agent 回報派送與指令結果 |
| | `GET /v1/packages/{id}/content` | Agent 向中央下載套件 |
| | `/v1/cache/…`（enroll、checkin、authorize、renew、packages） | 快取主機 |
| 管理網頁（443） | `/`、`/devices`、`/compliance`……；靜態檔 `/static/*`；狀態數字 `/ui/status` | 瀏覽器 |

## 憑證與信任

系統自帶私有 CA，由 `endpoint-server ca-init` 產生到 `EM_CA_DIR`（預設 `./pki`）：

```
根 CA（root.pem / root.key，10 年）── 請把 root.key 移到離線媒體
 └─ 中繼 CA（intermediate.pem / .key，5 年）── 伺服器持有，簽發以下憑證
     ├─ 伺服器憑證（server.pem / .key，825 天）：Agent API 與管理網頁共用
     ├─ 裝置憑證（每台 Agent 一張，365 天，Agent 自動更新）
     └─ 快取憑證（每台快取一張）
```

- `ca-init` 後面要列出 Agent 連線用的**所有名稱**（DNS 名稱或 IP），例如 `ca-init /pki em.example.com 10.0.0.5`。Agent 使用的伺服器網址，主機必須是其中之一。
- Agent 與快取以 `root.pem` 驗證中央；中央以中繼 CA 驗證 Agent 與快取的用戶端憑證。
- 管理網頁預設使用同一張伺服器憑證。瀏覽器需要信任 `root.pem`（可用 GPO 發到 IT 人員的電腦），或改用公司 CA 簽發的憑證。
- `root.key` 只在重新產生中繼 CA 時需要，平時請離線保存。

## 部署

### 1. 中央伺服器（Docker Compose）

在 Linux 伺服器上：

```bash
cd deploy
cp .env.example .env          # 修改 EM_DB_PASSWORD 與 EM_AGENT_PUBLIC_URL
mkdir -p pki agent && sudo chown 65532:65532 pki   # 容器以 uid 65532 執行
docker compose build
docker run --rm -v "$PWD/pki:/pki" endpoint-manager-server ca-init /pki em.example.com
```

**把 `deploy/pki/root.key` 移到離線儲存媒體後從伺服器刪除。**

從 GitHub Release 下載 `endpoint-agent-<版本>.msi`（通用範本）放到 `deploy/agent/endpoint-agent.msi`，然後：

```bash
docker compose up -d
docker compose run --rm server admin-create admin    # 輸入第一個平台管理員的密碼（至少 12 字元）
```

Compose 的連接埠對應：

| 主機 | 容器 | 服務 |
|---|---|---|
| 443 | 8444 | 管理網頁 |
| 8443 | 8443 | Agent API |
| （不發布） | db:5432 | PostgreSQL，只在容器網路內 |

Volume：
- `pgdata`：資料庫。
- `packages`：派送套件。
- `./pki`：唯讀掛載的憑證。
- `./agent`：唯讀掛載的 MSI 範本。

備份時至少備份 `pgdata`、`packages` 與 `pki`（`root.key` 除外，另行離線保存）。

`docker compose stop` 時，伺服器會先寫出記憶體中的報到資料再結束。

### 2. 環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `DATABASE_URL` | （必填） | PostgreSQL 連線字串。Windows 上主機請寫 `127.0.0.1`，不要寫 `localhost`：否則每次連線會先試 IPv6，多等約 2 秒。 |
| `EM_CA_DIR` | `./pki` | 憑證目錄 |
| `EM_AGENT_LISTEN` | `0.0.0.0:8443` | Agent API 的監聽位址 |
| `EM_WEB_LISTEN` | `0.0.0.0:443` | 管理網頁的監聽位址 |
| `EM_AGENT_PUBLIC_URL` | （空） | 管理網頁產生安裝檔時預填的伺服器網址，例如 `https://em.example.com:8443` |
| `EM_AGENT_MSI` | （空） | 通用範本 MSI 的路徑；沒設時「建立並下載安裝檔」不會出現 |
| `EM_PACKAGE_DIR` | `packages` | 派送套件的存放目錄 |
| `EM_DOWNLOAD_CONCURRENCY` | 50 | 同時下載套件的上限，超過時回 503，Agent 稍後再試 |
| `EM_ENROLL_PER_IP_PER_MINUTE` | 60 | 每個來源 IP 每分鐘的註冊次數上限 |
| `EM_RECOMPUTE_CONCURRENCY` | 4（最高 16） | 合規規則變更後全量重算時，同時處理的裝置數 |
| `EM_DISPLAY_UTC_OFFSET` | 8 | 管理網頁顯示時間用的時區（小時，-12～14） |
| `EM_WEBHOOK_SECRET` | （空） | 合規通知 Webhook 的 HMAC 簽章密鑰 |

### 3. 安裝 Agent

管理網頁 →「註冊金鑰」→ 填好名稱、次數、群組、有效天數與伺服器網址 →「**建立並下載安裝檔**」。下載的 `endpoint-agent.msi` 已包好伺服器網址、註冊金鑰與根憑證：

- 手動安裝：`msiexec /i endpoint-agent.msi /qn`
- GPO：電腦設定 → 原則 → 軟體設定 → 軟體安裝，直接指定這個 MSI（放在只有網域電腦能讀取的共用資料夾）。

電腦的群組由註冊金鑰決定；平台管理員可以在裝置頁把電腦移到別的群組。

安裝檔內含註冊金鑰，請當成機密保管：
- Windows 會把安裝過的 MSI 快取在每台電腦的 `C:\Windows\Installer`，一般使用者讀得到裡面的金鑰。
- 因此從網頁下載安裝檔時，有效天數必填（最多 90 天）。
- **派送完成後，請在網頁作廢這把金鑰。**

伺服器網址必須是 `https://主機:埠`，主機須為 `ca-init` 時給的名稱之一。

沒有網頁時，可以用指令產生安裝檔：

```bash
EM_CA_DIR=deploy/pki endpoint-server agent-msi endpoint-agent-<版本>.msi out.msi https://em.example.com:8443 <金鑰>
```

- **升級**：直接安裝新版的通用範本 MSI，設定與註冊身分沿用。**升級順序：先升級伺服器，再升級 Agent。**
- **改伺服器網址**：直接安裝另一次下載的安裝檔，會取代原本的安裝（同版本也可以）。已註冊的電腦沿用原本的身分與群組（群組請在網頁移動）。
- **同一群電腦只用一個派送來源。** GPO 指派了安裝檔 A、又手動裝了另一個下載的 B 時，B 會取代 A，GPO 下次開機又裝回 A，兩者會一直互換。要改用新安裝檔時，請把 GPO 改指向新的 MSI。
- **解除安裝**會刪除 `C:\ProgramData\EndpointManager`（含裝置憑證）；之後重新安裝，需在網頁核准重新註冊。
- **資料目錄只放 Agent 自己的檔案。** 權限被改、被換成 junction，或出現子目錄時，服務會拒絕啟動（結束代碼 2，原因寫在事件檢視器）。重新安裝時會整個重建；已註冊的電腦需要新的註冊金鑰，並在網頁核准重新註冊。

Agent 的檔案（`C:\ProgramData\EndpointManager`，可用 `EM_AGENT_DIR` 覆寫，只有 SYSTEM 與 Administrators 能存取）：

- `config.json`：伺服器網址與註冊金鑰；註冊成功後金鑰會被清除。
- `root.pem`：根 CA 憑證。
- `state.json`：裝置身分與私鑰。
- `commands.json`：遠端指令的執行紀錄，用來去重。

命令列：

| 指令 | 用途 |
|---|---|
| `endpoint-agent service` | 由 Windows 服務啟動 |
| `endpoint-agent run` | 主控台模式（開發／除錯），Ctrl+C 結束 |
| `endpoint-agent configure`／`unconfigure` | 由 MSI 在安裝／解除安裝時呼叫，一般不需手動執行 |

### 4. 分點快取（選用）

設定流程：
1. 在管理網頁「據點與快取」建立據點（網段）。
2. 在「快取」分頁建立快取註冊金鑰。
3. 在快取主機上執行 `enroll`。
4. 回到網頁核准，並指定這台快取服務的據點。

#### Windows

以系統管理員的命令列執行。`enroll` 會把資料目錄 `%ProgramData%\EndpointManager\Cache` 的權限限制為 SYSTEM 與 Administrators。

```bat
mkdir "C:\Program Files\EndpointManager"
copy endpoint-cache.exe "C:\Program Files\EndpointManager\"
"C:\Program Files\EndpointManager\endpoint-cache.exe" enroll --server https://em.example.com:8443 --root root.pem ^
    --token <快取金鑰> --name 台北快取 --url https://cache-tp.example.com:8443 --dns cache-tp.example.com,10.1.2.3
sc.exe create EndpointManagerCache binPath= "\"C:\Program Files\EndpointManager\endpoint-cache.exe\" service" start= auto
sc.exe failure EndpointManagerCache reset= 86400 actions= restart/60000/restart/60000/restart/60000
sc.exe failureflag EndpointManagerCache 1
sc.exe start EndpointManagerCache
```

- `--url` 的主機必須在 `--dns` 裡，而且不能是中央伺服器的名稱。端點用這個網址連快取，並以快取憑證上的名稱驗證。
- `binPath` 裡的路徑要用 `\"…\"` 包起來。路徑有空白又沒加引號時，Windows 會先嘗試執行 `C:\Program.exe`（未加引號的服務路徑弱點）。
- 核准前，服務每 30 秒向中央詢問一次；核准後才開始提供下載。記錄檔是資料目錄的 `cache.log`。
- `sc.exe failureflag … 1` 讓服務異常結束時也會自動重新啟動。

#### Linux

```bash
sudo useradd --system --no-create-home endpoint-cache
sudo install -d -o endpoint-cache -m 0700 /var/lib/endpoint-cache
sudo install -m 0755 endpoint-cache /usr/local/bin/
# endpoint-cache 帳號讀不到你家目錄的檔案：先把 root.pem 放到它讀得到的位置
sudo install -m 0644 root.pem /var/lib/endpoint-cache/root-in.pem
sudo -u endpoint-cache endpoint-cache enroll --data-dir /var/lib/endpoint-cache \
    --server https://em.example.com:8443 --root /var/lib/endpoint-cache/root-in.pem --token <快取金鑰> \
    --name 台北快取 --url https://cache-tp.example.com:8443 --dns cache-tp.example.com
sudo install -m 0644 deploy/endpoint-cache.service /etc/systemd/system/
sudo systemctl enable --now endpoint-cache
```

- 在 `config.json` 指定其他儲存目錄（`storage_dir`）時，要在 unit 加上 `ReadWritePaths=<目錄>`，因為 unit 使用 `ProtectSystem=strict`。
- 要監聽 1024 以下的連接埠時，取消 unit 中 `AmbientCapabilities=CAP_NET_BIND_SERVICE` 的註解。

#### Docker

```bash
docker build -f deploy/cache.Dockerfile -t endpoint-cache .
docker volume create endpoint-cache-data
docker run --rm -v endpoint-cache-data:/data -v "$PWD/root.pem:/root.pem:ro" endpoint-cache \
    enroll --data-dir /data --server https://em.example.com:8443 --root /root.pem --token <快取金鑰> \
    --name 台北快取 --url https://cache-tp.example.com:8443 --dns cache-tp.example.com
docker run -d --restart unless-stopped -p 8443:8443 -v endpoint-cache-data:/data endpoint-cache
```

容器以 uid 65532 執行。改用主機目錄時，先執行 `sudo chown 65532:65532 <目錄>`，並把權限設為 0700。

## 功能說明

### 管理網頁與角色

管理網頁左側是功能選單，頂端有裝置搜尋（`Ctrl+K`）與深色／淺色主題切換。

| 角色 | 權限 |
|---|---|
| 平台管理員 | 全部電腦；帳號、群組、據點、腳本、稽核記錄 |
| 群組管理員 | 只看得到、只管理被指派群組的電腦：除役、核准重新註冊、建立該群組的註冊金鑰、下遠端指令 |
| 唯讀檢視者 | 只能檢視被指派群組的電腦 |

同一台電腦重灌後重新註冊，會列在總覽的「待核准」，需要管理員核准後才會接手原裝置的記錄。

### 合規

「合規」頁（`/compliance`）以已收集的盤點資料檢查每台電腦。

- **規則**（平台管理員建立）：
  - 禁止軟體：可加「只禁止低於某版本」。
  - 必要軟體：可設最低版本。
  - 軟體白名單。
  - 最低組建號：作業系統主號，或「組建＋最低 UBR」，例如 22631.4317。
  - 必要 KB。
- **比對方式**：名稱與發行者用 `*` 萬用字元，不分大小寫。版本逐段比較，所以 `10.0.9` 小於 `10.0.10`。
- **套用範圍**：預設全部電腦，可以限定或排除群組。被規則引用的群組不能刪除。
- **結果**：
  - 分為違規、未知（資料不足以判斷）、豁免。
  - 豁免由平台管理員在裝置頁的「合規」分頁設定，必填原因與有效天數，最長 365 天。
- **歷程與 CSV**：
  - 違規新增、解除都會記錄在歷程，預設保留 365 天（設定 `violation_history_days`）。
  - 「未知」的出現與消失不記錄（例如規則剛上線、資料還沒收集時），但「未知 → 違規」會記錄。
  - 違規清單可以匯出 CSV。欄位以 `= + - @` 開頭時會加 `'`，避免 Excel 當成公式執行。
- **通知**（`/compliance/notify`）：
  - 違規新增或解除時，依彙整間隔呼叫一次 Webhook，可以串接 SIEM、Teams 等。
  - 第一次啟用時從當下開始送，不會補送舊事件。
  - Webhook 只接受 `https://`，不跟隨重新導向。
  - 設定 `EM_WEBHOOK_SECRET` 後，每個請求帶兩個標頭：
    - `X-EM-Timestamp`：送出時間（Unix 秒）。
    - `X-EM-Signature: sha256=<hex>`：以密鑰對「時間戳記 + `.` + 內文」算出的 HMAC-SHA256。

    接收端應驗證簽章，並拒絕時間戳記與現在相差超過 5 分鐘的請求。

#### 組態基準

除了軟體與修補，另有七種組態規則：

- **登錄檔值**：指定 HKLM 下的路徑與值名稱。比對方式有等於、不等於、大於等於、小於等於、包含、存在、不存在；可以設定「未設定時視為符合」。
- **服務**：指定服務必須停用或必須執行中。
- **防火牆**：網域、私人、公用設定檔必須啟用。
- **BitLocker**：系統磁碟或所有固定磁碟必須保護中。
- **Defender**：即時保護、防竄改、病毒碼幾天內更新。
- **密碼原則**：本機帳號的最短長度、最長使用天數、鎖定門檻。
- **本機管理員**：Administrators 群組只允許清單內的成員（可用 `*` 萬用字元，也可比對 SID，例如 `*-500`）。

「合規 → 範本」有 22 條內建範本，例如 SMBv1、NTLMv2、LSA 保護、UAC，每條都附 Microsoft 文件出處。

登錄檔讀取的限制：

- Agent 只讀取規則需要的值，清單由伺服器在報到時下發。
- 只能讀 HKLM。SAM、SECURITY 子樹與 Winlogon 的自動登入密碼一律拒絕，Agent 與伺服器各檢查一次。
- 所有啟用中的登錄檔規則加起來，最多 `registry_max_values` 個不同的值（預設 1000，最高 5000）。
- 容量：規則上線後的全量重算，每秒約寫 67,000 筆結果（裝置數 × 規則數）。詳見 [docs/loadtest.md](docs/loadtest.md)。

組態規則需要 Agent 0.3.0 以上，舊版 Agent 的結果為「未知」。

### 軟體派送

「派送」頁（`/deployments`）以**期望狀態**派送 MSI／EXE，例如「這些群組要裝 X」或「必須移除 Y」。新加入範圍的電腦會自動補裝，被使用者移除的軟體會在下一次檢查時重新安裝。

- **套件**（平台管理員）：上傳 .msi／.exe，最大 2 GiB。
  - MSI 會自動讀出名稱、版本、發行者與 ProductCode。安裝固定用 `msiexec /i … /qn /norestart`，移除以 ProductCode 執行。
  - EXE 要填靜默安裝參數；要能移除時，再填移除參數。
  - **偵測規則**（名稱、發行者、最低版本）用來判斷是否已安裝。安裝程式回報成功、卻偵測不到時，算失敗。
- **派送**：
  - 選擇套件、安裝或移除，以及範圍（包含／排除群組）。
  - 可以設**試點群組**：先只派送給試點群組，確認沒問題後再擴大到全部。
  - **自動暫停**：失敗率超過門檻（預設 10%，至少 20 台有結果）時自動暫停。
- **Agent 的行為**：
  - 一次處理一個派送。
  - 只執行大小與 SHA-256 都相符的檔案。
  - 超過 60 分鐘就結束整個安裝程式的程序樹。
  - 結束碼 3010／1641 記為「成功（待重開機）」，**不會自動重新開機**。
  - 失敗後 24 小時再試，同一輪最多 3 次。

需要 Agent 0.4.0 以上。

### 分點快取的行為

- **據點**以網段（CIDR）定義。端點報到時，依回報的本機 IP 對應據點；網段重疊時，前綴最長的優先。
- **端點遇到快取無法使用時**，依據點設定處理：
  - 「快取無法使用時改向中央下載」：勾選時，端點改向中央下載（之後 5 分鐘內都直接向中央）。
  - 不勾選時，端點等快取恢復，適合 WAN 頻寬很小的據點。
  - 快取回 503（忙碌）時，一律照 `Retry-After` 稍後再試。
- **快取本身**：
  - 每 60 秒向中央報到，並依序預先下載所有進行中派送用到的套件。
  - 端點要的套件不在本機時，立即向中央下載；同一個檔案只下載一次。
  - 每個下載請求都向中央確認這台端點是否被指派，結果保存 5 分鐘。中央連不上時，5 分鐘內允許過的端點繼續服務，其他回 503。
- **頻寬與磁碟**：頻寬上限只限制快取的預先下載；磁碟超過上限時，從最久沒用的套件開始刪除。

需要 Agent 0.7.0 以上。

### Windows Update 控制

「Windows Update」頁（`/updates`）依群組設定 Windows Update for Business 原則。Agent 把原則寫入 `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` 並回報結果；更新本身仍由 Windows Update 或 WSUS 提供。

- **可設定的項目**：品質／功能更新延後天數、期限與寬限期、寬限期結束前不自動重開機、使用中時段，以及暫停（Windows 最多暫停 35 天）。
- **群組**：
  - 一個群組只能屬於一個原則。
  - 沒有原則的群組，Agent 完全不改動 Windows Update 設定。
- **與 GPO 的關係**：受管群組的電腦不要再用 GPO 管 Windows Update。Agent 發現自己寫入的值被改掉時，回報「衝突」並停止覆寫。
- **移出範圍**：原則刪除或裝置換群組時，Agent 只刪除自己寫過、而且沒被改過的值。
- **相關合規規則**：「太久沒更新」「待重開機太久」「更新原則衝突」。這三種依 Agent 每 24 小時一次的回報判定，所以連線中的電腦跨過門檻後，**最晚約一天**才會出現違規。

需要伺服器與 Agent 都在 0.5.0 以上。

### 遠端指令

「遠端指令」頁（`/commands`）與裝置頁的「遠端指令」分頁，可以對單台或整個群組下指令。指令在裝置**下次報到時**送達。

- **固定動作**：
  - 重新收集盤點、立即套用派送與原則。
  - 重新開機、關機：延遲 0–60 分鐘，會通知登入的使用者。
- **腳本**（只限平台管理員）：
  - PowerShell 腳本以 **SYSTEM** 用 Windows PowerShell 5.1 執行。
  - 收回結束碼與最後 64 KiB 的輸出；逾時（1–120 分鐘）時結束整個程序樹。
  - 預設需要**另一位平台管理員核准**，核准的是特定 SHA-256 的版本。
  - Agent 執行前會再驗證一次 SHA-256。
- **過期**：指令可設 1 小時到 30 天後過期，過期前沒報到的裝置不會執行。
- **不重複執行**：Agent 依本機的 `commands.json` 去重，同一個指令不會執行兩次。但這個檔案遺失時，還沒過期的指令可能再執行一次，所以**腳本請設計成可以重複執行**。

需要伺服器與 Agent 都在 0.6.0 以上。

## 開發

需要 Rust stable 與 PostgreSQL 17。

```bash
docker run -d --name em-postgres -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5432:5432 postgres:17
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres
cargo test --workspace
```

在本機執行伺服器：

```bash
cargo run -p endpoint-server -- ca-init ./pki localhost
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/endpoint_manager
echo '<密碼>' | cargo run -p endpoint-server -- admin-create admin
cargo run -p endpoint-server -- token-create pilot 10 台北總部 30
cargo run -p endpoint-server -- serve
```

Windows 內建的 curl（Schannel）測試時，要加 `--ssl-no-revoke`：

```bash
curl --ssl-no-revoke --cacert pki/root.pem https://localhost:8443/healthz
```

專案結構：

| 路徑 | 內容 |
|---|---|
| `crates/protocol` | Agent、快取與伺服器共用的資料格式 |
| `crates/server` | 中央伺服器：Agent API、管理網頁（askama 範本、`static/` 下的 CSS／JS）、背景工作 |
| `crates/agent` | Windows Agent |
| `crates/cache` | 分點快取 |
| `installer/` | Agent 的 WiX 安裝檔 |
| `deploy/` | Dockerfile、Docker Compose、systemd unit |
| `tools/loadsim` | 負載測試工具，見 [docs/loadtest.md](docs/loadtest.md) |
| `docs/superpowers/specs/` | 設計文件 |

### 自行建置範本 MSI

需要 .NET SDK 與 WiX v5。WiX 從 v6 起對營利組織收取 Open Source Maintenance Fee，所以本專案固定使用 v5。

```powershell
dotnet tool install --global wix --version 5.0.2
.\installer\build.ps1        # 產生 target\endpoint-agent-<版本>.msi
```

程式碼簽章：先建置並簽署 `endpoint-agent.exe`，再加上 `-NoCargo` 包成 MSI。

```powershell
cargo build --release -p endpoint-agent
signtool sign /fd SHA256 /tr <時間戳記伺服器> /td SHA256 /sha1 <憑證指紋> target\release\endpoint-agent.exe
.\installer\build.ps1 -NoCargo
```

網頁產生的安裝檔改寫過 MSI 內容，所以 MSI 本身不帶簽章；其中的 `endpoint-agent.exe` 簽章仍然有效。
