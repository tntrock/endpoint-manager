# Endpoint Manager

[![CI](https://github.com/tntrock/endpoint-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/tntrock/endpoint-manager/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/tntrock/endpoint-manager/graph/badge.svg)](https://codecov.io/gh/tntrock/endpoint-manager)
[![CodeQL](https://github.com/tntrock/endpoint-manager/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/tntrock/endpoint-manager/security/code-scanning)
[![Audit](https://github.com/tntrock/endpoint-manager/actions/workflows/audit.yml/badge.svg)](https://github.com/tntrock/endpoint-manager/actions/workflows/audit.yml)
[![Release](https://img.shields.io/github/v/release/tntrock/endpoint-manager)](https://github.com/tntrock/endpoint-manager/releases/latest)
[![License: GPL-3.0](https://img.shields.io/github/license/tntrock/endpoint-manager)](LICENSE)

企業端點管理工具（Windows 與 Linux）：資產盤點、合規檢查、軟體派送、Windows Update 控制、遠端指令，並可在分點放快取主機節省 WAN 頻寬。派送與 Windows Update 只適用 Windows；合規規則在 Linux 上只有容器規則。

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
| `endpoint-agent` | 每台受管的電腦：Windows（Windows 服務，以 SYSTEM 執行）或 x86_64 Linux（systemd 服務，以 root 執行） | 定期向中央報到、上傳盤點、取得要執行的派送／更新原則／遠端指令並回報結果。Linux 只有盤點與遠端指令。 |
| `endpoint-cache` | 分點的一台 Windows 或 Linux 主機（選用） | 向中央預先下載派送套件，提供給同據點的端點。端點仍直接向中央報到，只有**套件下載**改走快取。 |

設計重點：

- **所有連線都由端點往中央發起**（輪詢），中央不會主動連到端點。端點電腦不需要開任何對內的連接埠，也可以在 NAT 後面。
- 指令與派送在端點**下次報到時**送達，預設報到間隔 60 秒。平台管理員可以在「設定 → 報到與收集」調整報到間隔與各區段的收集間隔（報到最短 30 秒、收集最短 5 分鐘、最長都是 7 天），頁面會依裝置數量估算每秒報到次數。改動在各 Agent 下一次報到後生效，並寫入稽核記錄；「離線」的判斷（3 倍報到間隔）會跟著變。
- Agent 與快取都用中央發的用戶端憑證做 mTLS 認證，不需要網域帳號。

## 網路連線與連接埠

### 連線清單

| # | 來源 | 目的 | 連接埠 | 協定 | 用途 | 必要 |
|---|---|---|---|---|---|---|
| 1 | IT 管理員的瀏覽器 | 中央伺服器 | **TCP 443**（`EM_WEB_LISTEN`） | HTTPS | 管理網頁 | 必要 |
| 2 | 所有端點 | 中央伺服器 | **TCP 8443**（`EM_AGENT_LISTEN`） | HTTPS，註冊後為 mTLS | 註冊、報到、盤點、取得派送／原則／指令、回報結果、下載套件、憑證更新 | 必要 |
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
| | `GET /metrics` | Prometheus（需要 `EM_METRICS_TOKEN`，沒設定時回 404） |
| | `GET /login/oidc`、`GET /login/oidc/callback` | 瀏覽器（單一登入，沒設定時回 404） |

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

從 GitHub Release 下載 `endpoint-agent-<版本>.msi`（通用範本）放到 `deploy/agent/endpoint-agent.msi`。要管理 Linux 時，再把 `endpoint-agent_<版本>_amd64.deb`、`endpoint-agent-<版本>-1.x86_64.rpm` 改名為 `deploy/agent/endpoint-agent.deb`、`endpoint-agent.rpm`（用不到的可以不放）。然後：

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
- `./agent`：唯讀掛載的 MSI 範本與 Linux 安裝包。

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
| `EM_AGENT_DEB`、`EM_AGENT_RPM` | （空） | Linux agent 的 deb／rpm 路徑，原樣提供下載；沒設時註冊金鑰頁不顯示對應的下載按鈕 |
| `EM_PACKAGE_DIR` | `packages` | 派送套件的存放目錄 |
| `EM_DOWNLOAD_CONCURRENCY` | 50 | 同時下載套件的上限，超過時回 503，Agent 稍後再試 |
| `EM_ENROLL_PER_IP_PER_MINUTE` | 60 | 每個來源 IP 每分鐘的註冊次數上限 |
| `EM_RECOMPUTE_CONCURRENCY` | 4（最高 16） | 合規規則變更後全量重算時，同時處理的裝置數 |
| `EM_DISPLAY_UTC_OFFSET` | 8 | 管理網頁顯示時間用的時區（小時，-12～14） |
| `EM_WEBHOOK_SECRET` | （空） | 合規通知 Webhook 的 HMAC 簽章密鑰 |
| `EM_METRICS_TOKEN` | （空） | `/metrics` 的 Bearer 權杖，至少 32 字元；沒設定時不提供監控指標 |
| `EM_OIDC_ISSUER` 等 | （空） | 單一登入，見「單一登入（OIDC）」 |

### 3. 安裝 Agent

#### Windows

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

#### Linux

支援 x86_64、以 systemd 管理服務的發行版（Debian／Ubuntu 系列、RHEL／Rocky／Alma／Fedora 系列等）。執行檔是 musl 靜態連結，不依賴發行版的函式庫。

安裝包（GitHub Release 或 CI 的 `agent-linux` 產物）：

| 檔案 | 用途 |
|---|---|
| `endpoint-agent_<版本>_amd64.deb` | Debian／Ubuntu |
| `endpoint-agent-<版本>-1.x86_64.rpm` | RHEL 系列 |
| `endpoint-agent-<版本>-x86_64-linux.tar.gz` | 其他發行版、手動安裝 |

管理網頁 →「註冊金鑰」→ 填好名稱、次數、群組、有效天數與伺服器網址 →「**建立**」。頁面會出現「Linux 安裝」區塊：

1. deb／rpm 的下載按鈕（伺服器設定了 `EM_AGENT_DEB`／`EM_AGENT_RPM` 才有）。在自己的電腦下載後用 `scp` 複製到 Linux 電腦，所以 Linux 電腦不需要對外網路。
2. 安裝指令：`sudo apt install ./<檔名>.deb` 或 `sudo dnf install ./<檔名>.rpm`。安裝後服務已啟用，但還沒註冊前不會啟動。
3. 已填好伺服器網址、金鑰與根憑證的 `sudo endpoint-agent configure …` 指令，有複製按鈕。執行後會自動啟動服務，電腦隨即註冊並出現在後台。

這行指令含金鑰，會留在 shell 歷程。網頁上的指令開頭有一個空白，bash 預設（`HISTCONTROL=ignorespace`）不會記錄；**註冊完成後請在網頁作廢這把金鑰**。

金鑰只顯示這一次。沒有網頁時，`--root-ca` 的值是 `root.pem` 去掉頭尾兩行後接成的一行 base64：

```bash
sudo endpoint-agent configure --server-url https://em.example.com:8443 --token <金鑰> \
  --root-ca "$(grep -v -- ----- root.pem | tr -d '\n')"
```

- **升級**：安裝新版的 deb／rpm，設定與註冊身分沿用，服務自動重新啟動。**升級順序：先升級伺服器，再升級 Agent。**
- **移除**：`sudo apt remove endpoint-agent` 或 `sudo dnf remove endpoint-agent`。會停止服務並刪除資料目錄（含裝置憑證）；之後重新安裝，需在網頁核准重新註冊。
- **tar.gz**：把 `endpoint-agent` 放到 `/usr/bin`、`endpoint-agent.service` 放到 `/etc/systemd/system/`，執行 `systemctl daemon-reload && systemctl enable endpoint-agent`，再執行上面的 `configure`。
- **沒有 systemd**（例如 Alpine 的 OpenRC）：以 root 執行 `configure` 後，自行用該系統的服務管理常駐 `endpoint-agent run`。

Agent 的檔案（`/var/lib/endpoint-manager`，權限 0700、只有 root 能存取）與 Windows 版相同：`config.json`、`root.pem`、`state.json`、`commands.json`。

Linux 電腦與 Windows 的差異：

- 盤點：基本資訊、硬體、軟體（dpkg／rpm）、服務（systemd）、帳號與權限（可登入的帳號、誰有 root 權限，包括 sudoers 與非 root 的 UID 0）。不回報任何密碼雜湊。
- 遠端指令：重新收集、重新開機、關機、sh 腳本。PowerShell 腳本只派給 Windows，sh 腳本只派給 Linux；對群組下指令時會略過作業系統不符的電腦。
- 不參與軟體派送與 Windows Update 原則，也不會被算進這些頁面的統計。合規只套用容器規則（見「容器合規規則」），其他合規規則不檢查 Linux。

#### 容器、WSL 與虛擬機

Agent 會回報自己在哪裡執行，裝置頁與裝置清單會顯示，裝置清單也能依此篩選：

| 顯示 | 判斷方式 |
|---|---|
| 實體機／虛擬機（KVM、VMware、Hyper-V…） | Linux：`systemd-detect-virt --vm`，沒有時看 DMI 的製造商與型號；Windows：WMI 的製造商與型號 |
| 容器（docker、podman、lxc…） | `systemd-detect-virt --container`，或 `/.dockerenv`、`/run/.containerenv`、PID 1 的 `container=` |
| WSL 1／WSL 2 | 核心版本字串含 `microsoft` |

- **虛擬機**：在虛擬機裡安裝 Agent，管理方式與一般電腦相同。虛擬化主機上的 Agent 會列出還沒裝 Agent 的虛擬機（見下方「虛擬化主機上的虛擬機」）。
- **WSL**：在 WSL 裡安裝 Linux Agent 即可。WSL 2 啟用 systemd 時 Agent 以服務執行；沒有 systemd 時要自己啟動 Agent。
- **容器**：不建議把 Agent 裝在應用程式容器（Docker、Kubernetes 的 Pod）裡。容器重建時 Agent 的狀態目錄也會消失，除非 `/var/lib/endpoint-manager` 是持久卷，否則每次重建都會註冊成一台新裝置；裝置頁會提示這一點。請改把 Agent 裝在跑容器的主機上。LXC 這類系統容器有完整的作業系統，可以照一般 Linux 安裝。
- 容器與 WSL 讀到的 BIOS UUID 與序號屬於所在的主機，所以在容器與 WSL 裡的 Agent 註冊時不送這兩個值，不會被誤判成主機的重新註冊或疑似重複。

**主機上的容器**：Linux Agent 會列出主機上的容器，裝置頁出現「容器」分頁（有偵測到容器執行環境才顯示）。

| 執行環境 | 讀取方式 |
|---|---|
| Docker、Podman | `docker`／`podman` 的 `ps` 與 `inspect` |
| containerd（Kubernetes 節點） | `crictl ps` 與 `crictl inspect`，附上 Namespace 與 Pod |
| containerd（非 Kubernetes） | `nerdctl`，逐一命名空間（略過 Docker 自己的 `moby`） |
| Incus、LXD 系統容器 | `incus list`，沒有時 `lxc list`；虛擬機不列 |

- 列出名稱、映像、狀態、健康檢查、啟動時間、對外連接埠；特權容器、使用主機網路、掛載 docker.sock 或根目錄的容器會標示警示。
- 執行中的全部列出；已停止的只列 7 天內結束的；每台最多 500 個。
- 一般使用者的 rootless Podman 容器：只在該使用者有登入工作階段（`/run/user/<UID>` 存在）時看得到，最多讀 50 個使用者。
- **不收集**容器的環境變數、啟動參數與標籤（常含密碼）。
- 變更歷史與時間軸記錄容器的新增、移除與映像更換；啟動、停止不記。
- 看不到的情況：containerd 主機沒有裝 `crictl` 或 `nerdctl`；以一般使用者執行的 rootless Docker；`systemd-nspawn`、Firecracker 等其他執行環境。
- Kubernetes 的容器在變更歷史裡以「Namespace／容器名稱」記錄，Pod 名稱每次部署都會換，不會因為滾動更新記一堆新增與移除。
- **容器映像頁**（`/containers`，側欄「資產」）：依映像（不含版本標籤）統計主機數與執行中的容器數，可依名稱、執行環境、群組、只看執行中篩選；點進去列出每台主機上的容器，可排序。群組管理員只看得到範圍內的主機。
- 伺服器要先升級到支援的版本，Agent 才會開始回報容器（舊版伺服器不認得這個區段）。

**虛擬化主機上的虛擬機**：Agent 會列出主機上的虛擬機，裝置頁出現「虛擬機」分頁（有偵測到虛擬化平台才顯示）。

| 平台 | Agent | 讀取方式 |
|---|---|---|
| Hyper-V | Windows | WMI `rootirtualization2` |
| KVM／libvirt | Linux | `virsh list --all --uuid`、`virsh dominfo` |
| Proxmox VE | Linux | `qm list`、`qm config`；LXC 容器用 `pct list`、`pct config` |

- 列出名稱、平台、狀態（執行中、已關機、已暫停、已儲存狀態）、vCPU、記憶體與平台記錄的作業系統類型。每台主機最多 500 台，執行中的優先。不收集磁碟、主控台密碼與 cloud-init 資料。
- **對到已註冊的裝置**：以虛擬機的 BIOS UUID 比對客體 Agent 註冊時回報的 SMBIOS UUID。有些平台客體讀到的前三段位元組順序相反，兩種寫法都會比對。
  - 主機的「虛擬機」分頁：對到的顯示裝置連結，對不到的標示「未安裝 Agent」。Proxmox 的 LXC 容器沒有 BIOS UUID，標示「無法配對」。
  - 虛擬機的裝置頁顯示「執行於 <主機>」。
  - **虛擬機頁**（`/vms`，側欄「資產」）：列出所有主機的虛擬機，可依名稱、群組篩選，或只看執行中、未安裝 Agent 的虛擬機。
  - 總覽的「需要處理」會列出執行中、卻沒有對到任何裝置的虛擬機數量，也就是漏裝 Agent 的清單。
- 變更歷史記錄虛擬機的新增、移除與改名；開關機不記。
- **限制**：叢集環境中虛擬機會在主機間搬移，後台顯示的是最後回報的主機；同一台虛擬機剛搬移時，舊主機下次回報前兩邊都會列出。
- 伺服器要先升級到支援的版本，Agent 才會開始回報虛擬機。

**容器合規規則**（只檢查 Linux 裝置）：

| 規則 | 違規條件 |
|---|---|
| 禁止映像 | 有容器使用符合樣式的映像；預設只看執行中的容器 |
| 容器權限 | 執行中的容器是特權容器、使用主機網路，或掛載容器執行環境的 socket（`docker.sock`、`podman.sock`、`containerd.sock`、`crio.sock`），依勾選項目檢查；可設例外映像 |
| 映像未固定版本 | 執行中的容器的映像沒有版本標籤或標籤是 `latest`，而且沒有用 digest（`@sha256:…`）固定；可設例外映像。LXC／Incus 系統容器不檢查 |

- **映像樣式**用 `*` 萬用字元，不分大小寫。不寫版本標籤就比對所有版本；Docker Hub 的完整寫法也算，所以 `nginx` 同時符合 `nginx:1.27` 與 `docker.io/library/nginx:1.27`。
- 沒有回報容器資料的裝置（沒有容器執行環境，或舊版 Agent）**不適用**，不算違規也不算未知。
- 容器執行環境讀取失敗、又沒有找到符合的容器時是「未知」，附上錯誤訊息。
- Kubernetes 的容器（經 crictl 讀取）讀不到特權與主機網路設定，不計入這兩項檢查，違規細節會註明幾個無法判斷。
- 違規細節最多列出 20 個容器。有容器執行環境的 Linux 裝置頁會出現「合規」分頁與豁免設定。

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

#### 兩步驟驗證

**建議所有帳號都開啟**，尤其是平台管理員：平台管理員可以在所有電腦以 SYSTEM／root 執行腳本，帳號被盜的影響很大。

- **設定**：右上角帳號選單 →「兩步驟驗證」。
  - 用驗證器 App（Microsoft Authenticator、Google Authenticator 等）掃描 QR code，輸入 6 位數字後啟用。
  - 啟用時會顯示 10 組復原碼，**只顯示這一次**，請妥善保存。每組只能用一次，手機遺失時可以代替驗證碼登入。
- **登入**：密碼正確後再輸入驗證碼。驗證碼錯誤與密碼錯誤合計 5 次會鎖定 15 分鐘；同一個驗證碼不能重複使用。
- **伺服器時間**要正確（建議啟用 NTP）。驗證碼每 30 秒更換，伺服器與手機的時間只能相差約 30 秒。
- **要求所有帳號使用**（平台管理員，「帳號」頁上方）：開啟後，還沒設定的帳號登入後只能先完成設定。**開啟前請先設定好自己的帳號。**
- **手機遺失又沒有復原碼**：請平台管理員在帳號頁「重設兩步驟驗證」。所有平台管理員都無法登入時，在伺服器上執行：

  ```bash
  docker compose run --rm server admin-reset-mfa <帳號>
  ```

需要伺服器 0.9.0 以上。

#### 單一登入（OIDC）

可以用公司的身分提供者登入，例如 Microsoft Entra ID、Google Workspace、Keycloak、Okta 等支援 OpenID Connect 的系統。員工離職時，在公司的身分系統停用帳號，就不能再登入管理網頁。

1. **在身分提供者註冊應用程式**（Web 類型，機密用戶端），重新導向網址填 `https://<管理網頁>/login/oidc/callback`。
2. **設定伺服器的環境變數**後重新啟動：

   | 環境變數 | 說明 |
   |---|---|
   | `EM_OIDC_ISSUER` | Issuer，例如 Entra ID 是 `https://login.microsoftonline.com/<租戶 ID>/v2.0` |
   | `EM_OIDC_CLIENT_ID`、`EM_OIDC_CLIENT_SECRET` | 註冊的應用程式 |
   | `EM_OIDC_REDIRECT_URL` | 與第 1 步相同的網址 |
   | `EM_OIDC_USERNAME_CLAIM` | 用哪個欄位對應帳號名稱，預設 `email`。Entra ID 建議用 `preferred_username` |
   | `EM_OIDC_LABEL` | 登入頁按鈕的文字，預設「使用公司帳號登入」 |

3. **建立帳號**：在「帳號」頁建立名稱與公司帳號相同的帳號，例如 `alice@corp.example`，並指定角色與群組。單一登入**不會自動建立帳號**。
4. 使用者在登入頁按「使用公司帳號登入」。第一次登入時，帳號會和這個公司帳號綁定，之後只認綁定的公司帳號，即使對方改了 email 也一樣。

- **只用單一登入**：「帳號」頁可以設定「密碼登入只限平台管理員」。開啟後，其他帳號一定要走單一登入；平台管理員保留密碼登入，在身分提供者故障時使用。
- **兩步驟驗證**由身分提供者負責：單一登入不再要求本系統的驗證碼，「所有帳號都必須使用兩步驟驗證」也不套用在單一登入。請在身分提供者要求 MFA。
- **員工改用新的公司帳號**：在帳號頁「解除綁定」，下次單一登入時會綁定新的公司帳號。
- 伺服器要能連到身分提供者（HTTPS 443），使用系統信任的根憑證。

需要伺服器 0.10.0 以上。

Windows 與 Linux 裝置在同一份清單：

- **裝置列表**可以依作業系統篩選，Linux 裝置在作業系統欄位旁有標籤。
- **Linux 裝置頁**只顯示有資料的分頁：遠端指令、軟體、服務、帳號與權限、變更歷史；有容器執行環境時多出「容器」與「合規」（容器規則）。安全設定、派送、更新、修補只適用 Windows。
- **帳號與權限**分頁列出：
  - 管理權限名單：UID 0、sudo／wheel／admin 群組成員、sudoers 授權。root 以外的 UID 0 帳號會用紅色標示並排在最前面。
  - 可登入的帳號。
  - 看不懂的 sudoers 行，請人工確認。
- **軟體頁**預設只統計 Windows，可以切換成 Linux 或全部。Linux 的套件數量很多，混在一起會讓 Windows 的結果難以閱讀。

### 網路介面與多重連線

裝置頁的「網路」分頁列出每張網卡（Windows 與 Linux 都有）：名稱、種類、是否連線、位址、預設閘道、DNS，Wi-Fi 另列 SSID。

- **種類**：有線、Wi-Fi、行動網路（含手機 USB 分享）、VPN、虛擬。
  - Windows 依 WMI `MSFT_NetAdapter` 的介面類型與網卡描述判斷。
  - Linux 依 `/sys/class/net` 判斷，位址與閘道讀 `ip` 指令，DNS 讀 `resolvectl` 或 `/etc/resolv.conf`。
  - 沒有位址的虛擬網卡（例如 Docker 每個容器的 veth）不列出。
- **多重連線**：符合下列任一條件，分頁上方會標示並說明原因：
  1. 兩張以上已連線的實體網卡都有預設閘道。VPN 與虛擬網卡不算。
  2. 一張網卡的位址在某個據點的網段內，另一張網卡經由據點以外的閘道連線，例如公司網路加手機熱點。這需要先在「據點」設定網段。
- **本機監看與暫存**：Agent 在本機監看網卡變化，寫進狀態目錄的 `events.jsonl`，報到時一起送出，伺服器確認收到後才刪除。
  - Windows 由位址變更通知觸發，另外每 5 分鐘檢查一次；Linux 每 15 秒檢查一次。
  - 插上 4G 網卡幾分鐘就拔掉，即使剛好落在兩次報到之間也記得到；連不上伺服器時先存著，恢復後補送（每次最多 200 筆，還有剩就 5 秒後再送）。
  - 本機最多存 5,000 筆、30 天，超過就刪最舊的，後台的時間軸會註明有缺漏。
  - 伺服器依事件重播出每段多重連線的起訖時間，列在「網路」分頁的「多重連線紀錄」與時間軸。事件有缺漏時標示「可能不完整」。
  - 伺服器保留事件 180 天、已結束的多重連線紀錄 365 天。
- **合規規則「多重連線」**：回溯期間內出現過多重連線就算違規。
  - 可以設定回溯天數（預設 7 天）、最短持續時間、例外網卡名稱（萬用字元）、例外網段，以及「只看公司網路＋外部網路」。
  - 例外是套用在每段期間開始時的網卡狀態上重新判斷，所以排除某張網卡之後，只靠它構成的期間就不算。
  - 期間結束並超過回溯天數後，自動恢復符合（每小時檢查一次）。修改據點網段時會重算。
  - 只套用到 Windows 裝置。
- **裝置清單篩選**：「多重連線（目前）」與「多重連線（7 天內）」，Windows 與 Linux 都適用。裝置頁的問題清單也會列出。
- **所有 IP**：
伺服器存下報到時回報的全部位址。裝置清單的 IP 欄顯示主要位址（有預設閘道的網卡上的第一個 IPv4），滑過顯示全部；搜尋任何一個位址都找得到這台裝置。
- 變更歷史與時間軸記錄網卡的新增、移除，以及種類、連線狀態、位址、閘道的改變。
- 伺服器要先升級到支援的版本，Agent 才會開始回報網路區段。

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
  - sh 腳本在 Linux 以 **root** 用 `/bin/sh` 執行；第一行是 `#!` 時改用該直譯器。環境變數只有固定的 `PATH`、`LANG=C.UTF-8` 與 `HOME=/root`。
  - 收回結束碼與最後 64 KiB 的輸出；逾時（1–120 分鐘）時結束整個程序樹。
  - 預設需要**另一位平台管理員核准**，核准的是特定 SHA-256 的版本。
  - Agent 執行前會再驗證一次 SHA-256。
- **過期**：指令可設 1 小時到 30 天後過期，過期前沒報到的裝置不會執行。
- **不重複執行**：Agent 依本機的 `commands.json` 去重，同一個指令不會執行兩次。但這個檔案遺失時，還沒過期的指令可能再執行一次，所以**腳本請設計成可以重複執行**。

需要伺服器與 Agent 都在 0.6.0 以上。

### 腳本與套件簽章（選用）

**用途**：中央伺服器被入侵時，端點仍然不會執行攻擊者的程式。

- 平常，端點會執行伺服器下發、且 SHA-256 相符的腳本與套件。這只能證明內容在傳送途中沒被改過。
- 伺服器或資料庫被入侵時，攻擊者可以自己「核准」腳本、上傳安裝檔。
- 開啟簽章後，端點**只執行由伺服器以外的金鑰簽章**的腳本與套件。簽章金鑰放在管理者自己的電腦，伺服器偽造不了簽章。

#### 1. 產生金鑰（在管理者的電腦）

從 GitHub Release 下載 `endpoint-sign`（Windows 用 `endpoint-sign.exe`，Linux 用 `endpoint-sign-<版本>-x86_64-linux`，下載後 `chmod +x`），然後執行：

```
endpoint-sign keygen sign-key-1.json     # 輸入兩次密語（至少 12 字元），印出公鑰與金鑰 ID
endpoint-sign keygen sign-key-2.json     # 第二把：離線備援
```

- 私鑰以密語加密。**金鑰檔放在離線媒體，密語另外保管**，兩者遺失任一個都無法再簽章。
- 建議一開始就設定兩把：一把日常用，一把鎖在保險箱。
- 第一版不支援線上換金鑰。要換金鑰時，需要重新設定所有端點。

#### 2. 設定端點信任的公鑰

公鑰**只能在端點本機設定**。伺服器改不了，伺服器產生的安裝檔也不會帶公鑰。

- **Windows**：安裝時加上 MSI 屬性 `SIGNING_KEYS`（逗號分隔），例如：

  ```
  msiexec /i endpoint-agent.msi /qn SIGNING_KEYS=公鑰1,公鑰2
  ```

  用 GPO 派送時，以 transform（.mst）設定這個屬性。之後升級沒帶這個屬性，就沿用原本的設定。

- **Linux**：

  ```
  sudo endpoint-agent configure --signing-key 公鑰1 --signing-key 公鑰2
  ```

公鑰格式錯誤會讓安裝失敗，不會默默變成「不要求簽章」。設定後，裝置頁會顯示「要求簽章：是」，並列出金鑰 ID。

#### 3. 簽章（每個腳本版本、每個套件各一次）

1. 在腳本詳細頁（**先核准**）或套件頁，按「下載簽章請求」。
2. 在管理者的電腦執行：

   ```
   endpoint-sign sign sign-key-1.json script-12-signing-request.json
   endpoint-sign sign sign-key-1.json package-7-signing-request.json --file 原廠安裝檔.exe
   ```

   工具做的事：
   - **腳本**：自己重新計算內容的雜湊，並印出全文，讓你確認簽的是什麼。
   - **套件**：用 `--file` 指定你從原廠取得的安裝檔，比對雜湊與大小。不指定時，等於相信伺服器上的檔案。
3. 把印出的簽章貼回頁面的「上傳簽章」。
   - 伺服器會用端點回報的公鑰先驗證一次，貼錯會立刻提示。
   - 還沒有端點回報公鑰時，只檢查格式。

**簽章會自動清除的情況**：

- 腳本：內容或逾時被修改。
- 套件：安裝參數、移除參數被修改。

這兩種情況都要重新簽章。已經建立的指令，保留建立當時的簽章。

#### 端點的行為

- 沒有簽章、簽章不符，或欄位被改過的腳本／套件：不執行，並回報「這台電腦要求簽章：…，未執行」。
- 套件的安裝與移除都會檢查簽章。
- 有端點要求簽章時，指令與派送表單會把未簽章的腳本或套件標成「未簽章」。

**不在簽章範圍內**：重新開機、關機、重新收集、立即套用，以及 Windows Update 原則。這些動作不能用來在端點執行程式。

伺服器仍然決定「哪些電腦執行哪個已簽章的內容」，所以只對**可以安全重複執行**的內容簽章。

需要伺服器與 Agent 都在 0.9.0 以上。

### 監控指標（Prometheus）

設定 `EM_METRICS_TOKEN`（至少 32 字元的隨機字串，例如 `openssl rand -hex 32`）後，管理網頁的連接埠會提供 `GET /metrics`：

```yaml
# prometheus.yml
scrape_configs:
  - job_name: endpoint-manager
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/em-metrics-token
    tls_config:
      ca_file: /etc/prometheus/em-root.pem   # 伺服器的根憑證 root.pem
    static_configs:
      - targets: ["em.example.com:443"]
```

- 只有統計數字，不含主機名稱、帳號等個別資料。不需要登入，也不受兩步驟驗證影響。
- 資料庫相關的數字每 15 秒更新一次，建議收集間隔 30 秒以上。

| 指標 | 說明 |
|---|---|
| `em_devices{os_family,status}` | 裝置數 |
| `em_devices_online{os_family}` | 在線的使用中裝置（最近 3 個報到週期內有報到） |
| `em_devices_violating` | 有合規違規的裝置數 |
| `em_command_targets_open{status}` | 尚未完成的指令目標 |
| `em_deployments{stage}`、`em_caches{status}`、`em_caches_stale` | 派送數、快取數，以及超過 5 分鐘沒報到的快取數 |
| `em_http_requests_total`、`em_http_request_duration_seconds` | 依連接埠（`agent`／`web`）與路由統計的請求數與處理時間 |
| `em_heartbeat_buffered`、`em_db_pool_connections` | 尚未寫入的報到數、資料庫連線數 |
| `em_table_rows_estimate{table}`、`em_database_size_bytes` | 主要資料表的估計列數、資料庫大小 |
| `em_retention_deleted_total{kind}`、`em_retention_last_success_timestamp_seconds` | 資料保留清除的列數、最近一次成功的時間 |
| `em_metrics_db_up` | 這次收集時資料庫查詢是否成功 |

告警範例：

```yaml
- alert: EndpointsOffline
  expr: sum(em_devices_online) < 0.8 * sum(em_devices{status="active"})
  for: 15m
- alert: CheckinSlow
  expr: histogram_quantile(0.95, sum by (le) (rate(em_http_request_duration_seconds_bucket{route="/v1/checkin"}[5m]))) > 1
  for: 10m
- alert: CacheDown
  expr: em_caches_stale > 0
  for: 10m
```

### 資料保留

平台管理員在「稽核記錄」頁的「資料保留」區塊設定，伺服器每小時清除一次：

| 資料 | 預設 | 可設定 |
|---|---|---|
| 遠端指令，以及每台的結果與輸出 | 180 天 | 0（永久保留）或 30–3650 天。只清除已經結束的指令 |
| 稽核記錄 | 永久保留 | 0（永久保留）或 365–3650 天 |

- 每次清除都會在稽核記錄留下一筆「清除過期資料」，記錄刪除的筆數。
- 盤點變更記錄固定保留 12 個月。合規違規歷程預設保留 365 天（設定 `violation_history_days`）。

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
| `crates/agent` | Agent（Windows 與 Linux） |
| `crates/cache` | 分點快取 |
| `crates/sign` | 簽章工具 `endpoint-sign`（金鑰與腳本／套件簽章） |
| `installer/` | Agent 的 WiX 安裝檔 |
| `packaging/linux/` | Linux Agent 的 systemd unit、deb 維護腳本與打包腳本（`build.sh`） |
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
