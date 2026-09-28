# Endpoint Manager

企業 Windows 端點管理工具（開發中）。第一期：Agent 報到與資產盤點。

授權：GPL-3.0-only

## 建置與測試

需要 Rust stable 與 PostgreSQL 17，並設定 `DATABASE_URL`。

```bash
docker run -d --name em-postgres -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5432:5432 postgres:17
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres
cargo test --workspace
```

## 執行伺服器（開發用）

```bash
cargo run -p endpoint-server -- ca-init ./pki localhost
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/endpoint_manager
cargo run -p endpoint-server -- token-create pilot 10 台北總部 30
cargo run -p endpoint-server -- serve
```

`ca-init` 產生的 `root.key` 是根 CA 私鑰，請移到離線儲存媒體後從伺服器刪除。

設計文件：`docs/superpowers/specs/`

注意事項：

- Windows 上的 `DATABASE_URL` 請用 `127.0.0.1` 而非 `localhost`，否則每次連線會先嘗試 IPv6 多等約 2 秒。
- Windows 內建的 curl（Schannel）測試時要加 `--ssl-no-revoke`，例如：
  `curl --ssl-no-revoke --cacert pki/root.pem https://localhost:8443/healthz`

## Agent（Windows）

```powershell
cargo build -p endpoint-agent --release
```

Agent 目錄（預設 `C:\ProgramData\EndpointManager`，可用 `EM_AGENT_DIR` 覆寫）需要：

- `root.pem`：伺服器 `ca-init` 產生的根 CA 憑證
- `config.json`：`{"server_url": "https://<伺服器>:8443", "enroll_token": "<token-create 產生的金鑰>"}`

執行方式：

- `endpoint-agent run`：主控台模式（開發／除錯），Ctrl+C 結束
- `endpoint-agent service`：由 Windows 服務啟動；啟動時會把 Agent 目錄權限限縮為只有 SYSTEM 與 Administrators
- `endpoint-agent configure` / `unconfigure`：由 MSI 在安裝／解除安裝時呼叫（寫入設定與根憑證、設定服務失敗自動重啟／刪除資料目錄），一般不需手動執行

註冊成功後 `config.json` 中的 `enroll_token` 會被清除，裝置身分與私鑰存在 `state.json`。

## 管理網頁

伺服器同時在 `EM_WEB_LISTEN`（預設 `0.0.0.0:443`）提供 HTTPS 管理網頁，使用 `ca-init` 產生的伺服器憑證；瀏覽器需信任 `pki/root.pem`（或改用公司 CA 簽發的伺服器憑證）。

建立第一個平台管理員（密碼從標準輸入讀取，至少 12 字元）：

```bash
echo '<密碼>' | cargo run -p endpoint-server -- admin-create admin
```

### 角色與群組

- **平台管理員**：全部電腦、帳號、群組、稽核記錄。
- **群組管理員**：只看得到、只管理被指派群組的電腦（除役、核准重新註冊、建立該群組的註冊金鑰）。
- **唯讀檢視者**：只能檢視被指派群組的電腦。

電腦的群組由註冊時使用的金鑰決定；平台管理員可在裝置頁把電腦移到別的群組。

同一台電腦重灌後重新註冊，會列在儀表板「待核准」，需管理員核准後才會接手原裝置記錄。時間以 `EM_DISPLAY_UTC_OFFSET`（小時，預設 8）顯示。

## 部署伺服器（Docker Compose）

在 Linux 伺服器上：

```bash
cd deploy
cp .env.example .env          # 修改 EM_DB_PASSWORD 與 EM_AGENT_PUBLIC_URL
mkdir -p pki agent && sudo chown 65532:65532 pki   # 容器以 uid 65532 執行
docker compose build
docker run --rm -v "$PWD/pki:/pki" endpoint-manager-server ca-init /pki em.example.com
```

**把 `deploy/pki/root.key` 移到離線儲存媒體後從伺服器刪除。** `ca-init` 後面可以接多個名稱（網域名稱或 IP），Agent 連線用的網址必須是其中之一。

從 GitHub Release 下載 `endpoint-agent-<版本>.msi`（通用範本）放到 `deploy/agent/endpoint-agent.msi`，然後：

```bash
docker compose up -d
docker compose run --rm server admin-create admin    # 輸入第一個平台管理員的密碼
```

- 管理網頁：`https://<伺服器>/`（容器內 8444 對應主機 443），建議防火牆只開放給 IT 網段。
- Agent API：`https://<伺服器>:8443`，需開放給所有端點。
- `docker compose stop` 時伺服器會先寫出記憶體中的報到資料再結束。

## 安裝 Agent

管理網頁 →「註冊金鑰」→ 填好名稱、次數、群組、有效天數與伺服器網址 →「**建立並下載安裝檔**」。下載的 `endpoint-agent.msi` 已包好伺服器網址、註冊金鑰與根憑證：

- 手動安裝：`msiexec /i endpoint-agent.msi /qn`
- GPO：電腦設定 → 原則 → 軟體設定 → 軟體安裝，直接指定這個 MSI（放在只有網域電腦能讀取的共用資料夾）。

安裝檔內含註冊金鑰，請當成機密保管，設定可使用次數與有效天數，用完即作廢。沒有網頁時可用指令產生：

```bash
EM_CA_DIR=deploy/pki endpoint-server agent-msi endpoint-agent-<版本>.msi out.msi https://em.example.com:8443 <金鑰>
```

- 升級：直接安裝新版的通用範本 MSI，設定與註冊身分沿用。
- 同一版本已安裝時，要先解除安裝才能改裝另一個安裝檔。
- 解除安裝會刪除 `C:\ProgramData\EndpointManager`（含裝置憑證）；之後重新安裝需在網頁核准重新註冊。

### 自行建置範本 MSI

需要 .NET SDK 與 WiX v5（v6 起 WiX 對營利組織收取 Open Source Maintenance Fee，本專案固定使用 v5）：

```powershell
dotnet tool install --global wix --version 5.0.2
.\installer\build.ps1        # 產生 target\endpoint-agent-<版本>.msi
```

### 程式碼簽章

先建置並簽 `endpoint-agent.exe`，再以 `-NoCargo` 包成 MSI：

```powershell
cargo build --release -p endpoint-agent
signtool sign /fd SHA256 /tr <時間戳記伺服器> /td SHA256 /sha1 <憑證指紋> target\release\endpoint-agent.exe
.\installer\build.ps1 -NoCargo
```

網頁產生的安裝檔改寫過 MSI 內容，MSI 本身不帶簽章；其中的 `endpoint-agent.exe` 簽章仍然有效。

## 負載測試

`tools/loadsim` 模擬大量 Agent（註冊、心跳、上傳軟體清單），結果與重跑方法見 [docs/loadtest.md](docs/loadtest.md)。
