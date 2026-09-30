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

## 合規

管理網頁的「合規」頁（`/compliance`）以已收集的盤點資料檢查每台電腦：

- **規則**（平台管理員建立）：
  - 禁止軟體：可加「只禁止低於某版本」。
  - 必要軟體：可設最低版本。
  - 軟體白名單。
  - 最低組建號：作業系統主號，或「組建＋最低 UBR」，例如 22631.4317。
  - 必要 KB。
- **比對方式**：名稱與發行者用 `*` 萬用字元、不分大小寫。版本逐段比較，所以 `10.0.9` 小於 `10.0.10`。
- **套用範圍**：預設全部電腦，可限定或排除群組。被規則引用的群組不能刪除。
- **結果**：分違規、未知（資料不足以判斷）、豁免。豁免由平台管理員在裝置頁的「合規」分頁設定，必填原因與有效天數，最長 365 天。
- **違規歷程與 CSV**：
  - 違規新增、解除都會記錄在歷程，預設保留 365 天（設定 `violation_history_days`）。「未知」的出現與消失不記錄（例如規則剛上線、資料還沒收集時），但「未知 → 違規」會記錄。
  - 違規清單可匯出 CSV。欄位以 `= + - @` 開頭時會加 `'`，避免 Excel 當公式執行。
- **通知**（`/compliance/notify`）：違規新增或解除時，依彙整間隔呼叫一次 Webhook，可串接 SIEM、Teams 等。第一次啟用時從當下開始送，不會補送舊事件。Email 通知尚未提供。

Webhook 只接受 `https://`，不跟隨重新導向。簽章密鑰只放環境變數 `EM_WEBHOOK_SECRET`。設定密鑰後，每個請求會帶兩個標頭：

- `X-EM-Timestamp`：送出時間（Unix 秒）。
- `X-EM-Signature: sha256=<hex>`：以密鑰對「時間戳記 + `.` + 內文」算出的 HMAC-SHA256。

接收端應驗證簽章，並拒絕時間戳記與現在相差超過 5 分鐘的請求。

### 組態基準

除了軟體與修補，另有七種組態規則：

- **登錄檔值**：指定 HKLM 下的路徑與值名稱，比對方式有等於、不等於、大於等於、小於等於、包含、存在、不存在；可設「未設定時視為符合」。
- **服務**：指定服務必須停用或必須執行中。
- **防火牆**：網域、私人、公用設定檔必須啟用。
- **BitLocker**：系統磁碟或所有固定磁碟必須保護中。
- **Defender**：即時保護、防竄改、病毒碼幾天內更新。
- **密碼原則**：本機帳號的最短長度、最長使用天數、鎖定門檻。
- **本機管理員**：Administrators 群組只允許清單內的成員（`*` 萬用字元）。

規則頁的「從範本建立」有 22 條內建範本（SMBv1、NTLMv2、LSA 保護、UAC 等），每條都附 Microsoft 文件出處。同一範本只能建立一次，建立後可再修改。

登錄檔讀取的限制：

- Agent 只讀取規則需要的值，由伺服器在報到時下發清單。
- 只能讀 HKLM。拒絕 SAM、SECURITY 子樹與 Winlogon 的自動登入密碼，Agent 與伺服器各檢查一次。
- 所有啟用中的登錄檔規則加起來，最多 `registry_max_values` 個不同的值（預設 1000，最高 5000）。
- 容量：規則上線後的全量重算每秒約寫 67,000 筆結果（裝置數 × 規則數），5 分鐘約 2,000 萬筆，例如三萬台搭配約 670 條規則；超過時重算期間的結果會暫時是「未知」。重算同時處理的裝置數由 `EM_RECOMPUTE_CONCURRENCY` 設定（預設 4，最高 16）；調高會更快，但資料庫忙碌時會拖慢 Agent 報到。詳見 [docs/loadtest.md](docs/loadtest.md)。

裝置頁的「安全設定」分頁顯示防火牆、BitLocker、Defender、密碼原則與本機管理員；「登錄檔」頁（`/registry`）可查詢全公司某個值的分布。

組態規則需要 Agent 0.3.0 以上，舊版 Agent 的結果為「未知」。**升級順序：先升級伺服器，再升級 Agent。** Agent 會在伺服器支援時才送新的區段，伺服器降版時也會自動退回。

## 軟體派送

管理網頁的「派送」頁（`/deployments`）以**期望狀態**派送 MSI／EXE：「這些群組要裝 X」或「必須移除 Y」。新加入範圍的電腦會自動補裝，被使用者移除的軟體會在下一次檢查時重新安裝。

- **套件**（`/packages`，平台管理員）：上傳 .msi／.exe（最大 2 GiB）。
  - MSI 會自動讀出名稱、版本、發行者與 ProductCode；安裝固定用 `msiexec /i … /qn /norestart`，移除以 ProductCode 執行。
  - EXE 要填靜默安裝參數，要能移除時再填移除參數。
  - **偵測規則**（名稱、發行者、最低版本）用來判斷是否已安裝：安裝程式回報成功但偵測不到時算失敗。
- **派送**（平台管理員建立）：選套件、安裝或移除、範圍（包含／排除群組）。
  - **試點群組**：先只派送給試點群組，確認後按「擴大到全部」。
  - **自動暫停**：失敗率超過門檻（預設 10%，至少 20 台有結果）時自動暫停。先排除原因再按「重試失敗」，失敗的裝置會重新嘗試。
  - 群組管理員可以看派送狀態，但台數與裝置只含自己範圍內的裝置。
- **Agent 的行為**：
  - 每次報到取得「這台該執行的派送」，在背景一次處理一個，不影響報到與盤點。
  - 只執行大小與 SHA-256 都相符的檔案；安裝檔存在 Agent 資料目錄（只有 SYSTEM 與 Administrators 能寫入），執行後刪除。
  - 超過 60 分鐘就結束整個安裝程式的程序樹；結束碼 3010／1641 記為「成功（待重開機）」，**不會自動重新開機**。
  - 失敗後 24 小時再試，同一輪最多 3 次；安裝途中服務被停止或電腦重開機也算一次。
  - 伺服器忙碌（同時下載數用完）時依 `Retry-After` 稍後再下載。
- **設定**：
  - `EM_PACKAGE_DIR`：套件檔案目錄（Docker Compose 為 `packages` volume）。
  - `EM_DOWNLOAD_CONCURRENCY`：同時下載的上限（預設 50）；超過時回 503，Agent 稍後再試。
- 派送需要 Agent 0.4.0 以上；舊版 Agent 會忽略派送。

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
- 派送的套件檔案存在 `packages` volume，備份資料庫時一併備份。

## 安裝 Agent

管理網頁 →「註冊金鑰」→ 填好名稱、次數、群組、有效天數與伺服器網址 →「**建立並下載安裝檔**」。下載的 `endpoint-agent.msi` 已包好伺服器網址、註冊金鑰與根憑證：

- 手動安裝：`msiexec /i endpoint-agent.msi /qn`
- GPO：電腦設定 → 原則 → 軟體設定 → 軟體安裝，直接指定這個 MSI（放在只有網域電腦能讀取的共用資料夾）。

安裝檔內含註冊金鑰，請當成機密保管。Windows 會把安裝過的 MSI 快取在每台電腦的 `C:\Windows\Installer`，一般使用者讀得到裡面的金鑰，所以從網頁下載安裝檔時有效天數必填（最多 90 天），**派送完成後請在網頁作廢這把金鑰**。伺服器網址必須是 `https://主機:埠`（主機須為 `ca-init` 時給的名稱之一）。沒有網頁時可用指令產生：

```bash
EM_CA_DIR=deploy/pki endpoint-server agent-msi endpoint-agent-<版本>.msi out.msi https://em.example.com:8443 <金鑰>
```

- 升級：直接安裝新版的通用範本 MSI，設定與註冊身分沿用。
- 要改伺服器網址：直接安裝另一次下載的安裝檔，會取代原本的安裝（同版本也可以）。已註冊的電腦沿用原本的身分與群組（群組請在網頁移動）。
- 同一群電腦只用一個派送來源：GPO 指派了安裝檔 A，又手動裝了另一個下載的 B，B 會取代 A，GPO 下次開機又裝回 A，兩者會一直互換。要改用新安裝檔時，請把 GPO 改指向新的 MSI。
- 解除安裝會刪除 `C:\ProgramData\EndpointManager`（含裝置憑證）；之後重新安裝需在網頁核准重新註冊。
- 資料目錄只放 Agent 自己的檔案。權限被改、被換成 junction，或出現子目錄時，服務會拒絕啟動（結束代碼 2，原因寫在事件檢視器），重新安裝時會整個重建；已註冊的電腦需要新的註冊金鑰並在網頁核准重新註冊。

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
