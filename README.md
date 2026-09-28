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
- `endpoint-agent service`：由 Windows 服務啟動；啟動時會把 Agent 目錄權限限縮為只有 SYSTEM 與 Administrators（正式安裝由 MSI 設定，見計畫 4）

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
