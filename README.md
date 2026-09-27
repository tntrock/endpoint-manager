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
cargo run -p endpoint-server -- token-create pilot 10 IT 30
cargo run -p endpoint-server -- serve
```

`ca-init` 產生的 `root.key` 是根 CA 私鑰，請移到離線儲存媒體後從伺服器刪除。

設計文件：`docs/superpowers/specs/`

注意事項：

- Windows 上的 `DATABASE_URL` 請用 `127.0.0.1` 而非 `localhost`，否則每次連線會先嘗試 IPv6 多等約 2 秒。
- Windows 內建的 curl（Schannel）測試時要加 `--ssl-no-revoke`，例如：
  `curl --ssl-no-revoke --cacert pki/root.pem https://localhost:8443/healthz`
