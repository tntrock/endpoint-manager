# 負載測試（30,000 台模擬）

規格 §7 的兩項驗收標準，以 `tools/loadsim` 透過真實 API 測試（每次請求都新建 TLS 連線，與真實 Agent 相同）。

## 結果（2026-09-28）

| 項目 | 標準 | 結果 | |
|---|---|---|---|
| 註冊 30,000 台（同一把金鑰、並行 50） | — | 2 分 13 秒，0 錯誤 | |
| 心跳 500 次／秒，持續 120 秒 | p99 < 200ms、0 錯誤 | 59,999 次，p50 3.9ms、**p99 24ms**、最大 184ms，0 錯誤 | ✅ |
| 30,000 台各上傳 150 筆軟體清單 | 10 分鐘內、0 錯誤、無資料遺失 | **64 秒**，p50 138ms、p99 778ms，0 錯誤；30,000 台報到皆確認已存入，`device_software` = 4,500,000 列 | ✅ |

伺服器記錄：無 ERROR。WARN 為 sqlx 的慢查詢提示——註冊時 169 次（所有裝置共用同一把金鑰，`enroll_tokens.used_count` 同一列鎖住排隊）、上傳時 32 次 COMMIT 與 80 次取得連線超過 2 秒（連線池 32 條用滿）、心跳批次寫入 12,931 列一次 1.2 秒。

## 測試環境與限制

- Intel Core i5-12400（6 核 12 緒）、24GB、Windows 11 Home。
- 伺服器（release 版）、loadsim、PostgreSQL 17.11（Docker Desktop 容器）**全部在同一台電腦**：loadsim 的 TLS 交握與伺服器搶同一顆 CPU，資料庫也跑在 Docker Desktop 的虛擬機內，實際 Linux 伺服器的表現應該更好。
- 網路是本機迴路，沒有真實網路延遲。
- 模擬的軟體清單每台 150 筆、名稱在各台之間共用；心跳不帶區段 hash（伺服器每次都要求上傳，但 loadsim 不上傳，只量報到延遲）。

## 重跑方法

```bash
docker exec em-postgres psql -U postgres -c "CREATE DATABASE em_load"
cargo build --release -p endpoint-server -p loadsim
cd target/release
./endpoint-server ca-init pki 127.0.0.1
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/em_load EM_CA_DIR=pki \
       EM_AGENT_LISTEN=127.0.0.1:18443 EM_WEB_LISTEN=127.0.0.1:18444 EM_ENROLL_PER_IP_PER_MINUTE=1000000
./endpoint-server token-create loadsim 30000        # 記下金鑰
./endpoint-server serve &                            # 另開視窗亦可

./loadsim enroll    --server https://127.0.0.1:18443 --root pki/root.pem --token <金鑰> --count 30000 --out devices.json
./loadsim heartbeat --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --rate 500 --secs 120
./loadsim upload    --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --items 150 --concurrency 100
```

`heartbeat` 與 `upload` 未達標準時以非 0 結束（`--max-p99-ms`、`--max-secs` 可調）。`EM_ENROLL_PER_IP_PER_MINUTE` 只在測試環境調高；正式環境維持預設 60。
