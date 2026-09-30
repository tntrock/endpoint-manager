# 負載測試（30,000 台模擬）

規格 §7 的兩項驗收標準，以 `tools/loadsim` 透過真實 API 測試（每次請求都新建 TLS 連線，與真實 Agent 相同）。

## 結果（2026-09-28）

| 項目 | 標準 | 結果 | |
|---|---|---|---|
| 註冊 30,000 台（同一把金鑰、並行 50） | — | 2 分 13 秒，0 錯誤 | |
| 心跳 500 次／秒，持續 120 秒 | p99 < 200ms、0 錯誤 | 59,999 次，p50 3.9ms、**p99 24ms**、最大 184ms，0 錯誤 | ✅ |
| 30,000 台各上傳 150 筆軟體清單 | 10 分鐘內、0 錯誤、無資料遺失 | **64 秒**，p50 138ms、p99 778ms，0 錯誤；30,000 台報到皆確認已存入，`device_software` = 4,500,000 列 | ✅ |

伺服器記錄：無 ERROR。WARN 為 sqlx 的慢查詢提示——註冊時 169 次（所有裝置共用同一把金鑰，`enroll_tokens.used_count` 同一列鎖住排隊）、上傳時 32 次 COMMIT 與 80 次取得連線超過 2 秒（連線池 32 條用滿）、心跳批次寫入 12,931 列一次 1.2 秒。

## 合規（2026-09-29）

30,000 台各有 150 筆軟體（未上傳修補與基本資料），套用 `tools/loadsim/rules.sql` 的 50 條規則：

- 禁止軟體 20 條：每台都命中。
- 必要軟體 20 條：約六成命中。
- 必要 KB 8 條、最低組建號 1 條：因為沒有資料，結果都是「未知」。
- 白名單 1 條：全部通過。

規則上線後共產生 870,000 筆違規、270,000 筆未知，並寫入 1,140,000 筆歷程。

| 項目 | 標準 | 結果 | |
|---|---|---|---|
| 規則上線後全量重算 30,000 台 | 5 分鐘內 | **258 秒** | ✅ |
| 重算期間心跳 500 次／秒，持續 120 秒 | p99 < 100ms | p50 4.8ms、**p99 19.8ms**、0 錯誤 | ✅ |
| 有 50 條規則時，上傳觸發的單台評估 | p99 < 20ms | p50 9.8ms、**p99 18.3ms**、最大 31ms | ✅ |

**先前的版本沒有達標。** 當時違規與歷程是逐筆寫入：規則上線時每台約有 38 筆結果，每台要跑約 80 次資料庫往返。結果重算 15 分鐘只完成 22,000 台，評估 p99 為 99ms。改成每種寫入一次批次送出（`UNNEST`）後才達標。

**餘裕不大。** 重算 258 秒接近 5 分鐘上限，評估 p99 18.3ms 也接近 20ms。規則或裝置再增加時，可考慮讓重算平行處理多台裝置，目前只用一條連線依序處理（計畫 11 已改為平行，見下方「組態基準」）。

評估耗時取自伺服器 debug 日誌（`compliance refresh elapsed_us`），不含 HTTP 與 TLS。沒有規則時同一項約為 p99 14ms，主要是寫入盤點資料本身的時間。

## 組態基準（第三期，2026-09-29）

30,000 台各有 150 筆軟體，套用 `tools/loadsim/config_rules.sql`：1,000 條登錄檔規則（每條一個值），加上防火牆、密碼原則規則各一條。`loadsim config` 讓每台先報到取得查詢清單，再上傳 `security` 與 1,000 個登錄檔值，最後以新雜湊報到確認。偶數台的值與規則不符、公用防火牆關閉；所有台的密碼最短長度都不足。

### 改善前（計畫 10）

| 項目 | 標準 | 結果 | |
|---|---|---|---|
| 規則上線後全量重算 30,000 台 | 5 分鐘內 | **1,280 秒（21 分 20 秒）** | ❌ |
| 重算期間心跳 500 次／秒，持續 120 秒 | p99 < 100ms | p50 5.6ms、p99 20.4ms、0 錯誤 | ✅ |
| 30,000 台上傳 `security` ＋ 1,000 個登錄檔值 | 0 錯誤、無資料遺失 | 1,286 秒，0 錯誤；全部確認已存入，`device_registry` = 30,000,000 列（6.5 GB） | ✅ |
| 上傳期間心跳 500 次／秒，持續 180 秒 | p99 < 100ms | p50 10.5ms、**p99 82.8ms**、最大 950ms、0 錯誤 | ✅ |
| 上傳觸發的單台評估（第一次上傳，每台約 1,000 筆結果由未知轉為符合或違規） | p99 < 20ms | p50 53ms、**p99 796ms**、最大 14.6 秒 | ❌ |
| 同上，資料不變時再上傳一次（5,000 台） | p99 < 20ms | p50 23ms、**p99 201ms** | ❌ |

結果數量正確：15,045,000 筆違規（15,000 台 × 1,000 個值＋15,000 台防火牆＋30,000 台密碼原則），沒有殘留的未知。

**兩項未達標，原因如下：**

- **全量重算慢。** 規則剛上線時，每台都還沒有這些值，所以每台產生 1,002 筆「未知」，共 30,060,000 筆結果與同樣數量的歷程事件。重算只用一條連線、一台一台處理，每秒約寫 23,000 筆。瓶頸在資料庫寫入，伺服器本身幾乎閒置（0.06 核）。
- **單台評估慢。** 每次上傳要重寫 1,000 列 `device_registry`，第一次上傳還要把 1,000 筆結果由未知改成符合或違規，並寫入 1,000 筆歷程。上傳期間有 469 次 COMMIT 超過 1 秒（sqlx 慢查詢警告），資料庫在 Docker Desktop 內，寫入量大時 COMMIT 會排隊。

**實測可承受的量（以 5 分鐘重算為準，同一台電腦）：** 全量重算的時間大致和「裝置數 × 規則數」成正比，約每秒 23,000 筆。5 分鐘內約能處理 700 萬筆，也就是三萬台搭配約 230 條規則，或每台 1,000 個值時約 7,000 台。

### 效能改善後（計畫 11，2026-09-30）

改善了三處：
- 全量重算平行處理多台裝置（`EM_RECOMPUTE_CONCURRENCY`，預設 4）。
- 「未知」的出現與消失不寫歷程。
- 登錄檔只寫入有變動的值。

| 項目 | 標準 | 改善前 | 改善後 | |
|---|---|---|---|---|
| 規則上線後全量重算 30,000 台 | 5 分鐘內 | 1,280 秒 | **446 秒（7 分 26 秒）** | ❌ |
| 重算期間心跳 500 次／秒，持續 120 秒 | p99 < 100ms | p99 20.4ms | p50 6.3ms、**p99 29.6ms**、0 錯誤 | ✅ |
| 30,000 台上傳 `security` ＋ 1,000 個登錄檔值 | 0 錯誤、無資料遺失 | 1,286 秒 | **1,220 秒**，0 錯誤；全部確認已存入，`device_registry` = 30,000,000 列 | ✅ |
| 上傳期間心跳 500 次／秒，持續 180 秒 | p99 < 100ms | p99 82.8ms | p50 8.8ms、**p99 40.8ms**、0 錯誤 | ✅ |
| 上傳觸發的單台評估：第一次上傳（每台約 1,000 筆結果由未知轉為符合或違規） | p99 < 20ms | p99 796ms | p50 38ms、**p99 684ms** | ❌ |
| 同上：資料不變時再上傳（5,000 台，並行 100） | p99 < 20ms | p99 201ms | p50 25ms、**p99 49ms** | ❌ |
| 同上：資料不變時再上傳（200 台，一次一台） | p99 < 20ms | — | p50 11.8ms、**p99 20.9ms** | ❌ |

歷程事件從 60,120,000 筆降為 15,045,000 筆，只剩「未知 → 違規」。違規數量與改善前相同，也是 15,045,000 筆。

**重算並行數的取捨（同一台電腦）：**

| `EM_RECOMPUTE_CONCURRENCY` | 全量重算 | 重算期間心跳 p99 |
|---|---|---|
| 1（改善前） | 1,280 秒 | 20.4ms |
| 4（預設） | 446 秒 | 29.6ms |
| 8 | 349 秒 | **594ms**（超過 100ms 標準） |

8 路時資料庫被佔滿，報到延遲會超標。報到延遲影響所有 Agent，所以預設用 4 路。

**仍未達標的部分：**

- **全量重算 446 秒。** 在這台電腦上，要壓到 5 分鐘內就得犧牲報到延遲。資料庫獨立一台、磁碟較快時可以把並行數調高。
- **單台評估。** 一次只處理一台時 p99 為 20.9ms，仍略超過 20ms 標準。並行 100 時，時間主要花在排隊：連線池只有 32 條，而且資料庫跟負載工具在同一台電腦。第一次上傳時每台有 1,000 筆結果同時改變，屬於一次性的尖峰。

**實測可承受的量（重算 5 分鐘、預設 4 路、同一台電腦）：** 全量重算每秒約寫 67,000 筆結果（裝置數 × 規則數），5 分鐘約 2,000 萬筆。以三萬台計，約可承受 670 條規則；每台 1,000 個值時約 20,000 台。

## 軟體派送（第四期，2026-09-30）

30,000 台，1 個 10 MB 套件、10 個派送（全部裝置），伺服器 `EM_DOWNLOAD_CONCURRENCY=50`。`loadsim deploy`（並行 60）讓每台報到取得 10 個指派，下載並驗證第一個套件的大小與 SHA-256（不寫磁碟），再回報 10 筆結果。

| 項目 | 標準 | 結果 | |
|---|---|---|---|
| 有 10 個派送時，心跳 500 次／秒，持續 60 秒 | p99 < 100ms | p50 6.0ms、**p99 22.2ms**、0 錯誤 | ✅ |
| 30,000 台各下載 10 MB 並回報 | 超過同時下載上限只回 503、沒有其他 5xx、全部回報成功 | **332 秒**，0 錯誤；503 重試 2 次；伺服器日誌沒有 ERROR；`deployment_status` = 30,000 筆成功＋270,000 筆已符合 | ✅ |
| 同時進行的心跳 500 次／秒，持續 180 秒（參考，非標準） | — | p99 1.35 秒 | |
| 同上，loadsim 並行 300（壓測同時下載上限） | 超過上限只回 503、沒有其他 5xx | **293 秒**，0 錯誤；503 重試 131 次，全部依 Retry-After 重試成功；伺服器日誌沒有 ERROR；300,000 筆結果正確 | ✅ |

下載期間的報到延遲變差：332 秒內傳輸約 300 GB（TLS），loadsim 與伺服器在同一台電腦搶 CPU。實際部署時伺服器與端點不在同一台，而且分點快取（之後的子專案）會分擔下載；需要時可以調低 `EM_DOWNLOAD_CONCURRENCY`，犧牲派送速度換取報到延遲。

## Windows Update 控制（第五期，2026-09-30）

30,000 台（每台 150 筆軟體），5 個群組各一個更新原則（品質更新延後 7 天、期限 3／寬限 2、使用中時段 8–18），所有裝置平均分到這 5 個群組；合規規則為 `rules.sql` 的 50 條。`loadsim updates`（並行 60）讓每台報到取得原則，再以 `PUT /v1/update-status` 回報一次狀態。

| 項目 | 標準 | 結果 | |
|---|---|---|---|
| 有 5 個原則時，心跳 500 次／秒，持續 120 秒 | p99 < 100ms | p50 5.0ms、**p99 17.8ms**、0 錯誤 | ✅ |
| 30,000 台報到並上傳狀態 | 沒有 5xx，全部寫入 | **46.6 秒**（644 台／秒），0 錯誤；`update_policy_status` = 30,000 筆；伺服器日誌沒有 ERROR | ✅ |
| 加入 3 條更新規則（`patch_age`、`reboot_pending`、`update_policy`）前後的全量重算 | 增加不超過 10% | 50 條 **58.0 秒** → 53 條 **57.9 秒**（沒有增加） | ✅ |

每次上傳狀態都會重新評估這台（和盤點上傳相同）；`loadsim updates` 量到的每台耗時（報到＋上傳狀態，含評估）p99 為 114ms，僅供參考。三種新規則只讀 `update_policy_status` 一列，重算成本可忽略。

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

合規部分：伺服器以 `RUST_LOG=info,endpoint_server::compliance=debug` 啟動並把日誌寫到檔案，完成一次 `upload` 後執行下面的指令：

```bash
docker exec -i em-postgres psql -U postgres -d em_load < ../../tools/loadsim/rules.sql   # 建立 50 條規則，觸發全量重算
./loadsim heartbeat --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --rate 500 --secs 120 --max-p99-ms 100
grep -a "compliance recompute finished" server.log        # elapsed_secs 為重算耗時
./loadsim upload    --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --items 150 --concurrency 100
sed -E "s/\x1b\[[0-9;]*m//g" server.log | grep "compliance refresh" | tail -n 30000 \
  | sed -E 's/.*elapsed_us=([0-9]+).*/\1/' | sort -n | awk '{a[NR]=$1} END {print "p99_us", a[int(NR*0.99)]}'
```

`heartbeat` 與 `upload` 未達標準時以非 0 結束（`--max-p99-ms`、`--max-secs` 可調）。`EM_ENROLL_PER_IP_PER_MINUTE` 只在測試環境調高；正式環境維持預設 60。

組態部分：在上面的步驟完成一次 `upload` 後執行下面的指令：

```bash
docker exec -i em-postgres psql -U postgres -d em_load < ../../tools/loadsim/config_rules.sql   # 1,002 條規則，觸發全量重算
./loadsim heartbeat --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --rate 500 --secs 120 --max-p99-ms 100
grep -a "compliance recompute finished" server.log        # 等重算完成，elapsed_secs 為重算耗時
./loadsim heartbeat ... --rate 500 --secs 180 --max-p99-ms 100 &                  # 同時量報到
./loadsim config    --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --concurrency 100 --max-secs 3600
```

單台評估的 p99 用和合規部分相同的指令，從 `config` 開始後的日誌計算。

派送部分：

```bash
./loadsim make-package --out pkg.bin --size-mb 10            # 印出 sha256 與大小
cp pkg.bin packages/<sha256>                                  # 伺服器的 EM_PACKAGE_DIR
docker exec -i em-postgres psql -U postgres -d em_load -v sha=<sha256> -v size=<大小> < ../../tools/loadsim/deploy_setup.sql
./loadsim heartbeat --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --rate 500 --secs 60 --max-p99-ms 100
./loadsim deploy    --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --concurrency 60
```

Windows Update 部分：在完成 `upload` 與 `rules.sql` 的重算後執行下面的指令：

```bash
docker exec -i em-postgres psql -U postgres -d em_load -v ON_ERROR_STOP=1 < ../../tools/loadsim/updates_setup.sql
./loadsim heartbeat --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --rate 500 --secs 120 --max-p99-ms 100
./loadsim updates   --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --concurrency 60
# 重算比較：先只 bump generation 量基準，再加入 3 條更新規則量一次
docker exec em-postgres psql -U postgres -d em_load -c "UPDATE compliance_state SET generation = generation + 1"
grep -a "compliance recompute finished" server.log
```
