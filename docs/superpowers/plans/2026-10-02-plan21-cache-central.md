# 計畫 21：分點快取（中央伺服器）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 中央伺服器端的分點快取支援：
- 據點與網段對應。
- 報到下發 `package_source`。
- 快取註冊與核准、簽發快取憑證。
- 給快取的三個 API：報到、下載、授權。
- 派送結果記錄下載來源。

**Architecture:**
- 協定型別放在新模組 `protocol::branch`。
- 伺服器新增模組 `crates/server/src/branch/`：
  - `sites.rs`：據點管理、`site_for`。
  - `assign.rs`：據點與快取的記憶體快取，依 generation 失效。
  - `caches.rs`：註冊、核准、狀態管理。
  - `api.rs`：快取用的 API 與 `AuthedCache` extractor。
- 快取憑證比照裝置：新表 `cache_certs` 以指紋辨識，舊憑證保留到原到期日。
- 裝置的下載授權抽成 `deploy::api::device_may_download`，中央下載與快取授權共用。

**Tech Stack:** Rust、axum、sqlx（PostgreSQL `inet`／`cidr` 以文字傳遞）、rcgen。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-10-02-branch-cache-design.md`

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 協定新欄位一律 `#[serde(default)]`。
- 快取憑證以**指紋**辨識，與 `AuthedDevice` 相同。規格 §2.1 寫的 `cert_serial` 改成 `cache_certs` 表，並同步修改規格。
- 快取 API 只接受狀態是 `active`、而且憑證有效（未撤銷、未過期）的快取。
- 快取註冊金鑰（`kind='cache'`）與裝置金鑰互相不能使用。
- 所有管理動作寫稽核紀錄，並讓 `branch_state.generation` 加 1。
- 測試指令：
  - `cargo test -p protocol`
  - `cargo test -p endpoint-server`
  - 完整測試：`cargo test --workspace -j 4`
  - 最後跑 clippy 和 fmt。

## Review Focus
1. 快取憑證不能當作裝置憑證：`AuthedDevice` 查的是 `device_certs`，快取的指紋不在裡面。同樣地，裝置憑證也不能呼叫快取 API。
2. 停用快取後，它的憑證立刻不能呼叫快取 API，報到也不再把它指派給端點。
3. `authorize` 必須與中央下載的規則完全一致：非使用中的裝置、已撤銷的憑證、未指派的套件都拒絕；暫停中的派送仍允許。
4. 端點回報多個 IP、其中一個符合據點時要能對應。網段重疊時，前綴最長的勝出。
5. 快取向中央下載時，只能拿到未停止派送用到的套件。

---

### Task 1：協定型別 `protocol::branch`

**Files:**
- Create：`crates/protocol/src/branch.rs`
- Modify：`crates/protocol/src/lib.rs`
  - 加 `pub mod branch;`。
  - `CheckinResponse` 加 `#[serde(default, skip_serializing_if = "Option::is_none")] pub package_source: Option<branch::PackageSource>`。
  - 這個檔案含 NUL 字元，要用 Python 編輯。
- Modify：`crates/protocol/src/deploy.rs`：`DeployResult` 加 `#[serde(default, skip_serializing_if = "Option::is_none")] pub source: Option<DownloadSource>`。
- Modify：`crates/server/src/checkin.rs`（暫時填 `package_source: None`），以及所有建立 `DeployResult` 的地方（Agent、loadsim、測試補 `source: None`）。

**Produces:**
```rust
pub struct PackageSource { pub cache_id: i64, pub url: String, pub fallback_to_central: bool }
#[serde(rename_all = "snake_case")] pub enum DownloadSource { Cache, Central, #[serde(other)] Unknown }
pub struct CacheEnrollRequest { pub token: String, pub name: String, pub url: String, pub dns_names: Vec<String>, pub csr_pem: String }
pub struct CacheEnrollResponse { pub cache_id: i64, pub poll_secret: String }
pub struct CacheEnrollPoll { pub cache_id: i64, pub poll_secret: String }
#[serde(rename_all = "snake_case")] pub enum CacheEnrollState { Pending, Approved, Rejected, #[serde(other)] Unknown }
pub struct CacheEnrollPollResponse { pub state: CacheEnrollState, #[serde(default)] pub certificate_chain_pem: Option<String>, #[serde(default)] pub root_pem: Option<String> }
pub struct CacheCheckin { pub version: String, pub disk_used_bytes: u64, pub stored: Vec<StoredPackage> }
pub struct StoredPackage { pub package_id: i64, pub size: u64 }
pub struct CachePackage { pub id: i64, pub sha256: String, pub size: u64 }
pub struct CacheCheckinResponse { pub packages: Vec<CachePackage>, pub bandwidth_limit_mbps: Option<u32>, pub disk_limit_gb: u32, pub renew_certificate: bool }
pub struct CacheAuthorize { pub device_cert_fingerprint: String, pub package_id: i64 }
pub struct CacheAuthorizeResponse { pub allowed: bool }
pub const MAX_STORED: usize = 10_000;
impl CacheEnrollRequest { pub fn validate(&self) -> Result<(), &'static str> }
// 驗證規則：
//   name：1–100 字，不能有控制字元
//   url：以 https:// 開頭，最多 300 字
//   dns_names：1–10 個，每個 1–253 字，只允許 [A-Za-z0-9.-:]（主機名稱或 IP）
//   csr_pem：最多 8 KiB
```

- [ ] **Step 1：寫失敗測試**（`branch.rs` 內）
  - 舊版 `CheckinResponse` 可以解析，`package_source` 是 None。
  - `DeployResult` 沒有 `source` 時可以解析；`"source":"cache"` 往返；未知值解析成 `Unknown`。
  - `CacheEnrollRequest::validate` 的邊界：
    - url 是 `http://` 時失敗。
    - dns 含空白時失敗。
    - 11 個 dns 失敗。
    - 名稱含 `\t` 失敗。
    - 正常值通過。
- [ ] **Step 2：** 執行 `cargo test -p protocol branch`，預期 FAIL。
- [ ] **Step 3：** 實作，並修改所有建構處讓它能編譯（`cargo build --workspace -j 4`）。
- [ ] **Step 4：** 執行 `cargo test -p protocol`，預期 PASS。
- [ ] **Step 5：** Commit「協定：分點快取型別」。

### Task 2：資料表、據點管理與報到下發

**Files:**
- Create：`crates/server/migrations/0016_branch_cache.sql`
- Create：`crates/server/src/branch/mod.rs`、`sites.rs`、`assign.rs`
- Modify：`crates/server/src/lib.rs`（`pub mod branch;`；`AppState` 加 `pub branch: Arc<branch::assign::BranchCache>`）、`checkin.rs`
- Test：`crates/server/tests/branch.rs`（新檔）

**Migration：**
```sql
CREATE TABLE sites (
    id                   BIGSERIAL PRIMARY KEY,
    name                 TEXT NOT NULL UNIQUE,
    cidrs                CIDR[] NOT NULL CHECK (cardinality(cidrs) > 0),
    fallback_to_central  BOOLEAN NOT NULL DEFAULT true,
    bandwidth_limit_mbps INT CHECK (bandwidth_limit_mbps > 0),
    disk_limit_gb        INT NOT NULL DEFAULT 100 CHECK (disk_limit_gb > 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE caches (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    site_id          BIGINT UNIQUE REFERENCES sites(id) ON DELETE SET NULL,
    url              TEXT NOT NULL,
    dns_names        TEXT[] NOT NULL,
    csr_pem          TEXT NOT NULL,
    poll_secret_hash TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled', 'rejected')),
    last_seen        TIMESTAMPTZ,
    version          TEXT,
    disk_used_bytes  BIGINT,
    enroll_token_id  BIGINT REFERENCES enroll_tokens(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE cache_certs (
    serial       TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL UNIQUE,
    cache_id     BIGINT NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
    not_after    TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE cache_packages (
    cache_id    BIGINT NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
    package_id  BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    size        BIGINT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cache_id, package_id)
);
ALTER TABLE enroll_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'device'
    CHECK (kind IN ('device', 'cache'));
ALTER TABLE deployment_status ADD COLUMN source TEXT CHECK (source IN ('cache', 'central'));
CREATE TABLE branch_state (generation BIGINT NOT NULL);
INSERT INTO branch_state VALUES (0);
```

**Produces:**
```rust
// sites.rs
pub struct SiteInput { pub name: String, pub cidrs: Vec<String>, pub fallback_to_central: bool, pub bandwidth_limit_mbps: Option<i32>, pub disk_limit_gb: i32 }
pub async fn create_site(pool, &SiteInput, actor: &str) -> anyhow::Result<i64>;
pub async fn update_site(pool, id, &SiteInput, actor: &str) -> anyhow::Result<()>;
pub async fn delete_site(pool, id, actor: &str) -> anyhow::Result<()>;
/// 正規化網段（主機位元清零，例如 10.1.2.3/16 → 10.1.0.0/16）；格式錯誤回 Err
pub fn parse_cidr(s: &str) -> anyhow::Result<(std::net::IpAddr, u8)>;
// assign.rs
pub struct SiteEntry { pub site_id: i64, pub cidrs: Vec<(IpAddr, u8)>, pub source: Option<PackageSource> }
pub struct BranchSet { pub generation: i64, pub sites: Vec<SiteEntry> }
impl BranchSet {
    /// 回報的 IP 中，被前綴最長的網段包含的據點；前綴長度相同時 site_id 小的優先
    pub fn site_for(&self, ips: &[IpAddr]) -> Option<&SiteEntry>;
    pub fn source_for(&self, ips: &[String]) -> Option<PackageSource>;  // 解析失敗的 IP 略過
}
#[derive(Default)] pub struct BranchCache { /* 比照 DeployCache：get / get_throttled / invalidate */ }
```

**規則：**
- **網段驗證**：
  - 每個網段用 `parse_cidr` 檢查，存成正規化後的字串，並去重。
  - 同一個網段已屬於其他據點時，回「網段 X 已屬於據點 Y」。
  - 名稱 1–100 字、不能有控制字元。
  - 磁碟上限 1–100000 GB、頻寬上限 1–100000 Mbps。
- **`source`**：該據點有 `status='active'` 的快取時，才有值：`PackageSource { cache_id, url, fallback_to_central }`。
- **報到**：
  - 使用中的裝置：`package_source = branch.source_for(&req.ip_addresses)`。
  - 非使用中的裝置：None。
- **稽核動作**：`site_create`、`site_update`、`site_delete`。每個異動都讓 generation 加 1。

- [ ] **Step 1：寫失敗測試**
  - `assign.rs` 單元測試：
    - `10.1.0.0/16` 與 `10.1.2.0/24` 重疊時，`10.1.2.5` 對應到 /24 的據點，`10.1.9.9` 對應到 /16。
    - IPv6 `fd00::/8` 可以對應。
    - 多個 IP 中只有第二個符合時，仍能對應。
    - 都不符合時是 None。
    - 前綴長度相同時，site_id 小的優先。
  - `parse_cidr`：
    - `10.1.2.3/16` 正規化成 `10.1.0.0/16`。
    - `10.1.0.0/33`、`abc`、`10.1.0.0` 都失敗（沒有前綴也要失敗）。
  - `tests/branch.rs`：
    - 建立據點，網段 `127.0.0.0/8`。測試 Agent 報到時回報的 IP，比照既有測試的 `CheckinRequest.ip_addresses`，填 `127.0.0.5`。
    - 沒有快取時 `package_source` 是 None。
    - 直接在資料庫插入一台 active 的快取，`invalidate` 後報到：`package_source` 的 url 與 fallback 正確。
    - 快取改成 disabled 後報到是 None。
    - 停用（retired）的裝置報到是 None。
    - 重複網段錯誤訊息含據點名稱；名稱重複失敗。
    - 刪除據點後，快取的 site_id 變成 NULL。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --lib branch` 和 `--test branch`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 同樣的指令，預期 PASS。
- [ ] **Step 5：** Commit「分點快取：據點與報到下發」。

### Task 3：快取註冊、核准與憑證

**Files:**
- Create：`crates/server/src/branch/caches.rs`、`crates/server/src/branch/api.rs`（`AuthedCache`、enroll、poll、renew）
- Modify：`crates/server/src/ca.rs`：新增 `sign_cache_csr(csr_pem, cache_id, dns_names, now) -> IssuedCert`。
  - SAN：dns_names，IP 形式的用 `SanType::IpAddress`，其他用 DnsName。
  - EKU：ServerAuth 加 ClientAuth；CN 是 `cache-<id>`。
- Modify：`crates/server/src/tokens.rs`：
  - `NewToken` 加 `kind: TokenKind`（Device／Cache）。
  - `consume_token` 加參數 `kind`，查詢條件加上 `AND kind = $2`。
  - 修改所有呼叫處：裝置 enroll 用 Device。
- Modify：`lib.rs` 的 `agent_router`：
  - `.route("/v1/cache/enroll", post(branch::api::enroll))`
  - `.route("/v1/cache/enroll/poll", post(branch::api::poll))`
  - `.route("/v1/cache/renew", post(branch::api::renew))`
- Test：`crates/server/tests/branch.rs`

**Produces:**
```rust
pub struct AuthedCache { pub cache_id: i64, pub site_id: Option<i64>, pub cert_not_after: DateTime<Utc> }
// extractor：PeerCert 指紋 → cache_certs（未撤銷、未過期）JOIN caches（status='active'）
pub async fn approve(pool, ca: &Ca, id: i64, site_id: i64, actor) -> anyhow::Result<()>;  // 簽發憑證、寫入 cache_certs、狀態改 active
pub async fn reject(pool, id, actor) -> anyhow::Result<()>;     // 只限 pending
pub async fn set_disabled(pool, id, disabled: bool, actor) -> anyhow::Result<()>;  // disabled 時撤銷所有 cache_certs
pub async fn assign_site(pool, id, site_id: Option<i64>, actor) -> anyhow::Result<()>;
pub async fn delete_cache(pool, id, actor) -> anyhow::Result<()>;
```

**流程：**
- **enroll**（不需要用戶端憑證）：
  1. 呼叫 `validate`。
  2. `consume_token(kind=Cache)`；不符時回 401。
  3. 檢查 CSR 能被解析，只看公鑰。
  4. 產生 `poll_secret`（32 bytes 隨機 hex），資料庫只存它的 SHA-256。
  5. INSERT 一筆 `status='pending'`；名稱重複時回 409。
  6. 稽核動作：`cache_enroll`，actor 是 `token:<id>`。
  7. 回傳 `cache_id` 與 `poll_secret`。
  8. 比照裝置 enroll，套用相同的 IP 速率限制（`enroll_limiter`）。
- **poll**：
  - `cache_id` 加 `poll_secret` 相符（以雜湊比對）才回應，否則回 401。
  - pending 時回 `Pending`。
  - rejected 時回 `Rejected`。
  - active 或 disabled 時：回 `Approved`，附上最新一張有效 cache_cert 的憑證鏈與 root_pem。
  - 憑證 PEM 要存在 `cache_certs` 裡，所以 `cache_certs` 加一個 `pem TEXT NOT NULL` 欄位（在 migration 0016 裡）。
- **approve**：
  1. 只限 pending。
  2. `site_id` 必須存在，而且沒有其他快取占用。
  3. 用存好的 `csr_pem` 與 `dns_names` 簽發憑證，寫入 cache_certs（serial、fingerprint、not_after、pem）。
  4. 狀態改成 active，site_id 設好。
  5. generation 加 1，稽核動作是 `cache_approve`。
- **renew**：
  - 需要 `AuthedCache`。
  - 效期剩 30 天以上時回 400；否則簽發新憑證，加一筆 cache_cert，舊的保留。
  - 回傳 `RenewResponse`（沿用既有的型別）。
- **set_disabled(true)**：
  - 所有 cache_certs 的 `revoked_at` 設為 now。
  - 狀態改成 disabled。
  - 稽核動作是 `cache_disable`。
- **啟用（false）**：
  - 簽發一張新憑證，用存好的 CSR。
  - 狀態改成 active。
  - 快取下次 poll 時拿到新憑證（計畫 22 處理：快取的 mTLS 被拒時改走 poll）。
  - 稽核動作是 `cache_enable`。
- **錯誤**：一般錯誤用 anyhow；網頁的 403 對應在計畫 23 處理。

- [ ] **Step 1：寫失敗測試**（`tests/branch.rs`）
  - 用 `tokens::create_token` 建立兩種金鑰（kind 分別是 Device 與 Cache）。
  - 裝置金鑰拿去 `/v1/cache/enroll`：401。快取金鑰拿去裝置的 `/v1/enroll`：401。
  - 快取 enroll 成功後 poll 是 Pending；poll_secret 錯誤時 401。
  - `approve` 之後：
    - poll 是 Approved，附上憑證鏈。
    - 用 rcgen 或 x509 解析憑證：SAN 含 `cache-tp.test` 與 `127.0.0.1`，EKU 含 serverAuth 與 clientAuth。
  - 用這張快取憑證（加上 enroll 時的私鑰）建立 reqwest client：
    - 呼叫 `/v1/checkin`（裝置 API）：401。
  - `set_disabled(true)` 之後，快取憑證呼叫快取 API（Task 4 的 `/v1/cache/checkin`）被拒。這項在 Task 4 測。
  - `reject` 只限 pending；`approve` 指定已被占用的據點會失敗。
  - 稽核紀錄有 `cache_enroll`、`cache_approve`。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test branch enroll`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-server`，預期 PASS。既有的 enroll 與 token 測試要一起更新。
- [ ] **Step 5：** Commit「分點快取：快取註冊、核准與憑證」。

### Task 4：快取 API 與下載來源

**Files:**
- Modify：`crates/server/src/branch/api.rs`：新增 `checkin`、`package_content`、`authorize`。
- Modify：`crates/server/src/deploy/api.rs`：
  - 抽出 `pub async fn device_may_download(st: &AppState, device_id: Uuid, package_id: i64) -> Result<Option<PackageSpec>, AppError>`，中央 `download` 改用它。
  - 抽出串流檔案的共用函式 `stream_package(st, sha256) -> Result<Response, AppError>`，含許可證與 Content-Length。
  - `result` 寫入 `source`：`r.source` 是 Cache 或 Central 時寫入，否則寫 NULL。
- Modify：`lib.rs`：`agent_router` 加上
  - `.route("/v1/cache/checkin", post(branch::api::checkin))`
  - `.route("/v1/cache/packages/{id}/content", get(branch::api::package_content))`
  - `.route("/v1/cache/authorize", post(branch::api::authorize))`
- Test：`crates/server/tests/branch.rs`

**規則：**
- **`checkin`（`AuthedCache`）**：
  - 驗證：`stored` 最多 `MAX_STORED` 筆、version 最多 50 字。
  - 更新 `last_seen`、`version`、`disk_used_bytes`。
  - `cache_packages` 改成差異寫入：刪掉不在清單的，upsert 有變的。不存在的 package_id 要先過濾掉，不能因外鍵失敗。
  - 回傳內容：
    - `packages`：`SELECT DISTINCT p.id, p.sha256, p.size FROM packages p JOIN deployments d ON d.package_id = p.id WHERE d.stage <> 'stopped'`。
    - 據點的頻寬與磁碟上限；快取沒有據點時用預設 100 GB、不限頻寬。
    - `renew_certificate`：效期剩不到 30 天時為 true。
- **`package_content`（`AuthedCache`）**：套件必須在上述清單裡，否則回 404；用 `stream_package` 串流，共用 `st.downloads` 的許可證，額滿時回 503 並帶 `Retry-After`。
- **`authorize`（`AuthedCache`）**：
  1. 用 `device_cert_fingerprint` 查 `device_certs`（未撤銷、未過期），取得 device_id。
  2. 用 `device_may_download(st, device_id, package_id)` 判斷。
  3. 有結果時回 `allowed: true`，其他情況（包括指紋不存在）都回 `allowed: false`。
  - 指紋格式要驗證：64 個 hex 字元，否則回 400。

- [ ] **Step 1：寫失敗測試**
  - 準備環境：比照 `tests/deploy.rs` 建立套件與派送（全部裝置），以及一台已核准（active）的快取，以它的憑證建立 client。
  - `checkin`：
    - `packages` 含該套件的 id、sha256、size。
    - 回報 stored 後，`cache_packages` 寫入。
    - 包含不存在的 package_id 時不會失敗。
    - 停止派送後，`packages` 是空的。
  - `package_content`：清單內的套件內容與雜湊正確；不在清單的 id 回 404。
  - `authorize`：
    - 被指派的裝置是 allowed。
    - 不存在的指紋是 denied。
    - 撤銷裝置憑證（`UPDATE device_certs SET revoked_at = now()`）後是 denied。
    - 非使用中的裝置是 denied。
    - 派送暫停時仍是 allowed。
    - 指紋格式錯誤回 400。
  - **停用快取**：`set_disabled(true)` 之後，三個 API 都回 401。
  - **裝置憑證呼叫快取 API**：401。
  - **`result` 帶 `source: Cache`**：`deployment_status.source` 是 `cache`；舊格式沒帶 source 時是 NULL。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-server --test branch`，預期新測試 FAIL。
- [ ] **Step 3：** 實作。既有的 `tests/deploy.rs` 下載測試要維持通過。
- [ ] **Step 4：** 執行 `cargo test --workspace -j 4`、clippy、fmt，全部 PASS。
- [ ] **Step 5：** 同步修改規格：§2.1 的 `cert_serial` 改成 `cache_certs` 表，§2.5 的 `cert_serial` 改成 `device_cert_fingerprint`。Commit「分點快取：快取 API 與下載來源」。
