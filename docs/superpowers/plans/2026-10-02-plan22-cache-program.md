# 計畫 22：分點快取程式 `endpoint-cache` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新程式 `endpoint-cache`，放在各據點：
- 向中央註冊，等管理員核准後取得憑證。
- 以 mTLS 對端點提供 `GET /v1/packages/{id}/content`，每個請求先向中央確認授權（結果快取 5 分鐘）。
- 預先下載派送用到的套件；沒存的套件按需向中央下載，同一個套件同時只下載一次。
- 清除過期與超量的套件；憑證到期前自動換發並熱更新。
- Windows 服務與 Linux（systemd／Docker）。

**Architecture:** 新 crate `crates/cache`（lib `endpoint_cache` + 執行檔 `endpoint-cache`），只依賴 `protocol`，不依賴中央或 Agent 的 crate（整合測試以 dev-dependency 啟動真實中央）。模組：
- `config.rs`：資料目錄、`config.json`、權限。
- `identity.rs`：金鑰、CSR、憑證、`enroll.json`（cache_id、poll_secret）的讀寫。
- `central.rs`：向中央的 HTTP 用戶端（註冊、輪詢、報到、換發、授權、下載並驗證）。
- `store.rs`：本機套件檔（以 sha256 命名）、暫存檔清理、存取時間、清除策略。
- `fetch.rs`：目前的套件清單（catalog）與 single-flight 下載。
- `auth.rs`：授權結果快取。
- `server.rs`：mTLS 監聽（可熱更新的伺服器憑證）與下載 handler。
- `run.rs`：背景迴圈（報到、預先下載、清除、換發、被停用時改為輪詢）。
- `main.rs`：子命令 `enroll`、`run`、`service`（Windows）。

**Tech Stack:** Rust、tokio、axum、hyper、tokio-rustls／rustls（ring）、reqwest、rcgen、sha2。全部是 workspace 既有依賴，Windows 服務沿用 Agent 用的 `windows-service`。不加新 crate。

**Spec:** `docs/superpowers/specs/2026-10-02-branch-cache-design.md`（§3、§6、§7「快取程式」）

## Global Constraints
- 使用者可見文字和程式註解都用繁體中文，風格同既有程式碼。
- 設定檔改用 **`config.json`**（與 Agent 一致，不加 toml 依賴）；規格 §3 的 `cache.toml` 在 Task 5 同步修改。
- 設定預設值：監聽 `0.0.0.0:8443`、儲存目錄 `<資料目錄>/packages`、同時下載上限 200。
- 資料目錄預設：Windows `%ProgramData%\EndpointManager\Cache`；其他平台 `/var/lib/endpoint-cache`。所有子命令都接受 `--data-dir`。
- 資料目錄權限：Windows 只允許 SYSTEM 與 Administrators（`icacls` 以 SID 設定，與語系無關）；Linux 0700。
- 只信任中央的 `root.pem`：對中央連線、驗證端點憑證都用它。
- 授權快取 5 分鐘；中央連不上時 5 分鐘內允許過的組合繼續允許，其他回 503 + `Retry-After: 60`；拒絕回 403。
- 同時下載上限額滿回 503 + `Retry-After: 60`。
- 下載先寫暫存檔，SHA-256 與大小都符合才改名；不符刪檔回 502。
- 預先下載依序一個一個來，有頻寬上限時限速；按需下載不限速。
- 清除：不在清單上的套件最後存取超過 7 天刪除；超過磁碟上限時先刪不在清單上的、再刪清單上的，各自從最久沒用的開始，正在傳送的不刪。
- 測試指令：
  - `cargo test -p endpoint-cache`（整合測試需要 `DATABASE_URL`）
  - 完整測試：`cargo test --workspace -j 4`
  - 最後跑 clippy 和 fmt。

## Review Focus
1. 端點憑證被撤銷後，最晚 5 分鐘（授權快取到期）就無法再從快取下載，即使檔案在本機。
2. 中央給的檔案與清單的 sha256／大小不符時，任何端點都拿不到這個檔案，暫存檔被刪除，而且不會讓等待中的其他請求拿到半個檔案。
3. 快取剛被核准、套件剛被指派（快取還沒報到）時，端點的請求不會因為清單過時而得到 404（按需刷新清單）。
4. 中央卡住（不回應）時，大量端點請求同一個沒存的套件不會排隊等很多次逾時：失敗結果短暫記住，其他人直接拿到 503。
5. 換發憑證時，新的金鑰與憑證成對寫入；中途失敗不會留下不成對的金鑰與憑證，重新啟動後仍能連線。

以上各點的測試分別放在 Task 3（1、2、3）、Task 2（4）、Task 1（5：`identity.rs` 的殘檔測試）。

---

### Task 1：crate 骨架、設定、身分與中央用戶端

**Files:**
- Modify：根目錄 `Cargo.toml`（members 加 `crates/cache`）
- Create：`crates/cache/Cargo.toml`、`src/lib.rs`、`src/config.rs`、`src/identity.rs`、`src/central.rs`
- Test：`crates/cache/tests/common/mod.rs`（啟動真實中央）、`crates/cache/tests/central.rs`

**`crates/cache/Cargo.toml`：**
```toml
[package]
name = "endpoint-cache"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "endpoint_cache"

[dependencies]
protocol.workspace = true
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
thiserror.workspace = true
tokio.workspace = true
axum.workspace = true
hyper.workspace = true
hyper-util.workspace = true
tower.workspace = true
rustls.workspace = true
tokio-rustls.workspace = true
rcgen.workspace = true
reqwest.workspace = true
sha2.workspace = true
hex.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
chrono.workspace = true

[target.'cfg(windows)'.dependencies]
windows-service = "0.8"

[dev-dependencies]
endpoint-server = { path = "../server" }
sqlx.workspace = true
tempfile.workspace = true
futures-util = "0.3"
uuid.workspace = true
```

**Interfaces（Produces）：**
```rust
// config.rs
pub const CONFIG_FILE: &str = "config.json";
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    #[serde(default = "default_listen")] pub listen: String,          // "0.0.0.0:8443"
    #[serde(default)] pub storage_dir: Option<PathBuf>,                // None → <data>/packages
    #[serde(default = "default_max_downloads")] pub max_downloads: usize, // 200
}
impl Config {
    pub fn load(dir: &Path) -> anyhow::Result<Config>;
    pub fn save(&self, dir: &Path) -> anyhow::Result<()>;            // write_atomic
    pub fn storage(&self, dir: &Path) -> PathBuf;
}
pub fn default_data_dir() -> PathBuf;
/// 建立資料目錄並限制權限（Windows：icacls 只留 SYSTEM 與 Administrators；Unix：0700）
pub fn secure_data_dir(dir: &Path) -> anyhow::Result<()>;
/// 先寫暫存檔再改名
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()>;

// identity.rs
pub struct Enrollment { pub cache_id: i64, pub poll_secret: String }   // enroll.json
pub struct Identity { pub key_pem: String, pub chain_pem: String }      // key.pem + cert.pem
pub fn new_key_and_csr() -> anyhow::Result<(String /*key_pem*/, String /*csr_pem*/)>;
pub fn load_root(dir: &Path) -> anyhow::Result<String>;               // root.pem
pub fn load_enrollment(dir: &Path) -> anyhow::Result<Option<Enrollment>>;
pub fn save_enrollment(dir: &Path, e: &Enrollment) -> anyhow::Result<()>;
pub fn load_identity(dir: &Path) -> anyhow::Result<Option<Identity>>;
/// 換發或核准後寫入：key.pem.new／cert.pem.new 都寫好後才依序改名（Review Focus 5）
pub fn save_identity(dir: &Path, id: &Identity) -> anyhow::Result<()>;
/// 註冊時產生的金鑰（尚無憑證）：pending.key
pub fn save_pending_key(dir: &Path, key_pem: &str) -> anyhow::Result<()>;
pub fn load_pending_key(dir: &Path) -> anyhow::Result<Option<String>>;
pub fn cert_not_after(chain_pem: &str) -> anyhow::Result<chrono::DateTime<chrono::Utc>>;

// central.rs
#[derive(Debug, thiserror::Error)]
pub enum CentralError {
    #[error("central unreachable or busy")] Unavailable(Option<Duration>),
    #[error("unauthorized")] Unauthorized,
    #[error("not found")] NotFound,
    #[error("rejected ({0}): {1}")] Rejected(u16, String),
    #[error("downloaded file does not match sha256/size")] Mismatch,
    #[error("io: {0}")] Io(#[from] std::io::Error),
}
pub struct Central { /* reqwest::Client（可替換身分）、base、downloads: AtomicU64 */ }
impl Central {
    pub fn new(base: &str, root_pem: &str, identity: Option<&Identity>) -> anyhow::Result<Central>;
    /// 換發後換上新的用戶端憑證（之後的請求使用新身分）
    pub fn set_identity(&self, id: &Identity) -> anyhow::Result<()>;
    pub async fn enroll(&self, r: &CacheEnrollRequest) -> Result<CacheEnrollResponse, CentralError>;
    pub async fn poll(&self, r: &CacheEnrollPoll) -> Result<CacheEnrollPollResponse, CentralError>;
    pub async fn checkin(&self, r: &CacheCheckin) -> Result<CacheCheckinResponse, CentralError>;
    pub async fn renew(&self, csr_pem: &str) -> Result<String /*chain*/, CentralError>;
    pub async fn authorize(&self, r: &CacheAuthorize) -> Result<bool, CentralError>;
    /// 下載到 dest（先寫 dest.part，驗證後改名）；limit_mbps 有值時限速
    pub async fn download(&self, p: &CachePackage, dest: &Path, limit_mbps: Option<u32>) -> Result<(), CentralError>;
    /// 實際開始的下載次數（測試與記錄用）
    pub fn downloads_started(&self) -> u64;
}
/// 限速：已傳 bytes、經過時間 → 還要等多久（純函式）
pub fn pace(bytes: u64, elapsed: Duration, limit_mbps: u32) -> Duration;
```

**實作要點：**
- HTTP 狀態對應：2xx 成功；401 → `Unauthorized`；404 → `NotFound`；400／409／413／422 → `Rejected`；其餘（含 503 的 `Retry-After`）與連線錯誤 → `Unavailable`。
- reqwest：`tls_certs_only([root])`、`http1_only()`、一般請求 60 秒逾時；下載用閒置 2 分鐘逾時（比照 Agent `client.rs` 的 `DOWNLOAD_IDLE`）。
- `set_identity`：以 `std::sync::RwLock<reqwest::Client>` 保存，換發後重建 client。
- `download`：邊寫邊算 SHA-256，超過大小立即停止回 `Mismatch`；結束後比對大小與雜湊；`Partial` 在 Drop 時刪除暫存檔（比照 Agent）。`downloads` 計數在送出請求時加 1。
- `pace`：`expected = bytes * 8 / (limit_mbps * 1_000_000)` 秒；`expected > elapsed` 時回差值，否則 0。
- `save_identity` 順序：寫 `key.pem.new` → 寫 `cert.pem.new` → 改名 key → 改名 cert。`load_identity` 依殘檔判斷：只有 `key.pem.new` = 沒寫完，刪掉；兩個都在 = 新的一對已寫好，完成兩個改名；只有 `cert.pem.new` = key 已改名，完成 cert 改名。
- `secure_data_dir`（Windows）：`icacls <dir> /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F`，結束代碼非 0 時回錯誤（含 stderr）。Unix：`set_permissions(0o700)`。

- [ ] **Step 1：寫失敗測試**
  - 單元測試（`central.rs`）：`pace(1_250_000, 0s, 10) == 1s`、`pace(1_250_000, 2s, 10) == 0`、`pace(0, 0s, 1) == 0`。
  - 單元測試（`config.rs`）：只有 `server_url` 的 JSON 可以載入並套用預設值；`storage()` 預設是 `<dir>/packages`；`save` 後 `load` 相同。
  - 單元測試（`identity.rs`）：
    - `save_identity` 後 `load_identity` 相同。
    - 模擬換發中途失敗：只寫了 `key.pem.new` → `load_identity` 仍回舊的成對金鑰與憑證，下次 `save_identity` 正常覆蓋殘檔。
    - 模擬改名到一半：`key.pem.new`、`cert.pem.new` 都在 → `load_identity` 先完成改名（兩個 `.new` 都在代表新的一對已完整寫好），回傳新的一對。
    - 模擬第一個改名完成後中斷：只剩 `cert.pem.new`（`key.pem` 已是新的）→ `load_identity` 完成 `cert.pem.new` → `cert.pem` 的改名，回傳新的一對。
  - `tests/common/mod.rs`：
    ```rust
    pub struct Env { pub pool: PgPool, pub state: AppState, pub url: String, pub root_pem: String, _pki: TempDir }
    /// 中央憑證名稱 localhost（快取用 127.0.0.1，不與中央衝突）
    pub async fn central(pool: PgPool) -> Env;
    pub async fn cache_token(e: &Env) -> String;                         // TokenKind::Cache
    pub async fn site(e: &Env, cidr: &str) -> i64;                       // sites::create_site
    /// 註冊 + 核准，回傳 (資料目錄, Enrollment)；資料目錄已有 config.json、root.pem、key.pem、cert.pem
    pub async fn approved_cache(e: &Env) -> (TempDir, Enrollment);
    pub async fn device(e: &Env) -> Identity;                            // 裝置註冊（裝置金鑰）
    pub async fn package(e: &Env, data: &[u8]) -> (i64, String /*sha*/); // 存檔 + create_package + 全公司派送
    ```
    中央憑證用 `ca::init_ca(dir, vec!["localhost".into(), "127.0.0.1".into()])`，快取連 `https://127.0.0.1:<port>`。測試中央不呼叫 `with_installer`，`server_names` 是空的，所以快取的 dns 用 `127.0.0.1` 不會被中央拒絕。
  - `tests/central.rs`（`#[sqlx::test(migrations = false)]`）：
    - 註冊 → `poll` 是 Pending → 核准 → `poll` 是 Approved 並附憑證鏈；用 `Identity` 建立的 `Central` 報到成功，回應的 `packages` 含 `package()` 建的套件。
    - `authorize`：裝置指紋 → true；`"0"*64` → false。
    - `download`：檔案內容與 sha256 正確、`downloads_started() == 1`；把中央套件檔改成等長的不同內容 → `Mismatch`，`dest` 與 `dest.part` 都不存在。
    - 沒有身分的 `Central` 報到 → `Unauthorized`。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-cache`，預期編譯失敗或 FAIL。
- [ ] **Step 3：** 實作上述模組。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-cache`，預期 PASS。
- [ ] **Step 5：** Commit「快取程式：骨架、設定與中央用戶端」。

---

### Task 2：本機儲存、清單與 single-flight

**Files:**
- Create：`crates/cache/src/store.rs`、`crates/cache/src/fetch.rs`
- Test：單元測試在兩個檔案內；`crates/cache/tests/fetch.rs`

**Interfaces（Produces）：**
```rust
// store.rs
pub const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
pub struct Store { /* dir、access: Mutex<HashMap<String, u64 /*unix 秒*/>>、in_use: Mutex<HashMap<String, usize>> */ }
impl Store {
    /// 建立目錄、刪除上次留下的 *.part、載入 access.json（在資料目錄，不在儲存目錄）
    pub fn open(storage: &Path, state_dir: &Path) -> anyhow::Result<Store>;
    pub fn path(&self, sha256: &str) -> PathBuf;                 // <storage>/<sha256>
    pub fn has(&self, sha256: &str, size: u64) -> bool;          // 檔案存在且大小相符
    pub fn touch(&self, sha256: &str);                           // 記錄存取時間
    /// 傳送期間持有；Drop 時減 1
    pub fn use_file(self: &Arc<Self>, sha256: &str) -> InUse;
    pub fn save_access(&self) -> anyhow::Result<()>;
    /// 依策略刪檔，回傳刪掉的 sha256
    pub fn evict(&self, listed: &HashSet<String>, disk_limit: u64, now: u64) -> anyhow::Result<Vec<String>>;
    pub fn used_bytes(&self) -> u64;
}
pub struct FileInfo { pub sha256: String, pub size: u64, pub last_access: u64, pub listed: bool, pub in_use: bool }
/// 純函式：要刪哪些（先刪過期且不在清單上的；之後超量時依「不在清單 → 在清單」、各自最久沒用的先刪；in_use 不刪）
pub fn eviction_plan(files: &[FileInfo], disk_limit: u64, now: u64, retention: u64) -> Vec<String>;

// fetch.rs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError { NotListed, Unavailable, Mismatch, Disk }
pub struct Catalog { /* RwLock<HashMap<i64, CachePackage>>、limits、上次刷新時間 */ }
impl Catalog {
    pub fn replace(&self, r: &CacheCheckinResponse);
    pub fn get(&self, id: i64) -> Option<CachePackage>;
    pub fn listed_shas(&self) -> HashSet<String>;
    pub fn limits(&self) -> (Option<u32>, u64 /*disk bytes*/);
}
pub struct Fetcher { /* central、store、catalog、locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<Option<(Instant, FetchError)>>>>> */ }
impl Fetcher {
    /// 確保套件在本機；同一個 id 同時只有一個下載，其他人等它完成。
    /// 30 秒內剛失敗過就直接回那個錯誤（Review Focus 4）
    pub async fn ensure(&self, p: &CachePackage, limit_mbps: Option<u32>) -> Result<PathBuf, FetchError>;
}
pub const FAILURE_MEMO: Duration = Duration::from_secs(30);
```

**實作要點：**
- `ensure`：取得該 id 的 `tokio::sync::Mutex` → 檔案已存在（`has`）就回 path → 鎖內記錄的失敗未滿 `FAILURE_MEMO` 就回該錯誤 → 否則 `central.download(p, store.path(sha), limit)`；成功清除失敗紀錄並 `touch`；失敗記錄 `(now, err)`。對應：`Unavailable/Unauthorized/NotFound/Rejected` → `Unavailable`，`Mismatch` → `Mismatch`，`Io` → `Disk`。
- 下載寫在 `<storage>/<sha>.part`，所以等待者只會看到完整改名後的檔案（Review Focus 2）。
- `access.json` 以 `write_atomic` 寫入；`open` 時刪除 `*.part`。

- [ ] **Step 1：寫失敗測試**
  - `eviction_plan` 單元測試（以 GB 為單位的小數字即可）：
    - 不在清單、最後存取 8 天前 → 刪；7 天內 → 保留；在清單上的 8 天前 → 保留（沒超量時）。
    - 超量：檔案 a（不在清單、3 天前）、b（不在清單、1 天前）、c（在清單、5 天前）、d（在清單、1 天前），上限只容得下兩個 → 刪 a、b。上限只容得下一個 → 刪 a、b、c。
    - `in_use` 的檔案永遠不刪，即使超量。
  - `Store` 單元測試：`open` 會刪除 `x.part`；`touch` + `save_access` 後重新 `open`，存取時間保留。
  - `tests/fetch.rs`（真實中央）：
    - 10 個 `ensure` 同時要同一個沒存的套件 → 全部成功，`central.downloads_started() == 1`。
    - 中央套件檔被改成等長不同內容 → 10 個同時 `ensure` 全部 `Mismatch`，`downloads_started() == 1`（失敗被記住），儲存目錄沒有該 sha 的檔案與 `.part`。
    - 中央網址指向已關閉的埠 → `Unavailable`；第二次呼叫在 30 秒內直接回 `Unavailable`，且不送出請求（`downloads_started()` 不變）。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-cache`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-cache`，預期 PASS。
- [ ] **Step 5：** Commit「快取程式：本機儲存與 single-flight」。

---

### Task 3：mTLS 伺服器、授權快取與下載 API

**Files:**
- Create：`crates/cache/src/auth.rs`、`crates/cache/src/server.rs`
- Test：`crates/cache/tests/serve.rs`

**Interfaces（Produces）：**
```rust
// auth.rs
pub const AUTH_TTL: Duration = Duration::from_secs(5 * 60);
pub struct AuthCache { /* ttl、Mutex<HashMap<(String, i64), (Instant, bool)>> */ }
impl AuthCache {
    pub fn new(ttl: Duration) -> AuthCache;
    /// 未過期的結果
    pub fn get(&self, fingerprint: &str, package_id: i64) -> Option<bool>;
    pub fn put(&self, fingerprint: &str, package_id: i64, allowed: bool);
    /// 移除過期項目（背景迴圈每次報到時呼叫，避免無限增長）
    pub fn prune(&self);
}

// server.rs
pub struct CacheState {
    pub central: Arc<Central>, pub fetcher: Arc<Fetcher>, pub store: Arc<Store>,
    pub catalog: Arc<Catalog>, pub auth: Arc<AuthCache>,
    pub downloads: Arc<tokio::sync::Semaphore>,              // max_downloads
    /// 清單過時時立即報到（Task 4 提供；測試可用什麼都不做的函式）。不加 futures 依賴，用 Pin<Box<dyn Future>>
    pub refresh: Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>,
}
pub fn router(st: CacheState) -> axum::Router;               // GET /v1/packages/{id}/content、GET /healthz
/// 伺服器憑證可熱更新：換發後呼叫 set
pub struct CertSlot { /* RwLock<Arc<rustls::sign::CertifiedKey>> */ }
impl CertSlot {
    pub fn new(id: &Identity) -> anyhow::Result<Arc<CertSlot>>;
    pub fn set(&self, id: &Identity) -> anyhow::Result<()>;
}
/// 要求用戶端憑證（信任 root.pem），伺服器憑證從 CertSlot 取
pub fn tls_config(root_pem: &str, slot: Arc<CertSlot>) -> anyhow::Result<Arc<rustls::ServerConfig>>;
/// accept 迴圈：握手 10 秒、標頭 10 秒、單連線最長 2 小時（大檔案）、同時連線上限；把 PeerCert 指紋放進 extension
pub async fn serve(listener: TcpListener, cfg: Arc<rustls::ServerConfig>, app: axum::Router, max_conns: usize) -> anyhow::Result<()>;
```

**下載 handler 順序：**
1. 取 `PeerCert` 指紋（沒有 → 401）。
2. `catalog.get(id)`；沒有時呼叫 `refresh` 一次再查（Review Focus 3）；仍沒有 → 404。
3. 授權：`auth.get` 有結果就用；否則 `central.authorize`：成功 → `put` 後使用；`CentralError` → 503 + `Retry-After: 60`。不允許 → 403。
4. `downloads.try_acquire_owned()` 失敗 → 503 + `Retry-After: 60`。許可跟著串流，結束時歸還。
5. `fetcher.ensure(p, None)`：`Mismatch` → 502；`Unavailable` → 503 + `Retry-After: 60`；`Disk` → 503 並記錄 error；`NotListed` → 404。
6. `store.use_file(sha)` + `touch`，開檔串流（64 KiB 區塊），帶 `Content-Length`。

`CertSlot` 實作 `rustls::server::ResolvesServerCert`（`resolve` 回目前的 `CertifiedKey`）；`CertifiedKey` 由 `rustls::crypto::ring::sign::any_supported_type` 建立。用戶端驗證用 `WebPkiClientVerifier::builder(roots).build()`（必須帶憑證）。accept 迴圈比照中央 `tls::serve_mtls`（複製，不依賴中央 crate），`max_lifetime` 改為 2 小時。

- [ ] **Step 1：寫失敗測試**（`tests/serve.rs`，真實中央 + 真實快取，用裝置憑證的 reqwest client 連快取）
  - 指派中的裝置下載 → 200，內容與雜湊正確，回應有 `Content-Length`；中央只被下載 1 次（之後再下載一次，`downloads_started()` 仍是 1）。
  - 沒被指派的套件（建立套件但不派送 → 不在清單）→ 404；另一個派送到其他群組的套件 → 403。
  - 用快取自己的憑證當用戶端 → 403（中央 authorize 回 false）。
  - 不帶用戶端憑證 → TLS 握手失敗（請求錯誤）。
  - 授權快取：`AuthCache::new(1s)`；下載成功後撤銷裝置憑證（`UPDATE device_certs SET revoked_at = now()`）→ 立即再下載仍是 200；等 1.1 秒 → 403（Review Focus 1）。
  - 中央連不上：`CacheState` 的 `central` 指向已關閉的埠、`auth` 預先 `put(fp, id, true)`、檔案已在本機 → 200；另一個沒授權過的指紋 → 503 且 `Retry-After: 60`。
  - 雜湊不符：中央套件檔改成等長不同內容 → 502；儲存目錄沒有該檔（Review Focus 2）。
  - 清單過時：快取報到後才建立新派送；`refresh` 用真的 `central.checkin` + `catalog.replace` → 第一次請求就是 200（Review Focus 3）。
  - `downloads` 為 0 個許可 → 503 且 `Retry-After: 60`。
  - `AuthCache` 單元測試：`put` 後 `get` 有值；TTL 過後 `get` 是 None；`prune` 移除過期項目。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-cache --test serve`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-cache`，預期 PASS。
- [ ] **Step 5：** Commit「快取程式：mTLS 伺服器與下載授權」。

---

### Task 4：背景迴圈、換發、子命令與 Windows 服務

**Files:**
- Create：`crates/cache/src/run.rs`、`crates/cache/src/main.rs`、`crates/cache/src/service.rs`（`#[cfg(windows)]`）、`crates/cache/src/logfile.rs`
- Test：`crates/cache/tests/run.rs`

**Interfaces（Produces）：**
```rust
// run.rs
pub const CHECKIN_EVERY: Duration = Duration::from_secs(60);
pub const POLL_EVERY: Duration = Duration::from_secs(30);
pub struct Cache { /* dir、config、state: CacheState、slot: Arc<CertSlot> */ }
impl Cache {
    /// 載入身分；尚未核准時每 POLL_EVERY 輪詢直到取得憑證（stop 為 true 時回 Ok(None)）
    pub async fn start(dir: &Path, stop: watch::Receiver<bool>) -> anyhow::Result<Option<Cache>>;
    /// 一次報到：回報已存套件 → 更新清單與上限 → 需要時換發 → 清除 → 存 access.json
    pub async fn checkin_once(&self) -> anyhow::Result<()>;
    /// 依清單逐一預先下載缺少的套件（限速；與按需下載共用 Fetcher）
    pub async fn prefetch(&self) -> usize;  // 這次下載了幾個
    /// 報到被拒（401）時：改為輪詢；重新啟用後拿到新憑證就換上
    pub async fn recover(&self) -> anyhow::Result<bool>;
    pub fn router(&self) -> axum::Router;
    pub fn tls(&self) -> anyhow::Result<Arc<rustls::ServerConfig>>;
}
/// enroll 子命令：寫 config.json、root.pem、pending.key、enroll.json，送出註冊
pub async fn enroll(dir: &Path, a: &EnrollArgs) -> anyhow::Result<i64>;
pub struct EnrollArgs { pub server: String, pub root_pem_path: PathBuf, pub token: String, pub name: String, pub url: String, pub dns: Vec<String> }
/// run 子命令與 Windows 服務共用：start → 監聽 → 每 60 秒 checkin_once + prefetch；stop 時結束
pub async fn run(dir: &Path, stop: watch::Receiver<bool>) -> anyhow::Result<()>;
```

**規則：**
- 換發：`renew_certificate` 為 true 時 `new_key_and_csr` → `central.renew` → `save_identity`（成對寫入）→ `central.set_identity` → `slot.set`。
- `checkin_once` 遇到 `Unauthorized` → 呼叫 `recover`：`poll` 拿到 `Approved` 且有憑證鏈、而且與目前的不同 → 用目前的 `key.pem` 配新憑證 `save_identity` 並換上；沒有憑證（停用中）→ 回 false，下次再試。
- `stored` 回報：清單上而且 `store.has` 的套件。
- 未核准就啟動：`start` 讀 `pending.key` 與 `enroll.json` 輪詢；`Approved` 後 `pending.key` → `key.pem`、憑證 → `cert.pem`，刪除 `pending.key`。`Rejected` → 回錯誤（需要重新註冊）。
- 日誌：`run` 輸出到 stdout；`service` 寫 `<資料目錄>/cache.log`，啟動時超過 10 MB 改名為 `cache.log.1`。
- `main.rs` 子命令：
  ```
  endpoint-cache enroll --server URL --root root.pem --token T --name N --url https://host[:port] --dns a,b [--data-dir D]
  endpoint-cache run [--data-dir D]
  endpoint-cache service [--data-dir D]      # Windows 服務入口（SCM 啟動）
  ```
  其他參數印出用法並以非 0 結束。`enroll` 會先 `secure_data_dir`。
- Windows 服務名稱 `EndpointManagerCache`，結構比照 Agent `windows/service.rs`（Stop／Shutdown → watch 送 true）。

- [ ] **Step 1：寫失敗測試**（`tests/run.rs`，真實中央）
  - `enroll` → `Cache::start` 在背景輪詢；管理員核准後 `start` 回傳 Some；資料目錄有 `key.pem`、`cert.pem`，沒有 `pending.key`。
  - `checkin_once` + `prefetch` → 下載清單上的套件，`downloads_started() == 1`；中央 `cache_packages` 有這筆；再一次 `checkin_once` + `prefetch` → 回 0、下載次數不變。
  - 換發：把中央 `cache_certs.not_after` 改成 10 天後 → `checkin_once` 後 `cert.pem` 改變；用新的 TLS 設定連快取（reqwest 取得伺服器憑證指紋）看到的是新憑證；中央 `cache_certs` 多一筆。
  - 停用與重新啟用：`set_disabled(true)` → `checkin_once` 得到 Unauthorized → `recover` 回 false；`set_disabled(false)` → `recover` 回 true，新憑證可報到。
  - `pace` 已在 Task 1 測；這裡測預先下載有限速時仍能完成（`bandwidth_limit_mbps = 1`、10 KB 套件）。
- [ ] **Step 2：** 執行 `cargo test -p endpoint-cache --test run`，預期 FAIL。
- [ ] **Step 3：** 實作。
- [ ] **Step 4：** 執行 `cargo test -p endpoint-cache`，以及 `cargo build -p endpoint-cache`，`target/debug/endpoint-cache` 不帶參數時印出用法並以非 0 結束。
- [ ] **Step 5：** Commit「快取程式：背景工作、換發與服務」。

---

### Task 5：打包、CI 與規格同步

**Files:**
- Modify：`.github/workflows/ci.yml`
- Create：`deploy/cache.Dockerfile`、`deploy/endpoint-cache.service`
- Modify：`docs/superpowers/specs/2026-10-02-branch-cache-design.md`

**內容：**
- CI：
  - `agent-windows` 工作加一步 `cargo test -p endpoint-cache --lib`（確認 Windows 版編譯與單元測試）。
  - `msi` 工作加 `cargo build --release -p endpoint-cache`，artifact 加上 `target/release/endpoint-cache.exe`。
- `deploy/cache.Dockerfile`：比照 `deploy/Dockerfile`，建置 `endpoint-cache`，distroless nonroot，`ENTRYPOINT ["/usr/local/bin/endpoint-cache"]`、`CMD ["run", "--data-dir", "/data"]`，建置階段 `mkdir /data` 並 `--chown=65532:65532` 複製。
- `deploy/endpoint-cache.service`（systemd）：`ExecStart=/usr/local/bin/endpoint-cache run`、`Restart=on-failure`、`User=endpoint-cache`、`StateDirectory=endpoint-cache`、`StateDirectoryMode=0700`、`NoNewPrivileges=yes`、`ProtectSystem=strict`。
- 規格 §3：`cache.toml` 改為 `config.json`；§3.2 補充：清單過時時按需刷新、失敗結果記住 30 秒、被停用時改為輪詢。

- [ ] **Step 1：** 修改上述檔案。
- [ ] **Step 2：** 執行 `docker build -f deploy/cache.Dockerfile .`（本機有 Docker 時；沒有就以 CI 為準並記錄 ruling），`cargo test --workspace -j 4`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`，預期全部 PASS。
- [ ] **Step 3：** Commit「快取程式：打包與 CI」。
