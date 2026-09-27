# 計畫 1／4：伺服器核心（protocol + Agent API）實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 Cargo workspace、共用 protocol crate，以及可實際運作的伺服器 Agent API（註冊、心跳、盤點上傳、憑證續期），全部以整合測試驗證。

**Architecture:** `protocol` crate 定義所有訊息型別與正規化 hash；`server` crate 用 tokio-rustls 自行做 TLS accept，把用戶端憑證指紋放進 request extension，再交給 axum Router。Agent 身分一律以「憑證 SHA-256 指紋 → `device_certs` 查詢」判定（TLS 握手已證明持有私鑰），不信任 request body。資料存 PostgreSQL，SQL 用 runtime 查詢（`sqlx::query`），不用編譯期巨集，以免編譯時需要資料庫。

**Tech Stack:** Rust 2024 edition、axum 0.8、hyper 1 / hyper-util 0.1、tokio-rustls 0.26 + rustls 0.23（ring provider）、rcgen 0.14、x509-parser 0.18、sqlx 0.9（postgres）、flate2、reqwest（僅測試用）

**Spec:** `docs/superpowers/specs/2026-09-27-endpoint-inventory-design.md`

### 計畫分拆

第一期拆成四份計畫，各自產出可獨立測試的成果：

| 計畫 | 內容 | 依賴 |
|---|---|---|
| **1（本文件）** | workspace、protocol、伺服器 Agent API、CLI（ca-init／token-create／serve）、CI | — |
| 2 | Windows Agent（service、collectors、client、state） | 1 |
| 3 | 管理網頁（登入、裝置列表／詳細、搜尋、金鑰管理、audit_log） | 1 |
| 4 | MSI 安裝檔、Docker Compose 部署、`tools/loadsim` 負載測試 | 1、2 |

## Global Constraints

- 授權：`GPL-3.0-only`（workspace `license` 欄位；LICENSE 檔已存在）。
- Rust edition 2024，workspace resolver 3。
- TLS 一律 rustls + **ring** provider；**禁止** openssl／native-tls（`deny.toml` 封鎖 `openssl`、`openssl-sys`）。rcgen 同樣使用 `ring` feature，避免 aws-lc-rs 在 Windows 需要 cmake／nasm。
- 每則 Agent 訊息帶 `schema_version`，目前為 `1`；伺服器拒絕 `schema_version > 1`。
- 字串長度上限 1024 字元；每區段項目數上限 20,000。
- 請求大小上限 5MB（壓縮後）；gzip 解壓後上限 50MB。
- Agent 憑證效期 365 天；剩餘 < 30 天時回應 `renew_certificate: true`。
- 預設心跳 60 秒；software／patches／services 3600 秒；hardware 86400 秒（存於 `settings`）。
- 心跳熱欄位每 30 秒批次寫入。
- `inventory_changes` 按月分割區，保留 12 個月（含當月）。
- Agent API 監聽埠預設 `0.0.0.0:8443`。
- 不使用 clap 等 CLI 套件；參數手動解析。
- 程式碼中不得出現任何公司專屬資訊。

## Review Focus

1. **Agent 回報了伺服器從未收過的區段 hash**（新裝置第一次心跳）→ 伺服器必須要求上傳該區段，不可報錯。→ Task 8 `sections_to_request` 單元測試＋`checkin_requests_unknown_sections` 整合測試。
2. **多台同時用同一把註冊金鑰、剛好碰到 max_uses 上限**（GPO 大量派送時必然發生）→ 成功次數不得超過上限。→ Task 7 `concurrent_enroll_does_not_exceed_max_uses`。
3. **電腦重灌後重新註冊** → 沿用同一個 device_id，舊憑證立即失效（401）。→ Task 7 `reenroll_same_hardware_reuses_device_and_revokes_old_cert`。
4. **軟體清單中同名同架構同發行者的項目出現多次**（例如兩個版本的 Java 名稱相同）→ 差異比對不可出現假變更、寫入不可失敗。→ Task 9 `duplicate_software_entries_are_stable`。
5. **極長或異常字串**（DisplayName 上萬字元）→ 回 400，不是 500 或資料庫錯誤。→ Task 2 `validate_rejects_long_string`＋Task 9 `oversized_string_rejected`。

---

## 檔案結構

```
endpoint-manager/
├─ Cargo.toml                         workspace
├─ deny.toml
├─ .gitignore
├─ .github/workflows/ci.yml
├─ crates/protocol/
│  ├─ Cargo.toml
│  ├─ src/lib.rs                      訊息型別、Section、canonical hash、validate
│  └─ tests/fixtures/v1/*.json        schema v1 樣本
└─ crates/server/
   ├─ Cargo.toml
   ├─ migrations/0001_init.sql
   ├─ src/
   │  ├─ main.rs                      CLI：serve / ca-init / token-create
   │  ├─ lib.rs                       AppState、agent_router、healthz
   │  ├─ config.rs                    環境變數設定
   │  ├─ error.rs                     AppError → HTTP
   │  ├─ db.rs                        連線、migrate、settings 讀取
   │  ├─ partitions.rs                inventory_changes 分割區維護
   │  ├─ ca.rs                        CA 初始化、簽發、憑證解析
   │  ├─ tls.rs                       mTLS accept loop、PeerCert
   │  ├─ identity.rs                  AuthedDevice extractor
   │  ├─ tokens.rs                    註冊金鑰建立／消耗
   │  ├─ ratelimit.rs                 依 IP 的固定視窗限速
   │  ├─ enroll.rs                    裝置比對 + /v1/enroll
   │  ├─ heartbeat.rs                 熱欄位緩衝與批次寫入
   │  ├─ checkin.rs                   /v1/checkin
   │  ├─ diff.rs                      區段 → key/value、差異比對（純函式）
   │  ├─ inventory.rs                 /v1/inventory/{section}、解壓、儲存
   │  └─ renew.rs                     /v1/renew
   └─ tests/
      ├─ common/mod.rs                TestServer、TestAgent
      ├─ enroll.rs
      ├─ checkin.rs
      ├─ inventory.rs
      └─ renew.rs
```

---

### Task 0: 環境準備（人工，執行前一次）

- [x] **Step 1: 以 Docker 啟動 PostgreSQL 17（本機開發／測試用，只綁 127.0.0.1）**

```bash
docker run -d --name em-postgres --restart unless-stopped -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5432:5432 postgres:17
docker exec em-postgres psql -U postgres -c "CREATE DATABASE endpoint_manager;"
```

- [x] **Step 2: 設定測試用連線字串**（`#[sqlx::test]` 會在此伺服器上自動建立／刪除測試資料庫）

```powershell
[Environment]::SetEnvironmentVariable("DATABASE_URL", "postgres://postgres:postgres@127.0.0.1:5432/postgres", "User")
```

- [ ] **Step 3: 建立 GitHub repo 並推送 main（僅含規格與授權）**

```bash
cd /d/VSCode/endpoint-manager
gh repo create tntrock/endpoint-manager --public --source . --push
git switch -c feat/plan1-server-core
```

之後所有工作都在 `feat/plan1-server-core` 分支上，完成後開 PR。

---

### Task 1: Workspace 骨架與 CI

**Files:**
- Create: `Cargo.toml`、`.gitignore`、`deny.toml`、`.github/workflows/ci.yml`
- Create: `crates/protocol/Cargo.toml`、`crates/protocol/src/lib.rs`
- Create: `crates/server/Cargo.toml`、`crates/server/src/lib.rs`、`crates/server/src/main.rs`

**Interfaces:**
- Produces: workspace 可 `cargo build`；兩個 crate 名稱 `protocol`、`endpoint-server`（lib 名 `endpoint_server`）。

- [ ] **Step 1: 建立 workspace `Cargo.toml`**

```toml
[workspace]
resolver = "3"
members = ["crates/protocol", "crates/server"]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "GPL-3.0-only"
repository = "https://github.com/tntrock/endpoint-manager"

[workspace.dependencies]
protocol = { path = "crates/protocol" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
chrono = { version = "0.4", default-features = false, features = ["std", "clock", "serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
sha2 = "0.11"
hex = "0.4"
thiserror = "2"
anyhow = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "time", "sync", "signal"] }
axum = "0.8"
hyper = { version = "1", features = ["server", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["tokio", "server-auto", "service"] }
tower = { version = "0.5", features = ["util"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12", "logging"] }
tokio-rustls = { version = "0.26", default-features = false, features = ["ring", "tls12", "logging"] }
rcgen = { version = "0.14", default-features = false, features = ["ring", "pem", "x509-parser", "crypto"] }
x509-parser = "0.18"
time = "0.3"
sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio", "postgres", "uuid", "chrono", "migrate", "macros"] }
flate2 = "1"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

[profile.release]
panic = "abort"
lto = true
codegen-units = 1
```

> 注意：`sqlx 0.9`、`reqwest 0.13` 的 feature 名稱若與上方不同，以 `cargo add` 後的實際 feature 清單為準（可用 context7 查 `/launchbadge/sqlx`），並回報差異。

- [ ] **Step 2: 建立 `.gitignore`**

```
/target
*.pem
*.key
/pki
```

- [ ] **Step 3: 建立 `crates/protocol/Cargo.toml` 與空的 `src/lib.rs`**

```toml
[package]
name = "protocol"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
uuid.workspace = true
sha2.workspace = true
hex.workspace = true
thiserror.workspace = true
```

`crates/protocol/src/lib.rs`：

```rust
//! Agent 與伺服器之間的共用訊息格式。
```

- [ ] **Step 4: 建立 `crates/server/Cargo.toml`、`src/lib.rs`、`src/main.rs`**

```toml
[package]
name = "endpoint-server"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "endpoint_server"

[dependencies]
protocol.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
uuid.workspace = true
sha2.workspace = true
hex.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tokio.workspace = true
axum.workspace = true
hyper.workspace = true
hyper-util.workspace = true
tower.workspace = true
rustls.workspace = true
tokio-rustls.workspace = true
rcgen.workspace = true
x509-parser.workspace = true
time.workspace = true
sqlx.workspace = true
flate2.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true

[dev-dependencies]
reqwest = { version = "0.13", default-features = false, features = ["json", "rustls"] }
tempfile = "3"
```

`crates/server/src/lib.rs`：

```rust
//! Endpoint Manager 伺服器。
```

`crates/server/src/main.rs`：

```rust
fn main() {}
```

- [ ] **Step 5: 建立 `deny.toml`**

```toml
[advisories]
version = 2
yanked = "deny"

[licenses]
version = 2
allow = [
    "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause",
    "ISC", "Unicode-3.0", "Zlib", "MPL-2.0", "CDLA-Permissive-2.0", "GPL-3.0-only",
]

[bans]
multiple-versions = "warn"
deny = [{ name = "openssl" }, { name = "openssl-sys" }, { name = "native-tls" }]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

- [ ] **Step 6: 建立 `.github/workflows/ci.yml`**

```yaml
name: CI
on:
  pull_request:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17
        env:
          POSTGRES_PASSWORD: postgres
        ports: ["5432:5432"]
        options: >-
          --health-cmd "pg_isready -U postgres"
          --health-interval 5s --health-timeout 5s --health-retries 10
    env:
      DATABASE_URL: postgres://postgres:postgres@127.0.0.1:5432/postgres
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo test --workspace

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2
```

- [ ] **Step 7: 確認可編譯**

Run: `cargo build --workspace`
Expected: 成功，無錯誤。

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: workspace 骨架、cargo-deny 與 CI"
```

---

### Task 2: protocol crate — 訊息型別、canonical hash、驗證

**Files:**
- Modify: `crates/protocol/src/lib.rs`
- Create: `crates/protocol/tests/fixtures/v1/checkin.json`、`crates/protocol/tests/fixtures/v1/software.json`
- Create: `crates/protocol/tests/fixtures_v1.rs`

**Interfaces:**
- Produces（後續所有 task 使用）：
  - `pub const SCHEMA_VERSION: u32 = 1; pub const MAX_STRING_LEN: usize = 1024; pub const MAX_ITEMS: usize = 20_000;`
  - `pub enum Section { Basic, Hardware, Software, Patches, Services }`，`Section::ALL`、`as_str(self) -> &'static str`、`parse(&str) -> Option<Section>`
  - `EnrollRequest { schema_version, enroll_token, csr_pem, hostname, smbios_uuid: Option<String>, bios_serial: Option<String>, mac_addresses: Vec<String> }`
  - `EnrollResponse { device_id: Uuid, certificate_chain_pem: String }`
  - `CheckinRequest { schema_version, agent_version, boot_time: DateTime<Utc>, logged_on_user: Option<String>, ip_addresses: Vec<String>, section_hashes: BTreeMap<Section,String>, section_errors: BTreeMap<Section,String> }`
  - `CheckinResponse { next_checkin_seconds: u32, request_sections: Vec<Section>, collection_intervals: CollectionIntervals, renew_certificate: bool }`
  - `CollectionIntervals { software_secs: u32, patches_secs: u32, services_secs: u32, hardware_secs: u32 }`
  - `BasicInfo { hostname, domain: Option<String>, is_domain_joined: bool, os_caption: String, os_build: String }`
  - `HardwareInfo { manufacturer: Option<String>, model: Option<String>, cpu: Option<String>, ram_mb: u64, disks: Vec<Disk> }`、`Disk { name, size_bytes: u64, free_bytes: u64 }`
  - `SoftwareItem { name, version: Option<String>, publisher: Option<String>, install_date: Option<String>, arch: Arch }`、`enum Arch { X64, X86, User }`（序列化為 `"x64"`／`"x86"`／`"user"`）
  - `PatchItem { kb, installed_on: Option<String> }`
  - `ServiceItem { name, display_name: Option<String>, start_mode: String, state: String, binary_path: Option<String> }`
  - `enum InventoryPayload { Basic(BasicInfo), Hardware(HardwareInfo), Software(Vec<SoftwareItem>), Patches(Vec<PatchItem>), Services(Vec<ServiceItem>) }`（`#[serde(tag="section", content="data")]`），方法 `section()`、`normalize(&mut self)`、`canonical_hash(&self) -> String`、`validate(&self) -> Result<(), ValidationError>`
  - `InventoryUpload { schema_version: u32, payload: InventoryPayload }`（payload 以 `#[serde(flatten)]` 攤平）
  - `RenewRequest { csr_pem }`、`RenewResponse { certificate_chain_pem }`
  - `pub fn validate_strings<T: Serialize>(value: &T) -> Result<(), ValidationError>`
  - `pub enum ValidationError { StringTooLong { len: usize }, TooManyItems { count: usize } }`

- [ ] **Step 1: 寫失敗的單元測試**（附加在 `crates/protocol/src/lib.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn sw(name: &str, ver: &str) -> SoftwareItem {
        SoftwareItem {
            name: name.into(),
            version: Some(ver.into()),
            publisher: None,
            install_date: None,
            arch: Arch::X64,
        }
    }

    #[test]
    fn hash_is_independent_of_item_order() {
        let a = InventoryPayload::Software(vec![sw("A", "1"), sw("B", "2")]);
        let b = InventoryPayload::Software(vec![sw("B", "2"), sw("A", "1")]);
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn hash_changes_when_version_changes() {
        let a = InventoryPayload::Software(vec![sw("A", "1")]);
        let b = InventoryPayload::Software(vec![sw("A", "2")]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let h = InventoryPayload::Patches(vec![]).canonical_hash();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_rejects_long_string() {
        let p = InventoryPayload::Software(vec![sw(&"x".repeat(MAX_STRING_LEN + 1), "1")]);
        assert_eq!(
            p.validate(),
            Err(ValidationError::StringTooLong { len: MAX_STRING_LEN + 1 })
        );
    }

    #[test]
    fn validate_counts_chars_not_bytes() {
        // 1024 個中文字 = 3072 bytes，仍應通過
        let p = InventoryPayload::Software(vec![sw(&"軟".repeat(MAX_STRING_LEN), "1")]);
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_too_many_items() {
        let items = (0..=MAX_ITEMS).map(|i| sw(&i.to_string(), "1")).collect();
        assert_eq!(
            InventoryPayload::Software(items).validate(),
            Err(ValidationError::TooManyItems { count: MAX_ITEMS + 1 })
        );
    }

    #[test]
    fn upload_serializes_with_section_tag() {
        let u = InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: InventoryPayload::Patches(vec![PatchItem { kb: "KB500".into(), installed_on: None }]),
        };
        let v = serde_json::to_value(&u).unwrap();
        assert_eq!(v["section"], "patches");
        assert_eq!(v["data"][0]["kb"], "KB500");
        assert_eq!(v["schema_version"], 1);
    }

    #[test]
    fn section_parse_roundtrip() {
        for s in Section::ALL {
            assert_eq!(Section::parse(s.as_str()), Some(s));
        }
        assert_eq!(Section::parse("nope"), None);
    }
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test -p protocol`
Expected: 編譯失敗（型別尚未定義）。

- [ ] **Step 3: 實作 `crates/protocol/src/lib.rs`**（放在 tests 模組之上）

```rust
//! Agent 與伺服器之間的共用訊息格式。

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_STRING_LEN: usize = 1024;
pub const MAX_ITEMS: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    Basic,
    Hardware,
    Software,
    Patches,
    Services,
}

impl Section {
    pub const ALL: [Section; 5] = [
        Section::Basic,
        Section::Hardware,
        Section::Software,
        Section::Patches,
        Section::Services,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Section::Basic => "basic",
            Section::Hardware => "hardware",
            Section::Software => "software",
            Section::Patches => "patches",
            Section::Services => "services",
        }
    }

    pub fn parse(s: &str) -> Option<Section> {
        Section::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub schema_version: u32,
    pub enroll_token: String,
    pub csr_pem: String,
    pub hostname: String,
    pub smbios_uuid: Option<String>,
    pub bios_serial: Option<String>,
    pub mac_addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
    /// 裝置憑證 + 中繼 CA + 根 CA，PEM 串接
    pub certificate_chain_pem: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckinRequest {
    pub schema_version: u32,
    pub agent_version: String,
    pub boot_time: DateTime<Utc>,
    pub logged_on_user: Option<String>,
    pub ip_addresses: Vec<String>,
    pub section_hashes: BTreeMap<Section, String>,
    pub section_errors: BTreeMap<Section, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionIntervals {
    pub software_secs: u32,
    pub patches_secs: u32,
    pub services_secs: u32,
    pub hardware_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckinResponse {
    pub next_checkin_seconds: u32,
    pub request_sections: Vec<Section>,
    pub collection_intervals: CollectionIntervals,
    pub renew_certificate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BasicInfo {
    pub hostname: String,
    pub domain: Option<String>,
    pub is_domain_joined: bool,
    pub os_caption: String,
    pub os_build: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Disk {
    pub name: String,
    pub size_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub cpu: Option<String>,
    pub ram_mb: u64,
    pub disks: Vec<Disk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X64,
    X86,
    /// 安裝在使用者層級（HKU）
    User,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
            Arch::User => "user",
        }
    }

    pub fn parse(s: &str) -> Option<Arch> {
        [Arch::X64, Arch::X86, Arch::User].into_iter().find(|a| a.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SoftwareItem {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub arch: Arch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PatchItem {
    pub kb: String,
    pub installed_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceItem {
    pub name: String,
    pub display_name: Option<String>,
    pub start_mode: String,
    pub state: String,
    pub binary_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "section", content = "data", rename_all = "lowercase")]
pub enum InventoryPayload {
    Basic(BasicInfo),
    Hardware(HardwareInfo),
    Software(Vec<SoftwareItem>),
    Patches(Vec<PatchItem>),
    Services(Vec<ServiceItem>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryUpload {
    pub schema_version: u32,
    #[serde(flatten)]
    pub payload: InventoryPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RenewRequest {
    pub csr_pem: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RenewResponse {
    pub certificate_chain_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("string too long: {len} chars")]
    StringTooLong { len: usize },
    #[error("too many items: {count}")]
    TooManyItems { count: usize },
}

impl InventoryPayload {
    pub fn section(&self) -> Section {
        match self {
            InventoryPayload::Basic(_) => Section::Basic,
            InventoryPayload::Hardware(_) => Section::Hardware,
            InventoryPayload::Software(_) => Section::Software,
            InventoryPayload::Patches(_) => Section::Patches,
            InventoryPayload::Services(_) => Section::Services,
        }
    }

    /// 排序所有清單，讓相同內容產生相同的序列化結果。
    pub fn normalize(&mut self) {
        match self {
            InventoryPayload::Basic(_) => {}
            InventoryPayload::Hardware(h) => h.disks.sort(),
            InventoryPayload::Software(v) => v.sort(),
            InventoryPayload::Patches(v) => v.sort(),
            InventoryPayload::Services(v) => v.sort(),
        }
    }

    /// 正規化後 JSON 的 SHA-256（小寫 hex）。Agent 與伺服器都用這個函式。
    pub fn canonical_hash(&self) -> String {
        let mut c = self.clone();
        c.normalize();
        let bytes = serde_json::to_vec(&c).expect("payload serializes");
        hex::encode(Sha256::digest(&bytes))
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        let count = match self {
            InventoryPayload::Basic(_) => 1,
            InventoryPayload::Hardware(h) => h.disks.len(),
            InventoryPayload::Software(v) => v.len(),
            InventoryPayload::Patches(v) => v.len(),
            InventoryPayload::Services(v) => v.len(),
        };
        if count > MAX_ITEMS {
            return Err(ValidationError::TooManyItems { count });
        }
        validate_strings(self)
    }
}

/// 檢查任意可序列化值中所有字串（含 map key）不超過 MAX_STRING_LEN 字元。
pub fn validate_strings<T: Serialize>(value: &T) -> Result<(), ValidationError> {
    fn walk(v: &serde_json::Value) -> Result<(), ValidationError> {
        match v {
            serde_json::Value::String(s) => check(s),
            serde_json::Value::Array(a) => a.iter().try_for_each(walk),
            serde_json::Value::Object(o) => o.iter().try_for_each(|(k, v)| {
                check(k)?;
                walk(v)
            }),
            _ => Ok(()),
        }
    }
    fn check(s: &str) -> Result<(), ValidationError> {
        let len = s.chars().count();
        if len > MAX_STRING_LEN {
            Err(ValidationError::StringTooLong { len })
        } else {
            Ok(())
        }
    }
    walk(&serde_json::to_value(value).expect("value serializes"))
}
```

> `EnrollRequest.csr_pem` 與 `RenewRequest.csr_pem` 可能超過 1024 字元，因此**不要**對這兩個型別整體呼叫 `validate_strings`；伺服器端只驗證其他欄位（見 Task 7）。

- [ ] **Step 4: 執行單元測試確認通過**

Run: `cargo test -p protocol`
Expected: 8 個測試 PASS。

- [ ] **Step 5: 建立 v1 相容性樣本與測試**

`crates/protocol/tests/fixtures/v1/checkin.json`：

```json
{
  "schema_version": 1,
  "agent_version": "0.1.0",
  "boot_time": "2026-09-28T01:02:03Z",
  "logged_on_user": "CORP\\alice",
  "ip_addresses": ["10.0.0.5"],
  "section_hashes": { "software": "abc", "basic": "def" },
  "section_errors": { "patches": "WMI timeout" }
}
```

`crates/protocol/tests/fixtures/v1/software.json`：

```json
{
  "schema_version": 1,
  "section": "software",
  "data": [
    { "name": "7-Zip 23.01 (x64)", "version": "23.01", "publisher": "Igor Pavlov", "install_date": "20240101", "arch": "x64" },
    { "name": "Zoom", "version": null, "publisher": null, "install_date": null, "arch": "user" }
  ]
}
```

`crates/protocol/tests/fixtures_v1.rs`：

```rust
//! schema v1 的樣本必須永遠能被解析（伺服器需相容舊版 Agent）。

use protocol::{CheckinRequest, InventoryPayload, InventoryUpload, Section};

#[test]
fn v1_checkin_parses() {
    let r: CheckinRequest =
        serde_json::from_str(include_str!("fixtures/v1/checkin.json")).unwrap();
    assert_eq!(r.section_hashes[&Section::Software], "abc");
    assert_eq!(r.section_errors[&Section::Patches], "WMI timeout");
}

#[test]
fn v1_software_upload_parses() {
    let u: InventoryUpload =
        serde_json::from_str(include_str!("fixtures/v1/software.json")).unwrap();
    match u.payload {
        InventoryPayload::Software(v) => assert_eq!(v.len(), 2),
        other => panic!("unexpected {other:?}"),
    }
}
```

- [ ] **Step 6: 執行所有 protocol 測試**

Run: `cargo test -p protocol`
Expected: 10 個測試 PASS。

- [ ] **Step 7: Commit**

```bash
git add crates/protocol
git commit -m "feat(protocol): 訊息型別、canonical hash 與字串驗證"
```

---

### Task 3: 資料庫 migration、settings、分割區維護

**Files:**
- Create: `crates/server/migrations/0001_init.sql`
- Create: `crates/server/src/db.rs`、`crates/server/src/partitions.rs`
- Modify: `crates/server/src/lib.rs`

**Interfaces:**
- Produces:
  - `db::migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError>`
  - `db::Settings { checkin_interval_secs: u32, intervals: protocol::CollectionIntervals }`、`db::load_settings(pool: &PgPool) -> Result<Settings, sqlx::Error>`
  - `partitions::maintain_partitions(pool: &PgPool, now: DateTime<Utc>) -> Result<(), sqlx::Error>`
  - 純函式：`partitions::partition_name(y: i32, m: u32) -> String`、`month_add(y: i32, m: u32, delta: i32) -> (i32, u32)`、`parse_partition_name(&str) -> Option<(i32, u32)>`、`partitions_to_drop(existing: &[String], now_y: i32, now_m: u32, keep_months: i32) -> Vec<String>`

- [ ] **Step 1: 建立 `crates/server/migrations/0001_init.sql`**

```sql
CREATE TABLE enroll_tokens (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    group_label TEXT,
    expires_at  TIMESTAMPTZ,
    max_uses    INTEGER NOT NULL CHECK (max_uses > 0),
    used_count  INTEGER NOT NULL DEFAULT 0,
    revoked_at  TIMESTAMPTZ,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id               UUID PRIMARY KEY,
    hostname         TEXT NOT NULL,
    domain           TEXT,
    is_domain_joined BOOLEAN NOT NULL DEFAULT false,
    smbios_uuid      TEXT,
    bios_serial      TEXT,
    management_type  TEXT NOT NULL DEFAULT 'agent'
                     CHECK (management_type IN ('agent', 'legacy_import')),
    status           TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'retired', 'duplicate_suspect')),
    last_seen_at     TIMESTAMPTZ,
    last_ip          TEXT,
    logged_on_user   TEXT,
    boot_time        TIMESTAMPTZ,
    agent_version    TEXT,
    os_caption       TEXT,
    os_build         TEXT,
    section_errors   JSONB NOT NULL DEFAULT '{}',
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    enroll_token_id  BIGINT REFERENCES enroll_tokens(id)
);
CREATE INDEX devices_smbios_uuid_idx ON devices (smbios_uuid);
CREATE INDEX devices_hostname_idx ON devices (hostname);

CREATE TABLE device_certs (
    serial      TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    device_id   UUID NOT NULL REFERENCES devices(id),
    not_after   TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX device_certs_device_idx ON device_certs (device_id);

CREATE TABLE device_hardware (
    device_id    UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    manufacturer TEXT,
    model        TEXT,
    cpu          TEXT,
    ram_mb       BIGINT NOT NULL,
    disks        JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE device_software (
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT,
    publisher    TEXT,
    install_date TEXT,
    arch         TEXT NOT NULL
);
CREATE INDEX device_software_device_idx ON device_software (device_id);
CREATE INDEX device_software_name_idx ON device_software (name);

CREATE TABLE device_patches (
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kb           TEXT NOT NULL,
    installed_on TEXT
);
CREATE INDEX device_patches_device_idx ON device_patches (device_id);
CREATE INDEX device_patches_kb_idx ON device_patches (kb);

CREATE TABLE device_services (
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    display_name TEXT,
    start_mode   TEXT NOT NULL,
    state        TEXT NOT NULL,
    binary_path  TEXT
);
CREATE INDEX device_services_device_idx ON device_services (device_id);

CREATE TABLE inventory_sections (
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    section    TEXT NOT NULL,
    hash       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, section)
);

CREATE TABLE inventory_changes (
    id          BIGSERIAL,
    device_id   UUID NOT NULL,
    section     TEXT NOT NULL,
    change      TEXT NOT NULL CHECK (change IN ('added', 'removed', 'updated')),
    item_key    TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, detected_at)
) PARTITION BY RANGE (detected_at);
CREATE INDEX inventory_changes_device_idx ON inventory_changes (device_id, detected_at);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);
INSERT INTO settings (key, value) VALUES
    ('checkin_interval_secs', '60'),
    ('software_interval_secs', '3600'),
    ('patches_interval_secs', '3600'),
    ('services_interval_secs', '3600'),
    ('hardware_interval_secs', '86400');
```

- [ ] **Step 2: 寫分割區純函式的失敗測試**（`crates/server/src/partitions.rs`）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_format() {
        assert_eq!(partition_name(2026, 9), "inventory_changes_y2026m09");
    }

    #[test]
    fn month_add_wraps_years() {
        assert_eq!(month_add(2026, 12, 1), (2027, 1));
        assert_eq!(month_add(2026, 1, -1), (2025, 12));
        assert_eq!(month_add(2026, 9, -11), (2025, 10));
    }

    #[test]
    fn parse_roundtrip_and_rejects_garbage() {
        assert_eq!(parse_partition_name("inventory_changes_y2026m09"), Some((2026, 9)));
        assert_eq!(parse_partition_name("inventory_changes_y2026m13"), None);
        assert_eq!(parse_partition_name("something_else"), None);
    }

    #[test]
    fn drops_only_older_than_keep_window() {
        let existing = vec![
            partition_name(2025, 9),
            partition_name(2025, 10),
            partition_name(2026, 9),
            "unrelated_table".to_string(),
        ];
        // 保留 12 個月（含當月 2026-09）→ 最舊保留 2025-10
        assert_eq!(
            partitions_to_drop(&existing, 2026, 9, 12),
            vec![partition_name(2025, 9)]
        );
    }
}
```

- [ ] **Step 3: 執行確認失敗**

Run: `cargo test -p endpoint-server partitions`
Expected: 編譯失敗（函式未定義）。

- [ ] **Step 4: 實作 `partitions.rs`**（放在測試模組之上）

```rust
//! inventory_changes 按月分割區的建立與清理。

use chrono::{DateTime, Datelike, Utc};
use sqlx::PgPool;

pub const KEEP_MONTHS: i32 = 12;
const PREFIX: &str = "inventory_changes_y";

pub fn partition_name(y: i32, m: u32) -> String {
    format!("{PREFIX}{y:04}m{m:02}")
}

pub fn month_add(y: i32, m: u32, delta: i32) -> (i32, u32) {
    let idx = y * 12 + (m as i32 - 1) + delta;
    (idx.div_euclid(12), (idx.rem_euclid(12) + 1) as u32)
}

pub fn parse_partition_name(name: &str) -> Option<(i32, u32)> {
    let rest = name.strip_prefix(PREFIX)?;
    let (y, m) = rest.split_once('m')?;
    let (y, m): (i32, u32) = (y.parse().ok()?, m.parse().ok()?);
    (1..=12).contains(&m).then_some((y, m))
}

pub fn partitions_to_drop(existing: &[String], now_y: i32, now_m: u32, keep_months: i32) -> Vec<String> {
    let cutoff = month_add(now_y, now_m, -(keep_months - 1));
    existing
        .iter()
        .filter(|n| parse_partition_name(n).is_some_and(|ym| ym < cutoff))
        .cloned()
        .collect()
}

/// 建立當月與未來兩個月的分割區，刪除超過保留期限的分割區。
pub async fn maintain_partitions(pool: &PgPool, now: DateTime<Utc>) -> Result<(), sqlx::Error> {
    let (y, m) = (now.year(), now.month());
    for delta in 0..3 {
        let (sy, sm) = month_add(y, m, delta);
        let (ey, em) = month_add(y, m, delta + 1);
        // 名稱與日期全由數字組成，無注入風險
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS {} PARTITION OF inventory_changes \
             FOR VALUES FROM ('{sy:04}-{sm:02}-01') TO ('{ey:04}-{em:02}-01')",
            partition_name(sy, sm)
        );
        sqlx::query(&sql).execute(pool).await?;
    }
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_inherits i \
         JOIN pg_class c ON c.oid = i.inhrelid \
         JOIN pg_class p ON p.oid = i.inhparent \
         WHERE p.relname = 'inventory_changes'",
    )
    .fetch_all(pool)
    .await?;
    for name in partitions_to_drop(&existing, y, m, KEEP_MONTHS) {
        // name 已由 parse_partition_name 驗證為固定格式
        sqlx::query(&format!("DROP TABLE IF EXISTS {name}")).execute(pool).await?;
    }
    Ok(())
}
```

- [ ] **Step 5: 實作 `db.rs`**

```rust
//! 資料庫連線、migration 與 settings。

use protocol::CollectionIntervals;
use sqlx::PgPool;

pub async fn migrate(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub checkin_interval_secs: u32,
    pub intervals: CollectionIntervals,
}

pub async fn load_settings(pool: &PgPool) -> Result<Settings, sqlx::Error> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT key, (value #>> '{}')::bigint FROM settings WHERE key LIKE '%_secs'")
            .fetch_all(pool)
            .await?;
    let get = |k: &str, default: u32| {
        rows.iter()
            .find(|(key, _)| key == k)
            .and_then(|(_, v)| u32::try_from(*v).ok())
            .unwrap_or(default)
    };
    Ok(Settings {
        checkin_interval_secs: get("checkin_interval_secs", 60),
        intervals: CollectionIntervals {
            software_secs: get("software_interval_secs", 3600),
            patches_secs: get("patches_interval_secs", 3600),
            services_secs: get("services_interval_secs", 3600),
            hardware_secs: get("hardware_interval_secs", 86400),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = false)]
    async fn migrate_and_default_settings(pool: PgPool) {
        migrate(&pool).await.unwrap();
        let s = load_settings(&pool).await.unwrap();
        assert_eq!(s.checkin_interval_secs, 60);
        assert_eq!(s.intervals.hardware_secs, 86400);
    }

    #[sqlx::test(migrations = false)]
    async fn maintain_partitions_is_idempotent(pool: PgPool) {
        migrate(&pool).await.unwrap();
        let now = chrono::Utc::now();
        crate::partitions::maintain_partitions(&pool, now).await.unwrap();
        crate::partitions::maintain_partitions(&pool, now).await.unwrap();
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_inherits i JOIN pg_class p ON p.oid = i.inhparent \
             WHERE p.relname = 'inventory_changes'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(n, 3);
    }
}
```

- [ ] **Step 6: 在 `lib.rs` 加入模組**

```rust
//! Endpoint Manager 伺服器。

pub mod db;
pub mod partitions;
```

- [ ] **Step 7: 執行測試**

Run: `cargo test -p endpoint-server`
Expected: 分割區 4 個 + db 2 個測試 PASS。

- [ ] **Step 8: Commit**

```bash
git add crates/server
git commit -m "feat(server): 資料庫 schema、settings 與分割區維護"
```

---

### Task 4: CA — 初始化、簽發裝置憑證、解析憑證

**Files:**
- Create: `crates/server/src/ca.rs`
- Modify: `crates/server/src/lib.rs`（加 `pub mod ca;`）

**Interfaces:**
- Produces:
  - `ca::init_ca(dir: &Path, server_names: Vec<String>) -> anyhow::Result<()>`：寫出 `root.pem`、`root.key`、`intermediate.pem`、`intermediate.key`、`server.pem`（伺服器憑證 + 中繼）、`server.key`
  - `ca::Ca::load(dir: &Path) -> anyhow::Result<Ca>`
  - `Ca::sign_device_csr(&self, csr_pem: &str, device_id: Uuid, now: DateTime<Utc>) -> anyhow::Result<IssuedCert>`
  - `Ca::chain_pem(&self) -> &str`（中繼 + 根）
  - `pub struct IssuedCert { pub serial: String, pub fingerprint: String, pub pem: String, pub not_after: DateTime<Utc> }`
  - `ca::fingerprint(der: &[u8]) -> String`（SHA-256 小寫 hex）
  - `ca::device_id_of(der: &[u8]) -> Option<Uuid>`（從 CN 解析）
  - `pub const DEVICE_CERT_DAYS: i64 = 365;`

- [ ] **Step 1: 寫失敗測試**（`ca.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};

    fn csr() -> String {
        let key = KeyPair::generate().unwrap();
        CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap()
    }

    #[test]
    fn init_then_sign_device_cert() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        for f in ["root.pem", "root.key", "intermediate.pem", "intermediate.key", "server.pem", "server.key"] {
            assert!(dir.path().join(f).exists(), "{f} missing");
        }

        let ca = Ca::load(dir.path()).unwrap();
        let id = Uuid::new_v4();
        let now = Utc::now();
        let issued = ca.sign_device_csr(&csr(), id, now).unwrap();

        let der = pem_to_der(&issued.pem);
        assert_eq!(device_id_of(&der), Some(id));
        assert_eq!(fingerprint(&der), issued.fingerprint);
        assert_eq!(issued.serial.len(), 32);
        assert!((issued.not_after - now - chrono::Duration::days(DEVICE_CERT_DAYS)).num_seconds().abs() < 5);
        assert!(ca.chain_pem().matches("BEGIN CERTIFICATE").count() == 2);
    }

    #[test]
    fn serials_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        let ca = Ca::load(dir.path()).unwrap();
        let a = ca.sign_device_csr(&csr(), Uuid::new_v4(), Utc::now()).unwrap();
        let b = ca.sign_device_csr(&csr(), Uuid::new_v4(), Utc::now()).unwrap();
        assert_ne!(a.serial, b.serial);
    }

    #[test]
    fn garbage_csr_is_error() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        let ca = Ca::load(dir.path()).unwrap();
        assert!(ca.sign_device_csr("not a csr", Uuid::new_v4(), Utc::now()).is_err());
    }

    fn pem_to_der(pem: &str) -> Vec<u8> {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap().to_vec()
    }
}
```

`tempfile` 需同時加入 `[dev-dependencies]`（Task 1 已加）。

- [ ] **Step 2: 執行確認失敗**

Run: `cargo test -p endpoint-server ca::`
Expected: 編譯失敗。

- [ ] **Step 3: 實作 `ca.rs`**

```rust
//! 私有 CA：根 CA（應離線保存）→ 中繼 CA（伺服器持有）→ 裝置／伺服器憑證。

use std::path::Path;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEVICE_CERT_DAYS: i64 = 365;

pub struct IssuedCert {
    pub serial: String,
    pub fingerprint: String,
    pub pem: String,
    pub not_after: DateTime<Utc>,
}

pub struct Ca {
    issuer: Issuer<'static, KeyPair>,
    chain_pem: String,
}

fn to_time(dt: DateTime<Utc>) -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(dt.timestamp()).expect("valid timestamp")
}

fn cn(name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, name);
    dn
}

/// 128-bit 隨機序號；首位元組確保 1..=0x7f，DER 編碼後長度固定、不會補零。
fn random_serial() -> [u8; 16] {
    let mut s = Uuid::new_v4().into_bytes();
    s[0] = (s[0] & 0x7f).max(1);
    s
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

pub fn device_id_of(der: &[u8]) -> Option<Uuid> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    Uuid::parse_str(cn).ok()
}

fn write_secret(path: &Path, contents: &str) -> anyhow::Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn init_ca(dir: &Path, server_names: Vec<String>) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let now = Utc::now();

    let mut root_params = CertificateParams::default();
    root_params.distinguished_name = cn("Endpoint Manager Root CA");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    root_params.not_before = to_time(now - Duration::minutes(5));
    root_params.not_after = to_time(now + Duration::days(3650));
    let root_key = KeyPair::generate()?;
    let root_cert = root_params.self_signed(&root_key)?;
    let root_key_pem = root_key.serialize_pem();
    let root_issuer = Issuer::new(root_params, root_key);

    let mut int_params = CertificateParams::default();
    int_params.distinguished_name = cn("Endpoint Manager Intermediate CA");
    int_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    int_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    int_params.use_authority_key_identifier_extension = true;
    int_params.not_before = to_time(now - Duration::minutes(5));
    int_params.not_after = to_time(now + Duration::days(1825));
    let int_key = KeyPair::generate()?;
    let int_cert = int_params.signed_by(&int_key, &root_issuer)?;
    let int_key_pem = int_key.serialize_pem();
    let int_issuer = Issuer::new(int_params, int_key);

    let mut srv_params = CertificateParams::new(server_names)?;
    srv_params.distinguished_name = cn("Endpoint Manager Server");
    srv_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    srv_params.use_authority_key_identifier_extension = true;
    srv_params.not_before = to_time(now - Duration::minutes(5));
    srv_params.not_after = to_time(now + Duration::days(825));
    let srv_key = KeyPair::generate()?;
    let srv_cert = srv_params.signed_by(&srv_key, &int_issuer)?;

    std::fs::write(dir.join("root.pem"), root_cert.pem())?;
    write_secret(&dir.join("root.key"), &root_key_pem)?;
    std::fs::write(dir.join("intermediate.pem"), int_cert.pem())?;
    write_secret(&dir.join("intermediate.key"), &int_key_pem)?;
    std::fs::write(dir.join("server.pem"), format!("{}{}", srv_cert.pem(), int_cert.pem()))?;
    write_secret(&dir.join("server.key"), &srv_key.serialize_pem())?;
    Ok(())
}

impl Ca {
    pub fn load(dir: &Path) -> anyhow::Result<Ca> {
        let read = |f: &str| {
            std::fs::read_to_string(dir.join(f)).with_context(|| format!("reading {f}"))
        };
        let int_pem = read("intermediate.pem")?;
        let int_key = KeyPair::from_pem(&read("intermediate.key")?)?;
        let issuer = Issuer::from_ca_cert_pem(&int_pem, int_key)?;
        let chain_pem = format!("{}{}", int_pem, read("root.pem")?);
        Ok(Ca { issuer, chain_pem })
    }

    pub fn chain_pem(&self) -> &str {
        &self.chain_pem
    }

    /// 只取 CSR 的公鑰；主體、用途、效期一律由伺服器決定。
    pub fn sign_device_csr(&self, csr_pem: &str, device_id: Uuid, now: DateTime<Utc>) -> anyhow::Result<IssuedCert> {
        let csr = CertificateSigningRequestParams::from_pem(csr_pem).context("invalid CSR")?;
        let serial = random_serial();
        let not_after = now + Duration::days(DEVICE_CERT_DAYS);

        let mut params = CertificateParams::default();
        params.distinguished_name = cn(&device_id.to_string());
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        params.not_before = to_time(now - Duration::minutes(5));
        params.not_after = to_time(not_after);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.use_authority_key_identifier_extension = true;

        let cert = params.signed_by(&csr.public_key, &self.issuer)?;
        Ok(IssuedCert {
            serial: hex::encode(serial),
            fingerprint: fingerprint(cert.der()),
            pem: cert.pem(),
            not_after: DateTime::from_timestamp(not_after.timestamp(), 0).expect("valid"),
        })
    }
}
```

> 若 rcgen 0.14 的實際 API（`Issuer::from_ca_cert_pem`、`KeyPair::serialize_pem`、`signed_by` 參數）與上方不符，以 context7 `/rustls/rcgen` 文件為準調整，並保持本 task 的 Interfaces 不變。

- [ ] **Step 4: 執行測試**

Run: `cargo test -p endpoint-server ca::`
Expected: 3 個測試 PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/server
git commit -m "feat(server): 兩層私有 CA 與裝置憑證簽發"
```

---

### Task 5: 註冊金鑰與 IP 限速

**Files:**
- Create: `crates/server/src/tokens.rs`、`crates/server/src/ratelimit.rs`
- Modify: `crates/server/src/lib.rs`

**Interfaces:**
- Produces:
  - `tokens::NewToken { name: String, group_label: Option<String>, expires_at: Option<DateTime<Utc>>, max_uses: i32, created_by: String }`
  - `tokens::create_token(pool: &PgPool, t: &NewToken) -> Result<(i64, String), sqlx::Error>`（回傳 id 與**明碼金鑰**，明碼只出現這一次）
  - `tokens::consume_token(conn: &mut PgConnection, token: &str) -> Result<Option<i64>, sqlx::Error>`（成功回傳 token id；原子性遞增 used_count）
  - `tokens::hash_token(token: &str) -> String`
  - `ratelimit::RateLimiter::new(max: u32, window: Duration) -> RateLimiter`、`check(&self, ip: IpAddr, now: Instant) -> bool`

- [ ] **Step 1: 寫失敗測試**

`ratelimit.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn allows_up_to_max_then_blocks_until_window_passes() {
        let rl = RateLimiter::new(2, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let t0 = Instant::now();
        assert!(rl.check(ip, t0));
        assert!(rl.check(ip, t0));
        assert!(!rl.check(ip, t0));
        assert!(rl.check(ip, t0 + Duration::from_secs(61)));
    }

    #[test]
    fn ips_are_independent() {
        let rl = RateLimiter::new(1, Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), t0));
        assert!(rl.check(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), t0));
    }
}
```

`tokens.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn new_token(max_uses: i32, expires_at: Option<DateTime<Utc>>) -> NewToken {
        NewToken { name: "t".into(), group_label: None, expires_at, max_uses, created_by: "test".into() }
    }

    #[sqlx::test(migrations = false)]
    async fn consume_respects_max_uses(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let (id, tok) = create_token(&pool, &new_token(1, None)).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        assert_eq!(consume_token(&mut c, &tok).await.unwrap(), Some(id));
        assert_eq!(consume_token(&mut c, &tok).await.unwrap(), None);
    }

    #[sqlx::test(migrations = false)]
    async fn expired_revoked_and_wrong_tokens_rejected(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let past = Utc::now() - chrono::Duration::hours(1);
        let (_, expired) = create_token(&pool, &new_token(10, Some(past))).await.unwrap();
        let (rid, revoked) = create_token(&pool, &new_token(10, None)).await.unwrap();
        sqlx::query("UPDATE enroll_tokens SET revoked_at = now() WHERE id = $1")
            .bind(rid).execute(&pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        assert_eq!(consume_token(&mut c, &expired).await.unwrap(), None);
        assert_eq!(consume_token(&mut c, &revoked).await.unwrap(), None);
        assert_eq!(consume_token(&mut c, "nope").await.unwrap(), None);
    }

    #[sqlx::test(migrations = false)]
    async fn plaintext_is_not_stored(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let (_, tok) = create_token(&pool, &new_token(1, None)).await.unwrap();
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM enroll_tokens")
            .fetch_one(&pool).await.unwrap();
        assert_ne!(stored, tok);
        assert_eq!(stored, hash_token(&tok));
    }
}
```

- [ ] **Step 2: 執行確認失敗**

Run: `cargo test -p endpoint-server tokens:: ratelimit::`
Expected: 編譯失敗。

- [ ] **Step 3: 實作 `ratelimit.rs`**

```rust
//! 依 IP 的固定視窗限速（用於未經 mTLS 的註冊端點）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max: u32,
    window: Duration,
    hits: Mutex<HashMap<IpAddr, (Instant, u32)>>,
}

impl RateLimiter {
    pub fn new(max: u32, window: Duration) -> Self {
        Self { max, window, hits: Mutex::new(HashMap::new()) }
    }

    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        let mut hits = self.hits.lock().expect("ratelimit lock");
        if hits.len() > 100_000 {
            hits.retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let entry = hits.entry(ip).or_insert((now, 0));
        if now.duration_since(entry.0) >= self.window {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= self.max
    }
}
```

- [ ] **Step 4: 實作 `tokens.rs`**

```rust
//! 註冊金鑰。資料庫只存 SHA-256；查詢以 hash 比對，不會有逐字元比較的時序洩漏。

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

pub struct NewToken {
    pub name: String,
    pub group_label: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: i32,
    pub created_by: String,
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub async fn create_token(pool: &PgPool, t: &NewToken) -> Result<(i64, String), sqlx::Error> {
    let token = generate_token();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO enroll_tokens (name, token_hash, group_label, expires_at, max_uses, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&t.name)
    .bind(hash_token(&token))
    .bind(&t.group_label)
    .bind(t.expires_at)
    .bind(t.max_uses)
    .bind(&t.created_by)
    .fetch_one(pool)
    .await?;
    Ok((id, token))
}

/// 單一 UPDATE 完成檢查與遞增，並發時也不會超過 max_uses。
pub async fn consume_token(conn: &mut PgConnection, token: &str) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE enroll_tokens SET used_count = used_count + 1 \
         WHERE token_hash = $1 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND used_count < max_uses \
         RETURNING id",
    )
    .bind(hash_token(token))
    .fetch_optional(conn)
    .await
}
```

- [ ] **Step 5: `lib.rs` 加入 `pub mod ratelimit; pub mod tokens;`，執行測試**

Run: `cargo test -p endpoint-server tokens:: ratelimit::`
Expected: 5 個測試 PASS。

- [ ] **Step 6: Commit**

```bash
git add crates/server
git commit -m "feat(server): 註冊金鑰建立/消耗與 IP 限速"
```

---

### Task 6: AppState、錯誤處理、mTLS 監聽、身分驗證、測試框架

**Files:**
- Create: `crates/server/src/error.rs`、`tls.rs`、`identity.rs`
- Modify: `crates/server/src/lib.rs`
- Create: `crates/server/tests/common/mod.rs`、`crates/server/tests/checkin.rs`（本 task 先放 healthz 與 401 測試）

**Interfaces:**
- Consumes: `ca::{Ca, fingerprint, init_ca}`、`db::migrate`、`partitions::maintain_partitions`、`ratelimit::RateLimiter`
- Produces:
  - `error::AppError`（`Unauthorized`、`BadRequest(String)`、`PayloadTooLarge`、`TooManyRequests`、`Db(sqlx::Error)`、`Internal(anyhow::Error)`），實作 `IntoResponse`
  - `lib::AppState { pool: PgPool, ca: Arc<Ca>, heartbeat: Arc<heartbeat::HeartbeatBuffer>, enroll_limiter: Arc<RateLimiter> }`、`AppState::new(pool, ca) -> AppState`
  - `lib::agent_router(state: AppState) -> Router`
  - `tls::PeerCert { pub fingerprint: String }`、`tls::server_config(ca_dir: &Path) -> anyhow::Result<Arc<rustls::ServerConfig>>`、`tls::serve_mtls(listener: TcpListener, config: Arc<ServerConfig>, app: Router) -> anyhow::Result<()>`
  - `identity::AuthedDevice { device_id: Uuid, cert_not_after: DateTime<Utc> }`（axum extractor）
  - 測試：`common::TestServer::start(pool) -> TestServer`、`TestServer::client(Option<&TestAgent>) -> reqwest::Client`、`url(&str) -> String`、`create_token(max_uses: i32) -> String`、`enroll(token, smbios, serial) -> reqwest::Response`、`enroll_ok(token, smbios, serial) -> TestAgent`；`common::TestAgent { device_id, key_pem, chain_pem }`；`common::make_csr() -> (String, String)`（CSR pem、key pem）

> 本 task 需要 `heartbeat::HeartbeatBuffer` 型別存在才能編譯 AppState。先建立空殼：
> ```rust
> // crates/server/src/heartbeat.rs
> pub struct HeartbeatBuffer;
> impl HeartbeatBuffer { pub fn new() -> Self { Self } }
> ```
> Task 8 會補完。

- [ ] **Step 1: 實作 `error.rs`**

```rust
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("too many requests")]
    TooManyRequests,
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<protocol::ValidationError> for AppError {
    fn from(e: protocol::ValidationError) -> Self {
        AppError::BadRequest(e.to_string())
    }
}

fn db_unavailable(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed | sqlx::Error::Io(_) | sqlx::Error::Tls(_)
    )
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let retry = |status: StatusCode| {
            let mut r = status.into_response();
            r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
            r
        };
        match self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            AppError::TooManyRequests => retry(StatusCode::TOO_MANY_REQUESTS),
            AppError::Db(e) if db_unavailable(&e) => {
                tracing::error!(error = %e, "database unavailable");
                retry(StatusCode::SERVICE_UNAVAILABLE)
            }
            AppError::Db(e) => {
                tracing::error!(error = %e, "database error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
```

- [ ] **Step 2: 實作 `tls.rs`**

```rust
//! 自行 accept TLS，把用戶端憑證指紋放進 request extension 後交給 axum。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

#[derive(Clone, Debug)]
pub struct PeerCert {
    pub fingerprint: String,
}

/// 用戶端憑證「可選」：/v1/enroll 不需要憑證，其他端點由 AuthedDevice 強制要求。
pub fn server_config(ca_dir: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(ca_dir.join("root.pem"))?)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()?;
    let certs = CertificateDer::pem_file_iter(ca_dir.join("server.pem"))?
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(ca_dir.join("server.key"))?;
    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub async fn serve_mtls(listener: TcpListener, config: Arc<ServerConfig>, app: Router) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, remote): (_, SocketAddr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| PeerCert { fingerprint: crate::ca::fingerprint(c) });
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(remote));
                if let Some(p) = &peer {
                    req.extensions_mut().insert(p.clone());
                }
                app.clone().oneshot(req)
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}
```

- [ ] **Step 3: 實作 `identity.rs`**

```rust
//! 已驗證的 Agent 身分。TLS 握手已證明對方持有憑證私鑰；
//! 這裡再以指紋比對 device_certs，確認憑證是本系統簽發、未撤銷、未過期。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::AppError;
use crate::tls::PeerCert;
use crate::AppState;

#[derive(Debug, Clone)]
pub struct AuthedDevice {
    pub device_id: Uuid,
    pub cert_not_after: DateTime<Utc>,
}

impl FromRequestParts<AppState> for AuthedDevice {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let peer = parts.extensions.get::<PeerCert>().ok_or(AppError::Unauthorized)?;
        let row: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT device_id, not_after FROM device_certs \
             WHERE fingerprint = $1 AND revoked_at IS NULL AND not_after > now()",
        )
        .bind(&peer.fingerprint)
        .fetch_optional(&state.pool)
        .await?;
        let (device_id, cert_not_after) = row.ok_or(AppError::Unauthorized)?;
        Ok(AuthedDevice { device_id, cert_not_after })
    }
}
```

- [ ] **Step 4: 更新 `lib.rs`**

```rust
//! Endpoint Manager 伺服器。

pub mod ca;
pub mod db;
pub mod error;
pub mod heartbeat;
pub mod identity;
pub mod partitions;
pub mod ratelimit;
pub mod tls;
pub mod tokens;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;
use sqlx::PgPool;

pub const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
pub const ENROLL_PER_IP_PER_MINUTE: u32 = 60;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub ca: Arc<ca::Ca>,
    pub heartbeat: Arc<heartbeat::HeartbeatBuffer>,
    pub enroll_limiter: Arc<ratelimit::RateLimiter>,
}

impl AppState {
    pub fn new(pool: PgPool, ca: ca::Ca) -> Self {
        Self {
            pool,
            ca: Arc::new(ca),
            heartbeat: Arc::new(heartbeat::HeartbeatBuffer::new()),
            enroll_limiter: Arc::new(ratelimit::RateLimiter::new(
                ENROLL_PER_IP_PER_MINUTE,
                Duration::from_secs(60),
            )),
        }
    }
}

async fn healthz(State(st): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&st.pool).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub fn agent_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
```

- [ ] **Step 5: 建立測試框架 `tests/common/mod.rs`**

```rust
#![allow(dead_code)]

use std::net::SocketAddr;

use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use protocol::{EnrollRequest, EnrollResponse, SCHEMA_VERSION};
use rcgen::{CertificateParams, KeyPair};
use sqlx::PgPool;
use tokio::net::TcpListener;
use uuid::Uuid;

pub struct TestServer {
    pub addr: SocketAddr,
    pub pool: PgPool,
    pub state: AppState,
    root_pem: String,
    _dir: tempfile::TempDir,
}

pub struct TestAgent {
    pub device_id: Uuid,
    pub key_pem: String,
    pub chain_pem: String,
}

pub fn make_csr() -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap();
    (csr, key.serialize_pem())
}

impl TestServer {
    pub async fn start(pool: PgPool) -> TestServer {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        ca::init_ca(dir.path(), vec!["localhost".into()]).unwrap();
        db::migrate(&pool).await.unwrap();
        partitions::maintain_partitions(&pool, chrono::Utc::now()).await.unwrap();

        let state = AppState::new(pool.clone(), ca::Ca::load(dir.path()).unwrap());
        let cfg = tls::server_config(dir.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(tls::serve_mtls(listener, cfg, agent_router(state.clone())));

        let root_pem = std::fs::read_to_string(dir.path().join("root.pem")).unwrap();
        TestServer { addr, pool, state, root_pem, _dir: dir }
    }

    pub fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{}", self.addr.port(), path)
    }

    pub fn client(&self, agent: Option<&TestAgent>) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_pem(self.root_pem.as_bytes()).unwrap())
            .resolve("localhost", self.addr);
        if let Some(a) = agent {
            let pem = format!("{}{}", a.chain_pem, a.key_pem);
            b = b.identity(reqwest::Identity::from_pem(pem.as_bytes()).unwrap());
        }
        b.build().unwrap()
    }

    pub async fn create_token(&self, max_uses: i32) -> String {
        tokens::create_token(
            &self.pool,
            &tokens::NewToken {
                name: "test".into(),
                group_label: None,
                expires_at: None,
                max_uses,
                created_by: "test".into(),
            },
        )
        .await
        .unwrap()
        .1
    }

    pub async fn enroll_with_csr(&self, token: &str, csr: &str, smbios: Option<&str>, serial: Option<&str>) -> reqwest::Response {
        self.client(None)
            .post(self.url("/v1/enroll"))
            .json(&EnrollRequest {
                schema_version: SCHEMA_VERSION,
                enroll_token: token.into(),
                csr_pem: csr.into(),
                hostname: "PC-001".into(),
                smbios_uuid: smbios.map(Into::into),
                bios_serial: serial.map(Into::into),
                mac_addresses: vec!["00:11:22:33:44:55".into()],
            })
            .send()
            .await
            .unwrap()
    }

    pub async fn enroll(&self, token: &str, smbios: Option<&str>, serial: Option<&str>) -> reqwest::Response {
        let (csr, _) = make_csr();
        self.enroll_with_csr(token, &csr, smbios, serial).await
    }

    pub async fn enroll_ok(&self, token: &str, smbios: Option<&str>, serial: Option<&str>) -> TestAgent {
        let (csr, key_pem) = make_csr();
        let resp = self.enroll_with_csr(token, &csr, smbios, serial).await;
        assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap_or_default());
        let body: EnrollResponse = resp.json().await.unwrap();
        TestAgent { device_id: body.device_id, key_pem, chain_pem: body.certificate_chain_pem }
    }
}
```

`crates/server/Cargo.toml` 的 `[dev-dependencies]` 補上 `rcgen.workspace = true`、`rustls.workspace = true`（測試直接使用）。

> reqwest 0.13 的 rustls 相關 builder 方法名稱（`tls_built_in_root_certs`、`identity`）若有變動，以 context7 查 reqwest 文件為準。

- [ ] **Step 6: 寫第一批整合測試 `tests/checkin.rs`**

```rust
mod common;

use common::TestServer;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn healthz_ok_without_client_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let r = s.client(None).get(s.url("/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
}
```

- [ ] **Step 7: 執行測試**

Run: `cargo test -p endpoint-server --test checkin`
Expected: 1 個測試 PASS（證明 TLS accept loop、Router、測試框架可運作）。

- [ ] **Step 8: Commit**

```bash
git add crates/server
git commit -m "feat(server): mTLS 監聽、錯誤對應、AuthedDevice 與整合測試框架"
```

---

### Task 7: 註冊端點 `/v1/enroll`

**Files:**
- Create: `crates/server/src/enroll.rs`
- Modify: `crates/server/src/lib.rs`（`pub mod enroll;`，router 加 `.route("/v1/enroll", post(enroll::enroll))`）
- Create: `crates/server/tests/enroll.rs`

**Interfaces:**
- Consumes: `tokens::consume_token`、`Ca::sign_device_csr`、`Ca::chain_pem`、`AppState.enroll_limiter`
- Produces:
  - `enroll::DeviceMatch { Reuse(Uuid), NewDuplicateSuspect, New }`
  - `enroll::match_device(candidates: &[(Uuid, Option<String>)], bios_serial: Option<&str>) -> DeviceMatch`
  - `enroll::normalize_smbios(raw: Option<&str>) -> Option<String>`（大寫；全 0 或全 F 等無效值回 None）
  - handler `enroll::enroll`

- [ ] **Step 1: 寫純函式失敗測試**（`enroll.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_serial_reuses() {
        let id = Uuid::new_v4();
        assert_eq!(match_device(&[(id, Some("SN1".into()))], Some("SN1")), DeviceMatch::Reuse(id));
    }

    #[test]
    fn different_serial_is_duplicate_suspect() {
        assert_eq!(
            match_device(&[(Uuid::new_v4(), Some("SN1".into()))], Some("SN2")),
            DeviceMatch::NewDuplicateSuspect
        );
    }

    #[test]
    fn missing_serial_never_reuses() {
        assert_eq!(
            match_device(&[(Uuid::new_v4(), None)], None),
            DeviceMatch::NewDuplicateSuspect
        );
    }

    #[test]
    fn no_candidates_is_new() {
        assert_eq!(match_device(&[], Some("SN1")), DeviceMatch::New);
    }

    #[test]
    fn bogus_smbios_ignored() {
        assert_eq!(normalize_smbios(Some("00000000-0000-0000-0000-000000000000")), None);
        assert_eq!(normalize_smbios(Some("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")), None);
        assert_eq!(normalize_smbios(Some("  ")), None);
        assert_eq!(normalize_smbios(Some("4c4c4544-0042")), Some("4C4C4544-0042".into()));
    }
}
```

- [ ] **Step 2: 寫整合測試 `tests/enroll.rs`**

```rust
mod common;

use common::TestServer;
use protocol::{CheckinRequest, SCHEMA_VERSION};
use sqlx::PgPool;

fn checkin_body() -> CheckinRequest {
    CheckinRequest {
        schema_version: SCHEMA_VERSION,
        agent_version: "0.1.0".into(),
        boot_time: chrono::Utc::now(),
        logged_on_user: None,
        ip_addresses: vec![],
        section_hashes: Default::default(),
        section_errors: Default::default(),
    }
}

#[sqlx::test(migrations = false)]
async fn enroll_with_valid_token_creates_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let (host, status): (String, String) =
        sqlx::query_as("SELECT hostname, status FROM devices WHERE id = $1")
            .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!((host.as_str(), status.as_str()), ("PC-001", "active"));
    assert_eq!(a.chain_pem.matches("BEGIN CERTIFICATE").count(), 3);
}

#[sqlx::test(migrations = false)]
async fn enroll_with_bad_token_is_401(pool: PgPool) {
    let s = TestServer::start(pool).await;
    assert_eq!(s.enroll("wrong", None, None).await.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn concurrent_enroll_does_not_exceed_max_uses(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let futs = (0..10).map(|i| {
        let serial = format!("SN-{i}");
        let uuid = format!("UUID-{i}");
        let (s, tok) = (&s, &tok);
        async move { s.enroll(tok, Some(&uuid), Some(&serial)).await.status().as_u16() }
    });
    let statuses = futures_util::future::join_all(futs).await;
    assert_eq!(statuses.iter().filter(|&&c| c == 200).count(), 3);
    assert_eq!(statuses.iter().filter(|&&c| c == 401).count(), 7);
}

#[sqlx::test(migrations = false)]
async fn reenroll_same_hardware_reuses_device_and_revokes_old_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let first = s.enroll_ok(&tok, Some("UUID-A"), Some("SN-A")).await;
    let second = s.enroll_ok(&tok, Some("uuid-a"), Some("SN-A")).await;
    assert_eq!(first.device_id, second.device_id);

    let old = s.client(Some(&first)).post(s.url("/v1/checkin")).json(&checkin_body()).send().await.unwrap();
    assert_eq!(old.status(), 401);
    let new = s.client(Some(&second)).post(s.url("/v1/checkin")).json(&checkin_body()).send().await.unwrap();
    assert_eq!(new.status(), 200);
}

#[sqlx::test(migrations = false)]
async fn same_smbios_different_serial_marked_duplicate_suspect(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let a = s.enroll_ok(&tok, Some("UUID-VM"), Some("SN-1")).await;
    let b = s.enroll_ok(&tok, Some("UUID-VM"), Some("SN-2")).await;
    assert_ne!(a.device_id, b.device_id);
    let status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(b.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(status, "duplicate_suspect");
}

#[sqlx::test(migrations = false)]
async fn invalid_csr_is_400_and_token_not_consumed(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let r = s.enroll_with_csr(&tok, "garbage", None, None).await;
    assert_eq!(r.status(), 400);
    s.enroll_ok(&tok, None, None).await; // 金鑰仍可使用一次
}

#[sqlx::test(migrations = false)]
async fn future_schema_version_rejected(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let (csr, _) = common::make_csr();
    let r = s.client(None).post(s.url("/v1/enroll"))
        .json(&serde_json::json!({
            "schema_version": 99, "enroll_token": tok, "csr_pem": csr, "hostname": "X",
            "smbios_uuid": null, "bios_serial": null, "mac_addresses": []
        }))
        .send().await.unwrap();
    assert_eq!(r.status(), 400);
}
```

`[dev-dependencies]` 加 `futures-util = "0.3"`、`serde_json.workspace = true`、`chrono.workspace = true`。
（`/v1/checkin` 在 Task 8 才實作；`reenroll_...` 測試在 Task 8 完成前會以 404 失敗，屬預期。）

- [ ] **Step 3: 執行確認失敗**

Run: `cargo test -p endpoint-server enroll`
Expected: 編譯失敗（`match_device` 等未定義）。

- [ ] **Step 4: 實作 `enroll.rs`**

```rust
//! /v1/enroll：以註冊金鑰換取裝置憑證。

use std::net::SocketAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, State};
use chrono::Utc;
use protocol::{EnrollRequest, EnrollResponse, SCHEMA_VERSION, validate_strings};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::tokens;

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceMatch {
    Reuse(Uuid),
    NewDuplicateSuspect,
    New,
}

pub fn match_device(candidates: &[(Uuid, Option<String>)], bios_serial: Option<&str>) -> DeviceMatch {
    let serial = bios_serial.map(str::trim).filter(|s| !s.is_empty());
    if let Some(serial) = serial {
        if let Some((id, _)) = candidates.iter().find(|(_, s)| s.as_deref() == Some(serial)) {
            return DeviceMatch::Reuse(*id);
        }
    }
    if candidates.is_empty() { DeviceMatch::New } else { DeviceMatch::NewDuplicateSuspect }
}

pub fn normalize_smbios(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim().to_ascii_uppercase();
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.is_empty() || hex.chars().all(|c| c == '0') || hex.chars().all(|c| c == 'F') {
        None
    } else {
        Some(s)
    }
}

pub async fn enroll(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, AppError> {
    if !st.enroll_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    if req.schema_version > SCHEMA_VERSION {
        return Err(AppError::BadRequest("unsupported schema_version".into()));
    }
    validate_strings(&(&req.hostname, &req.smbios_uuid, &req.bios_serial, &req.mac_addresses))?;

    let mut tx = st.pool.begin().await?;
    let token_id = tokens::consume_token(&mut *tx, &req.enroll_token)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let smbios = normalize_smbios(req.smbios_uuid.as_deref());
    let serial = req.bios_serial.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let candidates: Vec<(Uuid, Option<String>)> = match &smbios {
        Some(u) => sqlx::query_as(
            "SELECT id, bios_serial FROM devices WHERE smbios_uuid = $1 AND status <> 'retired' FOR UPDATE",
        )
        .bind(u)
        .fetch_all(&mut *tx)
        .await?,
        None => vec![],
    };

    let device_id = match match_device(&candidates, serial) {
        DeviceMatch::Reuse(id) => {
            sqlx::query("UPDATE device_certs SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL")
                .bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE devices SET hostname = $2, enroll_token_id = $3 WHERE id = $1")
                .bind(id).bind(&req.hostname).bind(token_id).execute(&mut *tx).await?;
            id
        }
        m => {
            let id = Uuid::new_v4();
            let status = if m == DeviceMatch::NewDuplicateSuspect { "duplicate_suspect" } else { "active" };
            sqlx::query(
                "INSERT INTO devices (id, hostname, smbios_uuid, bios_serial, status, enroll_token_id) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(id).bind(&req.hostname).bind(&smbios).bind(serial).bind(status).bind(token_id)
            .execute(&mut *tx).await?;
            id
        }
    };

    let issued = st
        .ca
        .sign_device_csr(&req.csr_pem, device_id, Utc::now())
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    sqlx::query("INSERT INTO device_certs (serial, fingerprint, device_id, not_after) VALUES ($1, $2, $3, $4)")
        .bind(&issued.serial).bind(&issued.fingerprint).bind(device_id).bind(issued.not_after)
        .execute(&mut *tx).await?;
    tx.commit().await?;

    tracing::info!(%device_id, token_id, "device enrolled");
    Ok(Json(EnrollResponse {
        device_id,
        certificate_chain_pem: format!("{}{}", issued.pem, st.ca.chain_pem()),
    }))
}
```

> 錯誤時提早 return 會 drop `tx`，sqlx 自動 rollback，因此 CSR 無效時金鑰使用次數不會增加。

- [ ] **Step 5: 執行測試**

Run: `cargo test -p endpoint-server enroll`
Expected: 5 個單元測試 PASS；整合測試中除 `reenroll_same_hardware_reuses_device_and_revokes_old_cert`（等 Task 8）外全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add crates/server
git commit -m "feat(server): /v1/enroll 註冊端點與重灌/重複裝置判斷"
```

---

### Task 8: 心跳 `/v1/checkin` 與熱欄位批次寫入

**Files:**
- Modify: `crates/server/src/heartbeat.rs`（取代空殼）
- Create: `crates/server/src/checkin.rs`
- Modify: `crates/server/src/lib.rs`（`pub mod checkin;`，router 加 `.route("/v1/checkin", post(checkin::checkin))`）
- Modify: `crates/server/tests/checkin.rs`

**Interfaces:**
- Consumes: `AuthedDevice`、`db::load_settings`
- Produces:
  - `heartbeat::HotFields { seen_at: DateTime<Utc>, ip: Option<String>, logged_on_user: Option<String>, boot_time: DateTime<Utc>, agent_version: String, section_errors: serde_json::Value }`
  - `HeartbeatBuffer::new()`、`record(&self, id: Uuid, hot: HotFields)`、`flush(&self, pool: &PgPool) -> Result<usize, sqlx::Error>`
  - `checkin::sections_to_request(stored: &HashMap<Section, String>, reported: &BTreeMap<Section, String>) -> Vec<Section>`
  - `pub const RENEW_BEFORE_DAYS: i64 = 30;`

- [ ] **Step 1: 寫失敗測試**

`checkin.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_unknown_and_changed_sections_only() {
        let stored = HashMap::from([(Section::Software, "a".to_string()), (Section::Basic, "b".to_string())]);
        let reported = BTreeMap::from([
            (Section::Software, "a".to_string()),  // 相同 → 不要求
            (Section::Basic, "CHANGED".to_string()), // 變更 → 要求
            (Section::Patches, "x".to_string()),   // 伺服器沒有 → 要求
        ]);
        assert_eq!(sections_to_request(&stored, &reported), vec![Section::Basic, Section::Patches]);
    }
}
```

`tests/checkin.rs` 追加：

```rust
use protocol::{CheckinRequest, CheckinResponse, SCHEMA_VERSION, Section};
use std::collections::BTreeMap;

fn body(hashes: BTreeMap<Section, String>) -> CheckinRequest {
    CheckinRequest {
        schema_version: SCHEMA_VERSION,
        agent_version: "0.1.0".into(),
        boot_time: chrono::Utc::now(),
        logged_on_user: Some("CORP\\alice".into()),
        ip_addresses: vec!["10.0.0.5".into()],
        section_hashes: hashes,
        section_errors: BTreeMap::from([(Section::Patches, "WMI timeout".to_string())]),
    }
}

#[sqlx::test(migrations = false)]
async fn checkin_without_client_cert_is_401(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let r = s.client(None).post(s.url("/v1/checkin")).json(&body(BTreeMap::new())).send().await.unwrap();
    assert_eq!(r.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn checkin_requests_unknown_sections(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let hashes = BTreeMap::from([(Section::Software, "h1".into()), (Section::Basic, "h2".into())]);
    let r: CheckinResponse = s.client(Some(&a)).post(s.url("/v1/checkin")).json(&body(hashes))
        .send().await.unwrap().json().await.unwrap();
    assert_eq!(r.request_sections, vec![Section::Basic, Section::Software]);
    assert_eq!(r.next_checkin_seconds, 60);
    assert!(!r.renew_certificate);
}

#[sqlx::test(migrations = false)]
async fn heartbeat_flush_updates_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    s.client(Some(&a)).post(s.url("/v1/checkin")).json(&body(BTreeMap::new())).send().await.unwrap();

    assert_eq!(s.state.heartbeat.flush(&s.pool).await.unwrap(), 1);
    let (ip, user, errors): (Option<String>, Option<String>, String) = sqlx::query_as(
        "SELECT last_ip, logged_on_user, section_errors::text FROM devices WHERE id = $1",
    ).bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(user.as_deref(), Some("CORP\\alice"));
    assert!(errors.contains("WMI timeout"));
    assert_eq!(s.state.heartbeat.flush(&s.pool).await.unwrap(), 0);
}

#[sqlx::test(migrations = false)]
async fn renew_flag_when_cert_expiring(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE device_certs SET not_after = now() + interval '10 days' WHERE device_id = $1")
        .bind(a.device_id).execute(&s.pool).await.unwrap();
    let r: CheckinResponse = s.client(Some(&a)).post(s.url("/v1/checkin")).json(&body(BTreeMap::new()))
        .send().await.unwrap().json().await.unwrap();
    assert!(r.renew_certificate);
}

#[sqlx::test(migrations = false)]
async fn revoked_cert_is_401(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE device_certs SET revoked_at = now() WHERE device_id = $1")
        .bind(a.device_id).execute(&s.pool).await.unwrap();
    let r = s.client(Some(&a)).post(s.url("/v1/checkin")).json(&body(BTreeMap::new())).send().await.unwrap();
    assert_eq!(r.status(), 401);
}
```

- [ ] **Step 2: 執行確認失敗**

Run: `cargo test -p endpoint-server --test checkin`
Expected: 編譯失敗。

- [ ] **Step 3: 實作 `heartbeat.rs`**

```rust
//! 心跳熱欄位先存記憶體，定期批次寫入，避免每次心跳都寫資料庫。

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub const FLUSH_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub seen_at: DateTime<Utc>,
    pub ip: Option<String>,
    pub logged_on_user: Option<String>,
    pub boot_time: DateTime<Utc>,
    pub agent_version: String,
    pub section_errors: serde_json::Value,
}

#[derive(Default)]
pub struct HeartbeatBuffer {
    inner: Mutex<HashMap<Uuid, HotFields>>,
}

impl HeartbeatBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, id: Uuid, hot: HotFields) {
        self.inner.lock().expect("heartbeat lock").insert(id, hot);
    }

    /// 寫入失敗時把資料放回（不覆蓋期間收到的較新資料）。
    pub async fn flush(&self, pool: &PgPool) -> Result<usize, sqlx::Error> {
        let batch = std::mem::take(&mut *self.inner.lock().expect("heartbeat lock"));
        if batch.is_empty() {
            return Ok(0);
        }
        let mut ids = Vec::with_capacity(batch.len());
        let (mut seen, mut ips, mut users, mut boots, mut vers, mut errs) =
            (vec![], vec![], vec![], vec![], vec![], vec![]);
        for (id, h) in &batch {
            ids.push(*id);
            seen.push(h.seen_at);
            ips.push(h.ip.clone());
            users.push(h.logged_on_user.clone());
            boots.push(h.boot_time);
            vers.push(h.agent_version.clone());
            errs.push(h.section_errors.to_string());
        }
        let result = sqlx::query(
            "UPDATE devices d SET last_seen_at = v.seen, last_ip = v.ip, logged_on_user = v.usr, \
                 boot_time = v.boot, agent_version = v.ver, section_errors = v.errs::jsonb \
             FROM UNNEST($1::uuid[], $2::timestamptz[], $3::text[], $4::text[], $5::timestamptz[], $6::text[], $7::text[]) \
                 AS v(id, seen, ip, usr, boot, ver, errs) \
             WHERE d.id = v.id",
        )
        .bind(&ids).bind(&seen).bind(&ips).bind(&users).bind(&boots).bind(&vers).bind(&errs)
        .execute(pool)
        .await;
        match result {
            Ok(_) => Ok(batch.len()),
            Err(e) => {
                let mut inner = self.inner.lock().expect("heartbeat lock");
                for (id, h) in batch {
                    inner.entry(id).or_insert(h);
                }
                Err(e)
            }
        }
    }
}
```

- [ ] **Step 4: 實作 `checkin.rs`**

```rust
//! /v1/checkin：記錄心跳，告訴 Agent 要上傳哪些區段。

use std::collections::{BTreeMap, HashMap};

use axum::Json;
use axum::extract::State;
use chrono::{Duration, Utc};
use protocol::{CheckinRequest, CheckinResponse, SCHEMA_VERSION, Section, validate_strings};

use crate::AppState;
use crate::db::load_settings;
use crate::error::AppError;
use crate::heartbeat::HotFields;
use crate::identity::AuthedDevice;

pub const RENEW_BEFORE_DAYS: i64 = 30;

pub fn sections_to_request(stored: &HashMap<Section, String>, reported: &BTreeMap<Section, String>) -> Vec<Section> {
    reported
        .iter()
        .filter(|(s, h)| stored.get(s) != Some(*h))
        .map(|(s, _)| *s)
        .collect()
}

pub async fn checkin(
    State(st): State<AppState>,
    device: AuthedDevice,
    Json(req): Json<CheckinRequest>,
) -> Result<Json<CheckinResponse>, AppError> {
    if req.schema_version > SCHEMA_VERSION {
        return Err(AppError::BadRequest("unsupported schema_version".into()));
    }
    validate_strings(&req)?;

    st.heartbeat.record(
        device.device_id,
        HotFields {
            seen_at: Utc::now(),
            ip: req.ip_addresses.first().cloned(),
            logged_on_user: req.logged_on_user.clone(),
            boot_time: req.boot_time,
            agent_version: req.agent_version.clone(),
            section_errors: serde_json::to_value(&req.section_errors).expect("serializable"),
        },
    );

    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT section, hash FROM inventory_sections WHERE device_id = $1")
            .bind(device.device_id)
            .fetch_all(&st.pool)
            .await?;
    let stored: HashMap<Section, String> = rows
        .into_iter()
        .filter_map(|(s, h)| Section::parse(&s).map(|s| (s, h)))
        .collect();

    let settings = load_settings(&st.pool).await?;
    Ok(Json(CheckinResponse {
        next_checkin_seconds: settings.checkin_interval_secs,
        request_sections: sections_to_request(&stored, &req.section_hashes),
        collection_intervals: settings.intervals,
        renew_certificate: device.cert_not_after - Utc::now() < Duration::days(RENEW_BEFORE_DAYS),
    }))
}
```

- [ ] **Step 5: 執行測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS，包含 Task 7 的 `reenroll_same_hardware_reuses_device_and_revokes_old_cert`。

- [ ] **Step 6: Commit**

```bash
git add crates/server
git commit -m "feat(server): /v1/checkin 心跳與熱欄位批次寫入"
```

---

### Task 9: 盤點上傳 `/v1/inventory/{section}` 與變更記錄

**Files:**
- Create: `crates/server/src/diff.rs`、`crates/server/src/inventory.rs`
- Modify: `crates/server/src/lib.rs`（`pub mod diff; pub mod inventory;`，router 加 `.route("/v1/inventory/{section}", put(inventory::upload))`）
- Create: `crates/server/tests/inventory.rs`

**Interfaces:**
- Consumes: `AuthedDevice`、`protocol::{InventoryUpload, InventoryPayload}`
- Produces:
  - `diff::items_of(p: &InventoryPayload) -> BTreeMap<String, String>`
  - `diff::ChangeKind { Added, Removed, Updated }`（`as_str()` → `"added"` 等）、`diff::Change { kind, key, old: Option<String>, new: Option<String> }`
  - `diff::diff(old: &BTreeMap<String,String>, new: &BTreeMap<String,String>) -> Vec<Change>`
  - `inventory::MAX_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024`
  - `inventory::decode_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, AppError>`
  - `inventory::store_section(pool: &PgPool, device_id: Uuid, payload: &InventoryPayload) -> Result<(), AppError>`
  - `inventory::load_payload(conn: &mut PgConnection, device_id: Uuid, section: Section) -> Result<Option<InventoryPayload>, sqlx::Error>`

**差異比對的 key／value 規則**（寫進 `diff.rs` 文件註解）：

| 區段 | key | value | 刻意排除 |
|---|---|---|---|
| basic | 欄位名（hostname、domain、is_domain_joined、os_caption、os_build） | 欄位值 | — |
| hardware | manufacturer、model、cpu、ram_mb、`disk:<name>` | 值；磁碟只取 size_bytes | free_bytes（天天變動） |
| software | `name\|arch\|publisher` | 同 key 所有版本排序後以 `, ` 串接 | install_date |
| patches | kb | installed_on（無則空字串） | — |
| services | name | `start_mode\|binary_path` | state（執行／停止經常變動） |

- [ ] **Step 1: 寫 diff 失敗測試**（`diff.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Arch, InventoryPayload, SoftwareItem};

    fn sw(name: &str, ver: &str) -> SoftwareItem {
        SoftwareItem { name: name.into(), version: Some(ver.into()), publisher: Some("P".into()), install_date: None, arch: Arch::X64 }
    }

    #[test]
    fn detects_added_removed_updated() {
        let old = items_of(&InventoryPayload::Software(vec![sw("A", "1"), sw("B", "1")]));
        let new = items_of(&InventoryPayload::Software(vec![sw("A", "2"), sw("C", "1")]));
        let d = diff(&old, &new);
        assert_eq!(d.len(), 3);
        assert!(d.contains(&Change { kind: ChangeKind::Updated, key: "A|x64|P".into(), old: Some("1".into()), new: Some("2".into()) }));
        assert!(d.contains(&Change { kind: ChangeKind::Removed, key: "B|x64|P".into(), old: Some("1".into()), new: None }));
        assert!(d.contains(&Change { kind: ChangeKind::Added, key: "C|x64|P".into(), old: None, new: Some("1".into()) }));
    }

    #[test]
    fn duplicate_software_entries_are_stable() {
        let a = InventoryPayload::Software(vec![sw("Java", "8"), sw("Java", "17")]);
        let b = InventoryPayload::Software(vec![sw("Java", "17"), sw("Java", "8")]);
        assert_eq!(items_of(&a)["Java|x64|P"], "17, 8");
        assert!(diff(&items_of(&a), &items_of(&b)).is_empty());
    }

    #[test]
    fn service_state_change_is_not_a_change() {
        let svc = |state: &str| protocol::ServiceItem {
            name: "Spooler".into(), display_name: None, start_mode: "Auto".into(),
            state: state.into(), binary_path: Some("spoolsv.exe".into()),
        };
        let a = items_of(&InventoryPayload::Services(vec![svc("Running")]));
        let b = items_of(&InventoryPayload::Services(vec![svc("Stopped")]));
        assert!(diff(&a, &b).is_empty());
    }
}
```

- [ ] **Step 2: 執行確認失敗**

Run: `cargo test -p endpoint-server diff::`
Expected: 編譯失敗。

- [ ] **Step 3: 實作 `diff.rs`**

```rust
//! 把區段內容轉成 key/value，再比對新舊差異。規則見計畫 Task 9 表格。

use std::collections::BTreeMap;

use protocol::InventoryPayload;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Added,
    Removed,
    Updated,
}

impl ChangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ChangeKind::Added => "added",
            ChangeKind::Removed => "removed",
            ChangeKind::Updated => "updated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: ChangeKind,
    pub key: String,
    pub old: Option<String>,
    pub new: Option<String>,
}

fn opt(s: &Option<String>) -> String {
    s.clone().unwrap_or_default()
}

pub fn items_of(p: &InventoryPayload) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    match p {
        InventoryPayload::Basic(b) => {
            m.insert("hostname".into(), b.hostname.clone());
            m.insert("domain".into(), opt(&b.domain));
            m.insert("is_domain_joined".into(), b.is_domain_joined.to_string());
            m.insert("os_caption".into(), b.os_caption.clone());
            m.insert("os_build".into(), b.os_build.clone());
        }
        InventoryPayload::Hardware(h) => {
            m.insert("manufacturer".into(), opt(&h.manufacturer));
            m.insert("model".into(), opt(&h.model));
            m.insert("cpu".into(), opt(&h.cpu));
            m.insert("ram_mb".into(), h.ram_mb.to_string());
            for d in &h.disks {
                m.insert(format!("disk:{}", d.name), d.size_bytes.to_string());
            }
        }
        InventoryPayload::Software(v) => {
            let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for s in v {
                let key = format!("{}|{}|{}", s.name, s.arch.as_str(), opt(&s.publisher));
                grouped.entry(key).or_default().push(opt(&s.version));
            }
            for (k, mut versions) in grouped {
                versions.sort();
                m.insert(k, versions.join(", "));
            }
        }
        InventoryPayload::Patches(v) => {
            for p in v {
                m.insert(p.kb.clone(), opt(&p.installed_on));
            }
        }
        InventoryPayload::Services(v) => {
            for s in v {
                m.insert(s.name.clone(), format!("{}|{}", s.start_mode, opt(&s.binary_path)));
            }
        }
    }
    m
}

pub fn diff(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>) -> Vec<Change> {
    let mut out = Vec::new();
    for (k, nv) in new {
        match old.get(k) {
            None => out.push(Change { kind: ChangeKind::Added, key: k.clone(), old: None, new: Some(nv.clone()) }),
            Some(ov) if ov != nv => out.push(Change {
                kind: ChangeKind::Updated, key: k.clone(), old: Some(ov.clone()), new: Some(nv.clone()),
            }),
            _ => {}
        }
    }
    for (k, ov) in old {
        if !new.contains_key(k) {
            out.push(Change { kind: ChangeKind::Removed, key: k.clone(), old: Some(ov.clone()), new: None });
        }
    }
    out
}
```

- [ ] **Step 4: 執行 diff 測試**

Run: `cargo test -p endpoint-server diff::`
Expected: 3 個測試 PASS。

- [ ] **Step 5: 寫上傳整合測試 `tests/inventory.rs`**

```rust
mod common;

use std::io::Write;

use common::{TestAgent, TestServer};
use protocol::{Arch, InventoryPayload, InventoryUpload, SCHEMA_VERSION, SoftwareItem};
use sqlx::PgPool;

fn sw(name: &str, ver: &str) -> SoftwareItem {
    SoftwareItem { name: name.into(), version: Some(ver.into()), publisher: None, install_date: None, arch: Arch::X64 }
}

fn upload(p: InventoryPayload) -> InventoryUpload {
    InventoryUpload { schema_version: SCHEMA_VERSION, payload: p }
}

async fn put(s: &TestServer, a: &TestAgent, section: &str, u: &InventoryUpload) -> u16 {
    s.client(Some(a)).put(s.url(&format!("/v1/inventory/{section}"))).json(u)
        .send().await.unwrap().status().as_u16()
}

async fn setup(pool: PgPool) -> (TestServer, TestAgent) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    (s, a)
}

#[sqlx::test(migrations = false)]
async fn upload_stores_rows_and_hash(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw("A", "1"), sw("B", "2")]);
    assert_eq!(put(&s, &a, "software", &upload(p.clone())).await, 204);

    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM device_software WHERE device_id = $1")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 2);
    let hash: String = sqlx::query_scalar("SELECT hash FROM inventory_sections WHERE device_id = $1 AND section = 'software'")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(hash, p.canonical_hash());
}

#[sqlx::test(migrations = false)]
async fn first_upload_is_baseline_second_records_changes(pool: PgPool) {
    let (s, a) = setup(pool).await;
    put(&s, &a, "software", &upload(InventoryPayload::Software(vec![sw("A", "1"), sw("B", "1")]))).await;
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM inventory_changes WHERE device_id = $1")
            .bind(a.device_id).fetch_one(&s.pool).await.unwrap()
    };
    assert_eq!(count().await, 0);

    put(&s, &a, "software", &upload(InventoryPayload::Software(vec![sw("A", "2"), sw("C", "1")]))).await;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT change, item_key FROM inventory_changes WHERE device_id = $1 ORDER BY item_key",
    ).bind(a.device_id).fetch_all(&s.pool).await.unwrap();
    assert_eq!(rows, vec![
        ("updated".into(), "A|x64|".into()),
        ("removed".into(), "B|x64|".into()),
        ("added".into(), "C|x64|".into()),
    ]);
}

#[sqlx::test(migrations = false)]
async fn roundtrip_through_db_produces_no_spurious_changes(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw("Java", "8"), sw("Java", "17"), sw("中文軟體", "1.0")]);
    put(&s, &a, "software", &upload(p.clone())).await;
    put(&s, &a, "software", &upload(p)).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM inventory_changes WHERE device_id = $1")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn basic_section_updates_device_columns(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Basic(protocol::BasicInfo {
        hostname: "PC-RENAMED".into(), domain: Some("corp.local".into()), is_domain_joined: true,
        os_caption: "Windows 11 Pro".into(), os_build: "26100".into(),
    });
    assert_eq!(put(&s, &a, "basic", &upload(p)).await, 204);
    let (h, joined): (String, bool) = sqlx::query_as("SELECT hostname, is_domain_joined FROM devices WHERE id = $1")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!((h.as_str(), joined), ("PC-RENAMED", true));
}

#[sqlx::test(migrations = false)]
async fn gzip_body_accepted(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let json = serde_json::to_vec(&upload(InventoryPayload::Software(vec![sw("A", "1")]))).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&json).unwrap();
    let r = s.client(Some(&a)).put(s.url("/v1/inventory/software"))
        .header("content-encoding", "gzip").header("content-type", "application/json")
        .body(gz.finish().unwrap()).send().await.unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn gzip_bomb_rejected(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let zeros = vec![0u8; 1024 * 1024];
    for _ in 0..60 {
        gz.write_all(&zeros).unwrap(); // 解壓後 60MB，壓縮後約 60KB
    }
    let r = s.client(Some(&a)).put(s.url("/v1/inventory/software"))
        .header("content-encoding", "gzip").body(gz.finish().unwrap()).send().await.unwrap();
    assert_eq!(r.status(), 413);
}

#[sqlx::test(migrations = false)]
async fn oversized_string_rejected(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw(&"x".repeat(10_000), "1")]);
    assert_eq!(put(&s, &a, "software", &upload(p)).await, 400);
}

#[sqlx::test(migrations = false)]
async fn section_path_mismatch_rejected(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Software(vec![sw("A", "1")]);
    assert_eq!(put(&s, &a, "patches", &upload(p)).await, 400);
}

#[sqlx::test(migrations = false)]
async fn upload_without_cert_is_401(pool: PgPool) {
    let (s, _) = setup(pool).await;
    let r = s.client(None).put(s.url("/v1/inventory/software"))
        .json(&upload(InventoryPayload::Software(vec![]))).send().await.unwrap();
    assert_eq!(r.status(), 401);
}
```

`[dev-dependencies]` 加 `flate2.workspace = true`。

- [ ] **Step 6: 執行確認失敗**

Run: `cargo test -p endpoint-server --test inventory`
Expected: 失敗（路由不存在 → 404 或編譯失敗）。

- [ ] **Step 7: 實作 `inventory.rs`**

```rust
//! /v1/inventory/{section}：接收整個區段，比對差異後在同一交易內替換。

use std::io::Read;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use flate2::read::GzDecoder;
use protocol::{
    Arch, BasicInfo, Disk, HardwareInfo, InventoryPayload, InventoryUpload, PatchItem,
    SCHEMA_VERSION, Section, ServiceItem, SoftwareItem,
};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::AppState;
use crate::diff::{diff, items_of};
use crate::error::AppError;
use crate::identity::AuthedDevice;

pub const MAX_DECOMPRESSED_BYTES: u64 = 50 * 1024 * 1024;

pub fn decode_body(headers: &HeaderMap, body: &[u8]) -> Result<Vec<u8>, AppError> {
    let gzip = headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    if !gzip {
        return Ok(body.to_vec());
    }
    let mut out = Vec::new();
    GzDecoder::new(body)
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|_| AppError::BadRequest("invalid gzip".into()))?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(AppError::PayloadTooLarge);
    }
    Ok(out)
}

pub async fn upload(
    State(st): State<AppState>,
    device: AuthedDevice,
    Path(section): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let section = Section::parse(&section).ok_or_else(|| AppError::BadRequest("unknown section".into()))?;
    let raw = decode_body(&headers, &body)?;
    let upload: InventoryUpload =
        serde_json::from_slice(&raw).map_err(|e| AppError::BadRequest(e.to_string()))?;
    if upload.schema_version > SCHEMA_VERSION {
        return Err(AppError::BadRequest("unsupported schema_version".into()));
    }
    if upload.payload.section() != section {
        return Err(AppError::BadRequest("section mismatch".into()));
    }
    upload.payload.validate()?;
    store_section(&st.pool, device.device_id, &upload.payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn store_section(pool: &PgPool, device_id: Uuid, payload: &InventoryPayload) -> Result<(), AppError> {
    let section = payload.section();
    let mut tx = pool.begin().await?;
    // 同一裝置同一區段的並發上傳依序處理
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("{device_id}:{}", section.as_str()))
        .execute(&mut *tx)
        .await?;

    if let Some(old) = load_payload(&mut *tx, device_id, section).await? {
        for c in diff(&items_of(&old), &items_of(payload)) {
            sqlx::query(
                "INSERT INTO inventory_changes (device_id, section, change, item_key, old_value, new_value) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(device_id).bind(section.as_str()).bind(c.kind.as_str())
            .bind(&c.key).bind(&c.old).bind(&c.new)
            .execute(&mut *tx)
            .await?;
        }
    }

    write_payload(&mut *tx, device_id, payload).await?;
    sqlx::query(
        "INSERT INTO inventory_sections (device_id, section, hash) VALUES ($1, $2, $3) \
         ON CONFLICT (device_id, section) DO UPDATE SET hash = EXCLUDED.hash, updated_at = now()",
    )
    .bind(device_id).bind(section.as_str()).bind(payload.canonical_hash())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 從資料庫重建區段內容；從未上傳過（無 inventory_sections 列）則回 None。
pub async fn load_payload(conn: &mut PgConnection, device_id: Uuid, section: Section) -> Result<Option<InventoryPayload>, sqlx::Error> {
    let exists: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM inventory_sections WHERE device_id = $1 AND section = $2")
            .bind(device_id).bind(section.as_str())
            .fetch_optional(&mut *conn).await?;
    if exists.is_none() {
        return Ok(None);
    }
    let payload = match section {
        Section::Basic => {
            let (hostname, domain, is_domain_joined, os_caption, os_build): (String, Option<String>, bool, Option<String>, Option<String>) =
                sqlx::query_as("SELECT hostname, domain, is_domain_joined, os_caption, os_build FROM devices WHERE id = $1")
                    .bind(device_id).fetch_one(&mut *conn).await?;
            InventoryPayload::Basic(BasicInfo {
                hostname, domain, is_domain_joined,
                os_caption: os_caption.unwrap_or_default(),
                os_build: os_build.unwrap_or_default(),
            })
        }
        Section::Hardware => {
            let (manufacturer, model, cpu, ram_mb, disks): (Option<String>, Option<String>, Option<String>, i64, String) =
                sqlx::query_as("SELECT manufacturer, model, cpu, ram_mb, disks::text FROM device_hardware WHERE device_id = $1")
                    .bind(device_id).fetch_one(&mut *conn).await?;
            let disks: Vec<Disk> = serde_json::from_str(&disks).unwrap_or_default();
            InventoryPayload::Hardware(HardwareInfo { manufacturer, model, cpu, ram_mb: ram_mb as u64, disks })
        }
        Section::Software => {
            let rows: Vec<(String, Option<String>, Option<String>, Option<String>, String)> = sqlx::query_as(
                "SELECT name, version, publisher, install_date, arch FROM device_software WHERE device_id = $1",
            ).bind(device_id).fetch_all(&mut *conn).await?;
            InventoryPayload::Software(rows.into_iter().map(|(name, version, publisher, install_date, arch)| SoftwareItem {
                name, version, publisher, install_date, arch: Arch::parse(&arch).unwrap_or(Arch::X64),
            }).collect())
        }
        Section::Patches => {
            let rows: Vec<(String, Option<String>)> =
                sqlx::query_as("SELECT kb, installed_on FROM device_patches WHERE device_id = $1")
                    .bind(device_id).fetch_all(&mut *conn).await?;
            InventoryPayload::Patches(rows.into_iter().map(|(kb, installed_on)| PatchItem { kb, installed_on }).collect())
        }
        Section::Services => {
            let rows: Vec<(String, Option<String>, String, String, Option<String>)> = sqlx::query_as(
                "SELECT name, display_name, start_mode, state, binary_path FROM device_services WHERE device_id = $1",
            ).bind(device_id).fetch_all(&mut *conn).await?;
            InventoryPayload::Services(rows.into_iter().map(|(name, display_name, start_mode, state, binary_path)| ServiceItem {
                name, display_name, start_mode, state, binary_path,
            }).collect())
        }
    };
    Ok(Some(payload))
}

async fn write_payload(conn: &mut PgConnection, device_id: Uuid, payload: &InventoryPayload) -> Result<(), sqlx::Error> {
    match payload {
        InventoryPayload::Basic(b) => {
            sqlx::query("UPDATE devices SET hostname = $2, domain = $3, is_domain_joined = $4, os_caption = $5, os_build = $6 WHERE id = $1")
                .bind(device_id).bind(&b.hostname).bind(&b.domain).bind(b.is_domain_joined).bind(&b.os_caption).bind(&b.os_build)
                .execute(&mut *conn).await?;
        }
        InventoryPayload::Hardware(h) => {
            sqlx::query(
                "INSERT INTO device_hardware (device_id, manufacturer, model, cpu, ram_mb, disks) VALUES ($1, $2, $3, $4, $5, $6::jsonb) \
                 ON CONFLICT (device_id) DO UPDATE SET manufacturer = EXCLUDED.manufacturer, model = EXCLUDED.model, \
                 cpu = EXCLUDED.cpu, ram_mb = EXCLUDED.ram_mb, disks = EXCLUDED.disks",
            )
            .bind(device_id).bind(&h.manufacturer).bind(&h.model).bind(&h.cpu).bind(h.ram_mb as i64)
            .bind(serde_json::to_string(&h.disks).expect("serializable"))
            .execute(&mut *conn).await?;
        }
        InventoryPayload::Software(v) => {
            sqlx::query("DELETE FROM device_software WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;
            let (mut n, mut ver, mut publ, mut date, mut arch) = (vec![], vec![], vec![], vec![], vec![]);
            for s in v {
                n.push(s.name.clone()); ver.push(s.version.clone()); publ.push(s.publisher.clone());
                date.push(s.install_date.clone()); arch.push(s.arch.as_str().to_string());
            }
            sqlx::query(
                "INSERT INTO device_software (device_id, name, version, publisher, install_date, arch) \
                 SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])",
            )
            .bind(device_id).bind(&n).bind(&ver).bind(&publ).bind(&date).bind(&arch)
            .execute(&mut *conn).await?;
        }
        InventoryPayload::Patches(v) => {
            sqlx::query("DELETE FROM device_patches WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;
            let kb: Vec<String> = v.iter().map(|p| p.kb.clone()).collect();
            let on: Vec<Option<String>> = v.iter().map(|p| p.installed_on.clone()).collect();
            sqlx::query("INSERT INTO device_patches (device_id, kb, installed_on) SELECT $1, * FROM UNNEST($2::text[], $3::text[])")
                .bind(device_id).bind(&kb).bind(&on).execute(&mut *conn).await?;
        }
        InventoryPayload::Services(v) => {
            sqlx::query("DELETE FROM device_services WHERE device_id = $1").bind(device_id).execute(&mut *conn).await?;
            let (mut n, mut dn, mut sm, mut st, mut bp) = (vec![], vec![], vec![], vec![], vec![]);
            for s in v {
                n.push(s.name.clone()); dn.push(s.display_name.clone()); sm.push(s.start_mode.clone());
                st.push(s.state.clone()); bp.push(s.binary_path.clone());
            }
            sqlx::query(
                "INSERT INTO device_services (device_id, name, display_name, start_mode, state, binary_path) \
                 SELECT $1, * FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[])",
            )
            .bind(device_id).bind(&n).bind(&dn).bind(&sm).bind(&st).bind(&bp)
            .execute(&mut *conn).await?;
        }
    }
    Ok(())
}
```

- [ ] **Step 8: 執行測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 9: Commit**

```bash
git add crates/server
git commit -m "feat(server): 盤點上傳、gzip 限制與變更記錄"
```

---

### Task 10: 憑證續期 `/v1/renew`

**Files:**
- Create: `crates/server/src/renew.rs`
- Modify: `crates/server/src/lib.rs`（`pub mod renew;`，router 加 `.route("/v1/renew", post(renew::renew))`）
- Create: `crates/server/tests/renew.rs`

**Interfaces:**
- Consumes: `AuthedDevice`、`Ca::sign_device_csr`、`checkin::RENEW_BEFORE_DAYS`
- Produces: handler `renew::renew`；舊憑證保留到原本到期日（避免回應遺失時 Agent 失聯）。

- [ ] **Step 1: 寫失敗測試 `tests/renew.rs`**

```rust
mod common;

use common::{TestAgent, TestServer, make_csr};
use protocol::{CheckinRequest, RenewRequest, RenewResponse, SCHEMA_VERSION};
use sqlx::PgPool;

fn checkin() -> CheckinRequest {
    CheckinRequest {
        schema_version: SCHEMA_VERSION, agent_version: "0.1.0".into(), boot_time: chrono::Utc::now(),
        logged_on_user: None, ip_addresses: vec![], section_hashes: Default::default(), section_errors: Default::default(),
    }
}

#[sqlx::test(migrations = false)]
async fn renew_not_due_is_400(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let (csr, _) = make_csr();
    let r = s.client(Some(&a)).post(s.url("/v1/renew")).json(&RenewRequest { csr_pem: csr }).send().await.unwrap();
    assert_eq!(r.status(), 400);
}

#[sqlx::test(migrations = false)]
async fn renew_when_due_returns_working_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE device_certs SET not_after = now() + interval '5 days' WHERE device_id = $1")
        .bind(a.device_id).execute(&s.pool).await.unwrap();

    let (csr, key_pem) = make_csr();
    let r: RenewResponse = s.client(Some(&a)).post(s.url("/v1/renew")).json(&RenewRequest { csr_pem: csr })
        .send().await.unwrap().json().await.unwrap();
    let renewed = TestAgent { device_id: a.device_id, key_pem, chain_pem: r.certificate_chain_pem };

    let status = s.client(Some(&renewed)).post(s.url("/v1/checkin")).json(&checkin()).send().await.unwrap().status();
    assert_eq!(status, 200);
    let old_status = s.client(Some(&a)).post(s.url("/v1/checkin")).json(&checkin()).send().await.unwrap().status();
    assert_eq!(old_status, 200, "舊憑證在原到期日前仍有效");
}
```

- [ ] **Step 2: 執行確認失敗**

Run: `cargo test -p endpoint-server --test renew`
Expected: FAIL（404）。

- [ ] **Step 3: 實作 `renew.rs`**

```rust
//! /v1/renew：憑證剩餘效期不足時，以現有 mTLS 身分換發新憑證。

use axum::Json;
use axum::extract::State;
use chrono::{Duration, Utc};
use protocol::{RenewRequest, RenewResponse};

use crate::AppState;
use crate::checkin::RENEW_BEFORE_DAYS;
use crate::error::AppError;
use crate::identity::AuthedDevice;

pub async fn renew(
    State(st): State<AppState>,
    device: AuthedDevice,
    Json(req): Json<RenewRequest>,
) -> Result<Json<RenewResponse>, AppError> {
    if device.cert_not_after - Utc::now() >= Duration::days(RENEW_BEFORE_DAYS) {
        return Err(AppError::BadRequest("renewal not due".into()));
    }
    let issued = st
        .ca
        .sign_device_csr(&req.csr_pem, device.device_id, Utc::now())
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    sqlx::query("INSERT INTO device_certs (serial, fingerprint, device_id, not_after) VALUES ($1, $2, $3, $4)")
        .bind(&issued.serial).bind(&issued.fingerprint).bind(device.device_id).bind(issued.not_after)
        .execute(&st.pool)
        .await?;
    tracing::info!(device_id = %device.device_id, "certificate renewed");
    Ok(Json(RenewResponse {
        certificate_chain_pem: format!("{}{}", issued.pem, st.ca.chain_pem()),
    }))
}
```

- [ ] **Step 4: 執行測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add crates/server
git commit -m "feat(server): /v1/renew 憑證續期"
```

---

### Task 11: CLI 與 `serve`（背景工作、優雅關閉）

**Files:**
- Create: `crates/server/src/config.rs`
- Modify: `crates/server/src/main.rs`、`crates/server/src/lib.rs`（`pub mod config;`、`pub async fn serve(cfg: Config)`）
- Create: `README.md`（最小：用途、授權、建置與執行指令）

**Interfaces:**
- Produces:
  - `config::Config { database_url: String, ca_dir: PathBuf, agent_listen: SocketAddr }`、`Config::from_env() -> anyhow::Result<Config>`
  - `endpoint_server::serve(cfg: Config) -> anyhow::Result<()>`
  - CLI：`endpoint-server serve`、`endpoint-server ca-init <dir> <server-dns-name>...`、`endpoint-server token-create <name> <max_uses> [group_label] [valid_days]`

- [ ] **Step 1: 寫 `config.rs` 與單元測試**

```rust
//! 由環境變數讀取設定。

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub database_url: String,
    pub ca_dir: PathBuf,
    pub agent_listen: SocketAddr,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
        Ok(Config {
            database_url: get("DATABASE_URL").context("DATABASE_URL is required")?,
            ca_dir: get("EM_CA_DIR").unwrap_or_else(|| "./pki".into()).into(),
            agent_listen: get("EM_AGENT_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:8443".into())
                .parse()
                .context("EM_AGENT_LISTEN")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_required() {
        let c = Config::from_lookup(|k| (k == "DATABASE_URL").then(|| "postgres://x".into())).unwrap();
        assert_eq!(c.agent_listen.port(), 8443);
        assert_eq!(c.ca_dir, PathBuf::from("./pki"));
        assert!(Config::from_lookup(|_| None).is_err());
    }
}
```

- [ ] **Step 2: 執行測試**

Run: `cargo test -p endpoint-server config::`
Expected: PASS。

- [ ] **Step 3: 在 `lib.rs` 加入 `serve`**

```rust
pub async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(32)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await?;
    db::migrate(&pool).await?;
    partitions::maintain_partitions(&pool, chrono::Utc::now()).await?;

    let state = AppState::new(pool.clone(), ca::Ca::load(&cfg.ca_dir)?);
    let tls_cfg = tls::server_config(&cfg.ca_dir)?;

    let hb = state.heartbeat.clone();
    let hb_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(heartbeat::FLUSH_INTERVAL_SECS));
        loop {
            tick.tick().await;
            if let Err(e) = hb.flush(&hb_pool).await {
                tracing::error!(error = %e, "heartbeat flush failed");
            }
        }
    });
    let part_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(24 * 3600));
        loop {
            tick.tick().await;
            if let Err(e) = partitions::maintain_partitions(&part_pool, chrono::Utc::now()).await {
                tracing::error!(error = %e, "partition maintenance failed");
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(cfg.agent_listen).await?;
    tracing::info!(addr = %cfg.agent_listen, "agent API listening");
    tokio::select! {
        r = tls::serve_mtls(listener, tls_cfg, agent_router(state.clone())) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    state.heartbeat.flush(&pool).await?;
    Ok(())
}
```

- [ ] **Step 4: 實作 `main.rs`**

```rust
use std::path::Path;

use anyhow::{Context, bail};
use endpoint_server::{config::Config, tokens};

const USAGE: &str = "usage:
  endpoint-server serve
  endpoint-server ca-init <dir> <server-dns-name>...
  endpoint-server token-create <name> <max_uses> [group_label] [valid_days]";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => endpoint_server::serve(Config::from_env()?).await,
        Some("ca-init") if args.len() >= 3 => {
            endpoint_server::ca::init_ca(Path::new(&args[1]), args[2..].to_vec())?;
            println!("CA 已建立於 {}。請將 root.key 移到離線儲存媒體後從伺服器刪除。", args[1]);
            Ok(())
        }
        Some("token-create") if args.len() >= 3 => {
            let cfg = Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            endpoint_server::db::migrate(&pool).await?;
            let max_uses: i32 = args[2].parse().context("max_uses")?;
            let days: Option<i64> = args.get(4).map(|d| d.parse()).transpose().context("valid_days")?;
            let (id, token) = tokens::create_token(
                &pool,
                &tokens::NewToken {
                    name: args[1].clone(),
                    group_label: args.get(3).cloned(),
                    expires_at: days.map(|d| chrono::Utc::now() + chrono::Duration::days(d)),
                    max_uses,
                    created_by: "cli".into(),
                },
            )
            .await?;
            println!("token id {id}：{token}\n（明碼只顯示這一次）");
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}
```

- [ ] **Step 5: 建立最小 `README.md`**

````markdown
# Endpoint Manager

企業 Windows 端點管理工具（開發中）。第一期：Agent 報到與資產盤點。

授權：GPL-3.0-only

## 建置與測試

需要 Rust stable 與 PostgreSQL 17，並設定 `DATABASE_URL`。

```bash
cargo test --workspace
```

## 執行伺服器（開發用）

```bash
cargo run -p endpoint-server -- ca-init ./pki localhost
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/endpoint_manager
cargo run -p endpoint-server -- token-create pilot 10 IT 30
cargo run -p endpoint-server -- serve
```

設計文件：`docs/superpowers/specs/`
````

- [ ] **Step 6: 手動冒煙測試**

```bash
createdb -U postgres endpoint_manager   # 或用 psql 建立
cargo run -p endpoint-server -- ca-init ./pki localhost
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/endpoint_manager cargo run -p endpoint-server -- token-create smoke 1
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/endpoint_manager cargo run -p endpoint-server -- serve
# 另一個終端機：
curl --cacert pki/root.pem https://localhost:8443/healthz -i
```

Expected: `HTTP/2 200`（或 `HTTP/1.1 200`）。Ctrl+C 後程式正常結束。

- [ ] **Step 7: 全部檢查**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: 無警告，全部 PASS。

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(server): CLI（serve/ca-init/token-create）、背景工作與 README"
```

---

### Task 12: 開 PR、自我審查、合併、清理分支

- [ ] **Step 1: 推送並建立 PR**

```bash
git push -u origin feat/plan1-server-core
gh pr create --base main --title "計畫 1：伺服器核心（protocol + Agent API）" --body "$(cat <<'EOF'
實作 docs/superpowers/plans/2026-09-28-plan1-server-core.md。

- protocol crate：訊息型別、canonical hash、字串驗證、v1 相容性樣本
- server：兩層 CA、mTLS、/v1/enroll、/v1/checkin、/v1/inventory/{section}、/v1/renew
- 心跳熱欄位批次寫入、inventory_changes 月分割區
- CLI：serve / ca-init / token-create
- CI：fmt、clippy、test（PostgreSQL service）、cargo-deny

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 2: 等 CI 完成並確認全綠**

Run: `gh pr checks --watch`
Expected: `test`、`deny` 皆通過。失敗就修正後再推。

- [ ] **Step 3: 自我審查 diff**（對照本計畫的 Review Focus 五項與 Global Constraints）

Run: `gh pr diff`

- [ ] **Step 4: 合併並刪除分支**

```bash
gh pr merge --squash --delete-branch
git switch main && git pull --prune
git branch -d feat/plan1-server-core 2>/dev/null || true
```
