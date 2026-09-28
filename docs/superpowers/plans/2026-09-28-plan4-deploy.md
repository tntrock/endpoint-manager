# 計畫 4／4：Agent 安裝檔（網頁下載）、Docker 部署與負載測試 實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 讓第一期可以實際導入：管理員在網頁建立註冊金鑰時直接下載「已包好伺服器網址、金鑰、根憑證」的 Agent MSI（可直接用 GPO 派送），伺服器以 Docker Compose 部署，並用 `tools/loadsim` 模擬 30,000 台驗證規格 §7 的負載標準。

**Architecture:** 以 WiX v5 建置一個**通用範本 MSI**（不含任何組織資訊，CI 產生、隨 GitHub Release 發佈）。伺服器持有範本，管理員下載時以純 Rust 的 `msi` crate 在記憶體中改寫範本的 `Property` 表（`SERVER_URL`、`ENROLL_TOKEN`、`ROOT_CA`）並換新 package code，直接回傳檔案。MSI 本身只做 Windows Installer 原生擅長的事：放檔案、安裝／啟動服務、登錄事件來源；需要邏輯的部分（強化資料目錄 ACL、寫入根憑證、合併 config.json、設定服務失敗復原）由 Agent 的 `configure`／`unconfigure` 子命令處理，MSI 以 deferred custom action（SYSTEM）呼叫。伺服器以多階段 Dockerfile 建成 distroless 映像，Compose 搭配 PostgreSQL 17，並處理 SIGTERM。loadsim 透過真實 API 註冊、報到、上傳，以伺服器回應驗證資料確實存入。

**Tech Stack:** WiX Toolset **v5.0.2**（dotnet tool）、`msi` crate 0.10（MIT，純 Rust）、windows-service 0.8、Docker（rust:1-bookworm → gcr.io/distroless/cc-debian12:nonroot）、postgres:17、既有的 axum／askama／tokio／reqwest／rcgen

**Spec:** `docs/superpowers/specs/2026-09-27-endpoint-inventory-design.md`（§1.5 成功標準、§3 installer/deploy/loadsim、§4.1 MSI 參數與伺服器驗證、§6.1 服務 ACL 與失敗復原、§6.4 簽章、§7 負載測試）

**前置：** 計畫 1～3 已合併（main `d6da313`）。

## 設計決定（使用者已確認：WiX v5、從網頁下載已包好設定的安裝檔）

1. **WiX v5.0.2**：v6 起有 Open Source Maintenance Fee，v7 起強制接受 EULA；v5 為 MS-RL、無此約束。不使用 WiX 擴充套件，只用核心 schema。
2. **通用範本 MSI**：`installer/build.ps1` 產生不含任何組織資訊的 `endpoint-agent-<版本>.msi`；CI 產生並上傳成 artifact，GitHub Release 附上它。範本也能直接用 `msiexec ... SERVER_URL=... ENROLL_TOKEN=... ROOT_CA=...` 安裝。
3. **網頁下載安裝檔**：註冊金鑰頁的建立表單多一個「建立並下載安裝檔」按鈕，與「建立」共用同一份表單（名稱、次數、群組、有效天數）加上「伺服器網址」欄位（預設 `EM_AGENT_PUBLIC_URL`）。按下後建立新金鑰、改寫範本、以附件回傳 `endpoint-agent.msi`。金鑰明碼不落地（不存 DB、不寫稽核記錄），只存在於這個 MSI 內。權限同建立金鑰（平台管理員、群組管理員限自己的群組）。稽核動作 `token_create`，detail 加上 `"installer": true` 與 `server_url`。
4. **伺服器網址必須符合伺服器憑證**：網址須為 `https://`，主機名稱（或 IP）必須在 `pki/server.pem` 的 SAN 內，否則 400——避免管理員填了憑證不涵蓋的 IP，派送後全部連不上。
5. **改寫方式**：`Property` 表先刪後插（範本不必預先有這些列），summary information 換新 UUID（package code），同一版本的不同下載才不會被 Windows Installer 當成同一個套件快取。
6. **`ROOT_CA` 屬性**：根憑證 PEM 去掉首尾行與換行的 base64（約 600 字元，單行）。Agent `configure --root-ca <b64>` 驗證後包回 PEM 寫入資料目錄。
7. **資料目錄與根憑證**：`configure` 先以 `harden_dir` 建立並強化 `C:\ProgramData\EndpointManager\`，**之後**才寫入 root.pem 與 config.json，一般使用者無法在中途偷換。
8. **config.json 合併規則**（`configure`）：
   - `server_url` = 命令列值，否則沿用既有值，兩者皆無 → 失敗（安裝中止）；必須以 `https://` 開頭。
   - `enroll_token`：已註冊（state.json 有 device_id）→ 一律清除；未註冊 → 命令列值，否則沿用既有值。
   - root.pem：有 `--root-ca` 就寫入；沒有則沿用既有檔；兩者皆無 → 失敗。
   - 空字串視為未提供（MSI 未設屬性時會傳 `""`）。
9. **服務失敗復原**：`configure` 以 SCM API 設定：失敗後 60 秒重啟 ×3、24 小時重置計數，並開啟「非當機的失敗也套用」（Agent 以 `ServiceSpecific(1)` 結束屬於此類）。
10. **服務 ACL**：Windows 預設的服務安全描述元已不允許一般使用者（IU/AU/SU）停止服務，不另外設定；MSI 測試會驗證。
11. **事件來源**：MSI 寫入 `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\EndpointManagerAgent`，`EventMessageFile` 指向 .NET Framework 4 內建的 `EventLogMessages.dll`（每個事件 ID 都對應 `%1`）。解除安裝時 MSI 自動移除。
12. **升級與解除安裝**：`MajorUpgrade`（預設排程，先移除舊版）。`unconfigure`（刪除資料目錄）只在 `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` 時執行。升級可直接用新版的**通用範本**（不帶任何屬性），設定與身分沿用。
13. **簽章**：改寫 MSI 會使 MSI 本身的簽章失效，所以下載的 MSI 不簽章；但範本內的 `endpoint-agent.exe` 可先簽章，改寫 `Property` 表不影響 exe 的簽章。README 說明。
14. **Docker**：容器內網頁監聽 `0.0.0.0:8444`，Compose 對外映射 `443:8444`、`8443:8443`；映像以 uid 65532 執行；`./pki` 與 `./agent`（放範本 MSI）唯讀掛載。伺服器收到 SIGTERM／Ctrl+C 都會寫出心跳緩衝後以 0 結束。
15. **loadsim 走真實 API**：新增 `EM_ENROLL_PER_IP_PER_MINUTE`（預設 60）讓測試環境可一次註冊 30,000 台；每次請求都新建連線（與真實 Agent 相同）；上傳後以下一次報到的 `request_sections` 不含 software 驗證資料確實存入。
16. **一併處理的延後項目**：Agent 的 Retry-After 夾在 10 秒～30 分鐘、伺服器 SIGTERM。其餘延後項目維持記錄在專案備忘，除非負載測試顯示它們是瓶頸。

## Global Constraints

- 授權 `GPL-3.0-only`；Rust edition 2024；TLS 只用 rustls + ring；不用 clap。新增依賴只有 `msi = "0.10"`（伺服器），須通過 cargo-deny。
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、cargo-deny 全部通過。
- WiX 固定 `5.0.2`，不得使用 v6 以上。
- 程式碼與文件不得出現特定公司資訊；範例網址用 `em.example.com`。
- 使用者看得到的訊息（網頁、CLI 提示、MSI 錯誤訊息、README）用繁體中文。
- 本機 `DATABASE_URL` 用 `127.0.0.1`，不用 `localhost`。本機 shell 沒有系統管理員權限：MSI 安裝測試只在 CI（windows-latest 為系統管理員）執行。
- 服務名稱與事件來源固定 `EndpointManagerAgent`；資料目錄 `C:\ProgramData\EndpointManager`；MSI 屬性名稱固定 `SERVER_URL`、`ENROLL_TOKEN`、`ROOT_CA`。

## Review Focus

1. **下載的 MSI 能真的安裝並連到伺服器**：Rust 改寫後的 MSI 要能被 Windows Installer 接受 → Task 5 CI 以 `agent-msi` 產生的 MSI 實際安裝並檢查 config.json、root.pem。
2. **註冊金鑰不能出現在 MSI 詳細記錄**（`/l*v` 常被收集給 IT）→ Task 5 檢查 install.log 不含金鑰。
3. **伺服器網址填錯（主機不在憑證 SAN）不能產生安裝檔、也不能留下多餘的金鑰** → Task 4 網頁測試。
4. **升級不能洗掉已註冊身分、已註冊的電腦重跑安裝不能把金鑰寫回磁碟** → Task 5 升級檢查、Task 2 `merge_config` 測試。
5. **`docker compose stop` 要以 0 結束且留下關閉記錄**（心跳緩衝寫出）→ Task 6 `smoke.sh`。

---

### Task 1: 伺服器：SIGTERM 與可調整的註冊限速

**Files:**
- Modify: `crates/server/src/config.rs`
- Modify: `crates/server/src/lib.rs`

**Interfaces:**
- Produces: `Config.enroll_per_ip_per_minute: u32`（環境變數 `EM_ENROLL_PER_IP_PER_MINUTE`，預設 `ENROLL_PER_IP_PER_MINUTE` = 60，須 ≥ 1）；`AppState::with_enroll_limit(self, per_minute: u32) -> Self`。

- [ ] **Step 1: 寫失敗測試**（`config.rs` 的 tests 模組）

```rust
    #[test]
    fn enroll_limit_env() {
        let base = |v: Option<&str>| {
            let v = v.map(String::from);
            Config::from_lookup(move |k| match k {
                "DATABASE_URL" => Some("postgres://x".into()),
                "EM_ENROLL_PER_IP_PER_MINUTE" => v.clone(),
                _ => None,
            })
        };
        assert_eq!(base(None).unwrap().enroll_per_ip_per_minute, 60);
        assert_eq!(base(Some("100000")).unwrap().enroll_per_ip_per_minute, 100_000);
        assert!(base(Some("0")).is_err());
        assert!(base(Some("abc")).is_err());
    }
```

- [ ] **Step 2: 執行確認失敗**：`cargo test -p endpoint-server --lib config::` → 編譯失敗（欄位不存在）。

- [ ] **Step 3: 實作**

`config.rs`：`Config` 加欄位 `pub enroll_per_ip_per_minute: u32,`，`from_lookup` 加：

```rust
            enroll_per_ip_per_minute: {
                let n: u32 = match get("EM_ENROLL_PER_IP_PER_MINUTE") {
                    Some(v) => v.parse().context("EM_ENROLL_PER_IP_PER_MINUTE")?,
                    None => crate::ENROLL_PER_IP_PER_MINUTE,
                };
                anyhow::ensure!(n >= 1, "EM_ENROLL_PER_IP_PER_MINUTE must be >= 1");
                n
            },
```

`lib.rs`：

```rust
    pub fn with_enroll_limit(mut self, per_minute: u32) -> Self {
        self.enroll_limiter = Arc::new(ratelimit::RateLimiter::new(
            per_minute,
            Duration::from_secs(60),
        ));
        self
    }
```

`serve()`：`AppState::new(...)` 串上 `.with_enroll_limit(cfg.enroll_per_ip_per_minute)`；`select!` 的 `ctrl_c()` 分支改成 `_ = shutdown_signal() => tracing::info!("shutting down"),`，並新增：

```rust
/// Ctrl+C 或（Unix）SIGTERM：docker stop 送的是 SIGTERM。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::error!(error = %e, "cannot install SIGTERM handler"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
```

用 `grep -rn "Config {" crates/` 確認沒有其他地方直接建構 `Config`（有的話補欄位）。

- [ ] **Step 4: 驗證**：`cargo test -p endpoint-server --lib config::` 通過；clippy 無警告。SIGTERM 的實際行為由 Task 6 的 smoke 測試驗證。

- [ ] **Step 5: Commit**：`git commit -am "伺服器：處理 SIGTERM、註冊限速可由環境變數調整"`

---

### Task 2: Agent：Retry-After 夾值、`configure`／`unconfigure` 子命令

**Files:**
- Modify: `crates/agent/src/client.rs`
- Modify: `crates/agent/src/config.rs`
- Create: `crates/agent/src/windows/install.rs`
- Modify: `crates/agent/src/windows/mod.rs`（`pub mod install;`）
- Modify: `crates/agent/src/windows/eventlog.rs`（頂端註解）
- Modify: `crates/agent/src/main.rs`
- Test: `crates/agent/tests/windows.rs`

**Interfaces:**
- Produces:
  - `client::retry_after(secs: u64) -> Duration`（夾在 `RETRY_AFTER_MIN` 10s ～ `RETRY_AFTER_MAX` 1800s）
  - `config::merge_config(existing: Option<AgentConfig>, enrolled: bool, server_url: Option<&str>, token: Option<&str>) -> anyhow::Result<AgentConfig>`
  - `config::root_pem_from_b64(b64: &str) -> anyhow::Result<String>`（驗證是一張 X.509 憑證，回傳 64 字元換行的 PEM）
  - `windows::install::configure(data: &Path, server_url: Option<&str>, token: Option<&str>, root_ca: Option<&str>) -> anyhow::Result<()>`
  - `windows::install::set_recovery() -> anyhow::Result<()>`
  - `windows::install::unconfigure(data: &Path) -> anyhow::Result<()>`
  - `windows::install::flag(args: &[OsString], name: &str) -> Option<String>`
  - CLI：`endpoint-agent configure [--server-url URL] [--token TOKEN] [--root-ca BASE64]`、`endpoint-agent unconfigure`（Task 5 的 MSI 呼叫）

- [ ] **Step 1: 寫失敗測試**

`client.rs` 尾端：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_clamped() {
        assert_eq!(retry_after(0), RETRY_AFTER_MIN);
        assert_eq!(retry_after(120), Duration::from_secs(120));
        assert_eq!(retry_after(u64::MAX), RETRY_AFTER_MAX);
    }
}
```

`config.rs` 的 tests 模組：

```rust
    fn cfg(url: &str, tok: Option<&str>) -> AgentConfig {
        AgentConfig {
            server_url: url.into(),
            enroll_token: tok.map(String::from),
        }
    }

    #[test]
    fn merge_fresh_install_needs_url() {
        assert!(merge_config(None, false, None, Some("t")).is_err());
        assert!(merge_config(None, false, Some("http://x"), None).is_err());
        assert_eq!(
            merge_config(None, false, Some("https://a:8443"), Some("t")).unwrap(),
            cfg("https://a:8443", Some("t"))
        );
    }

    #[test]
    fn merge_upgrade_keeps_existing_values() {
        let old = cfg("https://a:8443", Some("t"));
        assert_eq!(merge_config(Some(old.clone()), false, None, None).unwrap(), old);
        assert_eq!(
            merge_config(Some(old), false, Some("https://b:8443"), Some("u")).unwrap(),
            cfg("https://b:8443", Some("u"))
        );
    }

    #[test]
    fn merge_enrolled_never_writes_token_back() {
        let old = cfg("https://a:8443", None);
        assert_eq!(
            merge_config(Some(old.clone()), true, None, Some("t")).unwrap(),
            old
        );
        assert_eq!(
            merge_config(Some(cfg("https://a:8443", Some("stale"))), true, None, None)
                .unwrap()
                .enroll_token,
            None
        );
    }

    #[test]
    fn root_pem_roundtrip_and_rejects_garbage() {
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = rcgen::CertificateParams::default()
            .self_signed(&key)
            .unwrap()
            .pem();
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let back = root_pem_from_b64(&b64).unwrap();
        assert_eq!(back.replace(['\r', '\n'], ""), pem.replace(['\r', '\n'], ""));
        assert!(back.lines().all(|l| l.len() <= 64));
        assert!(root_pem_from_b64("bm90IGEgY2VydA==").is_err());
        assert!(root_pem_from_b64("***").is_err());
    }
```

`tests/windows.rs`（把 `harden_dir_takes_ownership_from_squatter` 內的 `net session` 判斷抽成 `fn elevated() -> bool` 共用）：

```rust
/// 需要系統管理員權限；一般權限下略過。
#[test]
fn configure_hardens_dir_and_writes_files() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    use endpoint_agent::config::AgentConfig;
    use endpoint_agent::windows::install::{configure, unconfigure};
    let key = rcgen::KeyPair::generate().unwrap();
    let pem = rcgen::CertificateParams::default()
        .self_signed(&key)
        .unwrap()
        .pem();
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");

    // 首次安裝缺根憑證 → 失敗
    assert!(configure(&data, Some("https://em.example.com:8443"), Some("tok"), None).is_err());

    configure(&data, Some("https://em.example.com:8443"), Some("tok"), Some(&b64)).unwrap();
    assert!(std::fs::read_to_string(data.join("root.pem")).unwrap().contains("BEGIN CERTIFICATE"));
    let c = AgentConfig::load(&data).unwrap();
    assert_eq!(c.enroll_token.as_deref(), Some("tok"));

    // 重跑（升級）不帶參數：全部沿用
    configure(&data, None, None, None).unwrap();
    assert_eq!(AgentConfig::load(&data).unwrap(), c);

    unconfigure(&data).unwrap();
    assert!(!data.exists());
    unconfigure(&data).unwrap(); // 不存在也成功
}
```

`crates/agent/Cargo.toml` 的 `[target.'cfg(windows)'.dev-dependencies]` 若沒有 rcgen：rcgen 已在一般 `[dev-dependencies]`，不需改。

- [ ] **Step 2: 執行確認失敗**：`cargo test -p endpoint-agent --lib` → 編譯失敗（`retry_after`、`merge_config`、`root_pem_from_b64` 不存在）。

- [ ] **Step 3: 實作**

`client.rs`：

```rust
/// 伺服器給的 Retry-After 夾在這個範圍：0 會讓 Agent 空轉，極大值會讓它失聯。
pub const RETRY_AFTER_MIN: Duration = Duration::from_secs(10);
pub const RETRY_AFTER_MAX: Duration = Duration::from_secs(30 * 60);

pub fn retry_after(secs: u64) -> Duration {
    Duration::from_secs(secs).clamp(RETRY_AFTER_MIN, RETRY_AFTER_MAX)
}
```

`send()` 內 `.map(Duration::from_secs)` 改為 `.map(retry_after)`。

`config.rs`：

```rust
/// 安裝／升級時合併設定：命令列值優先，否則沿用既有值；已註冊就不再保留註冊金鑰。
pub fn merge_config(
    existing: Option<AgentConfig>,
    enrolled: bool,
    server_url: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<AgentConfig> {
    let server_url = server_url
        .map(String::from)
        .or_else(|| existing.as_ref().map(|c| c.server_url.clone()))
        .context("SERVER_URL is required on first install")?;
    anyhow::ensure!(
        server_url.starts_with("https://"),
        "SERVER_URL must start with https://"
    );
    let enroll_token = if enrolled {
        None
    } else {
        token
            .map(String::from)
            .or_else(|| existing.and_then(|c| c.enroll_token))
    };
    Ok(AgentConfig {
        server_url,
        enroll_token,
    })
}

/// MSI 的 ROOT_CA 屬性（單行 base64 DER）→ PEM；不是一張可解析的 X.509 憑證就拒絕。
pub fn root_pem_from_b64(b64: &str) -> anyhow::Result<String> {
    let b64: String = b64.split_whitespace().collect();
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk)?);
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).context("ROOT_CA is not valid base64")?;
    x509_parser::parse_x509_certificate(&der).context("ROOT_CA is not an X.509 certificate")?;
    Ok(pem)
}
```

`windows/install.rs`：

```rust
//! MSI 的 custom action 呼叫（SYSTEM 身分）：`configure` 於安裝／升級、`unconfigure` 於解除安裝。

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions,
    ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service::SERVICE_NAME;
use crate::config::{AgentConfig, merge_config, root_pem_from_b64};
use crate::state::{AgentState, harden_dir, write_atomic};

/// 先強化資料目錄，之後才寫入 root.pem 與 config.json。
pub fn configure(
    data: &Path,
    server_url: Option<&str>,
    token: Option<&str>,
    root_ca: Option<&str>,
) -> anyhow::Result<()> {
    harden_dir(data)?;
    let root_path = data.join("root.pem");
    match root_ca {
        Some(b64) => write_atomic(&root_path, root_pem_from_b64(b64)?.as_bytes())?,
        None => anyhow::ensure!(root_path.exists(), "ROOT_CA is required on first install"),
    }
    let existing = AgentConfig::load(data).ok();
    let enrolled = AgentState::load(data)?.device_id.is_some();
    merge_config(existing, enrolled, server_url, token)?.save(data)
}

/// 失敗後 60 秒重啟（3 次）、24 小時重置；非當機的失敗（結束代碼非 0）也套用。
pub fn set_recovery() -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr
        .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("open service")?;
    let actions = (0..3)
        .map(|_| ServiceAction {
            action_type: ServiceActionType::Restart,
            delay: Duration::from_secs(60),
        })
        .collect();
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

pub fn unconfigure(data: &Path) -> anyhow::Result<()> {
    match std::fs::remove_dir_all(data) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// `--name value`；空字串視為未提供（MSI 未設屬性時傳 ""）。
pub fn flag(args: &[OsString], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    let v = args.get(i + 1)?.to_string_lossy().trim().to_string();
    (!v.is_empty()).then_some(v)
}
```

`main.rs` 的 match：

```rust
        Some("configure") => {
            use endpoint_agent::windows::{agent_dir, install};
            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
            install::configure(
                &agent_dir(),
                install::flag(&args, "--server-url").as_deref(),
                install::flag(&args, "--token").as_deref(),
                install::flag(&args, "--root-ca").as_deref(),
            )?;
            install::set_recovery()
        }
        Some("unconfigure") => {
            endpoint_agent::windows::install::unconfigure(&endpoint_agent::windows::agent_dir())
        }
        _ => anyhow::bail!(
            "usage: endpoint-agent run | service | configure [--server-url URL] [--token TOKEN] [--root-ca BASE64] | unconfigure"
        ),
```

`eventlog.rs` 頂端註解改為：「事件來源由 MSI 註冊，訊息檔用 .NET Framework 的 EventLogMessages.dll。」

- [ ] **Step 4: 驗證**：`cargo test -p endpoint-agent --lib` 通過；`cargo test -p endpoint-agent --test windows` 通過（本機非系統管理員會顯示 skipped；CI 實際執行）；clippy 無警告。

- [ ] **Step 5: Commit**：`git commit -am "Agent：Retry-After 夾值、新增 configure／unconfigure 供 MSI 呼叫"`

---

### Task 3: 伺服器：改寫範本 MSI（`installer.rs`）與 `agent-msi` 指令

**Files:**
- Modify: `crates/server/Cargo.toml`（`msi = "0.10"`）
- Create: `crates/server/src/installer.rs`
- Modify: `crates/server/src/lib.rs`（`pub mod installer;`）
- Modify: `crates/server/src/ca.rs`（`Ca` 保存 root PEM、`server_names(dir)`）
- Modify: `crates/server/src/main.rs`

**Interfaces:**
- Produces:
  - `installer::build_msi(template: &[u8], server_url: &str, token: &str, root_pem: &str) -> anyhow::Result<Vec<u8>>`
  - `installer::read_properties(msi: &[u8]) -> anyhow::Result<BTreeMap<String, String>>`
  - `installer::check_server_url(url: &str, names: &[String]) -> Result<(), String>`（錯誤訊息為繁體中文，可直接顯示）
  - `installer::root_b64(root_pem: &str) -> String`
  - `#[doc(hidden)] installer::sample_template() -> Vec<u8>`（測試用：只有 `Property` 表的最小 MSI）
  - `ca::Ca::root_pem(&self) -> &str`
  - `ca::server_names(dir: &Path) -> anyhow::Result<Vec<String>>`（`server.pem` 第一張憑證的 DNS／IP SAN）
  - CLI：`endpoint-server agent-msi <template.msi> <out.msi> <server_url> <token>`（根憑證取自 `EM_CA_DIR`）

- [ ] **Step 1: 寫失敗測試**（`installer.rs` 內）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "-----BEGIN CERTIFICATE-----\nQUJD\nREVG\n-----END CERTIFICATE-----\n";

    #[test]
    fn build_sets_properties_and_new_package_code() {
        let t = sample_template();
        let a = build_msi(&t, "https://em.example.com:8443", "tok-1", ROOT).unwrap();
        let p = read_properties(&a).unwrap();
        assert_eq!(p["SERVER_URL"], "https://em.example.com:8443");
        assert_eq!(p["ENROLL_TOKEN"], "tok-1");
        assert_eq!(p["ROOT_CA"], "QUJDREVG");
        assert_eq!(p["KEEP"], "me", "其他屬性不動");
        let b = build_msi(&t, "https://em.example.com:8443", "tok-2", ROOT).unwrap();
        assert_ne!(package_code(&a), package_code(&b));
        // 範本已有同名屬性時覆寫而不是重複
        let again = build_msi(&a, "https://other.example.com:8443", "tok-3", ROOT).unwrap();
        assert_eq!(read_properties(&again).unwrap()["SERVER_URL"], "https://other.example.com:8443");
    }

    #[test]
    fn server_url_must_match_certificate() {
        let names = vec!["em.example.com".to_string(), "10.1.2.3".to_string()];
        assert!(check_server_url("https://em.example.com:8443", &names).is_ok());
        assert!(check_server_url("https://EM.example.com:8443/", &names).is_ok());
        assert!(check_server_url("https://10.1.2.3:8443", &names).is_ok());
        assert!(check_server_url("https://10.1.2.4:8443", &names).is_err());
        assert!(check_server_url("http://em.example.com:8443", &names).is_err());
        assert!(check_server_url("https://em.example.com.evil.test:8443", &names).is_err());
        assert!(check_server_url("https://", &names).is_err());
    }

    fn package_code(msi: &[u8]) -> uuid::Uuid {
        msi::Package::open(std::io::Cursor::new(msi.to_vec()))
            .unwrap()
            .summary_info()
            .uuid()
            .unwrap()
    }
}
```

`ca.rs` tests 模組加：

```rust
    #[test]
    fn server_names_and_root_pem() {
        let dir = tempfile::tempdir().unwrap();
        init_ca(dir.path(), vec!["em.example.com".into(), "10.1.2.3".into()]).unwrap();
        assert_eq!(server_names(dir.path()).unwrap(), vec!["em.example.com", "10.1.2.3"]);
        let ca = Ca::load(dir.path()).unwrap();
        assert_eq!(ca.root_pem(), std::fs::read_to_string(dir.path().join("root.pem")).unwrap());
    }
```

- [ ] **Step 2: 執行確認失敗**：`cargo test -p endpoint-server --lib installer:: ca::` → 編譯失敗。

- [ ] **Step 3: 實作**

先在 docs.rs 確認 `msi` 0.10 的 API 名稱（`Package::open`、`create`、`create_table`、`Column::build`、`insert_rows`、`delete_rows`、`select_rows`、`summary_info_mut().set_uuid`、`flush`、`into_inner`）；以下以這些名稱撰寫，若實際名稱不同，照 docs 調整但行為不變。

`installer.rs`：

```rust
//! 由通用範本 MSI 產生「已包好伺服器網址、註冊金鑰、根憑證」的安裝檔：
//! 改寫 Property 表（先刪後插）並換新 package code。全部在記憶體中完成。

use std::collections::BTreeMap;
use std::io::Cursor;

use msi::{Column, Delete, Expr, Insert, Package, PackageType, Select, Value};

/// 根憑證 PEM → 單行 base64（MSI 的 ROOT_CA 屬性）。
pub fn root_b64(root_pem: &str) -> String {
    root_pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(str::trim)
        .collect()
}

pub fn build_msi(
    template: &[u8],
    server_url: &str,
    token: &str,
    root_pem: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut pkg = Package::open(Cursor::new(template.to_vec()))?;
    let root = root_b64(root_pem);
    for (k, v) in [
        ("SERVER_URL", server_url),
        ("ENROLL_TOKEN", token),
        ("ROOT_CA", root.as_str()),
    ] {
        pkg.delete_rows(Delete::from("Property").with(Expr::col("Property").eq(Expr::string(k))))?;
        pkg.insert_rows(Insert::into("Property").row(vec![Value::from(k), Value::from(v)]))?;
    }
    pkg.summary_info_mut().set_uuid(uuid::Uuid::new_v4());
    pkg.flush()?;
    Ok(pkg.into_inner()?.into_inner())
}

pub fn read_properties(msi: &[u8]) -> anyhow::Result<BTreeMap<String, String>> {
    let mut pkg = Package::open(Cursor::new(msi.to_vec()))?;
    let mut out = BTreeMap::new();
    for row in pkg.select_rows(Select::table("Property"))? {
        if let (Some(k), Some(v)) = (row[0].as_str(), row[1].as_str()) {
            out.insert(k.to_string(), v.to_string());
        }
    }
    Ok(out)
}

/// 網址必須是 https，且主機名稱（或 IP）在伺服器憑證的 SAN 內，否則 Agent 會連不上。
pub fn check_server_url(url: &str, names: &[String]) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("伺服器網址必須以 https:// 開頭")?;
    let authority = rest.split('/').next().unwrap_or_default();
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or_default(),
        None => authority.rsplit_once(':').map_or(authority, |(h, _)| h),
    };
    if host.is_empty() {
        return Err("伺服器網址缺少主機名稱".into());
    }
    if names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
        Ok(())
    } else {
        Err(format!(
            "「{host}」不在伺服器憑證的名稱內（{}），Agent 會無法連線",
            names.join("、")
        ))
    }
}

/// 測試用：只有 Property 表的最小 MSI。
#[doc(hidden)]
pub fn sample_template() -> Vec<u8> {
    let mut pkg = Package::create(PackageType::Installer, Cursor::new(Vec::new()))
        .expect("create package");
    pkg.create_table(
        "Property",
        vec![
            Column::build("Property").primary_key().id_string(72),
            Column::build("Value").formatted_string(0),
        ],
    )
    .expect("create Property table");
    pkg.insert_rows(Insert::into("Property").row(vec![Value::from("KEEP"), Value::from("me")]))
        .expect("insert");
    pkg.flush().expect("flush");
    pkg.into_inner().expect("into_inner").into_inner()
}
```

`ca.rs`：`Ca` 加欄位 `root_pem: String`（`load` 內已讀的 `root.pem` 存起來），加 `pub fn root_pem(&self) -> &str`；新增：

```rust
/// server.pem 第一張（伺服器）憑證的 SAN：DNS 名稱與 IP。
pub fn server_names(dir: &Path) -> anyhow::Result<Vec<String>> {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    use x509_parser::extensions::GeneralName;
    let pem = std::fs::read(dir.join("server.pem")).context("reading server.pem")?;
    let der = CertificateDer::pem_slice_iter(&pem)
        .next()
        .context("server.pem is empty")??;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
    let mut names = Vec::new();
    if let Some(san) = cert.subject_alternative_name()? {
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => names.push(d.to_string()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => names.push(std::net::Ipv4Addr::from(<[u8; 4]>::try_from(*b)?).to_string()),
                    16 => names.push(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*b)?).to_string()),
                    _ => {}
                },
                _ => {}
            }
        }
    }
    Ok(names)
}
```

（rcgen 對 `"10.1.2.3"` 會產生 IP SAN；若測試發現它產生 DNS SAN，上面兩種都會收集，結果相同。）

`main.rs`：USAGE 加一行 `endpoint-server agent-msi <template.msi> <out.msi> <server_url> <token>`，match 加：

```rust
        Some("agent-msi") if args.len() >= 5 => {
            let ca_dir = std::path::PathBuf::from(
                std::env::var("EM_CA_DIR").unwrap_or_else(|_| "./pki".into()),
            );
            let names = endpoint_server::ca::server_names(&ca_dir)?;
            endpoint_server::installer::check_server_url(&args[3], &names)
                .map_err(|m| anyhow::anyhow!(m))?;
            let root = std::fs::read_to_string(ca_dir.join("root.pem")).context("root.pem")?;
            let template = std::fs::read(&args[1]).context("template")?;
            let msi = endpoint_server::installer::build_msi(&template, &args[3], &args[4], &root)?;
            std::fs::write(&args[2], msi)?;
            println!("已產生 {}（內含註冊金鑰，請妥善保管）", args[2]);
            Ok(())
        }
```

- [ ] **Step 4: 驗證**：`cargo test -p endpoint-server --lib` 通過；clippy 無警告；`cargo deny check`（本機若無 cargo-deny 則以 CI 為準）。

- [ ] **Step 5: Commit**：`git commit -am "伺服器：由範本 MSI 產生已包好設定的安裝檔（agent-msi）"`

---

### Task 4: 管理網頁：建立金鑰並下載安裝檔

**Files:**
- Modify: `crates/server/src/config.rs`（`agent_msi`、`agent_public_url`）
- Modify: `crates/server/src/lib.rs`（AppState 欄位與 `with_installer`；`serve()` 串接）
- Modify: `crates/server/src/web/tokens.rs`
- Modify: `crates/server/templates/tokens.html`
- Modify: `crates/server/tests/common/mod.rs`
- Test: `crates/server/tests/web.rs`

**Interfaces:**
- Consumes: Task 3 的 `installer::*`、`ca::server_names`、`Ca::root_pem`。
- Produces:
  - `Config.agent_msi: Option<PathBuf>`（`EM_AGENT_MSI`）、`Config.agent_public_url: String`（`EM_AGENT_PUBLIC_URL`，預設空字串）
  - `AppState.agent_msi: Option<PathBuf>`、`AppState.agent_public_url: String`、`AppState.server_names: Arc<Vec<String>>`
  - `AppState::with_installer(self, msi: Option<PathBuf>, public_url: String, server_names: Vec<String>) -> Self`
  - `TestServer` 預設帶測試範本（`installer::sample_template()` 寫到 tempdir）、`server_names = ["localhost"]`、`public_url = "https://localhost:8443"`

- [ ] **Step 1: 寫失敗測試**（`tests/web.rs`）

```rust
#[sqlx::test(migrations = false)]
async fn installer_download_embeds_token_url_and_root(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北總部").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    assert!(html.contains("建立並下載安裝檔"));
    assert!(html.contains(r#"value="https://localhost:8443""#));
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "MSI pilot"),
            ("max_uses", "5"),
            ("group", &tp.to_string()),
            ("valid_days", ""),
            ("server_url", "https://localhost:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
    let bytes = r.bytes().await.unwrap();
    let p = endpoint_server::installer::read_properties(&bytes).unwrap();
    assert_eq!(p["SERVER_URL"], "https://localhost:8443");
    assert_eq!(p["ROOT_CA"], endpoint_server::installer::root_b64(&s.root_pem));
    // 包進去的金鑰可以註冊，且電腦歸入該群組
    let a = s.enroll_ok(&p["ENROLL_TOKEN"], None, None).await;
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, Some(tp));
    let detail: String = sqlx::query_scalar(
        "SELECT detail::text FROM audit_log WHERE action = 'token_create'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert!(detail.contains("\"installer\": true") || detail.contains("\"installer\":true"));
    assert!(!detail.contains(&p["ENROLL_TOKEN"]), "明碼不可寫進稽核記錄");
}

#[sqlx::test(migrations = false)]
async fn installer_with_wrong_host_is_rejected_without_creating_token(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "wrong host"),
            ("max_uses", "5"),
            ("server_url", "https://10.9.9.9:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("不在伺服器憑證的名稱內"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_tokens WHERE name = 'wrong host'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn group_admin_downloads_only_for_own_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let ks = s.group_id("高雄廠").await;
    let g = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&g, "/tokens").await;
    let r = g
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "other group"),
            ("max_uses", "5"),
            ("group", &ks.to_string()),
            ("server_url", "https://localhost:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
```

- [ ] **Step 2: 執行確認失敗**：`cargo test -p endpoint-server --test web installer` → 失敗（頁面沒有按鈕、表單不認識 `download`）。

- [ ] **Step 3: 實作**

`config.rs`：

```rust
    /// 通用範本 MSI 的路徑；未設定時網頁不提供「下載安裝檔」
    pub agent_msi: Option<PathBuf>,
    /// 下載安裝檔時預設的伺服器網址（例：https://em.example.com:8443）
    pub agent_public_url: String,
```

`from_lookup`：`agent_msi: get("EM_AGENT_MSI").filter(|s| !s.is_empty()).map(PathBuf::from),`、`agent_public_url: get("EM_AGENT_PUBLIC_URL").unwrap_or_default(),`。

`lib.rs`：AppState 加三個欄位（`new()` 內預設 `None`、`String::new()`、`Arc::new(vec![])`）與：

```rust
    pub fn with_installer(
        mut self,
        msi: Option<std::path::PathBuf>,
        public_url: String,
        server_names: Vec<String>,
    ) -> Self {
        self.agent_msi = msi;
        self.agent_public_url = public_url;
        self.server_names = Arc::new(server_names);
        self
    }
```

`serve()`：串上 `.with_installer(cfg.agent_msi.clone(), cfg.agent_public_url.clone(), ca::server_names(&cfg.ca_dir)?)`。

`web/tokens.rs`：
- `TokensPage` 加 `installer: bool`（`st.agent_msi.is_some()`）與 `public_url: String`；`page_for` 填入。
- `CreateForm` 加 `#[serde(default)] server_url: String`、`#[serde(default)] download: String`。
- `create()` 在 `max_uses`／`valid_days` 驗證之後、`create_token` 之前：

```rust
    let download = !f.download.is_empty();
    let server_url = f.server_url.trim();
    let template = if download {
        let path = st.agent_msi.as_ref().ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, "伺服器未設定安裝檔範本（EM_AGENT_MSI）")
                .into_response()
        })?;
        crate::installer::check_server_url(server_url, &st.server_names).map_err(|m| bad(&m))?;
        Some(tokio::fs::read(path).await.map_err(|e| {
            tracing::error!(error = %e, path = %path.display(), "cannot read agent MSI template");
            (StatusCode::SERVICE_UNAVAILABLE, "讀不到安裝檔範本").into_response()
        })?)
    } else {
        None
    };
```

- 稽核 detail 改為：

```rust
        serde_json::json!({
            "name": name, "max_uses": max_uses, "group_id": group, "valid_days": valid_days,
            "installer": download, "server_url": download.then_some(server_url)
        }),
```

- `drop(c);` 之後：

```rust
    if let Some(template) = template {
        let (url, root) = (server_url.to_string(), st.ca.root_pem().to_string());
        let msi = tokio::task::spawn_blocking(move || {
            crate::installer::build_msi(&template, &url, &token, &root)
        })
        .await
        .map_err(|e| action_error(anyhow::anyhow!(e)))?
        .map_err(action_error)?;
        return Ok((
            [
                (header::CONTENT_TYPE, "application/x-msi"),
                (header::CONTENT_DISPOSITION, "attachment; filename=\"endpoint-agent.msi\""),
            ],
            msi,
        )
            .into_response());
    }
```

（`action_error` 在 `web/devices.rs`，回 500 並記錄錯誤；若簽章不同，照既有 `db_error` 寫法包成 `(StatusCode::INTERNAL_SERVER_ERROR, ...)`。`header` 來自 `axum::http::header`。）

`templates/tokens.html` 的表單改為：

```html
<form method="post" action="/tokens">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <label>名稱 <input name="name" required maxlength="100"></label>
  <label>可使用次數 <input name="max_uses" type="number" min="1" value="100" required></label>
  <label>群組 <select name="group">{% for o in groups %}<option value="{{ o.value }}">{{ o.label }}</option>{% endfor %}</select></label>
  <label>有效天數 <input name="valid_days" type="number" min="1" placeholder="不限"></label>
  <button>建立</button>
  {% if installer %}
  <p>
    <label>伺服器網址 <input name="server_url" value="{{ public_url }}" placeholder="https://em.example.com:8443" size="40"></label>
    <button name="download" value="1">建立並下載安裝檔</button>
  </p>
  <p class="muted">安裝檔內含這把金鑰，可直接用 GPO 或 <code>msiexec /i endpoint-agent.msi /qn</code> 安裝。請當成機密保管，並設定可使用次數與有效天數。</p>
  {% endif %}
</form>
```

`tests/common/mod.rs`：`start_with` 內 `AppState::new(...)` 之後串上：

```rust
        let msi_path = dir.path().join("template.msi");
        std::fs::write(&msi_path, endpoint_server::installer::sample_template()).unwrap();
        let state = state.with_installer(
            Some(msi_path),
            "https://localhost:8443".into(),
            vec!["localhost".into()],
        );
```

- [ ] **Step 4: 驗證**：`cargo test -p endpoint-server` 全數通過（含原本 27 個網頁測試）；clippy 無警告。

- [ ] **Step 5: Commit**：`git commit -am "管理網頁：建立金鑰時可直接下載已包好設定的安裝檔"`

---

### Task 5: WiX 範本 MSI 與 CI 安裝測試

**Files:**
- Create: `installer/agent.wxs`
- Create: `installer/build.ps1`
- Create: `installer/test-msi.ps1`
- Modify: `.github/workflows/ci.yml`（新增 `msi` job）
- Modify: `.gitignore`（`*.msi`、`*.wixpdb`）

**Interfaces:**
- Consumes: Task 2 的 `configure`／`unconfigure`、Task 3 的 `agent-msi`。
- Produces: `installer/build.ps1 [-Version <x.y.z>] [-Out <msi>]` → 通用範本 MSI；CI artifact `agent-msi`（範本 MSI 與 `endpoint-agent.exe`）。

- [ ] **Step 1: 寫失敗測試**：`installer/test-msi.ps1`（需系統管理員；CI 執行）

```powershell
# MSI 安裝／升級／解除安裝測試。需要系統管理員權限（CI 的 windows runner）。
# $Msi：以 agent-msi 產生、已包好設定的安裝檔；$UpgradeMsi：較新版本的通用範本（不帶任何屬性）。
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$UpgradeMsi,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$RootPem
)
$ErrorActionPreference = "Stop"
$svcName = "EndpointManagerAgent"
$data = "C:\ProgramData\EndpointManager"
$evtKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$svcName"

function Check($cond, $msg) {
    if (-not $cond) { throw "FAIL: $msg" }
    Write-Host "ok: $msg"
}
function Msiexec($argList) {
    $p = Start-Process msiexec.exe -ArgumentList $argList -Wait -PassThru
    return $p.ExitCode
}
function B64($pem) { ((Get-Content $pem) | Where-Object { $_ -notmatch "^-----" }) -join "" }

# 安裝：不帶任何命令列參數，設定全部來自 MSI 內
Check ((Msiexec "/i `"$Msi`" /qn /l*v install.log") -eq 0) "install"
Check ((Get-Service $svcName).Status -eq "Running") "service running"
Check ((Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartMode -eq "Auto") "auto start"
$cfg = Get-Content "$data\config.json" -Raw | ConvertFrom-Json
Check ($cfg.server_url -eq "https://localhost:9") "server_url from MSI"
Check ($cfg.enroll_token -eq $Token) "token from MSI"
Check ((B64 "$data\root.pem") -eq (B64 $RootPem)) "root.pem from MSI"
$sddl = (Get-Acl $data).Sddl
Check ($sddl -match "^O:BA" -and $sddl -notmatch ";;;(BU|AU|WD|IU)\)") "data dir ACL: $sddl"
Check ((sc.exe qfailure $svcName | Out-String) -match "RESTART") "recovery = restart"
Check ((sc.exe qfailureflag $svcName | Out-String) -match "TRUE") "recovery on non-crash failures"
$sd = sc.exe sdshow $svcName | Out-String
foreach ($m in [regex]::Matches($sd, "\(A;;([A-Z]*);;;(IU|AU|BU|SU|WD)\)")) {
    Check ($m.Groups[1].Value -notmatch "WP") "users cannot stop service ($($m.Value))"
}
Check (Test-Path $evtKey) "event source registered"
Check (-not (Select-String -Path install.log -Pattern $Token -SimpleMatch -Quiet)) "token not in MSI log"

# 升級：用新版通用範本，資料與設定沿用
Set-Content "$data\keep.txt" "x"
Check ((Msiexec "/i `"$UpgradeMsi`" /qn /l*v upgrade.log") -eq 0) "upgrade"
Check (Test-Path "$data\keep.txt") "upgrade keeps data dir"
Check ((Get-Content "$data\config.json" -Raw | ConvertFrom-Json).enroll_token -eq $Token) "upgrade keeps token"
Check ((Get-Service $svcName).Status -eq "Running") "service running after upgrade"

# 解除安裝：全部移除
Check ((Msiexec "/x `"$UpgradeMsi`" /qn /l*v uninstall.log") -eq 0) "uninstall"
Check (-not (Get-Service $svcName -ErrorAction SilentlyContinue)) "service removed"
Check (-not (Test-Path $data)) "data dir removed"
Check (-not (Test-Path $evtKey)) "event source removed"
Write-Host "all MSI checks passed"
```

- [ ] **Step 2: 建置腳本**：`installer/build.ps1`

```powershell
# 建置通用範本 MSI（不含任何組織資訊）。
# 需要 .NET SDK 與 WiX v5：dotnet tool install --global wix --version 5.0.2
# 要簽章 endpoint-agent.exe 的話，在 cargo build 之後、wix build 之前簽。
param(
    [string]$Version = "",
    [string]$Out = ""
)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Version) {
    $Version = (Select-String -Path "$repo\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
}
if (-not $Out) { $Out = "$repo\target\endpoint-agent-$Version.msi" }
cargo build --release -p endpoint-agent --manifest-path "$repo\Cargo.toml"
if ($LASTEXITCODE) { throw "cargo build failed" }
wix build "$PSScriptRoot\agent.wxs" -arch x64 `
    -d "Version=$Version" -d "AgentExe=$repo\target\release\endpoint-agent.exe" -o $Out
if ($LASTEXITCODE) { throw "wix build failed" }
Write-Host "MSI: $Out"
```

- [ ] **Step 3: WiX 原始檔**：`installer/agent.wxs`

```xml
<!-- Endpoint Manager Agent 通用範本 MSI（WiX v5）。以 installer/build.ps1 建置。
     SERVER_URL／ENROLL_TOKEN／ROOT_CA 由伺服器下載時寫入 Property 表，或以 msiexec 命令列指定。 -->
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Endpoint Manager Agent" Manufacturer="Endpoint Manager"
           Version="$(Version)" UpgradeCode="C1FDEBF6-F5C5-46E4-A913-5B6690EB943B"
           Scope="perMachine" Codepage="65001">
    <MajorUpgrade DowngradeErrorMessage="已安裝較新版本的 Endpoint Manager Agent。" />
    <MediaTemplate EmbedCab="yes" />

    <Property Id="SERVER_URL" Secure="yes" />
    <Property Id="ENROLL_TOKEN" Secure="yes" Hidden="yes" />
    <Property Id="ROOT_CA" Secure="yes" />

    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="EndpointManager">
        <Component Id="AgentExe">
          <File Id="AgentExe" Source="$(AgentExe)" KeyPath="yes" />
          <ServiceInstall Name="EndpointManagerAgent" DisplayName="Endpoint Manager Agent"
                          Description="回報電腦資產資訊給 Endpoint Manager 伺服器。"
                          Type="ownProcess" Start="auto" ErrorControl="normal"
                          Account="LocalSystem" Arguments="service" />
          <ServiceControl Id="AgentSvc" Name="EndpointManagerAgent"
                          Start="install" Stop="both" Remove="uninstall" Wait="yes" />
          <RegistryKey Root="HKLM"
                       Key="SYSTEM\CurrentControlSet\Services\EventLog\Application\EndpointManagerAgent">
            <RegistryValue Name="EventMessageFile" Type="expandable"
                           Value="%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll" />
            <RegistryValue Name="TypesSupported" Type="integer" Value="7" />
          </RegistryKey>
        </Component>
      </Directory>
    </StandardDirectory>

    <Feature Id="Main">
      <ComponentRef Id="AgentExe" />
    </Feature>

    <!-- HideTarget：命令列含註冊金鑰，不寫入 MSI 記錄 -->
    <CustomAction Id="Configure" FileRef="AgentExe"
                  ExeCommand="configure --server-url &quot;[SERVER_URL]&quot; --token &quot;[ENROLL_TOKEN]&quot; --root-ca &quot;[ROOT_CA]&quot;"
                  Execute="deferred" Impersonate="no" Return="check" HideTarget="yes" />
    <CustomAction Id="Unconfigure" FileRef="AgentExe" ExeCommand="unconfigure"
                  Execute="deferred" Impersonate="no" Return="ignore" />
    <InstallExecuteSequence>
      <Custom Action="Configure" After="InstallServices" Condition="NOT REMOVE" />
      <Custom Action="Unconfigure" Before="RemoveFiles"
              Condition="REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE" />
    </InstallExecuteSequence>
  </Package>
</Wix>
```

若 WiX v5 不接受沒有 `Value` 的 `Property`，改成 `Value=""` 以外的寫法（例如移除這三個 `Property` 元素、只保留 `SecureCustomProperties`：`<Property Id="SecureCustomProperties" Value="SERVER_URL;ENROLL_TOKEN;ROOT_CA" />` 與 `<Property Id="MsiHiddenProperties" Value="ENROLL_TOKEN" />`）；以實際建置結果為準，並在 CI 驗證金鑰不入記錄。

- [ ] **Step 4: 本機建置確認**（不需系統管理員）：以使用者層級安裝 .NET SDK（`dotnet-install.ps1 -Channel 8.0 -InstallDir $env:LOCALAPPDATA\Microsoft\dotnet`）後 `dotnet tool install --global wix --version 5.0.2`，執行 `installer/build.ps1 -Out $env:CLAUDE_JOB_DIR\tmp\t.msi` → 產出範本；再以 `endpoint-server agent-msi` 改寫，並用 `installer::read_properties`（或 `msiinfo`／PowerShell `WindowsInstaller.Installer` COM）確認屬性寫入。

- [ ] **Step 5: CI job**（`.github/workflows/ci.yml`）

```yaml
  msi:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: dotnet tool install --global wix --version 5.0.2
      - name: build, patch and test MSI
        shell: pwsh
        run: |
          cargo build --release -p endpoint-server
          ./target/release/endpoint-server.exe ca-init target/ci-pki localhost
          ./installer/build.ps1 -Out target/template.msi
          ./installer/build.ps1 -Version 0.1.1 -Out target/upgrade.msi
          $env:EM_CA_DIR = "target/ci-pki"
          ./target/release/endpoint-server.exe agent-msi target/template.msi target/a.msi https://localhost:9 ci-secret-token-8f3a
          ./installer/test-msi.ps1 -Msi target/a.msi -UpgradeMsi target/upgrade.msi -Token ci-secret-token-8f3a -RootPem target/ci-pki/root.pem
      - uses: actions/upload-artifact@v4
        with:
          name: agent-msi
          path: |
            target/template.msi
            target/release/endpoint-agent.exe
      - if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: msi-logs
          path: "*.log"
```

注意：`build.ps1 -Version 0.1.1` 會重建 exe（版本相同，cargo 會直接用快取），第二個 MSI 只是 Package 版本較高，用來測升級。

- [ ] **Step 6: 推送分支、確認 `msi` job 通過**；失敗時下載 `msi-logs` 查原因。

- [ ] **Step 7: Commit**：`git add installer .github/workflows/ci.yml .gitignore && git commit -m "新增 WiX v5 範本 MSI 與 CI 安裝／升級／解除安裝測試"`

---

### Task 6: Docker Compose 部署與 smoke 測試

**Files:**
- Create: `deploy/Dockerfile`
- Create: `deploy/docker-compose.yml`
- Create: `deploy/.env.example`
- Create: `deploy/smoke.sh`
- Create: `.dockerignore`
- Modify: `.gitignore`（`/deploy/pki`、`/deploy/agent`、`/deploy/.env`）
- Modify: `.github/workflows/ci.yml`（新增 `deploy` job）

**Interfaces:**
- Consumes: Task 1 的 SIGTERM 處理、Task 4 的 `EM_AGENT_MSI`／`EM_AGENT_PUBLIC_URL`。
- Produces: 映像名 `endpoint-manager-server`；Compose 服務 `db`、`server`。

- [ ] **Step 1: 寫失敗測試**：`deploy/smoke.sh`

```bash
#!/usr/bin/env bash
# 建置映像 → 建立 CA → 啟動 → 檢查兩個監聽埠 → docker stop 應以 0 結束。
set -euo pipefail
cd "$(dirname "$0")"
export EM_DB_PASSWORD=smoke-test-password
docker compose build
mkdir -p pki agent
sudo chown 65532:65532 pki
docker run --rm -v "$PWD/pki:/pki" endpoint-manager-server ca-init /pki localhost
docker compose up -d
for _ in $(seq 60); do
  curl -skf https://localhost:8443/healthz && break
  sleep 2
done
curl -skf https://localhost:8443/healthz
test "$(curl -sk -o /dev/null -w '%{http_code}' https://localhost/login)" = 200
docker compose stop server
id=$(docker compose ps -aq server)
test "$(docker inspect -f '{{.State.ExitCode}}' "$id")" = 0
docker compose logs server | grep -q "shutting down"
docker compose down -v
sudo rm -rf pki agent
echo "smoke ok"
```

- [ ] **Step 2: 執行確認失敗**：`bash deploy/smoke.sh` → 失敗（compose 檔不存在）。

- [ ] **Step 3: 實作**

`deploy/Dockerfile`：

```dockerfile
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p endpoint-server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/endpoint-server /usr/local/bin/endpoint-server
ENTRYPOINT ["/usr/local/bin/endpoint-server"]
CMD ["serve"]
```

`.dockerignore`：

```
target
.git
.superpowers
deploy/pki
deploy/agent
deploy/.env
```

`deploy/docker-compose.yml`：

```yaml
services:
  db:
    image: postgres:17
    environment:
      POSTGRES_USER: em
      POSTGRES_PASSWORD: ${EM_DB_PASSWORD:?請在 .env 設定 EM_DB_PASSWORD}
      POSTGRES_DB: endpoint_manager
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U em -d endpoint_manager"]
      interval: 5s
      timeout: 5s
      retries: 20
    restart: unless-stopped

  server:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
    image: endpoint-manager-server
    depends_on:
      db:
        condition: service_healthy
    environment:
      DATABASE_URL: postgres://em:${EM_DB_PASSWORD}@db:5432/endpoint_manager
      EM_CA_DIR: /pki
      EM_AGENT_LISTEN: 0.0.0.0:8443
      EM_WEB_LISTEN: 0.0.0.0:8444
      EM_DISPLAY_UTC_OFFSET: ${EM_DISPLAY_UTC_OFFSET:-8}
      EM_AGENT_MSI: /agent/endpoint-agent.msi
      EM_AGENT_PUBLIC_URL: ${EM_AGENT_PUBLIC_URL:-}
    volumes:
      - ./pki:/pki:ro
      - ./agent:/agent:ro
    ports:
      - "8443:8443"
      - "443:8444"
    stop_grace_period: 30s
    restart: unless-stopped

volumes:
  pgdata:
```

`deploy/.env.example`：

```
EM_DB_PASSWORD=請改成長的隨機字串
EM_DISPLAY_UTC_OFFSET=8
# Agent 連線用的網址，主機名稱必須是 ca-init 時給的名稱之一
EM_AGENT_PUBLIC_URL=https://em.example.com:8443
```

- [ ] **Step 4: 本機驗證**：Docker Desktop 執行中，以 Git Bash 跑 `bash deploy/smoke.sh`（Windows 上沒有 `sudo`：本機驗證時把 `sudo chown`／`sudo rm` 暫時換成無 sudo 的版本，或只在 CI 驗證；以 CI 結果為準）。

- [ ] **Step 5: CI job**

```yaml
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bash deploy/smoke.sh
```

- [ ] **Step 6: Commit**：`git add deploy .dockerignore .gitignore .github/workflows/ci.yml && git commit -m "新增 Docker Compose 部署與 smoke 測試"`

---

### Task 7: 負載模擬器 `tools/loadsim`

**Files:**
- Modify: `Cargo.toml`（members 加 `"tools/loadsim"`）
- Create: `tools/loadsim/Cargo.toml`
- Create: `tools/loadsim/src/lib.rs`
- Create: `tools/loadsim/src/main.rs`
- Test: `tools/loadsim/tests/sim.rs`

**Interfaces:**
- Consumes: `endpoint_agent::client::ServerClient`（`new(base, root_pem, identity_pem)`、`enroll`、`checkin`、`upload`）；`protocol` 型別；Task 1 的 `EM_ENROLL_PER_IP_PER_MINUTE`。
- Produces:
  - `pub struct Target { pub server: String, pub root_pem: String }`
  - `pub struct Device { pub device_id: Uuid, pub identity_pem: String }`（Serialize/Deserialize）
  - `pub struct Report { pub ok: usize, pub errors: usize, pub p50: Duration, pub p99: Duration, pub max: Duration, pub elapsed: Duration }`
  - `pub fn percentile(sorted: &[Duration], p: f64) -> Duration`
  - `pub fn software(device: usize, items: usize) -> Vec<SoftwareItem>`
  - `pub async fn enroll(t: &Target, token: &str, count: usize, concurrency: usize) -> anyhow::Result<Vec<Device>>`
  - `pub async fn heartbeat(t: &Target, devices: &[Device], rate: u32, duration: Duration) -> Report`
  - `pub async fn upload(t: &Target, devices: &[Device], items: usize, concurrency: usize) -> (Report, usize /* unverified */)`

- [ ] **Step 1: 寫失敗測試**

`lib.rs` 內單元測試：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_nearest_rank() {
        let v: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
        assert_eq!(percentile(&v, 50.0), Duration::from_millis(50));
        assert_eq!(percentile(&v, 99.0), Duration::from_millis(99));
        assert_eq!(percentile(&v, 100.0), Duration::from_millis(100));
        assert_eq!(percentile(&[], 99.0), Duration::ZERO);
    }

    #[test]
    fn software_is_deterministic_and_valid() {
        let a = software(7, 150);
        assert_eq!(a.len(), 150);
        assert_eq!(a, software(7, 150));
        protocol::InventoryPayload::Software(a).validate().unwrap();
    }
}
```

`tests/sim.rs`（需要 DATABASE_URL）：

```rust
//! loadsim ↔ 真伺服器（小規模），確認三個情境端對端可用。

use std::time::Duration;

use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use loadsim::Target;
use sqlx::PgPool;
use tokio::net::TcpListener;

#[sqlx::test(migrations = false)]
async fn enroll_heartbeat_upload(pool: PgPool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["127.0.0.1".into()]).unwrap();
    db::migrate(&pool).await.unwrap();
    partitions::maintain_partitions(&pool, chrono::Utc::now()).await.unwrap();
    let state = AppState::new(pool.clone(), ca::Ca::load(pki.path()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(tls::serve_mtls(
        listener,
        tls::server_config(pki.path()).unwrap(),
        agent_router(state),
        tls::ConnLimits::default(),
    ));
    let (_, token) = tokens::create_token(
        &pool,
        &tokens::NewToken {
            name: "loadsim".into(),
            group_id: None,
            expires_at: None,
            max_uses: 5,
            created_by: "test".into(),
        },
    )
    .await
    .unwrap();
    let t = Target {
        server: format!("https://127.0.0.1:{port}"),
        root_pem: std::fs::read_to_string(pki.path().join("root.pem")).unwrap(),
    };

    let devices = loadsim::enroll(&t, &token, 5, 5).await.unwrap();
    assert_eq!(devices.len(), 5);

    let hb = loadsim::heartbeat(&t, &devices, 20, Duration::from_secs(1)).await;
    assert_eq!(hb.errors, 0);
    assert!(hb.ok >= 15, "{} ok", hb.ok);

    let (up, unverified) = loadsim::upload(&t, &devices, 50, 5).await;
    assert_eq!((up.ok, up.errors, unverified), (5, 0, 0));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM device_software")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 250);
}
```

- [ ] **Step 2: 執行確認失敗**：`cargo test -p loadsim` → 失敗（crate 不存在）。

- [ ] **Step 3: 實作**

`tools/loadsim/Cargo.toml`：

```toml
[package]
name = "loadsim"
version.workspace = true
edition.workspace = true
license.workspace = true
publish = false

[dependencies]
protocol.workspace = true
endpoint-agent = { path = "../../crates/agent" }
anyhow.workspace = true
chrono.workspace = true
rcgen.workspace = true
rustls.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
uuid.workspace = true

[dev-dependencies]
endpoint-server = { path = "../../crates/server" }
sqlx.workspace = true
tempfile.workspace = true
```

`tools/loadsim/src/lib.rs`：

```rust
//! 模擬大量 Agent：註冊、心跳、上傳完整軟體清單。每次請求都新建連線（與真實 Agent 相同）。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use endpoint_agent::client::ServerClient;
use protocol::{
    Arch, CheckinRequest, EnrollRequest, InventoryPayload, InventoryUpload, SCHEMA_VERSION,
    Section, SoftwareItem,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

#[derive(Clone)]
pub struct Target {
    pub server: String,
    pub root_pem: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: Uuid,
    pub identity_pem: String,
}

#[derive(Debug)]
pub struct Report {
    pub ok: usize,
    pub errors: usize,
    pub p50: Duration,
    pub p99: Duration,
    pub max: Duration,
    pub elapsed: Duration,
}

impl Report {
    fn new(mut ok_lat: Vec<Duration>, errors: usize, elapsed: Duration) -> Report {
        ok_lat.sort();
        Report {
            ok: ok_lat.len(),
            errors,
            p50: percentile(&ok_lat, 50.0),
            p99: percentile(&ok_lat, 99.0),
            max: ok_lat.last().copied().unwrap_or_default(),
            elapsed,
        }
    }
}

/// nearest-rank 百分位數；輸入須已排序。
pub fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// 每台電腦的軟體清單：名稱在各台之間共用（讓跨電腦搜尋有意義），版本依電腦略有不同。
pub fn software(device: usize, items: usize) -> Vec<SoftwareItem> {
    (0..items)
        .map(|k| SoftwareItem {
            name: format!("Loadsim Product {k:04}"),
            version: Some(format!("{}.{}.{}", k % 7, device % 3, k % 11)),
            publisher: Some(format!("Loadsim Vendor {:02}", k % 20)),
            install_date: Some("20260101".into()),
            arch: Arch::X64,
        })
        .collect()
}

fn client(t: &Target, d: Option<&Device>) -> anyhow::Result<ServerClient> {
    ServerClient::new(&t.server, &t.root_pem, d.map(|d| d.identity_pem.clone()))
}

fn checkin_req(section_hashes: BTreeMap<Section, String>) -> CheckinRequest {
    CheckinRequest {
        schema_version: SCHEMA_VERSION,
        agent_version: "loadsim".into(),
        boot_time: chrono::Utc::now() - chrono::Duration::hours(1),
        logged_on_user: Some(r"LOADSIM\user".into()),
        ip_addresses: vec!["10.0.0.1".into()],
        section_hashes,
        section_errors: BTreeMap::new(),
    }
}

async fn enroll_one(t: &Target, token: &str, n: usize) -> anyhow::Result<Device> {
    let key = rcgen::KeyPair::generate()?;
    let csr_pem = rcgen::CertificateParams::default()
        .serialize_request(&key)?
        .pem()?;
    let resp = client(t, None)?
        .enroll(&EnrollRequest {
            schema_version: SCHEMA_VERSION,
            enroll_token: token.into(),
            csr_pem,
            hostname: format!("LOADSIM-{n:05}"),
            smbios_uuid: Some(Uuid::new_v4().to_string()),
            bios_serial: Some(format!("LS{}", Uuid::new_v4().simple())),
            mac_addresses: vec![],
        })
        .await
        .map_err(|e| anyhow::anyhow!("enroll {n}: {e}"))?;
    Ok(Device {
        device_id: resp.device_id,
        identity_pem: format!("{}{}", resp.certificate_chain_pem, key.serialize_pem()),
    })
}

pub async fn enroll(
    t: &Target,
    token: &str,
    count: usize,
    concurrency: usize,
) -> anyhow::Result<Vec<Device>> {
    let sem = Arc::new(Semaphore::new(concurrency));
    let mut set = JoinSet::new();
    for n in 0..count {
        let permit = sem.clone().acquire_owned().await?;
        let (t, token) = (t.clone(), token.to_string());
        set.spawn(async move {
            let _permit = permit;
            enroll_one(&t, &token, n).await
        });
    }
    let mut out = Vec::with_capacity(count);
    while let Some(r) = set.join_next().await {
        out.push(r??);
    }
    Ok(out)
}

/// 以固定速率（每秒 rate 次）輪流讓各台報到，量測延遲（不含本機建立 client 的時間）。
pub async fn heartbeat(t: &Target, devices: &[Device], rate: u32, duration: Duration) -> Report {
    let mut tick = tokio::time::interval(Duration::from_secs_f64(1.0 / rate.max(1) as f64));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
    let start = Instant::now();
    let mut set = JoinSet::new();
    let mut i = 0;
    while start.elapsed() < duration && !devices.is_empty() {
        tick.tick().await;
        let (t, d) = (t.clone(), devices[i % devices.len()].clone());
        i += 1;
        set.spawn(async move {
            let c = client(&t, Some(&d)).ok()?;
            let s = Instant::now();
            c.checkin(&checkin_req(BTreeMap::new())).await.ok()?;
            Some(s.elapsed())
        });
    }
    collect(set, start).await
}

/// 每台上傳完整軟體清單，再報到一次確認伺服器不再要求 software（＝已存入）。
pub async fn upload(
    t: &Target,
    devices: &[Device],
    items: usize,
    concurrency: usize,
) -> (Report, usize) {
    let sem = Arc::new(Semaphore::new(concurrency));
    let unverified = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut set = JoinSet::new();
    for (n, d) in devices.iter().enumerate() {
        let permit = sem.clone().acquire_owned().await.expect("semaphore open");
        let (t, d, unverified) = (t.clone(), d.clone(), unverified.clone());
        set.spawn(async move {
            let _permit = permit;
            let payload = InventoryPayload::Software(software(n, items));
            let hash = payload.canonical_hash();
            let c = client(&t, Some(&d)).ok()?;
            let s = Instant::now();
            c.upload(&InventoryUpload {
                schema_version: SCHEMA_VERSION,
                payload,
            })
            .await
            .ok()?;
            let resp = c
                .checkin(&checkin_req(BTreeMap::from([(Section::Software, hash)])))
                .await
                .ok()?;
            if resp.request_sections.contains(&Section::Software) {
                unverified.fetch_add(1, Ordering::Relaxed);
            }
            Some(s.elapsed())
        });
    }
    let report = collect(set, start).await;
    (report, unverified.load(Ordering::Relaxed))
}

async fn collect(mut set: JoinSet<Option<Duration>>, start: Instant) -> Report {
    let (mut lat, mut errors) = (Vec::new(), 0);
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Some(d)) => lat.push(d),
            _ => errors += 1,
        }
    }
    Report::new(lat, errors, start.elapsed())
}
```

`tools/loadsim/src/main.rs`：

```rust
use std::time::Duration;

use anyhow::{Context, bail};
use loadsim::{Device, Report, Target};

const USAGE: &str = "usage:
  loadsim enroll    --server URL --root root.pem --token TOKEN --count N [--concurrency 50] --out devices.json
  loadsim heartbeat --server URL --root root.pem --devices devices.json [--rate 500] [--secs 60] [--max-p99-ms 200]
  loadsim upload    --server URL --root root.pem --devices devices.json [--items 150] [--concurrency 100] [--max-secs 600]";

fn arg(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn num<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> anyhow::Result<T> {
    match arg(args, name) {
        Some(v) => v.parse().map_err(|_| anyhow::anyhow!("{name}: invalid number")),
        None => Ok(default),
    }
}

fn need(args: &[String], name: &str) -> anyhow::Result<String> {
    arg(args, name).with_context(|| format!("{name} is required\n{USAGE}"))
}

fn print(r: &Report) {
    println!(
        "ok {} errors {} | p50 {:?} p99 {:?} max {:?} | elapsed {:?} ({:.0}/s)",
        r.ok,
        r.errors,
        r.p50,
        r.p99,
        r.max,
        r.elapsed,
        r.ok as f64 / r.elapsed.as_secs_f64()
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        bail!("{USAGE}")
    };
    let t = Target {
        server: need(&args, "--server")?,
        root_pem: std::fs::read_to_string(need(&args, "--root")?).context("reading --root")?,
    };
    let load = || -> anyhow::Result<Vec<Device>> {
        Ok(serde_json::from_slice(&std::fs::read(need(&args, "--devices")?)?)?)
    };
    match cmd.as_str() {
        "enroll" => {
            let count = num(&args, "--count", 0usize)?;
            let devices = loadsim::enroll(
                &t,
                &need(&args, "--token")?,
                count,
                num(&args, "--concurrency", 50)?,
            )
            .await?;
            std::fs::write(need(&args, "--out")?, serde_json::to_vec(&devices)?)?;
            println!("enrolled {}", devices.len());
        }
        "heartbeat" => {
            let r = loadsim::heartbeat(
                &t,
                &load()?,
                num(&args, "--rate", 500)?,
                Duration::from_secs(num(&args, "--secs", 60)?),
            )
            .await;
            print(&r);
            let max = Duration::from_millis(num(&args, "--max-p99-ms", 200)?);
            if r.errors > 0 || r.p99 > max {
                bail!("FAIL: errors {} / p99 {:?} (limit {max:?})", r.errors, r.p99);
            }
        }
        "upload" => {
            let (r, unverified) = loadsim::upload(
                &t,
                &load()?,
                num(&args, "--items", 150)?,
                num(&args, "--concurrency", 100)?,
            )
            .await;
            print(&r);
            println!("unverified {unverified}");
            let max = Duration::from_secs(num(&args, "--max-secs", 600)?);
            if r.errors > 0 || unverified > 0 || r.elapsed > max {
                bail!(
                    "FAIL: errors {} / unverified {unverified} / elapsed {:?}",
                    r.errors,
                    r.elapsed
                );
            }
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
```

- [ ] **Step 4: 驗證**：`cargo test -p loadsim` 全數通過；clippy 無警告。

- [ ] **Step 5: Commit**：`git add Cargo.toml Cargo.lock tools && git commit -m "新增負載模擬器 loadsim"`

---

### Task 8: 執行 30,000 台負載測試並記錄結果

**Files:**
- Create: `docs/loadtest.md`

這是規格 §7 的驗收關卡：兩項標準都要通過。不通過時用 superpowers:systematic-debugging 找根因（先看伺服器 tracing、PostgreSQL `pg_stat_activity`、CPU），修正後回到本 Task 重跑；修正程式要有對應測試並另外 commit。

- [ ] **Step 1: 準備環境**（本機；Docker Desktop 與 `em-postgres` 執行中）

```bash
docker exec em-postgres psql -U postgres -c "CREATE DATABASE em_load"
cargo build --release -p endpoint-server -p loadsim
mkdir -p "$CLAUDE_JOB_DIR/tmp/load" && cp target/release/endpoint-server.exe target/release/loadsim.exe "$CLAUDE_JOB_DIR/tmp/load/"
cd "$CLAUDE_JOB_DIR/tmp/load"
./endpoint-server.exe ca-init pki 127.0.0.1
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/em_load EM_CA_DIR=pki \
       EM_AGENT_LISTEN=127.0.0.1:18443 EM_WEB_LISTEN=127.0.0.1:18444 EM_ENROLL_PER_IP_PER_MINUTE=1000000
./endpoint-server.exe token-create loadsim 30000   # 記下金鑰
```

伺服器以背景工作執行 `./endpoint-server.exe serve`。

- [ ] **Step 2: 註冊 30,000 台**：`./loadsim.exe enroll --server https://127.0.0.1:18443 --root pki/root.pem --token <金鑰> --count 30000 --concurrency 50 --out devices.json`（記錄耗時）。

- [ ] **Step 3: 心跳 500 次／秒**：`./loadsim.exe heartbeat --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --rate 500 --secs 120` → 標準：errors 0、p99 < 200ms。

- [ ] **Step 4: 30,000 台上傳完整軟體清單**：`./loadsim.exe upload --server https://127.0.0.1:18443 --root pki/root.pem --devices devices.json --items 150 --concurrency 100 --max-secs 600` → 標準：10 分鐘內完成、errors 0、unverified 0。另以 `SELECT count(*) FROM device_software` 確認 = 4,500,000。

- [ ] **Step 5: 記錄**：`docs/loadtest.md` 寫入測試機規格（CPU、記憶體、OS；loadsim 與伺服器同機的限制）、指令、三個步驟的輸出與是否通過，以及重跑方法。

- [ ] **Step 6: 清理**：停止伺服器；`docker exec em-postgres psql -U postgres -c "DROP DATABASE em_load"`。

- [ ] **Step 7: Commit**：`git add docs/loadtest.md && git commit -m "記錄 30,000 台負載測試結果"`

---

### Task 9: 文件與發佈

**Files:**
- Modify: `README.md`

- [ ] **Step 1: README 新增章節**（繁體中文）：
  - **部署伺服器（Docker Compose）**：`cp deploy/.env.example deploy/.env` 改密碼與 `EM_AGENT_PUBLIC_URL` → `mkdir deploy/pki deploy/agent && sudo chown 65532:65532 deploy/pki` → `docker compose -f deploy/docker-compose.yml build` → `docker run --rm -v "$PWD/deploy/pki:/pki" endpoint-manager-server ca-init /pki em.example.com` → **把 `deploy/pki/root.key` 移到離線媒體並從伺服器刪除** → 從 GitHub Release 下載 `endpoint-agent-<版本>.msi` 放到 `deploy/agent/endpoint-agent.msi` → `docker compose -f deploy/docker-compose.yml up -d` → `docker compose -f deploy/docker-compose.yml run --rm server admin-create admin`。防火牆：443 只開給 IT 網段、8443 開給所有端點。
  - **安裝 Agent**：管理網頁 → 註冊金鑰 →「建立並下載安裝檔」；手動安裝 `msiexec /i endpoint-agent.msi /qn`；GPO：電腦設定 → 軟體安裝，直接指定下載的 MSI（放在只有網域電腦可讀的共用資料夾）。安裝檔內含金鑰，要設可使用次數與有效天數，用完即作廢。沒有網頁時可用 `endpoint-server agent-msi` 產生。同版本已安裝時要先解除安裝才能換另一個安裝檔；升級直接安裝新版範本即可。
  - **自行建置範本 MSI**：安裝 .NET SDK 與 `dotnet tool install --global wix --version 5.0.2`（說明為何固定 v5）→ `installer/build.ps1`。
  - **程式碼簽章**：`signtool sign /fd SHA256 /tr <時間戳記伺服器> /td SHA256 /sha1 <憑證指紋> target\release\endpoint-agent.exe`，在 `build.ps1` 的 cargo build 之後、wix build 之前簽；網頁產生的 MSI 經過改寫，MSI 本身不帶簽章（內含的 exe 簽章仍有效）。
  - **負載測試**：連到 `docs/loadtest.md`。
  - Agent 章節補上 `configure`／`unconfigure`（由 MSI 呼叫）。

- [ ] **Step 2: Commit**：`git commit -am "README：部署、安裝檔下載、簽章、負載測試說明"`

- [ ] **Step 3: PR → 審查 → 合併**：推送分支開 PR，CI 五個 job（test、deny、agent-windows、msi、deploy）全綠；最終審查修正 Critical／Important；squash merge 並刪除分支。

- [ ] **Step 4: GitHub Release v0.1.0**：從合併後 main 的 CI 下載 `agent-msi` artifact（`gh run download <run-id> -n agent-msi`），改名為 `endpoint-agent-0.1.0.msi`，產生兩個檔案的 `.sha256`（`sha256sum` 格式），`gh release create v0.1.0 endpoint-agent-0.1.0.msi endpoint-agent-0.1.0.msi.sha256 endpoint-agent.exe endpoint-agent.exe.sha256`；說明寫明：MSI 是通用範本，放到伺服器後由管理網頁產生各組織的安裝檔；伺服器以 Docker Compose 從原始碼建置。
