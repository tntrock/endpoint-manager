# 計畫 4／4：MSI 安裝檔、Docker 部署與負載測試 實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 讓第一期可以實際導入：Agent 以 MSI 安裝（可 GPO 派送），伺服器以 Docker Compose 部署，並用 `tools/loadsim` 模擬 30,000 台驗證規格 §7 的負載標準。

**Architecture:** MSI 只做 Windows Installer 原生擅長的事：放檔案、安裝／啟動服務、登錄事件來源。需要邏輯的部分（強化資料目錄 ACL、複製根憑證、合併 config.json、設定服務失敗復原）由 Agent 新增的 `configure`／`unconfigure` 子命令處理，MSI 以 deferred custom action（SYSTEM）呼叫，邏輯因此能用 Rust 測試。根 CA 在**建置 MSI 時**嵌入（各公司用自己的 root.pem 建置），`SERVER_URL`、`ENROLL_TOKEN` 可在建置時給預設值（GPO 不必做 transform），也可在 `msiexec` 命令列覆寫。伺服器以多階段 Dockerfile 建成 distroless 映像，Compose 搭配 PostgreSQL 17，並處理 SIGTERM。loadsim 透過真實 API 註冊、報到、上傳，以伺服器回應驗證資料確實存入。

**Tech Stack:** WiX Toolset **v5.0.2**（dotnet tool）、windows-service 0.8、Docker（rust:1-bookworm → gcr.io/distroless/cc-debian12:nonroot）、postgres:17、既有的 tokio／reqwest／rcgen

**Spec:** `docs/superpowers/specs/2026-09-27-endpoint-inventory-design.md`（§1.5 成功標準、§3 installer/deploy/loadsim、§4.1 MSI 參數、§6.1 服務 ACL 與失敗復原、§6.4 簽章、§7 負載測試）

**前置：** 計畫 1～3 已合併（main `d6da313`）。

## 設計決定

1. **WiX v5.0.2**（使用者決定）：v6 起有 Open Source Maintenance Fee，v7 起強制接受 EULA；v5 為 MS-RL、無此約束。不使用 WiX 擴充套件（Util 等），只用核心 schema。
2. **根 CA 建置時嵌入**：`installer/build.ps1 -RootPem <root.pem> -ServerUrl <url> [-EnrollToken <token>]`。GitHub Release 因此**不附 MSI**（沒有通用的根 CA），只附 `endpoint-agent.exe` 與 `.sha256`；README 說明如何自行建置 MSI。
3. **檔案位置**：`C:\Program Files\EndpointManager\{endpoint-agent.exe, root.pem}`（僅系統管理員可寫）；資料目錄 `C:\ProgramData\EndpointManager\` 由 `configure` 以 `harden_dir` 建立並強化後，才從安裝目錄複製 root.pem 進去——避免一般使用者預先建立資料目錄、在 MSI 放檔與強化之間偷換 root.pem。
4. **config.json 合併規則**（`configure`）：
   - `server_url` = 命令列值，否則沿用既有值，兩者皆無 → 失敗（安裝中止）；必須以 `https://` 開頭。
   - `enroll_token`：已註冊（state.json 有 device_id）→ 一律清除；未註冊 → 命令列值，否則沿用既有值。
   - 空字串視為未提供（MSI 未設屬性時會傳 `""`）。
5. **服務失敗復原**：`configure` 以 SCM API 設定：失敗後 60 秒重啟 ×3、24 小時重置計數，並開啟「非當機的失敗也套用」（Agent 以 `ServiceSpecific(1)` 結束屬於此類）。
6. **服務 ACL**：Windows 預設的服務安全描述元已不允許一般使用者（IU/AU/SU）停止服務，不另外設定；MSI 測試會驗證。
7. **事件來源**：MSI 寫入 `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\EndpointManagerAgent`，`EventMessageFile` 指向 .NET Framework 4 內建的 `EventLogMessages.dll`（每個事件 ID 都對應 `%1`，Win10+ 皆有），不必自己編訊息資源檔。解除安裝時 MSI 自動移除。
8. **升級與解除安裝**：`MajorUpgrade`（預設排程，先移除舊版）。`unconfigure`（刪除資料目錄）只在 `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` 時執行，升級不會刪掉憑證與 device_id。
9. **Docker**：容器內網頁監聽 `0.0.0.0:8444`，Compose 對外映射 `443:8444`、`8443:8443`；映像以 uid 65532 執行；`./pki` 唯讀掛載。`ca-init` 以 `docker run` 寫入 `./pki`（需先 `chown 65532`）。伺服器收到 SIGTERM／Ctrl+C 都會寫出心跳緩衝後以 0 結束。
10. **loadsim 走真實 API**：新增 `EM_ENROLL_PER_IP_PER_MINUTE`（預設 60）讓測試環境可一次註冊 30,000 台；每次請求都新建連線（與真實 Agent 相同，每週期重建 client）；上傳後以下一次報到的 `request_sections` 不含 software 驗證資料確實存入。
11. **一併處理的延後項目**：Agent 的 Retry-After 夾在 10 秒～30 分鐘（避免 `Retry-After: 0` 造成空轉）、伺服器 SIGTERM。其餘延後項目維持記錄在專案備忘，除非負載測試顯示它們是瓶頸。

## Global Constraints

- 授權 `GPL-3.0-only`；Rust edition 2024；TLS 只用 rustls + ring；不用 clap；不新增依賴套件（loadsim 只用 workspace 既有套件）。
- `cargo fmt --all --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace`、cargo-deny 全部通過。
- WiX 固定 `5.0.2`，不得使用 v6 以上。
- 程式碼與文件不得出現特定公司資訊；範例網址用 `em.example.com`。
- 使用者看得到的訊息（CLI 提示、MSI 錯誤訊息、README）用繁體中文。
- 本機 `DATABASE_URL` 用 `127.0.0.1`，不用 `localhost`。本機 shell 沒有系統管理員權限：MSI 安裝測試只在 CI（windows-latest 為系統管理員）執行。
- 服務名稱與事件來源固定 `EndpointManagerAgent`；資料目錄 `C:\ProgramData\EndpointManager`。

## Review Focus

1. **升級不能洗掉已註冊身分**：升級 MSI 後資料目錄內的檔案必須保留、服務繼續執行 → Task 3 `test-msi.ps1` 的升級檢查。
2. **註冊金鑰不能出現在 MSI 詳細記錄**（`/l*v` 常被收集給 IT）→ Task 3 檢查 install.log 不含金鑰。
3. **已註冊的電腦重跑安裝不能把金鑰寫回磁碟** → Task 2 `merge_config` 測試。
4. **`Retry-After: 0` 或極大值** → Task 2 夾值測試。
5. **`docker compose stop` 要以 0 結束且留下關閉記錄**（心跳緩衝寫出）→ Task 4 `smoke.sh`。

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

- [ ] **Step 4: 驗證**：`cargo test -p endpoint-server --lib config::` 通過；`cargo clippy --workspace --all-targets -- -D warnings` 無警告。SIGTERM 的實際行為由 Task 4 的 smoke 測試驗證。

- [ ] **Step 5: Commit**：`git commit -am "伺服器：處理 SIGTERM、註冊限速可由環境變數調整"`

---

### Task 2: Agent：Retry-After 夾值、`configure`／`unconfigure` 子命令

**Files:**
- Modify: `crates/agent/src/client.rs`
- Modify: `crates/agent/src/config.rs`
- Create: `crates/agent/src/windows/install.rs`
- Modify: `crates/agent/src/windows/mod.rs`（`pub mod install;`）
- Modify: `crates/agent/src/main.rs`
- Modify: `crates/agent/Cargo.toml`（無新套件；確認 windows-service 預設功能含 service_manager）
- Test: `crates/agent/tests/windows.rs`

**Interfaces:**
- Produces:
  - `client::retry_after(secs: u64) -> Duration`（夾在 `RETRY_AFTER_MIN` 10s ～ `RETRY_AFTER_MAX` 1800s）
  - `config::merge_config(existing: Option<AgentConfig>, enrolled: bool, server_url: Option<&str>, token: Option<&str>) -> anyhow::Result<AgentConfig>`
  - `windows::install::configure(data: &Path, exe_dir: &Path, server_url: Option<&str>, token: Option<&str>) -> anyhow::Result<()>`
  - `windows::install::set_recovery() -> anyhow::Result<()>`
  - `windows::install::unconfigure(data: &Path) -> anyhow::Result<()>`
  - CLI：`endpoint-agent configure [--server-url URL] [--token TOKEN]`、`endpoint-agent unconfigure`（Task 3 的 MSI 呼叫）

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
```

`tests/windows.rs`（沿用檔內 `harden_dir_takes_ownership_from_squatter` 的 `net session` 判斷，抽成 `fn elevated() -> bool` 共用）：

```rust
/// 需要系統管理員權限；一般權限下略過。
#[test]
fn configure_hardens_dir_and_writes_files() {
    if !elevated() {
        eprintln!("skipped: not elevated");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let exe_dir = tmp.path().join("bin");
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&exe_dir).unwrap();
    std::fs::write(exe_dir.join("root.pem"), b"ROOT").unwrap();

    endpoint_agent::windows::install::configure(
        &data,
        &exe_dir,
        Some("https://em.example.com:8443"),
        Some("tok"),
    )
    .unwrap();
    assert_eq!(std::fs::read(data.join("root.pem")).unwrap(), b"ROOT");
    let c = endpoint_agent::config::AgentConfig::load(&data).unwrap();
    assert_eq!(c.enroll_token.as_deref(), Some("tok"));

    // 重跑（升級）不帶參數：沿用
    endpoint_agent::windows::install::configure(&data, &exe_dir, None, None).unwrap();
    assert_eq!(
        endpoint_agent::config::AgentConfig::load(&data).unwrap(),
        c
    );

    endpoint_agent::windows::install::unconfigure(&data).unwrap();
    assert!(!data.exists());
    endpoint_agent::windows::install::unconfigure(&data).unwrap(); // 不存在也成功
}
```

- [ ] **Step 2: 執行確認失敗**：`cargo test -p endpoint-agent --lib` → 編譯失敗（`retry_after`、`merge_config` 不存在）。

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
```

`windows/install.rs`：

```rust
//! MSI 的 custom action 呼叫（SYSTEM 身分）：`configure` 於安裝／升級、`unconfigure` 於解除安裝。

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceFailureActions,
    ServiceFailureResetPeriod,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use super::service::SERVICE_NAME;
use crate::config::{AgentConfig, merge_config};
use crate::state::{AgentState, harden_dir, write_atomic};

/// 先強化資料目錄，再從安裝目錄（僅系統管理員可寫）複製 root.pem，最後合併 config.json。
pub fn configure(
    data: &Path,
    exe_dir: &Path,
    server_url: Option<&str>,
    token: Option<&str>,
) -> anyhow::Result<()> {
    harden_dir(data)?;
    write_atomic(&data.join("root.pem"), &std::fs::read(exe_dir.join("root.pem"))?)?;
    let existing = AgentConfig::load(data).ok();
    let enrolled = AgentState::load(data)?.device_id.is_some();
    merge_config(existing, enrolled, server_url, token)?.save(data)
}

/// 失敗後 60 秒重啟（3 次）、24 小時重置；非當機的失敗（結束代碼非 0）也套用。
pub fn set_recovery() -> anyhow::Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let svc = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
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

（若 `write_atomic` 的簽章回傳 `std::io::Result<()>`，`?` 可直接轉 anyhow。）

`main.rs` 的 match：

```rust
        Some("configure") => {
            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
            let exe = std::env::current_exe()?;
            let exe_dir = exe.parent().expect("exe has a parent dir");
            use endpoint_agent::windows::{agent_dir, install};
            install::configure(
                &agent_dir(),
                exe_dir,
                install::flag(&args, "--server-url").as_deref(),
                install::flag(&args, "--token").as_deref(),
            )?;
            install::set_recovery()
        }
        Some("unconfigure") => {
            endpoint_agent::windows::install::unconfigure(&endpoint_agent::windows::agent_dir())
        }
        _ => anyhow::bail!("usage: endpoint-agent run | service | configure [--server-url URL] [--token TOKEN] | unconfigure"),
```

`eventlog.rs` 頂端註解改為：「事件來源由 MSI 註冊，訊息檔用 .NET Framework 的 EventLogMessages.dll。」

- [ ] **Step 4: 驗證**：`cargo test -p endpoint-agent --lib` 通過；`cargo test -p endpoint-agent --test windows` 通過（本機非系統管理員會顯示 skipped；CI 實際執行）；clippy 無警告。

- [ ] **Step 5: Commit**：`git commit -am "Agent：Retry-After 夾值、新增 configure／unconfigure 供 MSI 呼叫"`

---

### Task 3: WiX MSI 與 CI 安裝測試

**Files:**
- Create: `installer/agent.wxs`
- Create: `installer/build.ps1`
- Create: `installer/test-msi.ps1`
- Modify: `.github/workflows/ci.yml`（新增 `msi` job）
- Modify: `.gitignore`（`*.msi`、`*.wixpdb`）

**Interfaces:**
- Consumes: Task 2 的 `configure`／`unconfigure` CLI。
- Produces: `installer/build.ps1 -RootPem <path> -ServerUrl <url> [-EnrollToken <t>] [-Version <x.y.z>] [-Out <msi>]`；MSI 屬性 `SERVER_URL`、`ENROLL_TOKEN`。

- [ ] **Step 1: 寫失敗測試**：`installer/test-msi.ps1`（需系統管理員；CI 執行）

```powershell
# MSI 安裝／升級／解除安裝測試。需要系統管理員權限（CI 的 windows runner）。
param(
    [Parameter(Mandatory)][string]$Msi,
    [Parameter(Mandatory)][string]$UpgradeMsi
)
$ErrorActionPreference = "Stop"
$svcName = "EndpointManagerAgent"
$data = "C:\ProgramData\EndpointManager"
$evtKey = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$svcName"
$token = "secret-token-8f3a"

function Check($cond, $msg) {
    if (-not $cond) { throw "FAIL: $msg" }
    Write-Host "ok: $msg"
}
function Msiexec($argList) {
    $p = Start-Process msiexec.exe -ArgumentList $argList -Wait -PassThru
    return $p.ExitCode
}

# 安裝（命令列帶金鑰）
Check ((Msiexec "/i `"$Msi`" /qn /l*v install.log ENROLL_TOKEN=$token") -eq 0) "install"
Check ((Get-Service $svcName).Status -eq "Running") "service running"
Check ((Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartMode -eq "Auto") "auto start"
$cfg = Get-Content "$data\config.json" -Raw | ConvertFrom-Json
Check ($cfg.server_url -eq "https://127.0.0.1:9") "server_url from build default"
Check ($cfg.enroll_token -eq $token) "token from command line"
Check ((Get-FileHash "$data\root.pem").Hash -eq (Get-FileHash "C:\Program Files\EndpointManager\root.pem").Hash) "root.pem copied"
$sddl = (Get-Acl $data).Sddl
Check ($sddl -match "^O:BA" -and $sddl -notmatch ";;;(BU|AU|WD|IU)\)") "data dir ACL: $sddl"
Check ((sc.exe qfailure $svcName | Out-String) -match "RESTART") "recovery = restart"
Check ((sc.exe qfailureflag $svcName | Out-String) -match "TRUE") "recovery on non-crash failures"
$sd = sc.exe sdshow $svcName | Out-String
foreach ($m in [regex]::Matches($sd, "\(A;;([A-Z]*);;;(IU|AU|BU|SU|WD)\)")) {
    Check ($m.Groups[1].Value -notmatch "WP") "users cannot stop service ($($m.Value))"
}
Check (Test-Path $evtKey) "event source registered"
Check (-not (Select-String -Path install.log -Pattern $token -SimpleMatch -Quiet)) "token not in MSI log"

# 升級：資料保留、金鑰沿用
Set-Content "$data\keep.txt" "x"
Check ((Msiexec "/i `"$UpgradeMsi`" /qn /l*v upgrade.log") -eq 0) "upgrade"
Check (Test-Path "$data\keep.txt") "upgrade keeps data dir"
Check ((Get-Content "$data\config.json" -Raw | ConvertFrom-Json).enroll_token -eq $token) "upgrade keeps token"
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
# 建置 Agent MSI。需要 .NET SDK 與 WiX v5：dotnet tool install --global wix --version 5.0.2
# 根 CA 會嵌入 MSI：每個組織用自己的 root.pem 建置。
param(
    [Parameter(Mandatory)][string]$RootPem,
    [Parameter(Mandatory)][string]$ServerUrl,
    [string]$EnrollToken = "",
    [string]$Version = "",
    [string]$Out = "target\endpoint-agent.msi"
)
$ErrorActionPreference = "Stop"
$repo = Split-Path $PSScriptRoot -Parent
if (-not $Version) {
    $Version = (Select-String -Path "$repo\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value
}
cargo build --release -p endpoint-agent --manifest-path "$repo\Cargo.toml"
if ($LASTEXITCODE) { throw "cargo build failed" }
wix build "$PSScriptRoot\agent.wxs" -arch x64 `
    -d "Version=$Version" -d "ServerUrl=$ServerUrl" -d "EnrollToken=$EnrollToken" `
    -d "AgentExe=$repo\target\release\endpoint-agent.exe" -d "RootPem=$((Resolve-Path $RootPem).Path)" `
    -o $Out
if ($LASTEXITCODE) { throw "wix build failed" }
Write-Host "MSI: $Out"
```

- [ ] **Step 3: WiX 原始檔**：`installer/agent.wxs`

```xml
<!-- Endpoint Manager Agent MSI（WiX v5）。以 installer/build.ps1 建置。 -->
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="Endpoint Manager Agent" Manufacturer="Endpoint Manager"
           Version="$(Version)" UpgradeCode="C1FDEBF6-F5C5-46E4-A913-5B6690EB943B"
           Scope="perMachine" Codepage="65001">
    <MajorUpgrade DowngradeErrorMessage="已安裝較新版本的 Endpoint Manager Agent。" />
    <MediaTemplate EmbedCab="yes" />

    <Property Id="SERVER_URL" Value="$(ServerUrl)" Secure="yes" />
    <?if $(EnrollToken) != "" ?>
    <Property Id="ENROLL_TOKEN" Value="$(EnrollToken)" Secure="yes" Hidden="yes" />
    <?else?>
    <Property Id="ENROLL_TOKEN" Secure="yes" Hidden="yes" />
    <?endif?>

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
        <Component Id="RootPem">
          <File Id="RootPem" Name="root.pem" Source="$(RootPem)" KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>

    <Feature Id="Main">
      <ComponentRef Id="AgentExe" />
      <ComponentRef Id="RootPem" />
    </Feature>

    <!-- HideTarget：命令列含註冊金鑰，不寫入 MSI 記錄 -->
    <CustomAction Id="Configure" FileRef="AgentExe"
                  ExeCommand="configure --server-url &quot;[SERVER_URL]&quot; --token &quot;[ENROLL_TOKEN]&quot;"
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

若 WiX v5 對無 `Value` 的 `Property` 報錯，改成在 `build.ps1` 未給金鑰時不宣告 `ENROLL_TOKEN` 而在 wxs 用 `<?ifdef?>`；以實際建置結果為準，並在 CI 驗證。

- [ ] **Step 4: 本機建置確認**（不需系統管理員）：以使用者層級安裝 .NET SDK（`dotnet-install.ps1 -Channel 8.0 -InstallDir $env:LOCALAPPDATA\Microsoft\dotnet`）後 `dotnet tool install --global wix --version 5.0.2`，再以 `$env:CLAUDE_JOB_DIR\tmp\pki\root.pem` 執行 `installer/build.ps1 -RootPem ... -ServerUrl https://127.0.0.1:9 -Out $env:CLAUDE_JOB_DIR\tmp\a.msi` → 產出 MSI。

- [ ] **Step 5: CI job**（`.github/workflows/ci.yml`）

```yaml
  msi:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: dotnet tool install --global wix --version 5.0.2
      - name: test root CA
        shell: bash
        run: |
          mkdir -p target/ci-pki
          openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -subj /CN=ci-root -days 2 -keyout target/ci-pki/root.key -out target/ci-pki/root.pem
      - name: build and test MSI
        shell: pwsh
        run: |
          ./installer/build.ps1 -RootPem target/ci-pki/root.pem -ServerUrl https://127.0.0.1:9 -Out target/a.msi
          ./installer/build.ps1 -RootPem target/ci-pki/root.pem -ServerUrl https://127.0.0.1:9 -Version 0.1.1 -Out target/b.msi
          ./installer/test-msi.ps1 -Msi target/a.msi -UpgradeMsi target/b.msi
      - if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: msi-logs
          path: "*.log"
```

`agent-windows` job 的測試指令不變（`configure_hardens_dir_and_writes_files` 會在 CI 以系統管理員身分執行）。

- [ ] **Step 6: 推送分支、確認 `msi` job 通過**；失敗時下載 `msi-logs` 查原因。

- [ ] **Step 7: Commit**：`git add installer .github/workflows/ci.yml .gitignore && git commit -m "新增 WiX v5 MSI 與 CI 安裝／升級／解除安裝測試"`

---

### Task 4: Docker Compose 部署與 smoke 測試

**Files:**
- Create: `deploy/Dockerfile`
- Create: `deploy/docker-compose.yml`
- Create: `deploy/.env.example`
- Create: `deploy/smoke.sh`
- Create: `.dockerignore`
- Modify: `.gitignore`（`/deploy/pki`、`/deploy/.env`）
- Modify: `.github/workflows/ci.yml`（新增 `deploy` job）

**Interfaces:**
- Consumes: Task 1 的 SIGTERM 處理。
- Produces: 映像名 `endpoint-manager-server`；Compose 服務 `db`、`server`。

- [ ] **Step 1: 寫失敗測試**：`deploy/smoke.sh`

```bash
#!/usr/bin/env bash
# 建置映像 → 建立 CA → 啟動 → 檢查兩個監聽埠 → docker stop 應以 0 結束。
set -euo pipefail
cd "$(dirname "$0")"
export EM_DB_PASSWORD=smoke-test-password
docker compose build
mkdir -p pki
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
sudo rm -rf pki
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
    volumes:
      - ./pki:/pki:ro
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
```

- [ ] **Step 4: 本機驗證**：Docker Desktop 執行中，以 Git Bash 跑 `bash deploy/smoke.sh`（Windows 上 `sudo` 不存在：本機驗證時把 `sudo chown`／`sudo rm` 暫時換成無 sudo 的版本，或只在 CI 驗證；以 CI 結果為準）。

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

### Task 5: 負載模擬器 `tools/loadsim`

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

- [ ] **Step 2: 執行確認失敗**：`cargo test -p loadsim` → 編譯失敗（crate 不存在）。

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
    let unverified = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
                unverified.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            Some(s.elapsed())
        });
    }
    let report = collect(set, start).await;
    (report, unverified.load(std::sync::atomic::Ordering::Relaxed))
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
    let Some(cmd) = args.first().cloned() else { bail!("{USAGE}") };
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
            let devices =
                loadsim::enroll(&t, &need(&args, "--token")?, count, num(&args, "--concurrency", 50)?)
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
                bail!("FAIL: errors {} / unverified {unverified} / elapsed {:?}", r.errors, r.elapsed);
            }
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
```

- [ ] **Step 4: 驗證**：`cargo test -p loadsim` 全數通過；`cargo clippy --workspace --all-targets -- -D warnings`；cargo-deny（新 crate 授權沿用 workspace）。

- [ ] **Step 5: Commit**：`git add Cargo.toml Cargo.lock tools && git commit -m "新增負載模擬器 loadsim"`

---

### Task 6: 執行 30,000 台負載測試並記錄結果

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

### Task 7: 文件與發佈

**Files:**
- Modify: `README.md`

- [ ] **Step 1: README 新增章節**（繁體中文）：
  - **部署伺服器（Docker Compose）**：`cp deploy/.env.example deploy/.env` 改密碼 → `mkdir deploy/pki && sudo chown 65532:65532 deploy/pki` → `docker compose -f deploy/docker-compose.yml build` → `docker run --rm -v "$PWD/deploy/pki:/pki" endpoint-manager-server ca-init /pki em.example.com` → **把 `deploy/pki/root.key` 移到離線媒體並從伺服器刪除** → `docker compose -f deploy/docker-compose.yml up -d` → `docker compose -f deploy/docker-compose.yml run --rm server admin-create admin` → `... run --rm server token-create 台北總部金鑰 500 台北總部 30`。防火牆：443 只開給 IT 網段、8443 開給所有端點。
  - **建置與派送 Agent MSI**：安裝 .NET SDK 與 `dotnet tool install --global wix --version 5.0.2`（說明為何固定 v5）；`installer/build.ps1 -RootPem deploy/pki/root.pem -ServerUrl https://em.example.com:8443 [-EnrollToken ...]`；手動安裝 `msiexec /i endpoint-agent.msi /qn ENROLL_TOKEN=...`；GPO：電腦設定 → 軟體安裝，金鑰於建置時嵌入（MSI 檔的存取權限要限制在網域電腦）。
  - **程式碼簽章**：`signtool sign /fd SHA256 /tr <時間戳記伺服器> /td SHA256 /sha1 <憑證指紋> target\release\endpoint-agent.exe`，在 `build.ps1` 之前簽 exe、之後簽 MSI。
  - **負載測試**：連到 `docs/loadtest.md`。
  - Agent 章節補上 `configure`／`unconfigure`（由 MSI 呼叫）。

- [ ] **Step 2: Commit**：`git commit -am "README：部署、MSI、簽章、負載測試說明"`

- [ ] **Step 3: PR → 審查 → 合併**：推送分支開 PR，CI 五個 job（test、deny、agent-windows、msi、deploy）全綠；最終審查修正 Critical／Important；squash merge 並刪除分支。

- [ ] **Step 4: GitHub Release v0.1.0**：本機 `cargo build --release -p endpoint-agent`，產生 `endpoint-agent.exe.sha256`（`sha256sum` 格式），`gh release create v0.1.0 target/release/endpoint-agent.exe endpoint-agent.exe.sha256`，說明寫明：MSI 需以自己的根 CA 自行建置（附 README 連結），伺服器以 Docker Compose 從原始碼建置。
