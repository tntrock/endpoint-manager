# 計畫 2／4：Windows Agent 實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增 `crates/agent`：以 Windows Service 執行的 Rust Agent。它會向計畫 1 的伺服器註冊，定時報到，收集五個區段的盤點資料（基本資訊、硬體、軟體、KB、服務），只在內容有變化時上傳，並在憑證快到期時自動續期。

**Architecture:** 把「與平台無關的邏輯」和「Windows 專屬的收集／系統整合」分開。

- **平台無關**：字串清理、軟體清單轉換、排程、退避、狀態檔、HTTP client、主迴圈 `Agent::run_cycle`。這些在 Linux CI 上也會編譯與測試，主迴圈用假的 `Collector` 對真實伺服器跑端對端測試。
- **Windows 專屬**：WMI、登錄檔、登錄檔變更監聽、事件檢視器、Windows Service。全部放在 `#[cfg(windows)] mod windows`，由 Windows 上的冒煙測試驗證。

**Tech Stack:** Rust 2024、tokio、reqwest 0.13（`rustls-no-provider` + ring）、rcgen 0.14（CSR）、flate2、wmi 0.18、winreg 0.56、windows-service 0.8、windows-sys 0.61

**Spec:** `docs/superpowers/specs/2026-09-27-endpoint-inventory-design.md`

**前置：** 計畫 1 已合併（PR #1），伺服器 API、`protocol` crate、`endpoint_server` lib 均可使用。

## Global Constraints

- 授權 `GPL-3.0-only`；Rust edition 2024。
- TLS 只用 rustls + **ring**；reqwest 一律使用 `default-features = false, features = ["json", "rustls-no-provider"]`，程式啟動時安裝 ring 為預設 provider。禁止 aws-lc-rs、openssl、native-tls。
- 只用 HTTP/1.1（伺服器 ALPN 只提供 `http/1.1`）：reqwest 設 `http1_only()`。
- Agent 只信任 `root.pem`（安裝時放入 Agent 目錄的根 CA），不使用系統信任憑證。
- Agent 目錄預設 `C:\ProgramData\EndpointManager`，可用環境變數 `EM_AGENT_DIR` 覆寫。目錄內檔案：`config.json`、`root.pem`、`state.json`。
- 服務模式下目錄 ACL 只留 SYSTEM（`S-1-5-18`）與 Administrators（`S-1-5-32-544`）。
- 送出前所有字串：移除 NUL（U+0000）、去頭尾空白、截斷到 `protocol::MAX_STRING_LEN`（1024 字元）；每區段項目數截斷到 `protocol::MAX_ITEMS`（20,000）。
- 上傳被伺服器以 4xx 拒絕的區段，記住被拒的 hash；hash 沒變之前不再重送，並把原因放進 `section_errors`。
- 預設心跳 60 秒、加 ±20% 隨機延遲；實際間隔以伺服器回應為準。
- 退避：60 秒起、每次失敗加倍、上限 30 分鐘，加 ±20% 隨機延遲；伺服器給 `Retry-After` 時以它為準。
- 每個 collector 呼叫逾時 60 秒，彼此獨立。
- 軟體區段：監聽 HKLM 64／32 位元 Uninstall 機碼變更，去抖動 10 秒後觸發收集；HKU（使用者層級）只靠每小時補收。
- 伺服器回 401 → Agent 停止報到並寫入事件檢視器，不自動重新註冊。
- 註冊成功後從 `config.json` 移除註冊金鑰。
- 服務程序以低優先權（BELOW_NORMAL）執行。
- 不使用 clap 等 CLI 套件。

## Review Focus

1. **WMI 回傳的 uint64 可能是字串或數字，屬性也可能是 null**（老舊或特殊硬體）→ 不可讓整個區段失敗。→ Task 2 `u64_any_accepts_number_string_and_null`。
2. **伺服器連續多天連不上** → Agent 不當掉、記憶體不增長、退避上限 30 分鐘。→ Task 4 退避測試＋Task 8 `unreachable_server_backs_off`。
3. **`state.json` 損毀**（寫到一半斷電）→ Agent 不可陷入「啟動→崩潰→重啟」迴圈；寫入需為原子操作。→ Task 5 `corrupt_state_is_set_aside`。
4. **端點時鐘不準**（BIOS 電池沒電、時鐘快了好幾天）→ `boot_time` 在未來，不可讓該電腦永遠報到失敗。→ Task 7 伺服器改為夾限而非拒絕，`future_boot_time_is_clamped`。
5. **設定檔缺漏或以一般使用者身分在主控台執行** → 要有清楚的錯誤訊息，不能 panic。→ Task 8 `missing_config_is_a_clear_error`。

---

## 檔案結構

```
crates/agent/
├─ Cargo.toml
├─ src/
│  ├─ main.rs              endpoint-agent.exe：run（主控台）/ service（SCM）
│  ├─ lib.rs
│  ├─ sanitize.rs          字串清理、區段截斷（純函式）
│  ├─ serde_util.rs        u64_any：接受數字／字串／null（WMI 用）
│  ├─ software.rs          Uninstall 機碼項目 → SoftwareItem（純函式）
│  ├─ schedule.rs          各區段何時該收集
│  ├─ backoff.rs           退避與隨機延遲
│  ├─ config.rs            config.json
│  ├─ state.rs             state.json（原子寫入、損毀處理）、目錄 ACL
│  ├─ client.rs            ServerClient：enroll / checkin / upload / renew
│  ├─ collector.rs         Collector trait、Identity、Heartbeat
│  ├─ agent.rs             Agent::run_cycle、run_agent 主迴圈
│  └─ windows/
│     ├─ mod.rs            agent_dir、run、run_console、低優先權
│     ├─ collect.rs        WindowsCollector（WMI）
│     ├─ registry.rs       讀 Uninstall 機碼
│     ├─ regwatch.rs       RegNotifyChangeKeyValue 監聽
│     ├─ eventlog.rs       事件檢視器 tracing writer
│     └─ service.rs        windows-service 整合
└─ tests/
   ├─ e2e.rs               假 Collector ↔ 真伺服器（需 PostgreSQL）
   └─ windows.rs           Windows 實機冒煙測試（#![cfg(windows)]）
```

伺服器端小修改：`crates/server/src/checkin.rs`（boot_time 夾限）。

---

### Task 0: 分支

- [ ] **Step 1**

```bash
cd /d/VSCode/endpoint-manager && git switch main && git pull && git switch -c feat/plan2-windows-agent
```

---

### Task 1: agent crate 骨架與 CI

**Files:**
- Modify: `Cargo.toml`（members、workspace deps）
- Modify: `crates/server/Cargo.toml`（reqwest 改用 workspace）
- Create: `crates/agent/Cargo.toml`、`crates/agent/src/lib.rs`、`crates/agent/src/main.rs`
- Modify: `.github/workflows/ci.yml`（新增 Windows job）

**Interfaces:**
- Produces: crate `endpoint-agent`（lib `endpoint_agent`，bin `endpoint-agent`）。

- [ ] **Step 1: workspace `Cargo.toml`**

`members` 改為 `["crates/protocol", "crates/server", "crates/agent"]`，`[workspace.dependencies]` 追加：

```toml
reqwest = { version = "0.13", default-features = false, features = ["json", "rustls-no-provider"] }
tempfile = "3"
```

`crates/server/Cargo.toml` 的 dev-dependencies 改為 `reqwest.workspace = true`、`tempfile.workspace = true`。

- [ ] **Step 2: `crates/agent/Cargo.toml`**

```toml
[package]
name = "endpoint-agent"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "endpoint_agent"

[dependencies]
protocol.workspace = true
serde.workspace = true
serde_json.workspace = true
chrono.workspace = true
uuid.workspace = true
thiserror.workspace = true
anyhow.workspace = true
tokio.workspace = true
rustls.workspace = true
rcgen.workspace = true
flate2.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
reqwest.workspace = true

[target.'cfg(windows)'.dependencies]
wmi = "0.18"
winreg = "0.56"
windows-service = "0.8"
windows-sys = { version = "0.61", features = [
    "Win32_Foundation",
    "Win32_System_Registry",
    "Win32_System_EventLog",
    "Win32_System_Threading",
] }

[dev-dependencies]
endpoint-server = { path = "../server" }
sqlx.workspace = true
tempfile.workspace = true
```

- [ ] **Step 3: 最小 `lib.rs`／`main.rs`**

```rust
// crates/agent/src/lib.rs
//! Endpoint Manager Windows Agent。
```

```rust
// crates/agent/src/main.rs
fn main() {}
```

- [ ] **Step 4: CI 新增 Windows job**（`.github/workflows/ci.yml` 的 `jobs:` 下）

```yaml
  agent-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test -p endpoint-agent --lib --test windows
```

（`tests/windows.rs` 在 Task 5 建立；在那之前這個 job 會失敗，屬預期。PR 開出時已存在。）

- [ ] **Step 5: 建置**

Run: `cargo build --workspace`
Expected: 成功。另確認 `Cargo.lock` 內沒有 `aws-lc`：`grep -c 'name = "aws-lc' Cargo.lock` → `0`。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "chore(agent): crate 骨架與 Windows CI job"
```

---

### Task 2: 字串清理與 WMI 數值容錯

**Files:**
- Create: `crates/agent/src/sanitize.rs`、`crates/agent/src/serde_util.rs`
- Modify: `crates/agent/src/lib.rs`

**Interfaces:**
- Produces:
  - `sanitize::clean(s: &str) -> String`（移除 NUL、trim、截斷至 MAX_STRING_LEN 字元）
  - `sanitize::sanitize(p: &mut InventoryPayload)`（所有字串 clean；空的 Option 字串變 None；清單截斷至 MAX_ITEMS）
  - `serde_util::u64_any<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error>`

- [ ] **Step 1: 寫失敗測試**

`sanitize.rs`：

```rust
//! 送出前的字串清理：伺服器拒絕 NUL 與超長字串（見 protocol::validate_strings）。

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Arch, InventoryPayload, MAX_ITEMS, MAX_STRING_LEN, SoftwareItem};

    fn sw(name: &str) -> SoftwareItem {
        SoftwareItem {
            name: name.into(),
            version: Some("  ".into()),
            publisher: Some("Pub\0".into()),
            install_date: None,
            arch: Arch::X64,
        }
    }

    #[test]
    fn clean_strips_nul_and_trims() {
        assert_eq!(clean("  a\0b \0"), "ab");
    }

    #[test]
    fn clean_truncates_by_chars() {
        let s = "軟".repeat(MAX_STRING_LEN + 5);
        assert_eq!(clean(&s).chars().count(), MAX_STRING_LEN);
    }

    #[test]
    fn sanitize_makes_payload_valid() {
        let mut p = InventoryPayload::Software(
            (0..MAX_ITEMS + 3).map(|i| sw(&format!("App\0{i}"))).collect(),
        );
        sanitize(&mut p);
        let InventoryPayload::Software(v) = &p else { unreachable!() };
        assert_eq!(v.len(), MAX_ITEMS);
        assert_eq!(v[0].name, "App0");
        assert_eq!(v[0].version, None, "空白字串變 None");
        assert_eq!(v[0].publisher.as_deref(), Some("Pub"));
        assert_eq!(p.validate(), Ok(()));
    }
}
```

`serde_util.rs`：

```rust
//! WMI 的 uint64 屬性有時以字串、有時以數字回傳，也可能是 null。

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct T {
        #[serde(default, deserialize_with = "super::u64_any")]
        n: Option<u64>,
    }

    #[test]
    fn u64_any_accepts_number_string_and_null() {
        let p = |j: &str| serde_json::from_str::<T>(j).unwrap().n;
        assert_eq!(p(r#"{"n": 42}"#), Some(42));
        assert_eq!(p(r#"{"n": "17179869184"}"#), Some(17_179_869_184));
        assert_eq!(p(r#"{"n": " 7 "}"#), Some(7));
        assert_eq!(p(r#"{"n": "garbage"}"#), None);
        assert_eq!(p(r#"{"n": null}"#), None);
        assert_eq!(p(r#"{}"#), None);
    }
}
```

`lib.rs` 加 `pub mod sanitize; pub mod serde_util;`

- [ ] **Step 2: 執行確認失敗**

Run: `cargo test -p endpoint-agent --lib`
Expected: 編譯失敗（`clean`、`sanitize`、`u64_any` 未定義）。

- [ ] **Step 3: 實作**

`sanitize.rs`（測試模組之上）：

```rust
use protocol::{InventoryPayload, MAX_ITEMS, MAX_STRING_LEN};

pub fn clean(s: &str) -> String {
    let no_nul: String = s.chars().filter(|c| *c != '\0').collect();
    no_nul.trim().chars().take(MAX_STRING_LEN).collect()
}

fn fix(s: &mut String) {
    *s = clean(s);
}

fn fix_opt(o: &mut Option<String>) {
    if let Some(s) = o {
        *s = clean(s);
        if s.is_empty() {
            *o = None;
        }
    }
}

pub fn sanitize(p: &mut InventoryPayload) {
    match p {
        InventoryPayload::Basic(b) => {
            fix(&mut b.hostname);
            fix_opt(&mut b.domain);
            fix(&mut b.os_caption);
            fix(&mut b.os_build);
        }
        InventoryPayload::Hardware(h) => {
            fix_opt(&mut h.manufacturer);
            fix_opt(&mut h.model);
            fix_opt(&mut h.cpu);
            h.disks.truncate(MAX_ITEMS);
            h.disks.iter_mut().for_each(|d| fix(&mut d.name));
        }
        InventoryPayload::Software(v) => {
            v.truncate(MAX_ITEMS);
            for s in v {
                fix(&mut s.name);
                fix_opt(&mut s.version);
                fix_opt(&mut s.publisher);
                fix_opt(&mut s.install_date);
            }
        }
        InventoryPayload::Patches(v) => {
            v.truncate(MAX_ITEMS);
            for p in v {
                fix(&mut p.kb);
                fix_opt(&mut p.installed_on);
            }
        }
        InventoryPayload::Services(v) => {
            v.truncate(MAX_ITEMS);
            for s in v {
                fix(&mut s.name);
                fix_opt(&mut s.display_name);
                fix(&mut s.start_mode);
                fix(&mut s.state);
                fix_opt(&mut s.binary_path);
            }
        }
    }
}
```

`serde_util.rs`：

```rust
use serde::{Deserialize, Deserializer};

pub fn u64_any<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Num {
        N(u64),
        S(String),
    }
    Ok(match Option::<Num>::deserialize(d)? {
        Some(Num::N(n)) => Some(n),
        Some(Num::S(s)) => s.trim().parse().ok(),
        None => None,
    })
}
```

- [ ] **Step 4: 執行測試**

Run: `cargo test -p endpoint-agent --lib`
Expected: 4 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): 字串清理與 WMI 數值容錯"
```

---

### Task 3: 軟體清單轉換

**Files:**
- Create: `crates/agent/src/software.rs`；Modify: `lib.rs`（`pub mod software;`）

**Interfaces:**
- Produces:
  - `software::UninstallEntry { display_name, display_version, publisher, install_date: Option<String>, system_component: Option<u32>, parent_key_name: Option<String>, release_type: Option<String> }`（derive `Debug, Clone, Default`）
  - `software::to_items(entries: &[UninstallEntry], arch: Arch) -> Vec<SoftwareItem>`
  - `software::is_user_sid(name: &str) -> bool`

**過濾規則**（「控制台 → 程式和功能」看得到的才算）：`DisplayName` 去空白後非空；`SystemComponent != 1`；沒有 `ParentKeyName`（更新套件）；`ReleaseType` 不是 `Update`／`Hotfix`／`Security Update`。完全相同的項目去重。

- [ ] **Step 1: 寫失敗測試**

```rust
//! Uninstall 機碼項目轉成 SoftwareItem（純函式，讀登錄檔在 windows/registry.rs）。

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str) -> UninstallEntry {
        UninstallEntry {
            display_name: Some(name.into()),
            display_version: Some("1.0".into()),
            ..Default::default()
        }
    }

    #[test]
    fn keeps_visible_programs_only() {
        let entries = vec![
            e("7-Zip"),
            UninstallEntry { system_component: Some(1), ..e("Hidden") },
            UninstallEntry { parent_key_name: Some("Office".into()), ..e("Office Update") },
            UninstallEntry { release_type: Some("Security Update".into()), ..e("KB123") },
            UninstallEntry { display_name: Some("   ".into()), ..Default::default() },
            UninstallEntry::default(),
        ];
        let items = to_items(&entries, Arch::X64);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "7-Zip");
        assert_eq!(items[0].version.as_deref(), Some("1.0"));
        assert_eq!(items[0].arch, Arch::X64);
    }

    #[test]
    fn identical_entries_deduplicated() {
        let items = to_items(&[e("A"), e("A"), e("B")], Arch::X86);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn user_sid_detection() {
        assert!(is_user_sid("S-1-5-21-111-222-333-1001"));
        assert!(!is_user_sid("S-1-5-21-111-222-333-1001_Classes"));
        assert!(!is_user_sid("S-1-5-18"));
        assert!(!is_user_sid(".DEFAULT"));
    }
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-agent --lib software`
Expected: 編譯失敗。

- [ ] **Step 3: 實作**

```rust
use protocol::{Arch, SoftwareItem};

#[derive(Debug, Clone, Default)]
pub struct UninstallEntry {
    pub display_name: Option<String>,
    pub display_version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub system_component: Option<u32>,
    pub parent_key_name: Option<String>,
    pub release_type: Option<String>,
}

const HIDDEN_RELEASE_TYPES: &[&str] = &["Update", "Hotfix", "Security Update"];

pub fn to_items(entries: &[UninstallEntry], arch: Arch) -> Vec<SoftwareItem> {
    let mut items: Vec<SoftwareItem> = entries
        .iter()
        .filter(|e| e.system_component != Some(1))
        .filter(|e| e.parent_key_name.is_none())
        .filter(|e| {
            e.release_type
                .as_deref()
                .is_none_or(|t| !HIDDEN_RELEASE_TYPES.contains(&t))
        })
        .filter_map(|e| {
            let name = e.display_name.as_deref()?.trim();
            (!name.is_empty()).then(|| SoftwareItem {
                name: name.to_string(),
                version: e.display_version.clone(),
                publisher: e.publisher.clone(),
                install_date: e.install_date.clone(),
                arch,
            })
        })
        .collect();
    items.sort();
    items.dedup();
    items
}

/// HKEY_USERS 底下真正的使用者設定檔（排除系統帳戶與 _Classes）。
pub fn is_user_sid(name: &str) -> bool {
    name.starts_with("S-1-5-21-") && !name.ends_with("_Classes")
}
```

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-agent --lib software`
Expected: 3 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): 軟體清單過濾與轉換"
```

---

### Task 4: 收集排程與退避

**Files:**
- Create: `crates/agent/src/schedule.rs`、`crates/agent/src/backoff.rs`；Modify: `lib.rs`

**Interfaces:**
- Produces:
  - `schedule::Schedule`（`Default`），`due(&self, now: Instant, iv: &CollectionIntervals) -> Vec<Section>`、`mark_collected(&mut self, s: Section, now: Instant)`、`trigger(&mut self, s: Section)`
  - `schedule::DEFAULT_INTERVALS: CollectionIntervals`（3600／3600／3600／86400）
  - `backoff::Backoff`（`Default`），`next_delay(&mut self, jitter: f64) -> Duration`、`reset(&mut self)`
  - `backoff::jitter() -> f64`（0.8～1.2）、`backoff::with_jitter(d: Duration, j: f64) -> Duration`
  - 常數 `backoff::MIN_DELAY = 60s`、`backoff::MAX_DELAY = 1800s`

- [ ] **Step 1: 寫失敗測試**

`schedule.rs`：

```rust
//! 各區段該不該收集：basic 每次心跳；其他依伺服器下發的間隔或被觸發。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_due_at_start() {
        let s = Schedule::default();
        assert_eq!(s.due(Instant::now(), &DEFAULT_INTERVALS), Section::ALL.to_vec());
    }

    #[test]
    fn respects_intervals_and_triggers() {
        let mut s = Schedule::default();
        let t0 = Instant::now();
        for sec in Section::ALL {
            s.mark_collected(sec, t0);
        }
        assert_eq!(s.due(t0, &DEFAULT_INTERVALS), vec![Section::Basic]);

        s.trigger(Section::Software);
        assert_eq!(s.due(t0, &DEFAULT_INTERVALS), vec![Section::Basic, Section::Software]);
        s.mark_collected(Section::Software, t0);
        assert_eq!(s.due(t0, &DEFAULT_INTERVALS), vec![Section::Basic]);

        let later = t0 + Duration::from_secs(3600);
        assert_eq!(
            s.due(later, &DEFAULT_INTERVALS),
            vec![Section::Basic, Section::Software, Section::Patches, Section::Services]
        );
        let much_later = t0 + Duration::from_secs(86_400);
        assert!(s.due(much_later, &DEFAULT_INTERVALS).contains(&Section::Hardware));
    }
}
```

`backoff.rs`：

```rust
//! 連不上伺服器時的退避：60 秒起每次加倍，上限 30 分鐘。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doubles_until_cap_then_resets() {
        let mut b = Backoff::default();
        let secs: Vec<u64> = (0..7).map(|_| b.next_delay(1.0).as_secs()).collect();
        assert_eq!(secs, vec![60, 120, 240, 480, 960, 1800, 1800]);
        b.reset();
        assert_eq!(b.next_delay(1.0).as_secs(), 60);
    }

    #[test]
    fn jitter_in_range() {
        for _ in 0..1000 {
            let j = jitter();
            assert!((0.8..=1.2).contains(&j), "{j}");
        }
        assert_eq!(with_jitter(Duration::from_secs(100), 0.8), Duration::from_secs(80));
    }
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-agent --lib`
Expected: 編譯失敗。

- [ ] **Step 3: 實作**

`schedule.rs`：

```rust
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use protocol::{CollectionIntervals, Section};

pub const DEFAULT_INTERVALS: CollectionIntervals = CollectionIntervals {
    software_secs: 3600,
    patches_secs: 3600,
    services_secs: 3600,
    hardware_secs: 86_400,
};

#[derive(Default)]
pub struct Schedule {
    last: HashMap<Section, Instant>,
    triggered: HashSet<Section>,
}

fn interval(s: Section, iv: &CollectionIntervals) -> Duration {
    let secs = match s {
        Section::Basic => 0,
        Section::Hardware => iv.hardware_secs,
        Section::Software => iv.software_secs,
        Section::Patches => iv.patches_secs,
        Section::Services => iv.services_secs,
    };
    Duration::from_secs(secs.into())
}

impl Schedule {
    pub fn due(&self, now: Instant, iv: &CollectionIntervals) -> Vec<Section> {
        Section::ALL
            .into_iter()
            .filter(|s| {
                self.triggered.contains(s)
                    || self
                        .last
                        .get(s)
                        .is_none_or(|t| now.saturating_duration_since(*t) >= interval(*s, iv))
            })
            .collect()
    }

    pub fn mark_collected(&mut self, s: Section, now: Instant) {
        self.last.insert(s, now);
        self.triggered.remove(&s);
    }

    pub fn trigger(&mut self, s: Section) {
        self.triggered.insert(s);
    }
}
```

`backoff.rs`：

```rust
use std::time::Duration;

use uuid::Uuid;

pub const MIN_DELAY: Duration = Duration::from_secs(60);
pub const MAX_DELAY: Duration = Duration::from_secs(1800);

#[derive(Default)]
pub struct Backoff {
    failures: u32,
}

impl Backoff {
    pub fn next_delay(&mut self, jitter: f64) -> Duration {
        let base = MIN_DELAY
            .saturating_mul(2u32.saturating_pow(self.failures))
            .min(MAX_DELAY);
        self.failures = self.failures.saturating_add(1);
        with_jitter(base, jitter)
    }

    pub fn reset(&mut self) {
        self.failures = 0;
    }
}

/// 0.8～1.2 的隨機倍率（用 UUID v4 的亂數，不另外引入 rand）。
pub fn jitter() -> f64 {
    0.8 + (Uuid::new_v4().as_u128() % 1001) as f64 / 1000.0 * 0.4
}

pub fn with_jitter(d: Duration, j: f64) -> Duration {
    d.mul_f64(j)
}
```

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-agent --lib`
Expected: 全部 PASS（累計 9）。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): 收集排程與退避"
```

---

### Task 5: 設定檔、狀態檔與目錄 ACL

**Files:**
- Create: `crates/agent/src/config.rs`、`crates/agent/src/state.rs`
- Create: `crates/agent/tests/windows.rs`
- Modify: `lib.rs`

**Interfaces:**
- Produces:
  - `config::AgentConfig { server_url: String, enroll_token: Option<String> }`（Serialize/Deserialize），`load(dir: &Path) -> anyhow::Result<Self>`（錯誤訊息含檔名）、`save(&self, dir: &Path) -> anyhow::Result<()>`
  - `state::AgentState { device_id: Option<Uuid>, chain_pem: Option<String>, key_pem: Option<String>, rejected: BTreeMap<Section, String> }`（`Default, Clone, Debug, PartialEq, Serialize, Deserialize`）
  - `AgentState::load(dir) -> anyhow::Result<Self>`：檔案不存在 → `Default`；內容損毀 → 改名為 `state.json.corrupt`、記 error log、回 `Default`
  - `AgentState::save(&self, dir) -> anyhow::Result<()>`：寫 `state.json.tmp` 後 rename（原子）
  - `AgentState::is_enrolled(&self) -> bool`、`identity_pem(&self) -> Option<String>`（chain + key）
  - `state::write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()>`（config 也用）
  - `state::secure_dir(dir: &Path) -> anyhow::Result<()>`：Windows 上以 `icacls` 設為只有 SYSTEM／Administrators；其他平台只建立目錄

- [ ] **Step 1: 寫失敗測試**

`config.rs`：

```rust
//! config.json：安裝時寫入（伺服器網址、註冊金鑰），註冊成功後移除金鑰。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_clear_error_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let err = AgentConfig::load(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("config.json"), "{err:#}");

        let c = AgentConfig {
            server_url: "https://em.corp.local:8443".into(),
            enroll_token: Some("tok".into()),
        };
        c.save(dir.path()).unwrap();
        assert_eq!(AgentConfig::load(dir.path()).unwrap().enroll_token.as_deref(), Some("tok"));
    }
}
```

`state.rs`：

```rust
//! state.json：裝置身分（含私鑰）與被拒區段；以原子方式寫入。

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_is_default() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(AgentState::load(dir.path()).unwrap(), AgentState::default());
    }

    #[test]
    fn roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = AgentState {
            device_id: Some(Uuid::new_v4()),
            chain_pem: Some("CHAIN".into()),
            key_pem: Some("KEY".into()),
            ..Default::default()
        };
        s.rejected.insert(Section::Software, "abc".into());
        s.save(dir.path()).unwrap();
        let back = AgentState::load(dir.path()).unwrap();
        assert_eq!(back, s);
        assert!(back.is_enrolled());
        assert_eq!(back.identity_pem().as_deref(), Some("CHAINKEY"));
        assert!(!dir.path().join("state.json.tmp").exists());
    }

    #[test]
    fn corrupt_state_is_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("state.json"), b"{\"device_id\": \"not-a-uu").unwrap();
        assert_eq!(AgentState::load(dir.path()).unwrap(), AgentState::default());
        assert!(dir.path().join("state.json.corrupt").exists());
        assert!(!dir.path().join("state.json").exists());
    }
}
```

`crates/agent/tests/windows.rs`：

```rust
//! Windows 實機冒煙測試。
#![cfg(windows)]

use std::process::Command;

use endpoint_agent::state::secure_dir;

/// 以 SDDL 檢查（不受系統語系影響）：只剩 SYSTEM (SY) 與 Administrators (BA)。
#[test]
fn secure_dir_leaves_only_system_and_admins() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("em");
    secure_dir(&target).unwrap();

    let save = dir.path().join("acl.txt");
    let ok = Command::new("icacls")
        .arg(&target)
        .arg("/save")
        .arg(&save)
        .status()
        .unwrap()
        .success();
    assert!(ok);
    let raw = std::fs::read(&save).unwrap();
    let utf16: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let sddl = String::from_utf16_lossy(&utf16);
    assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
    for other in [";;;BU)", ";;;AU)", ";;;WD)", ";;;CO)"] {
        assert!(!sddl.contains(other), "{other} in {sddl}");
    }

    // 還原，讓 tempdir 可以刪除（擁有者仍有 WRITE_DAC）
    Command::new("icacls").arg(&target).arg("/reset").status().unwrap();
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-agent --lib; cargo test -p endpoint-agent --test windows`
Expected: 編譯失敗。

- [ ] **Step 3: 實作**

`config.rs`：

```rust
use std::path::Path;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::state::write_atomic;

pub const FILE: &str = "config.json";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentConfig {
    pub server_url: String,
    pub enroll_token: Option<String>,
}

impl AgentConfig {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(FILE);
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(&dir.join(FILE), &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}
```

`state.rs`：

```rust
use std::collections::BTreeMap;
use std::path::Path;

use protocol::Section;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const FILE: &str = "state.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentState {
    pub device_id: Option<Uuid>,
    pub chain_pem: Option<String>,
    pub key_pem: Option<String>,
    /// 被伺服器拒絕的區段 → 被拒時的 hash；hash 改變前不再重送
    #[serde(default)]
    pub rejected: BTreeMap<Section, String>,
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

impl AgentState {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join(FILE);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        match serde_json::from_slice(&bytes) {
            Ok(s) => Ok(s),
            Err(e) => {
                tracing::error!(error = %e, "state.json is corrupt; moved to state.json.corrupt, re-enrollment required");
                std::fs::rename(&path, dir.join("state.json.corrupt"))?;
                Ok(Self::default())
            }
        }
    }

    pub fn save(&self, dir: &Path) -> anyhow::Result<()> {
        write_atomic(&dir.join(FILE), &serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    pub fn is_enrolled(&self) -> bool {
        self.device_id.is_some() && self.chain_pem.is_some() && self.key_pem.is_some()
    }

    pub fn identity_pem(&self) -> Option<String> {
        Some(format!("{}{}", self.chain_pem.as_ref()?, self.key_pem.as_ref()?))
    }
}

/// 建立目錄；Windows 上移除繼承權限，只留 SYSTEM 與 Administrators（以 SID 指定，不受語系影響）。
pub fn secure_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(windows)]
    {
        let status = std::process::Command::new("icacls")
            .arg(dir)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
            ])
            .stdout(std::process::Stdio::null())
            .status()?;
        anyhow::ensure!(status.success(), "icacls failed on {}", dir.display());
    }
    Ok(())
}
```

`lib.rs` 加 `pub mod config; pub mod state;`，`crates/agent/Cargo.toml` 的 `[dev-dependencies]` 已有 tempfile；lib 測試也要用 → 確認 `tempfile` 在 dev-dependencies（已在 Task 1）。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-agent --lib && cargo test -p endpoint-agent --test windows`
Expected: lib 全 PASS（累計 13）；windows 1 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): 設定檔、原子寫入的狀態檔與目錄 ACL"
```

---

### Task 6: ServerClient 與端對端測試框架

**Files:**
- Create: `crates/agent/src/client.rs`；Modify: `lib.rs`
- Create: `crates/agent/tests/e2e.rs`

**Interfaces:**
- Consumes: `endpoint_server::{ca, db, partitions, tls, tokens, AppState, agent_router}`（測試用）
- Produces:
  - `client::ClientError { Retry(Option<Duration>), Unauthorized, Rejected(u16, String) }`（thiserror；`From<reqwest::Error>` → `Retry(None)`）
  - `client::ServerClient::new(base: &str, root_pem: &str, identity_pem: Option<String>) -> anyhow::Result<Self>`
  - `enroll(&EnrollRequest) -> Result<EnrollResponse, ClientError>`、`checkin(&CheckinRequest) -> Result<CheckinResponse, ClientError>`、`upload(&InventoryUpload) -> Result<(), ClientError>`（gzip）、`renew(&RenewRequest) -> Result<RenewResponse, ClientError>`
  - 狀態碼對應：2xx 成功；401 → `Unauthorized`；429／503 → `Retry(Retry-After)`；其他 4xx → `Rejected(code, body)`；其他（5xx、連線錯誤）→ `Retry`
  - 測試框架：`Env { pool, state: AppState, dir: TempDir, _pki: TempDir, port: u16 }`、`env(pool, token_uses: i32) -> Env`（agent 目錄已寫好 `config.json`＋`root.pem`）

- [ ] **Step 1: 寫失敗測試 `tests/e2e.rs`**（框架＋client 測試）

```rust
//! 假 Collector ↔ 真伺服器。需要 DATABASE_URL（PostgreSQL）。

use endpoint_agent::client::{ClientError, ServerClient};
use endpoint_agent::config::AgentConfig;
use endpoint_server::{AppState, agent_router, ca, db, partitions, tls, tokens};
use protocol::{CheckinRequest, EnrollRequest, SCHEMA_VERSION};
use sqlx::PgPool;
use tempfile::TempDir;
use tokio::net::TcpListener;

struct Env {
    pool: PgPool,
    state: AppState,
    dir: TempDir,
    _pki: TempDir,
    port: u16,
}

impl Env {
    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    fn root_pem(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("root.pem")).unwrap()
    }
}

async fn env(pool: PgPool, token_uses: i32) -> Env {
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
        agent_router(state.clone()),
        tls::ConnLimits::default(),
    ));

    let (_, token) = tokens::create_token(
        &pool,
        &tokens::NewToken {
            name: "e2e".into(),
            group_label: None,
            expires_at: None,
            max_uses: token_uses,
            created_by: "test".into(),
        },
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(pki.path().join("root.pem"), dir.path().join("root.pem")).unwrap();
    AgentConfig {
        server_url: format!("https://127.0.0.1:{port}"),
        enroll_token: Some(token),
    }
    .save(dir.path())
    .unwrap();
    Env { pool, state, dir, _pki: pki, port }
}

fn csr() -> String {
    let key = rcgen::KeyPair::generate().unwrap();
    rcgen::CertificateParams::default().serialize_request(&key).unwrap().pem().unwrap()
}

#[sqlx::test(migrations = false)]
async fn client_maps_status_codes(pool: PgPool) {
    let e = env(pool, 1).await;
    let c = ServerClient::new(&e.url(), &e.root_pem(), None).unwrap();

    let checkin = CheckinRequest {
        schema_version: SCHEMA_VERSION,
        agent_version: "t".into(),
        boot_time: chrono::Utc::now(),
        logged_on_user: None,
        ip_addresses: vec![],
        section_hashes: Default::default(),
        section_errors: Default::default(),
    };
    assert!(matches!(c.checkin(&checkin).await, Err(ClientError::Unauthorized)));

    let enroll = |token: &str, csr: String| EnrollRequest {
        schema_version: SCHEMA_VERSION,
        enroll_token: token.into(),
        csr_pem: csr,
        hostname: "PC".into(),
        smbios_uuid: None,
        bios_serial: None,
        mac_addresses: vec![],
    };
    assert!(matches!(c.enroll(&enroll("bad", csr())).await, Err(ClientError::Unauthorized)));
    let token = AgentConfig::load(e.dir.path()).unwrap().enroll_token.unwrap();
    assert!(matches!(
        c.enroll(&enroll(&token, "garbage".into())).await,
        Err(ClientError::Rejected(400, _))
    ));
    assert!(c.enroll(&enroll(&token, csr())).await.is_ok());
}

#[tokio::test]
async fn unreachable_server_is_retry() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = tempfile::tempdir().unwrap();
    ca::init_ca(pki.path(), vec!["127.0.0.1".into()]).unwrap();
    let root = std::fs::read_to_string(pki.path().join("root.pem")).unwrap();
    let c = ServerClient::new("https://127.0.0.1:1", &root, None).unwrap();
    let r = c
        .renew(&protocol::RenewRequest { csr_pem: csr() })
        .await;
    assert!(matches!(r, Err(ClientError::Retry(None))), "{r:?}");
}
```

`crates/agent/Cargo.toml` 的 `[dev-dependencies]` 追加 `chrono.workspace = true`、`rcgen.workspace = true`、`rustls.workspace = true`、`tokio.workspace = true`。

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-agent --test e2e`
Expected: 編譯失敗（`client` 模組不存在）。

- [ ] **Step 3: 實作 `client.rs`**

```rust
//! 與伺服器通訊：只信任 root.pem、HTTP/1.1、上傳一律 gzip。

use std::io::Write;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use protocol::{
    CheckinRequest, CheckinResponse, EnrollRequest, EnrollResponse, InventoryUpload,
    RenewRequest, RenewResponse,
};
use reqwest::{StatusCode, header};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("server busy or unreachable")]
    Retry(Option<Duration>),
    #[error("unauthorized")]
    Unauthorized,
    #[error("rejected by server ({0}): {1}")]
    Rejected(u16, String),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        tracing::debug!(error = %e, "request failed");
        ClientError::Retry(None)
    }
}

pub struct ServerClient {
    http: reqwest::Client,
    base: String,
}

impl ServerClient {
    pub fn new(base: &str, root_pem: &str, identity_pem: Option<String>) -> anyhow::Result<Self> {
        let mut b = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(root_pem.as_bytes())?])
            .http1_only()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("endpoint-agent/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = identity_pem {
            b = b.identity(reqwest::Identity::from_pem(pem.as_bytes())?);
        }
        Ok(Self {
            http: b.build()?,
            base: base.trim_end_matches('/').to_string(),
        })
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response, ClientError> {
        let resp = rb.send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        Err(match status {
            StatusCode::UNAUTHORIZED => ClientError::Unauthorized,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                ClientError::Retry(retry_after)
            }
            s if s.is_client_error() => {
                ClientError::Rejected(s.as_u16(), resp.text().await.unwrap_or_default())
            }
            _ => ClientError::Retry(retry_after),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse, ClientError> {
        Ok(self.send(self.http.post(self.url("/v1/enroll")).json(req)).await?.json().await?)
    }

    pub async fn checkin(&self, req: &CheckinRequest) -> Result<CheckinResponse, ClientError> {
        Ok(self.send(self.http.post(self.url("/v1/checkin")).json(req)).await?.json().await?)
    }

    pub async fn renew(&self, req: &RenewRequest) -> Result<RenewResponse, ClientError> {
        Ok(self.send(self.http.post(self.url("/v1/renew")).json(req)).await?.json().await?)
    }

    pub async fn upload(&self, up: &InventoryUpload) -> Result<(), ClientError> {
        let json = serde_json::to_vec(up).expect("upload serializes");
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&json).expect("write to Vec");
        let body = gz.finish().expect("gzip to Vec");
        let url = self.url(&format!("/v1/inventory/{}", up.payload.section().as_str()));
        self.send(
            self.http
                .put(url)
                .header(header::CONTENT_ENCODING, "gzip")
                .header(header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await?;
        Ok(())
    }
}
```

`lib.rs` 加 `pub mod client;`

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-agent --test e2e`
Expected: 2 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(agent): ServerClient 與端對端測試框架"
```

---

### Task 7: 伺服器 boot_time 改為夾限（Review Focus 4）

計畫 1 對 `boot_time` 超出範圍回 400。端點時鐘快了一天以上時，這台電腦會永遠報到失敗；改為夾限到 `[2000-01-01, 伺服器現在時間]`。

**Files:**
- Modify: `crates/server/src/checkin.rs`
- Modify: `crates/server/tests/checkin.rs`（`absurd_boot_time_is_400` 改寫）

- [ ] **Step 1: 改寫測試**

把 `absurd_boot_time_is_400` 換成：

```rust
#[sqlx::test(migrations = false)]
async fn future_boot_time_is_clamped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let mut b = body(BTreeMap::new());
    b.boot_time = "+200000-01-01T00:00:00Z".parse().unwrap();
    let r = s
        .client(Some(&a))
        .post(s.url("/v1/checkin"))
        .json(&b)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    s.state.heartbeat.flush(&s.pool).await.unwrap();
    let boot: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT boot_time FROM devices WHERE id = $1")
            .bind(a.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(boot <= chrono::Utc::now());
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-server --test checkin future_boot_time`
Expected: FAIL（回 400）。

- [ ] **Step 3: 實作**（`checkin.rs`，取代原本的範圍檢查）

```rust
    let now = Utc::now();
    let earliest = DateTime::from_timestamp(946_684_800, 0).expect("2000-01-01");
    // 端點時鐘可能不準：夾限而不拒絕，避免該電腦永遠報到失敗
    let boot_time = req.boot_time.clamp(earliest, now);
```

並把 `HotFields { boot_time: req.boot_time, .. }` 改為 `boot_time`。

- [ ] **Step 4: 測試**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "fix(server): boot_time 超出範圍改為夾限，時鐘不準的端點仍可報到"
```

---

### Task 8: Collector trait 與 Agent 主迴圈

**Files:**
- Create: `crates/agent/src/collector.rs`、`crates/agent/src/agent.rs`；Modify: `lib.rs`
- Modify: `crates/agent/tests/e2e.rs`

**Interfaces:**
- Consumes: Task 2～6 全部
- Produces:
  - `collector::Identity { hostname: String, smbios_uuid: Option<String>, bios_serial: Option<String>, mac_addresses: Vec<String> }`
  - `collector::Heartbeat { boot_time: DateTime<Utc>, logged_on_user: Option<String>, ip_addresses: Vec<String> }`
  - `collector::Collector: Send + Sync + 'static`：`identity(&self) -> anyhow::Result<Identity>`、`heartbeat(&self) -> anyhow::Result<Heartbeat>`、`collect(&self, s: Section) -> anyhow::Result<InventoryPayload>`（皆為阻塞呼叫）
  - `agent::Cycle { Next(Duration), Stop }`（`Debug, PartialEq`）
  - `agent::Agent<C>`：`new(dir: &Path, collector: C) -> anyhow::Result<Self>`、`run_cycle(&mut self) -> Cycle`、`trigger(&mut self, s: Section)`、`state(&self) -> &AgentState`
  - `agent::plan_uploads(requested: &[Section], hashes: &BTreeMap<Section, String>, rejected: &BTreeMap<Section, String>) -> Vec<Section>`
  - `agent::run_agent<C: Collector>(agent: Agent<C>, shutdown: watch::Receiver<bool>, triggers: mpsc::UnboundedReceiver<Section>)`（async）
  - 常數 `agent::DEBOUNCE = 10s`、`agent::COLLECT_TIMEOUT = 60s`、`agent::AGENT_VERSION = env!("CARGO_PKG_VERSION")`

- [ ] **Step 1: 寫 plan_uploads 單元測試**（`agent.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_sections_rejected_with_same_hash() {
        let hashes = BTreeMap::from([
            (Section::Software, "h1".to_string()),
            (Section::Patches, "h2".to_string()),
            (Section::Services, "h3".to_string()),
        ]);
        let rejected = BTreeMap::from([
            (Section::Software, "h1".to_string()), // 同 hash → 跳過
            (Section::Patches, "old".to_string()), // hash 已變 → 重送
        ]);
        let requested = [Section::Software, Section::Patches, Section::Services, Section::Basic];
        assert_eq!(
            plan_uploads(&requested, &hashes, &rejected),
            vec![Section::Patches, Section::Services] // Basic 沒有資料 → 不送
        );
    }
}
```

- [ ] **Step 2: 追加端對端測試到 `tests/e2e.rs`**

```rust
use std::sync::{Arc, Mutex};
use std::time::Duration;

use endpoint_agent::agent::{Agent, Cycle};
use endpoint_agent::collector::{Collector, Heartbeat, Identity};
use protocol::{
    Arch, BasicInfo, HardwareInfo, InventoryPayload, PatchItem, Section, ServiceItem,
    SoftwareItem,
};

#[derive(Clone)]
struct Fake {
    software: Arc<Mutex<Vec<SoftwareItem>>>,
    fail_patches: bool,
}

fn app(name: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some("1.0".into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

impl Fake {
    fn new() -> Self {
        Fake { software: Arc::new(Mutex::new(vec![app("7-Zip")])), fail_patches: false }
    }
}

impl Collector for Fake {
    fn identity(&self) -> anyhow::Result<Identity> {
        Ok(Identity {
            hostname: "FAKE-PC".into(),
            smbios_uuid: Some("4C4C4544-0000-1111-2222-333344445555".into()),
            bios_serial: Some("SN-FAKE".into()),
            mac_addresses: vec!["00:11:22:33:44:55".into()],
        })
    }

    fn heartbeat(&self) -> anyhow::Result<Heartbeat> {
        Ok(Heartbeat {
            boot_time: chrono::Utc::now() - chrono::Duration::hours(1),
            logged_on_user: Some("CORP\\bob".into()),
            ip_addresses: vec!["10.1.1.1".into()],
        })
    }

    fn collect(&self, s: Section) -> anyhow::Result<InventoryPayload> {
        Ok(match s {
            Section::Basic => InventoryPayload::Basic(BasicInfo {
                hostname: "FAKE-PC".into(),
                domain: Some("corp.local".into()),
                is_domain_joined: true,
                os_caption: "Windows 11 Pro".into(),
                os_build: "26100".into(),
            }),
            Section::Hardware => InventoryPayload::Hardware(HardwareInfo {
                manufacturer: Some("Dell".into()),
                model: Some("OptiPlex".into()),
                cpu: Some("Intel".into()),
                ram_mb: 16_384,
                disks: vec![],
            }),
            Section::Software => InventoryPayload::Software(self.software.lock().unwrap().clone()),
            Section::Patches if self.fail_patches => anyhow::bail!("WMI timeout"),
            Section::Patches => InventoryPayload::Patches(vec![PatchItem {
                kb: "KB5000001".into(),
                installed_on: None,
            }]),
            Section::Services => InventoryPayload::Services(vec![ServiceItem {
                name: "Spooler".into(),
                display_name: None,
                start_mode: "Auto".into(),
                state: "Running".into(),
                binary_path: None,
            }]),
        })
    }
}

async fn count(e: &Env, sql: &str, id: uuid::Uuid) -> i64 {
    sqlx::query_scalar(sql).bind(id).fetch_one(&e.pool).await.unwrap()
}

fn next(c: Cycle) -> Duration {
    match c {
        Cycle::Next(d) => d,
        Cycle::Stop => panic!("agent stopped unexpectedly"),
    }
}

#[sqlx::test(migrations = false)]
async fn first_cycle_enrolls_and_uploads_all_sections(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    let wait = next(a.run_cycle().await);
    assert!(wait >= Duration::from_secs(48) && wait <= Duration::from_secs(72), "{wait:?}");

    let id = a.state().device_id.expect("enrolled");
    assert!(AgentConfig::load(e.dir.path()).unwrap().enroll_token.is_none(), "token removed");
    assert_eq!(count(&e, "SELECT count(*) FROM inventory_sections WHERE device_id = $1", id).await, 5);
    assert_eq!(count(&e, "SELECT count(*) FROM device_software WHERE device_id = $1", id).await, 1);
}

#[sqlx::test(migrations = false)]
async fn unchanged_inventory_is_not_reuploaded(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let id = a.state().device_id.unwrap();
    let stamp = || async {
        sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT max(updated_at) FROM inventory_sections WHERE device_id = $1",
        )
        .bind(id)
        .fetch_one(&e.pool)
        .await
        .unwrap()
    };
    let before = stamp().await;
    next(a.run_cycle().await);
    assert_eq!(stamp().await, before);
}

#[sqlx::test(migrations = false)]
async fn software_change_is_uploaded_and_recorded(pool: PgPool) {
    let e = env(pool, 1).await;
    let fake = Fake::new();
    let mut a = Agent::new(e.dir.path(), fake.clone()).unwrap();
    next(a.run_cycle().await);
    fake.software.lock().unwrap().push(app("Unapproved Tool"));
    a.trigger(Section::Software);
    next(a.run_cycle().await);
    let id = a.state().device_id.unwrap();
    assert_eq!(
        count(&e, "SELECT count(*) FROM inventory_changes WHERE device_id = $1 AND change = 'added'", id).await,
        1
    );
}

#[sqlx::test(migrations = false)]
async fn collector_error_reaches_server(pool: PgPool) {
    let e = env(pool, 1).await;
    let fake = Fake { fail_patches: true, ..Fake::new() };
    let mut a = Agent::new(e.dir.path(), fake).unwrap();
    next(a.run_cycle().await);
    e.state.heartbeat.flush(&e.pool).await.unwrap();
    let id = a.state().device_id.unwrap();
    let errors: String = sqlx::query_scalar("SELECT section_errors::text FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert!(errors.contains("WMI timeout"), "{errors}");
    assert_eq!(count(&e, "SELECT count(*) FROM inventory_sections WHERE device_id = $1", id).await, 4);
}

#[sqlx::test(migrations = false)]
async fn revoked_certificate_stops_agent(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    sqlx::query("UPDATE device_certs SET revoked_at = now()")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(a.run_cycle().await, Cycle::Stop);
}

#[sqlx::test(migrations = false)]
async fn unreachable_server_backs_off(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut cfg = AgentConfig::load(e.dir.path()).unwrap();
    cfg.server_url = "https://127.0.0.1:1".into();
    cfg.save(e.dir.path()).unwrap();
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    let first = next(a.run_cycle().await);
    let second = next(a.run_cycle().await);
    assert!(first >= Duration::from_secs(48), "{first:?}");
    assert!(second > first, "{first:?} then {second:?}");
    assert!(a.state().device_id.is_none());
}

#[sqlx::test(migrations = false)]
async fn expiring_certificate_is_renewed(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let old_chain = a.state().chain_pem.clone();
    sqlx::query("UPDATE device_certs SET not_after = now() + interval '5 days'")
        .execute(&e.pool)
        .await
        .unwrap();
    next(a.run_cycle().await);
    assert_ne!(a.state().chain_pem, old_chain);
    next(a.run_cycle().await); // 新憑證可用
}

#[sqlx::test(migrations = false)]
async fn restart_keeps_identity(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let id = a.state().device_id;
    drop(a);
    let mut b = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(b.run_cycle().await);
    assert_eq!(b.state().device_id, id);
    let devices: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&e.pool)
        .await
        .unwrap();
    assert_eq!(devices, 1);
}

#[test]
fn missing_config_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let err = Agent::new(dir.path(), Fake::new()).err().expect("must fail");
    assert!(format!("{err:#}").contains("config.json"), "{err:#}");
}
```

- [ ] **Step 3: 確認失敗**

Run: `cargo test -p endpoint-agent`
Expected: 編譯失敗（`collector`、`agent` 模組不存在）。

- [ ] **Step 4: 實作 `collector.rs`**

```rust
//! 收集來源的抽象：Windows 上是 WMI + 登錄檔，測試用假資料。所有方法都是阻塞呼叫。

use chrono::{DateTime, Utc};
use protocol::{InventoryPayload, Section};

#[derive(Debug, Clone)]
pub struct Identity {
    pub hostname: String,
    pub smbios_uuid: Option<String>,
    pub bios_serial: Option<String>,
    pub mac_addresses: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Heartbeat {
    pub boot_time: DateTime<Utc>,
    pub logged_on_user: Option<String>,
    pub ip_addresses: Vec<String>,
}

pub trait Collector: Send + Sync + 'static {
    fn identity(&self) -> anyhow::Result<Identity>;
    fn heartbeat(&self) -> anyhow::Result<Heartbeat>;
    fn collect(&self, section: Section) -> anyhow::Result<InventoryPayload>;
}
```

- [ ] **Step 5: 實作 `agent.rs`**（測試模組之上）

```rust
//! Agent 主迴圈：註冊 → 收集到期區段 → 報到 → 上傳伺服器要求的區段 → 視需要續期。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use chrono::Utc;
use protocol::{
    CheckinRequest, CollectionIntervals, EnrollRequest, InventoryPayload, InventoryUpload,
    RenewRequest, SCHEMA_VERSION, Section,
};
use tokio::sync::{mpsc, watch};

use crate::backoff::{Backoff, jitter, with_jitter};
use crate::client::{ClientError, ServerClient};
use crate::collector::{Collector, Heartbeat};
use crate::config::AgentConfig;
use crate::sanitize::{clean, sanitize};
use crate::schedule::{DEFAULT_INTERVALS, Schedule};
use crate::state::AgentState;

pub const DEBOUNCE: Duration = Duration::from_secs(10);
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(60);
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, PartialEq)]
pub enum Cycle {
    Next(Duration),
    Stop,
}

pub fn plan_uploads(
    requested: &[Section],
    hashes: &BTreeMap<Section, String>,
    rejected: &BTreeMap<Section, String>,
) -> Vec<Section> {
    requested
        .iter()
        .copied()
        .filter(|s| hashes.contains_key(s) && rejected.get(s) != hashes.get(s))
        .collect()
}

pub struct Agent<C: Collector> {
    dir: PathBuf,
    config: AgentConfig,
    root_pem: String,
    state: AgentState,
    collector: Arc<C>,
    schedule: Schedule,
    cache: BTreeMap<Section, InventoryPayload>,
    errors: BTreeMap<Section, String>,
    intervals: CollectionIntervals,
    backoff: Backoff,
}

fn new_csr() -> anyhow::Result<(String, String)> {
    let key = rcgen::KeyPair::generate()?;
    let csr = rcgen::CertificateParams::default()
        .serialize_request(&key)?
        .pem()?;
    Ok((csr, key.serialize_pem()))
}

impl<C: Collector> Agent<C> {
    pub fn new(dir: &Path, collector: C) -> anyhow::Result<Self> {
        let config = AgentConfig::load(dir)?;
        let root_path = dir.join("root.pem");
        let root_pem = std::fs::read_to_string(&root_path)
            .with_context(|| format!("reading {}", root_path.display()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            config,
            root_pem,
            state: AgentState::load(dir)?,
            collector: Arc::new(collector),
            schedule: Schedule::default(),
            cache: BTreeMap::new(),
            errors: BTreeMap::new(),
            intervals: DEFAULT_INTERVALS,
            backoff: Backoff::default(),
        })
    }

    pub fn state(&self) -> &AgentState {
        &self.state
    }

    pub fn trigger(&mut self, s: Section) {
        self.schedule.trigger(s);
    }

    fn retry_later(&mut self) -> Cycle {
        Cycle::Next(self.backoff.next_delay(jitter()))
    }

    /// 在 blocking 執行緒上呼叫 collector，並限制時間。
    async fn blocking<T: Send + 'static>(
        &self,
        f: impl FnOnce(&C) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let c = self.collector.clone();
        match tokio::time::timeout(COLLECT_TIMEOUT, tokio::task::spawn_blocking(move || f(&c))).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => Err(anyhow::anyhow!("collector panicked: {e}")),
            Err(_) => Err(anyhow::anyhow!("timed out after {}s", COLLECT_TIMEOUT.as_secs())),
        }
    }

    async fn enroll(&mut self) -> anyhow::Result<()> {
        let token = self
            .config
            .enroll_token
            .clone()
            .context("not enrolled and no enroll token in config.json (reinstall required)")?;
        let id = self.blocking(|c| c.identity()).await?;
        let (csr_pem, key_pem) = new_csr()?;
        let client = ServerClient::new(&self.config.server_url, &self.root_pem, None)?;
        let resp = client
            .enroll(&EnrollRequest {
                schema_version: SCHEMA_VERSION,
                enroll_token: token,
                csr_pem,
                hostname: clean(&id.hostname),
                smbios_uuid: id.smbios_uuid.as_deref().map(clean),
                bios_serial: id.bios_serial.as_deref().map(clean),
                mac_addresses: id.mac_addresses.iter().map(|m| clean(m)).collect(),
            })
            .await?;
        self.state.device_id = Some(resp.device_id);
        self.state.chain_pem = Some(resp.certificate_chain_pem);
        self.state.key_pem = Some(key_pem);
        self.state.save(&self.dir)?;
        self.config.enroll_token = None;
        self.config.save(&self.dir)?;
        tracing::info!(device_id = %resp.device_id, "enrolled");
        Ok(())
    }

    async fn collect_due(&mut self) {
        let now = Instant::now();
        for s in self.schedule.due(now, &self.intervals) {
            match self.blocking(move |c| c.collect(s)).await {
                Ok(mut p) => {
                    sanitize(&mut p);
                    let still_rejected = self.state.rejected.get(&s) == Some(&p.canonical_hash());
                    if !still_rejected {
                        self.errors.remove(&s);
                    }
                    self.cache.insert(s, p);
                }
                Err(e) => {
                    tracing::warn!(section = s.as_str(), error = %e, "collection failed");
                    self.errors.insert(s, format!("{e:#}"));
                }
            }
            self.schedule.mark_collected(s, now);
        }
    }

    async fn renew(&mut self, client: &ServerClient) -> anyhow::Result<()> {
        let (csr_pem, key_pem) = new_csr()?;
        let r = client.renew(&RenewRequest { csr_pem }).await?;
        self.state.chain_pem = Some(r.certificate_chain_pem);
        self.state.key_pem = Some(key_pem);
        self.state.save(&self.dir)?;
        tracing::info!("certificate renewed");
        Ok(())
    }

    pub async fn run_cycle(&mut self) -> Cycle {
        if !self.state.is_enrolled() {
            if let Err(e) = self.enroll().await {
                tracing::warn!(error = %format!("{e:#}"), "enrollment failed");
                return self.retry_later();
            }
        }

        self.collect_due().await;
        let hb = self.blocking(|c| c.heartbeat()).await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "heartbeat info unavailable");
            Heartbeat { boot_time: Utc::now(), logged_on_user: None, ip_addresses: vec![] }
        });
        let client = match ServerClient::new(
            &self.config.server_url,
            &self.root_pem,
            self.state.identity_pem(),
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "cannot build client (bad certificate or root.pem?)");
                return self.retry_later();
            }
        };

        let hashes: BTreeMap<Section, String> =
            self.cache.iter().map(|(s, p)| (*s, p.canonical_hash())).collect();
        let req = CheckinRequest {
            schema_version: SCHEMA_VERSION,
            agent_version: AGENT_VERSION.into(),
            boot_time: hb.boot_time,
            logged_on_user: hb.logged_on_user.as_deref().map(clean),
            ip_addresses: hb.ip_addresses.iter().map(|i| clean(i)).collect(),
            section_hashes: hashes.clone(),
            section_errors: self.errors.iter().map(|(s, e)| (*s, clean(e))).collect(),
        };
        let resp = match client.checkin(&req).await {
            Ok(r) => r,
            Err(ClientError::Unauthorized) => {
                tracing::error!("certificate rejected by server; agent stops (reinstall required)");
                return Cycle::Stop;
            }
            Err(ClientError::Retry(Some(after))) => return Cycle::Next(after),
            Err(e) => {
                tracing::warn!(error = %e, "checkin failed");
                return self.retry_later();
            }
        };
        self.backoff.reset();
        self.intervals = resp.collection_intervals.clone();

        for s in plan_uploads(&resp.request_sections, &hashes, &self.state.rejected) {
            let up = InventoryUpload { schema_version: SCHEMA_VERSION, payload: self.cache[&s].clone() };
            match client.upload(&up).await {
                Ok(()) => {
                    self.state.rejected.remove(&s);
                }
                Err(ClientError::Rejected(code, msg)) => {
                    tracing::warn!(section = s.as_str(), code, %msg, "section rejected by server");
                    self.state.rejected.insert(s, hashes[&s].clone());
                    self.errors.insert(s, format!("rejected by server ({code}): {msg}"));
                }
                Err(ClientError::Unauthorized) => return Cycle::Stop,
                Err(ClientError::Retry(_)) => break,
            }
        }

        if resp.renew_certificate {
            if let Err(e) = self.renew(&client).await {
                tracing::warn!(error = %format!("{e:#}"), "certificate renewal failed");
            }
        }
        if let Err(e) = self.state.save(&self.dir) {
            tracing::error!(error = %e, "saving state failed");
        }
        Cycle::Next(with_jitter(
            Duration::from_secs(resp.next_checkin_seconds.into()),
            jitter(),
        ))
    }
}

/// 反覆執行 run_cycle，直到收到停止訊號或伺服器拒絕憑證。
/// 軟體變更觸發時先等 DEBOUNCE，合併短時間內的多次變更。
pub async fn run_agent<C: Collector>(
    mut agent: Agent<C>,
    mut shutdown: watch::Receiver<bool>,
    mut triggers: mpsc::UnboundedReceiver<Section>,
) {
    loop {
        let wait = match agent.run_cycle().await {
            Cycle::Stop => return,
            Cycle::Next(d) => d,
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => return,
            Some(s) = triggers.recv() => {
                agent.trigger(s);
                tokio::select! {
                    _ = tokio::time::sleep(DEBOUNCE) => {}
                    _ = shutdown.changed() => return,
                }
                while let Ok(s) = triggers.try_recv() {
                    agent.trigger(s);
                }
            }
        }
    }
}
```

`lib.rs` 加 `pub mod agent; pub mod collector;`

> `unreachable_server_backs_off` 的 `second > first` 取決於隨機延遲：第一次 60s×(0.8～1.2)＝48～72，第二次 120s×(0.8～1.2)＝96～144，永遠成立。

- [ ] **Step 6: 測試**

Run: `cargo test -p endpoint-agent`
Expected: lib 14 PASS；e2e 11 PASS（2 + 9）。

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat(agent): Agent 主迴圈、差異上傳、被拒區段不重送、憑證續期"
```

---

### Task 9: Windows 收集器（WMI＋登錄檔）

**Files:**
- Create: `crates/agent/src/windows/mod.rs`、`collect.rs`、`registry.rs`
- Modify: `crates/agent/src/lib.rs`（`#[cfg(windows)] pub mod windows;`）
- Modify: `crates/agent/tests/windows.rs`

**Interfaces:**
- Consumes: `collector::*`、`software::{UninstallEntry, to_items, is_user_sid}`、`serde_util::u64_any`
- Produces: `windows::collect::WindowsCollector`（unit struct，實作 `Collector`）；`windows::registry::read_all_software() -> Vec<SoftwareItem>`

- [ ] **Step 1: 寫冒煙測試**（附加到 `tests/windows.rs`）

```rust
use endpoint_agent::collector::Collector;
use endpoint_agent::sanitize::sanitize;
use endpoint_agent::windows::collect::WindowsCollector;
use protocol::{InventoryPayload, Section};

#[test]
fn collector_reports_this_machine() {
    let c = WindowsCollector;
    let id = c.identity().unwrap();
    assert!(!id.hostname.is_empty());

    let hb = c.heartbeat().unwrap();
    assert!(hb.boot_time < chrono::Utc::now());

    for s in Section::ALL {
        let mut p = c.collect(s).unwrap_or_else(|e| panic!("{s:?}: {e:#}"));
        sanitize(&mut p);
        assert_eq!(p.validate(), Ok(()), "{s:?}");
        match p {
            InventoryPayload::Basic(b) => assert!(!b.os_caption.is_empty()),
            InventoryPayload::Hardware(h) => assert!(h.ram_mb > 0),
            InventoryPayload::Software(v) => assert!(!v.is_empty()),
            InventoryPayload::Services(v) => assert!(v.iter().any(|s| s.name.eq_ignore_ascii_case("EventLog"))),
            InventoryPayload::Patches(_) => {}
        }
    }
}
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-agent --test windows`
Expected: 編譯失敗（`windows` 模組不存在）。

- [ ] **Step 3: 實作 `windows/registry.rs`**

```rust
//! 讀取 Uninstall 機碼：HKLM 64／32 位元與已載入的使用者設定檔（HKU）。

use protocol::{Arch, SoftwareItem};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY};

use crate::software::{UninstallEntry, is_user_sid, to_items};

pub const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

fn read_entries(root: &RegKey, path: &str, flags: u32) -> Vec<UninstallEntry> {
    let Ok(key) = root.open_subkey_with_flags(path, KEY_READ | flags) else {
        return vec![];
    };
    key.enum_keys()
        .filter_map(Result::ok)
        .filter_map(|name| key.open_subkey_with_flags(&name, KEY_READ | flags).ok())
        .map(|k| UninstallEntry {
            display_name: k.get_value("DisplayName").ok(),
            display_version: k.get_value("DisplayVersion").ok(),
            publisher: k.get_value("Publisher").ok(),
            install_date: k.get_value("InstallDate").ok(),
            system_component: k.get_value::<u32, _>("SystemComponent").ok(),
            parent_key_name: k.get_value("ParentKeyName").ok(),
            release_type: k.get_value("ReleaseType").ok(),
        })
        .collect()
}

pub fn read_all_software() -> Vec<SoftwareItem> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut items = to_items(&read_entries(&hklm, UNINSTALL, KEY_WOW64_64KEY), Arch::X64);
    items.extend(to_items(&read_entries(&hklm, UNINSTALL, KEY_WOW64_32KEY), Arch::X86));
    let hku = RegKey::predef(HKEY_USERS);
    for sid in hku.enum_keys().filter_map(Result::ok).filter(|s| is_user_sid(s)) {
        let path = format!(r"{sid}\{UNINSTALL}");
        items.extend(to_items(&read_entries(&hku, &path, 0), Arch::User));
    }
    items
}
```

- [ ] **Step 4: 實作 `windows/collect.rs`**

```rust
//! WMI 收集。每次呼叫建立新的 WMIConnection（在 blocking 執行緒上初始化 COM）。

use anyhow::Context;
use chrono::Utc;
use protocol::{
    BasicInfo, Disk, HardwareInfo, InventoryPayload, PatchItem, Section, ServiceItem,
};
use serde::Deserialize;
use wmi::{WMIConnection, WMIDateTime};

use crate::collector::{Collector, Heartbeat, Identity};
use crate::serde_util::u64_any;

#[derive(Deserialize)]
#[serde(rename = "Win32_ComputerSystem", rename_all = "PascalCase")]
struct ComputerSystem {
    name: Option<String>,
    domain: Option<String>,
    part_of_domain: Option<bool>,
    user_name: Option<String>,
    manufacturer: Option<String>,
    model: Option<String>,
    #[serde(default, deserialize_with = "u64_any")]
    total_physical_memory: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_OperatingSystem", rename_all = "PascalCase")]
struct OperatingSystem {
    caption: Option<String>,
    build_number: Option<String>,
    last_boot_up_time: Option<WMIDateTime>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_ComputerSystemProduct")]
struct Product {
    #[serde(rename = "UUID")]
    uuid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_BIOS", rename_all = "PascalCase")]
struct Bios {
    serial_number: Option<String>,
}

#[derive(Deserialize)]
struct Nic {
    #[serde(rename = "IPAddress")]
    ip_address: Option<Vec<String>>,
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_Processor", rename_all = "PascalCase")]
struct Processor {
    name: Option<String>,
}

#[derive(Deserialize)]
struct LogicalDisk {
    #[serde(rename = "DeviceID")]
    device_id: String,
    #[serde(rename = "Size", default, deserialize_with = "u64_any")]
    size: Option<u64>,
    #[serde(rename = "FreeSpace", default, deserialize_with = "u64_any")]
    free_space: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_QuickFixEngineering", rename_all = "PascalCase")]
struct QuickFix {
    #[serde(rename = "HotFixID")]
    hot_fix_id: Option<String>,
    installed_on: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "Win32_Service", rename_all = "PascalCase")]
struct Service {
    name: Option<String>,
    display_name: Option<String>,
    start_mode: Option<String>,
    state: Option<String>,
    path_name: Option<String>,
}

const NICS: &str =
    "SELECT IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE";
const FIXED_DISKS: &str = "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3";

fn wmi() -> anyhow::Result<WMIConnection> {
    WMIConnection::new().context("connecting to WMI")
}

fn computer_system(con: &WMIConnection) -> anyhow::Result<ComputerSystem> {
    con.query::<ComputerSystem>()?
        .into_iter()
        .next()
        .context("Win32_ComputerSystem returned nothing")
}

fn hostname(cs: &ComputerSystem) -> String {
    cs.name
        .clone()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_default()
}

pub struct WindowsCollector;

impl Collector for WindowsCollector {
    fn identity(&self) -> anyhow::Result<Identity> {
        let con = wmi()?;
        let cs = computer_system(&con)?;
        let product: Vec<Product> = con.query()?;
        let bios: Vec<Bios> = con.query()?;
        let nics: Vec<Nic> = con.raw_query(NICS)?;
        Ok(Identity {
            hostname: hostname(&cs),
            smbios_uuid: product.into_iter().next().and_then(|p| p.uuid),
            bios_serial: bios.into_iter().next().and_then(|b| b.serial_number),
            mac_addresses: nics.into_iter().filter_map(|n| n.mac_address).collect(),
        })
    }

    fn heartbeat(&self) -> anyhow::Result<Heartbeat> {
        let con = wmi()?;
        let cs = computer_system(&con)?;
        let os: Vec<OperatingSystem> = con.query()?;
        let nics: Vec<Nic> = con.raw_query(NICS)?;
        Ok(Heartbeat {
            boot_time: os
                .into_iter()
                .next()
                .and_then(|o| o.last_boot_up_time)
                .map(|t| t.0.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            logged_on_user: cs.user_name,
            ip_addresses: nics.into_iter().flat_map(|n| n.ip_address.unwrap_or_default()).collect(),
        })
    }

    fn collect(&self, section: Section) -> anyhow::Result<InventoryPayload> {
        if section == Section::Software {
            return Ok(InventoryPayload::Software(super::registry::read_all_software()));
        }
        let con = wmi()?;
        Ok(match section {
            Section::Basic => {
                let cs = computer_system(&con)?;
                let os = con.query::<OperatingSystem>()?.into_iter().next();
                InventoryPayload::Basic(BasicInfo {
                    hostname: hostname(&cs),
                    domain: cs.domain.clone(),
                    is_domain_joined: cs.part_of_domain.unwrap_or(false),
                    os_caption: os.as_ref().and_then(|o| o.caption.clone()).unwrap_or_default(),
                    os_build: os.and_then(|o| o.build_number).unwrap_or_default(),
                })
            }
            Section::Hardware => {
                let cs = computer_system(&con)?;
                let cpu: Vec<Processor> = con.query()?;
                let disks: Vec<LogicalDisk> = con.raw_query(FIXED_DISKS)?;
                InventoryPayload::Hardware(HardwareInfo {
                    manufacturer: cs.manufacturer,
                    model: cs.model,
                    cpu: cpu.into_iter().next().and_then(|p| p.name),
                    ram_mb: cs.total_physical_memory.unwrap_or(0) / (1024 * 1024),
                    disks: disks
                        .into_iter()
                        .map(|d| Disk {
                            name: d.device_id,
                            size_bytes: d.size.unwrap_or(0),
                            free_bytes: d.free_space.unwrap_or(0),
                        })
                        .collect(),
                })
            }
            Section::Patches => {
                let fixes: Vec<QuickFix> = con.query()?;
                InventoryPayload::Patches(
                    fixes
                        .into_iter()
                        .filter_map(|f| {
                            Some(PatchItem { kb: f.hot_fix_id?, installed_on: f.installed_on })
                        })
                        .collect(),
                )
            }
            Section::Services => {
                let services: Vec<Service> = con.query()?;
                InventoryPayload::Services(
                    services
                        .into_iter()
                        .filter_map(|s| {
                            Some(ServiceItem {
                                name: s.name?,
                                display_name: s.display_name,
                                start_mode: s.start_mode.unwrap_or_default(),
                                state: s.state.unwrap_or_default(),
                                binary_path: s.path_name,
                            })
                        })
                        .collect(),
                )
            }
            Section::Software => unreachable!("handled above"),
        })
    }
}
```

`windows/mod.rs`（本 task 先只有）：

```rust
//! Windows 專屬：收集、登錄檔監聽、事件檢視器、服務。

pub mod collect;
pub mod registry;
```

> WMI 的欄位名稱或型別若與上方不符（例如 `raw_query` 需要 struct 名稱），以 context7 `/websites/rs_crate_wmi` 文件與實機錯誤訊息為準調整，保持 `WindowsCollector` 介面不變。

- [ ] **Step 5: 測試**

Run: `cargo test -p endpoint-agent --test windows`
Expected: 2 PASS。另外 `cargo build -p endpoint-agent --target x86_64-unknown-linux-gnu` 不需要（CI Linux job 會證明非 Windows 可編譯）。

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(agent): Windows 收集器（WMI、Uninstall 機碼）"
```

---

### Task 10: 登錄檔監聽、事件檢視器、服務與執行檔

**Files:**
- Create: `crates/agent/src/windows/regwatch.rs`、`eventlog.rs`、`service.rs`
- Modify: `crates/agent/src/windows/mod.rs`、`crates/agent/src/main.rs`
- Modify: `crates/agent/tests/windows.rs`

**Interfaces:**
- Produces:
  - `windows::regwatch::watch(root: HKEY, path: &str, wow64: u32, on_change: impl Fn() + Send + 'static) -> std::io::Result<()>`（背景執行緒，同步阻塞等待變更）
  - `windows::regwatch::watch_software(tx: mpsc::UnboundedSender<Section>)`
  - `windows::eventlog::EventLog`：`open() -> io::Result<Self>`、`report(&self, ty: u16, msg: &str)`，實作 `tracing_subscriber::fmt::MakeWriter`
  - `windows::agent_dir() -> PathBuf`、`windows::run(dir, shutdown) -> anyhow::Result<()>`、`windows::run_console() -> anyhow::Result<()>`
  - `windows::service::run() -> anyhow::Result<()>`；`windows::service::SERVICE_NAME = "EndpointManagerAgent"`
  - 執行檔：`endpoint-agent run`（主控台，不改 ACL）、`endpoint-agent service`（由 SCM 啟動）

- [ ] **Step 1: 寫冒煙測試**（附加到 `tests/windows.rs`）

```rust
use std::sync::mpsc;
use std::time::Duration;

use endpoint_agent::windows::{eventlog::EventLog, regwatch};
use windows_sys::Win32::System::Registry::HKEY_CURRENT_USER;
use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER as WINREG_HKCU;

#[test]
fn registry_watch_fires_on_change() {
    let path = r"Software\EndpointManagerTest";
    let (key, _) = RegKey::predef(WINREG_HKCU).create_subkey(path).unwrap();
    let (tx, rx) = mpsc::channel();
    regwatch::watch(HKEY_CURRENT_USER, path, 0, move || {
        let _ = tx.send(());
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    key.set_value("probe", &"1").unwrap();
    assert!(rx.recv_timeout(Duration::from_secs(5)).is_ok(), "no notification");
    let _ = RegKey::predef(WINREG_HKCU).delete_subkey_all(path);
}

#[test]
fn eventlog_report_works() {
    let log = EventLog::open().unwrap();
    log.report(windows_sys::Win32::System::EventLog::EVENTLOG_INFORMATION_TYPE, "endpoint-agent test event");
}
```

`crates/agent/Cargo.toml` 追加：

```toml
[target.'cfg(windows)'.dev-dependencies]
winreg = "0.56"
windows-sys = { version = "0.61", features = ["Win32_System_Registry", "Win32_System_EventLog"] }
```

- [ ] **Step 2: 確認失敗**

Run: `cargo test -p endpoint-agent --test windows`
Expected: 編譯失敗。

- [ ] **Step 3: 實作 `regwatch.rs`**

```rust
//! RegNotifyChangeKeyValue：機碼（含子機碼）有變更時呼叫 on_change。

use protocol::Section;
use tokio::sync::mpsc;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_NOTIFY, KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_NAME, RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW,
};

use super::registry::UNINSTALL;

pub fn watch(
    root: HKEY,
    path: &str,
    wow64: u32,
    on_change: impl Fn() + Send + 'static,
) -> std::io::Result<()> {
    let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut key: HKEY = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(root, wide.as_ptr(), 0, KEY_NOTIFY | wow64, &mut key) };
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    let key = key as usize; // HKEY 是裸指標，轉成 usize 才能移到執行緒
    std::thread::spawn(move || loop {
        let rc = unsafe {
            RegNotifyChangeKeyValue(
                key as HKEY,
                1,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            unsafe { RegCloseKey(key as HKEY) };
            return;
        }
        on_change();
    });
    Ok(())
}

/// 監聽 HKLM 64／32 位元 Uninstall 機碼；HKU 變動太頻繁，只靠每小時補收。
pub fn watch_software(tx: mpsc::UnboundedSender<Section>) {
    for wow in [KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        let tx = tx.clone();
        if let Err(e) = watch(HKEY_LOCAL_MACHINE, UNINSTALL, wow, move || {
            let _ = tx.send(Section::Software);
        }) {
            tracing::warn!(error = %e, "cannot watch Uninstall key");
        }
    }
}
```

- [ ] **Step 4: 實作 `eventlog.rs`**

```rust
//! 把 tracing 輸出寫到「事件檢視器 → Windows 記錄 → 應用程式」。
//! 事件來源由 MSI 註冊（計畫 4）；未註冊時事件仍會寫入，只是檢視器顯示「找不到描述」。

use std::io::Write;

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW,
    ReportEventW,
};

pub const SOURCE: &str = "EndpointManagerAgent";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

pub struct EventLog(usize);

impl EventLog {
    pub fn open() -> std::io::Result<Self> {
        let src = wide(SOURCE);
        let h = unsafe { RegisterEventSourceW(std::ptr::null(), src.as_ptr()) };
        if h.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(h as usize))
        }
    }

    pub fn report(&self, ty: u16, msg: &str) {
        let w = wide(msg);
        let strings = [w.as_ptr()];
        unsafe {
            ReportEventW(
                self.0 as _,
                ty,
                0,
                1,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            );
        }
    }
}

pub struct EventLine<'a> {
    log: &'a EventLog,
    ty: u16,
    buf: Vec<u8>,
}

impl Write for EventLine<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for EventLine<'_> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.log.report(self.ty, String::from_utf8_lossy(&self.buf).trim_end());
        }
    }
}

impl<'a> MakeWriter<'a> for EventLog {
    type Writer = EventLine<'a>;

    fn make_writer(&'a self) -> EventLine<'a> {
        EventLine { log: self, ty: EVENTLOG_INFORMATION_TYPE, buf: Vec::new() }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> EventLine<'a> {
        let ty = match *meta.level() {
            Level::ERROR => EVENTLOG_ERROR_TYPE,
            Level::WARN => EVENTLOG_WARNING_TYPE,
            _ => EVENTLOG_INFORMATION_TYPE,
        };
        EventLine { log: self, ty, buf: Vec::new() }
    }
}
```

- [ ] **Step 5: 實作 `windows/mod.rs` 與 `service.rs`**

`windows/mod.rs`：

```rust
//! Windows 專屬：收集、登錄檔監聽、事件檢視器、服務。

pub mod collect;
pub mod eventlog;
pub mod registry;
pub mod regwatch;
pub mod service;

use std::path::{Path, PathBuf};

use tokio::sync::{mpsc, watch};
use windows_sys::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetCurrentProcess, SetPriorityClass,
};

use crate::agent::{Agent, run_agent};

pub fn agent_dir() -> PathBuf {
    std::env::var_os("EM_AGENT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData\EndpointManager"))
}

/// 以低優先權執行，避免完整盤點影響使用者。
fn lower_priority() {
    unsafe { SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS) };
}

pub async fn run(dir: &Path, shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
    lower_priority();
    let agent = Agent::new(dir, collect::WindowsCollector)?;
    let (tx, rx) = mpsc::unbounded_channel();
    regwatch::watch_software(tx);
    run_agent(agent, shutdown, rx).await;
    Ok(())
}

/// 開發／除錯用：在主控台執行，Ctrl+C 結束；不變更目錄 ACL。
pub fn run_console() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
    ).init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (tx, rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(true);
        });
        run(&agent_dir(), rx).await
    })
}
```

`service.rs`：

```rust
//! 由服務控制管理員（SCM）啟動：`endpoint-agent.exe service`。

use std::ffi::OsString;
use std::time::Duration;

use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
    ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::eventlog::EventLog;

pub const SERVICE_NAME: &str = "EndpointManagerAgent";

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "service failed");
    }
}

fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(70),
        process_id: None,
    }
}

fn run_service() -> anyhow::Result<()> {
    if let Ok(log) = EventLog::open() {
        tracing_subscriber::fmt()
            .with_writer(log)
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    let (tx, rx) = watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running))?;

    let dir = super::agent_dir();
    let result = crate::state::secure_dir(&dir).and_then(|()| {
        tokio::runtime::Runtime::new()?.block_on(super::run(&dir, rx))
    });
    if let Err(e) = &result {
        tracing::error!(error = %format!("{e:#}"), "agent stopped with error");
    }
    handle.set_service_status(status(ServiceState::Stopped))?;
    result
}
```

- [ ] **Step 6: 實作 `main.rs`**

```rust
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    match std::env::args().nth(1).as_deref() {
        Some("service") => endpoint_agent::windows::service::run(),
        Some("run") => endpoint_agent::windows::run_console(),
        _ => anyhow::bail!("usage: endpoint-agent run | service"),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("endpoint-agent only runs on Windows");
    std::process::exit(1);
}
```

- [ ] **Step 7: 測試與檢查**

Run: `cargo test -p endpoint-agent --test windows && cargo clippy --workspace --all-targets -- -D warnings`
Expected: windows 4 PASS；clippy 無警告。

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat(agent): 登錄檔監聽、事件檢視器、Windows Service 與執行檔"
```

---

### Task 11: 實機驗證、README、PR

- [ ] **Step 1: 主控台模式實機驗證**（一般使用者即可）

```bash
export DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/endpoint_manager
T=$CLAUDE_JOB_DIR/tmp; rm -rf $T/pki $T/agent; mkdir -p $T/agent
cargo run -p endpoint-server -- ca-init $T/pki localhost
TOKEN=$(cargo run -q -p endpoint-server -- token-create dev 5 | head -1 | sed 's/.*：//')
cp $T/pki/root.pem $T/agent/
printf '{"server_url":"https://localhost:18443","enroll_token":"%s"}' "$TOKEN" > $T/agent/config.json
EM_CA_DIR=$T/pki EM_AGENT_LISTEN=127.0.0.1:18443 cargo run -p endpoint-server -- serve &   # 背景
EM_AGENT_DIR=$T/agent timeout 90 cargo run -p endpoint-agent -- run
```

Expected: Agent log 出現 `enrolled`；資料庫 `SELECT hostname, os_caption FROM devices` 有這台電腦；`device_software` 筆數與「程式和功能」大致相符；`config.json` 的 `enroll_token` 變成 `null`。

- [ ] **Step 2: 服務模式驗證**（需要系統管理員權限；執行者沒有時，請使用者在 `!` 提示中執行，並記錄 ruling）

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\EndpointManager
Copy-Item $T\agent\root.pem C:\ProgramData\EndpointManager\
# 用新的金鑰寫 config.json 後：
sc.exe create EndpointManagerAgent binPath= "D:\VSCode\endpoint-manager\target\debug\endpoint-agent.exe service" start= demand
sc.exe start EndpointManagerAgent
Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -eq EndpointManagerAgent
sc.exe stop EndpointManagerAgent
sc.exe delete EndpointManagerAgent
```

Expected: 服務啟動後事件檢視器出現 `enrolled`；`icacls C:\ProgramData\EndpointManager` 只剩 SYSTEM 與 Administrators；`sc stop` 在 70 秒內完成。

- [ ] **Step 3: README 加 Agent 章節**

````markdown
## Agent（Windows）

```powershell
cargo build -p endpoint-agent --release
```

Agent 目錄（預設 `C:\ProgramData\EndpointManager`，可用 `EM_AGENT_DIR` 覆寫）需要：

- `root.pem`：伺服器 `ca-init` 產生的根 CA 憑證
- `config.json`：`{"server_url": "https://<伺服器>:8443", "enroll_token": "<token-create 產生的金鑰>"}`

執行方式：

- `endpoint-agent run`：主控台模式（開發／除錯），Ctrl+C 結束
- `endpoint-agent service`：由 Windows 服務啟動（正式安裝由 MSI 設定，見計畫 4）
````

- [ ] **Step 4: 全部檢查**

Run: `cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`
Expected: 全部通過。

- [ ] **Step 5: 最終審查、PR、合併**（依 executing-plans 與使用者的 PR 流程）

```bash
git push -u origin feat/plan2-windows-agent
gh pr create --base main --title "計畫 2：Windows Agent" --body-file <PR 說明>
gh pr checks --watch
gh pr merge --squash --delete-branch
git switch main && git pull --prune
```
