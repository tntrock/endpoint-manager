# 計畫 8：組態資料收集（協定、Agent、伺服器儲存）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Agent 收集 `security` 與 `registry` 兩個新區段並上傳，伺服器保存、記錄變更歷史，且新舊版本互通。

**Architecture:**
- `protocol` crate 新增型別與「登錄檔路徑守衛」`regpath`（Agent 與伺服器共用，確保兩端判斷一致）。
- Agent 的收集器在 `windows/security.rs`（防火牆、BitLocker、Defender、密碼原則、本機管理員）與 `windows/registry.rs`（讀取指定值）。主迴圈要等伺服器在報到回應中表明支援，才收集與回報新區段。
- 伺服器在 `inventory.rs` 讀寫新資料表，在 `diff.rs` 產生變更歷史。報到回應帶查詢清單（本計畫先回空清單；計畫 9 由規則填入）。

**Tech Stack:** Rust、serde、sha2、winreg、wmi、windows-sys（新增 `Win32_NetworkManagement_NetManagement` feature）、sqlx。

**Spec:** `docs/superpowers/specs/2026-09-29-config-baseline-design.md`（§2、§4.1、§4.2）

## Global Constraints

- 使用者可見文字與註解用繁體中文。
- 相容性：
  - 舊版伺服器的 `CheckinRequest` 反序列化**不認得新的 `Section` 值**，遇到就讓整個報到失敗。所以 Agent 只有在報到回應帶有 `registry_queries_hash`（新版伺服器才有）之後，才收集、雜湊、回報 `security`／`registry`。
  - 協定新欄位一律 `#[serde(default)]`；`None` 或空值不影響既有區段的雜湊。
- Agent 端的登錄檔守衛必須在 Agent 內執行（伺服器被入侵也無法繞過），並與伺服器共用 `protocol::regpath`。
- 不加新 crate（只加 windows-sys feature）。
- 測試指令：`cargo test -p protocol`、`cargo test -p endpoint-agent`、`cargo test -p endpoint-server`。
- 最後執行 `cargo clippy --workspace --all-targets -- -D warnings` 與 `cargo fmt --all --check`。
- `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres`

## Review Focus

1. 新版 Agent 對上舊版伺服器：報到不能失敗；新版伺服器上線後，Agent 下一輪就開始回報新區段。
2. 登錄檔守衛繞過：大小寫、`/`、重複 `\`、`..`、`HKEY_LOCAL_MACHINE` 別名、前後空白、值名稱大小寫都要擋住。
3. 任一項安全資訊收集失敗（沒有 BitLocker、Defender 被取代、WMI 損壞），其他項照常收集，錯誤不洗版。
4. 登錄檔值的轉換：REG_DWORD／QWORD 位元組序、多字串、二進位截斷、非 UTF-16 的字串都不能讓 Agent panic。
5. 伺服器保存與讀回內容後的雜湊必須和 Agent 算的一致，否則每次報到都會被要求重傳。

---

## File Structure

- Modify: `crates/protocol/src/lib.rs`
  - `Section::{Security, Registry}`、`SecurityInfo` 等型別、`RegistryQuery`、`RegistryValue`。
  - `CollectionIntervals` 與 `CheckinResponse` 新增欄位；`validate` 與 `normalize` 支援新區段。
- Create: `crates/protocol/src/regpath.rs`：路徑正規化、拒絕清單、查詢清單雜湊。
- Modify: `crates/agent/Cargo.toml`：新增 windows-sys feature。
- Modify: `crates/agent/src/collector.rs`：新增 `collect_registry`。
- Modify: `crates/agent/src/schedule.rs`：新區段的間隔。
- Modify: `crates/agent/src/agent.rs`：支援旗標、查詢清單、收集新區段。
- Modify: `crates/agent/src/sanitize.rs`
- Create: `crates/agent/src/windows/security.rs`
- Modify: `crates/agent/src/windows/registry.rs`：新增 `read_values`。
- Modify: `crates/agent/src/windows/collect.rs`：`collect` 支援 Security、`collect_registry`。
- Modify: `crates/agent/tests/e2e.rs`、`crates/agent/tests/windows.rs`
- Create: `crates/server/migrations/0007_config_baseline.sql`
- Modify: `crates/server/src/inventory.rs`、`crates/server/src/diff.rs`、`crates/server/src/checkin.rs`、`crates/server/src/db.rs`
- Modify: `crates/server/tests/inventory.rs`、`crates/server/tests/checkin.rs`

---

### Task 1: 協定型別與登錄檔守衛

**Files:**
- Modify: `crates/protocol/src/lib.rs`
- Create: `crates/protocol/src/regpath.rs`

**Interfaces:**
- Produces（`protocol`）：
  - `Section::Security`、`Section::Registry`（`as_str` 分別為 `"security"`、`"registry"`）。`Section::ALL` 變成 7 個，另加 `Section::LEGACY: [Section; 5]`（舊的五個）。
  - `Probe<T>`：`Ok(T)`／`Error(String)`，serde 外部標記為 `{"ok": ...}`／`{"error": "..."}`。
  - `FirewallInfo { domain: bool, private: bool, public: bool }`
  - `VolumeInfo { drive: String, is_system: bool, protected: bool }`
  - `DefenderInfo { active: bool, realtime: bool, tamper: bool, signature_updated: Option<DateTime<Utc>> }`
  - `PasswordPolicy { min_length: u32, max_age_days: u32, lockout_threshold: u32 }`
  - `AccountInfo { name: String, sid: String }`
  - `SecurityInfo { firewall: Probe<FirewallInfo>, bitlocker: Probe<Vec<VolumeInfo>>, defender: Probe<DefenderInfo>, password: Probe<PasswordPolicy>, admins: Probe<Vec<AccountInfo>> }`
  - `RegistryQuery { path: String, name: String }`
  - `RegState { Present, Absent, Denied }`、`RegKind { Dword, Qword, String, ExpandString, MultiString, Binary, Other, None }`（皆為 lowercase serde）
  - `RegistryValue { path, name, state: RegState, kind: RegKind, data: String }`
  - `InventoryPayload::Security(SecurityInfo)`、`InventoryPayload::Registry(Vec<RegistryValue>)`
  - `CollectionIntervals` 新增 `security_secs`、`registry_secs`（`#[serde(default = "default_hourly")]`，預設 3600）。
  - `CheckinResponse` 新增 `registry_queries: Vec<RegistryQuery>`（`#[serde(default)]`）與 `registry_queries_hash: Option<String>`（`#[serde(default, skip_serializing_if = "Option::is_none")]`）。
  - `pub const MAX_REGISTRY_VALUES: usize = 5000;`
  - `regpath::normalize(path: &str) -> Result<String, &'static str>`：輸出 `HKLM\...` 形式，子路徑保留原大小寫。
  - `regpath::check(path: &str, name: &str) -> Result<String, &'static str>`：正規化並套用拒絕清單，回傳正規化後的路徑。
  - `regpath::queries_hash(q: &[RegistryQuery]) -> String`：排序後的 SHA-256 hex，與輸入順序無關。
  - `regpath::DENIED_MESSAGE`

- [ ] **Step 1: 寫失敗測試**（`regpath.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_aliases_and_separators() {
        let n = |p| normalize(p).unwrap();
        assert_eq!(n(r"HKLM\SOFTWARE\Foo"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(n(r"hklm\SOFTWARE\Foo\"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(n("HKEY_LOCAL_MACHINE/SOFTWARE//Foo"), r"HKLM\SOFTWARE\Foo");
        assert_eq!(n(r"  HKLM\\SOFTWARE\\Foo  "), r"HKLM\SOFTWARE\Foo");
        for bad in [r"HKCU\Software", r"HKU\S-1-5-18", "SOFTWARE\\Foo", "", r"HKLM", r"HKLM\..\SAM", r"HKLM\SOFTWARE\a\..\b"] {
            assert!(normalize(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn deny_list_blocks_secrets_in_all_spellings() {
        for (p, name) in [
            (r"HKLM\SAM\SAM\Domains", "F"),
            (r"hklm\sam", ""),
            (r"HKEY_LOCAL_MACHINE/Security/Policy", "x"),
            (r"HKLM\SECURITY", "x"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword"),
            (r"hklm\software\microsoft\windows nt\currentversion\winlogon", "defaultpassword"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AltDefaultPassword"),
        ] {
            assert!(check(p, name).is_err(), "{p} {name}");
        }
        assert!(check(r"HKLM\SAMPLE\Key", "x").is_ok(), "SAM 前綴但不同機碼");
        assert!(check(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon").is_ok());
    }

    #[test]
    fn queries_hash_is_order_independent() {
        let a = RegistryQuery { path: r"HKLM\A".into(), name: "x".into() };
        let b = RegistryQuery { path: r"HKLM\B".into(), name: "y".into() };
        assert_eq!(queries_hash(&[a.clone(), b.clone()]), queries_hash(&[b.clone(), a.clone()]));
        assert_ne!(queries_hash(&[a.clone()]), queries_hash(&[b]));
        assert_eq!(queries_hash(&[]).len(), 64);
    }
}
```

另外在 `lib.rs` 的 `mod tests` 加：

```rust
    #[test]
    fn old_checkin_response_still_parses_and_new_fields_default() {
        let v = serde_json::json!({
            "next_checkin_seconds": 60, "request_sections": ["basic"],
            "collection_intervals": {"software_secs": 1, "patches_secs": 1, "services_secs": 1, "hardware_secs": 1},
            "renew_certificate": false
        });
        let r: CheckinResponse = serde_json::from_value(v).unwrap();
        assert!(r.registry_queries.is_empty() && r.registry_queries_hash.is_none());
        assert_eq!((r.collection_intervals.security_secs, r.collection_intervals.registry_secs), (3600, 3600));
    }

    #[test]
    fn security_probe_serializes_as_ok_or_error() {
        let p: Probe<FirewallInfo> = Probe::Error("boom".into());
        assert_eq!(serde_json::to_value(&p).unwrap(), serde_json::json!({"error": "boom"}));
        let p = Probe::Ok(FirewallInfo { domain: true, private: false, public: true });
        assert_eq!(serde_json::to_value(&p).unwrap()["ok"]["private"], false);
    }

    #[test]
    fn registry_upload_is_capped() {
        let v = (0..=MAX_REGISTRY_VALUES)
            .map(|i| RegistryValue {
                path: r"HKLM\X".into(),
                name: i.to_string(),
                state: RegState::Absent,
                kind: RegKind::None,
                data: String::new(),
            })
            .collect();
        assert!(InventoryPayload::Registry(v).validate().is_err());
    }
```

Run: `cargo test -p protocol`
Expected: 編譯錯誤（型別與 `regpath` 不存在）。

- [ ] **Step 2: 實作 `regpath.rs`**

```rust
//! 登錄檔路徑守衛：Agent 讀取前與伺服器建立規則時共用，確保兩端判斷一致。
//! 只允許 HKLM；拒絕 SAM、SECURITY 子樹與 Winlogon 的自動登入密碼。

use sha2::{Digest, Sha256};

use crate::RegistryQuery;

pub const DENIED_MESSAGE: &str = "不允許讀取這個位置（只能讀取 HKLM，且不能讀取 SAM、SECURITY 與自動登入密碼）";

const DENIED_SUBTREES: [&str; 2] = [r"HKLM\SAM", r"HKLM\SECURITY"];
const WINLOGON: &str = r"HKLM\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON";
const DENIED_WINLOGON_NAMES: [&str; 2] = ["DEFAULTPASSWORD", "ALTDEFAULTPASSWORD"];

/// 正規化成 `HKLM\子機碼\...`：接受 `HKEY_LOCAL_MACHINE` 別名、`/`、重複或結尾的 `\`、前後空白；
/// 不接受其他根機碼、沒有子機碼、或含 `.`／`..` 段落的路徑。
pub fn normalize(path: &str) -> Result<String, &'static str> {
    let path = path.trim().replace('/', "\\");
    let mut parts = path.split('\\').filter(|p| !p.is_empty());
    let root = parts.next().ok_or("登錄檔路徑必填")?;
    if !root.eq_ignore_ascii_case("HKLM") && !root.eq_ignore_ascii_case("HKEY_LOCAL_MACHINE") {
        return Err("登錄檔路徑必須以 HKLM\\ 開頭");
    }
    let rest: Vec<&str> = parts.collect();
    if rest.is_empty() {
        return Err("登錄檔路徑需要指定子機碼");
    }
    if rest.iter().any(|p| *p == "." || *p == "..") {
        return Err("登錄檔路徑不能包含 . 或 ..");
    }
    Ok(format!("HKLM\\{}", rest.join("\\")))
}

/// 正規化並套用拒絕清單，回傳正規化後的路徑。
pub fn check(path: &str, name: &str) -> Result<String, &'static str> {
    let p = normalize(path).map_err(|_| DENIED_MESSAGE)?;
    let upper = p.to_uppercase();
    let denied_subtree = DENIED_SUBTREES
        .iter()
        .any(|d| upper == *d || upper.starts_with(&format!("{d}\\")));
    let denied_value = upper == WINLOGON
        && DENIED_WINLOGON_NAMES.contains(&name.trim().to_uppercase().as_str());
    if denied_subtree || denied_value {
        return Err(DENIED_MESSAGE);
    }
    Ok(p)
}

/// 查詢清單的雜湊（不分順序、路徑不分大小寫）：Agent 用來判斷清單有沒有變。
pub fn queries_hash(q: &[RegistryQuery]) -> String {
    let mut keys: Vec<String> = q
        .iter()
        .map(|x| format!("{}\u{0}{}", x.path.to_uppercase(), x.name.to_uppercase()))
        .collect();
    keys.sort();
    keys.dedup();
    hex::encode(Sha256::digest(keys.join("\n").as_bytes()))
}
```

`normalize` 的錯誤訊息只給建立規則時使用；`check` 失敗一律回 `DENIED_MESSAGE`。另外注意：`hklm\sam` 會正規化成 `HKLM\sam`，轉大寫後命中拒絕清單。

- [ ] **Step 3: 實作 `lib.rs` 的型別**

- `pub mod regpath;`
- `Section` 加 `Security`、`Registry`，更新 `ALL`、`as_str`，並新增：
  ```rust
      /// 第三期以前就有的區段：新版 Agent 在確認伺服器支援前只回報這些
      pub const LEGACY: [Section; 5] = [Section::Basic, Section::Hardware, Section::Software, Section::Patches, Section::Services];
  ```
- 新型別全部 derive `Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize`（`Probe` 使用 `#[serde(rename_all = "lowercase")]`；`RegState`／`RegKind` 使用 `#[serde(rename_all = "snake_case")]`，所以 `ExpandString` 序列化為 `expand_string`）。
- `CollectionIntervals`：
  ```rust
      #[serde(default = "default_hourly")]
      pub security_secs: u32,
      #[serde(default = "default_hourly")]
      pub registry_secs: u32,
  ```
  加上 `fn default_hourly() -> u32 { 3600 }`。
- `CheckinResponse` 加上 Interfaces 所列的兩個欄位。
- `InventoryPayload` 加兩個變體；`section()` 補上對應。
- `normalize()`：
  - `Security`：`bitlocker` 與 `admins` 為 `Probe::Ok` 時各自排序。
  - `Registry`：排序。
- `validate()` 的 count：`Security` 為 1；`Registry` 為長度，並在通用檢查前先判斷：
  ```rust
  if let InventoryPayload::Registry(v) = self
      && v.len() > MAX_REGISTRY_VALUES
  {
      return Err(ValidationError::TooManyItems { count: v.len() });
  }
  ```
- `sha2`、`hex` 已是 protocol 的相依，不需新增。

- [ ] **Step 4: 修正編譯錯誤**

有 `match section` 或 `CollectionIntervals { .. }` 字面值的地方都要補上新欄位或分支。先執行下面兩個指令找出所有位置：

```bash
cargo build --workspace 2>&1 | grep -E "^error" -A5
grep -rn "CollectionIntervals {" crates
```

已知位置：

| 檔案 | 要補的內容 |
|---|---|
| `agent/src/schedule.rs` 的 `DEFAULT_INTERVALS` 與 `interval()` | 新區段的間隔 |
| `agent/src/sanitize.rs` | `Security`：清理字串欄位；`Registry`：`truncate(MAX_REGISTRY_VALUES)` 並清理字串 |
| `server/src/db.rs` 的 `Settings.intervals` | `security_secs`／`registry_secs` 先填 3600，Task 5 改讀設定 |
| `server/src/inventory.rs` 的 `load_payload`／`write_payload` | 新區段先 `unimplemented!()` 佔位，Task 5 實作 |
| `server/src/diff.rs` 的 `items_of` | 新區段先回空，Task 5 實作 |
| `agent/tests/e2e.rs` 的 `Fake::collect` | 新區段回固定資料，見 Task 3 |

Run: `cargo test -p protocol`
Expected: 全部 PASS。

Run: `cargo build --workspace`
Expected: 編譯成功。

- [ ] **Step 5: Commit**

```bash
git add -A crates
git commit -m "協定：security／registry 區段型別與登錄檔路徑守衛"
```

---

### Task 2: Agent 讀取登錄檔值（含守衛）

**Files:**
- Modify: `crates/agent/src/windows/registry.rs`
- Create 或 Modify: `crates/agent/src/regvalue.rs`（放可跨平台測試的轉換純函式）
- Modify: `crates/agent/src/lib.rs`（`pub mod regvalue;`）
- Test: `crates/agent/src/regvalue.rs`、`crates/agent/tests/windows.rs`

**Interfaces:**
- Produces：
  - `regvalue::render(vtype: u32, bytes: &[u8]) -> (RegKind, String)`：純函式，把原始位元組轉成回報格式。
  - `windows::registry::read_values(queries: &[RegistryQuery]) -> Vec<RegistryValue>`：守衛（`regpath::check`）→ 讀取 → `render`；最多處理 `MAX_REGISTRY_VALUES` 筆。

- [ ] **Step 1: 寫失敗測試**（`regvalue.rs`）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const REG_SZ: u32 = 1;
    const REG_EXPAND_SZ: u32 = 2;
    const REG_BINARY: u32 = 3;
    const REG_DWORD: u32 = 4;
    const REG_MULTI_SZ: u32 = 7;
    const REG_QWORD: u32 = 11;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn renders_each_type() {
        assert_eq!(render(REG_DWORD, &5u32.to_le_bytes()), (RegKind::Dword, "5".into()));
        assert_eq!(render(REG_QWORD, &(1u64 << 40).to_le_bytes()), (RegKind::Qword, (1u64 << 40).to_string()));
        assert_eq!(render(REG_SZ, &utf16("Windows 11")), (RegKind::String, "Windows 11".into()));
        assert_eq!(render(REG_EXPAND_SZ, &utf16("%SystemRoot%")), (RegKind::ExpandString, "%SystemRoot%".into()));
        let mut multi: Vec<u8> = utf16("a");
        multi.extend(utf16("b"));
        multi.extend([0, 0]);
        assert_eq!(render(REG_MULTI_SZ, &multi), (RegKind::MultiString, "a\nb".into()));
        assert_eq!(render(REG_BINARY, &[0xde, 0xad]), (RegKind::Binary, "dead".into()));
    }

    #[test]
    fn malformed_data_does_not_panic() {
        assert_eq!(render(REG_DWORD, &[1, 2]), (RegKind::Dword, String::new()), "長度不足");
        assert_eq!(render(REG_SZ, &[0x41]), (RegKind::String, String::new()), "奇數長度");
        let (k, d) = render(REG_SZ, &[0x00, 0xd8, 0x41, 0x00, 0, 0]); // 孤立的 surrogate
        assert_eq!(k, RegKind::String);
        assert!(d.contains('A'));
        let (_, d) = render(REG_BINARY, &vec![0xab; 5000]);
        assert_eq!(d.chars().count(), protocol::MAX_STRING_LEN, "截斷");
        assert_eq!(render(99, &[1]), (RegKind::Other, "01".into()));
    }
}
```

Run: `cargo test -p endpoint-agent --lib regvalue`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作 `regvalue.rs`**

```rust
//! 登錄檔原始值 → 回報格式（純函式，可在任何平台測試）。

use protocol::{MAX_STRING_LEN, RegKind};

fn cap(s: String) -> String {
    s.chars().take(MAX_STRING_LEN).collect()
}

fn utf16(bytes: &[u8]) -> Option<Vec<String>> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(
        units
            .split(|u| *u == 0)
            .map(String::from_utf16_lossy)
            .collect(),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().take(MAX_STRING_LEN / 2).map(|b| format!("{b:02x}")).collect()
}

pub fn render(vtype: u32, bytes: &[u8]) -> (RegKind, String) {
    match vtype {
        4 => (RegKind::Dword, bytes.get(..4).map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")).to_string()).unwrap_or_default()),
        11 => (RegKind::Qword, bytes.get(..8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")).to_string()).unwrap_or_default()),
        1 | 2 => {
            let kind = if vtype == 1 { RegKind::String } else { RegKind::ExpandString };
            let s = utf16(bytes).and_then(|v| v.into_iter().next()).unwrap_or_default();
            (kind, cap(s))
        }
        7 => {
            let parts = utf16(bytes).unwrap_or_default();
            let s = parts.into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join("\n");
            (RegKind::MultiString, cap(s))
        }
        3 => (RegKind::Binary, hex(bytes)),
        _ => (RegKind::Other, hex(bytes)),
    }
}
```

- [ ] **Step 3: 實作 `read_values`**（`windows/registry.rs`）

```rust
/// 依伺服器下發的清單讀取 HKLM 值。守衛在這裡執行：伺服器被入侵也讀不到拒絕清單內的值。
pub fn read_values(queries: &[RegistryQuery]) -> Vec<RegistryValue> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    queries
        .iter()
        .take(protocol::MAX_REGISTRY_VALUES)
        .map(|q| {
            let mut v = RegistryValue {
                path: q.path.clone(),
                name: q.name.clone(),
                state: RegState::Denied,
                kind: RegKind::None,
                data: String::new(),
            };
            let Ok(path) = protocol::regpath::check(&q.path, &q.name) else {
                return v;
            };
            let sub = path.strip_prefix("HKLM\\").expect("normalized");
            v.state = RegState::Absent;
            if let Ok(key) = hklm.open_subkey_with_flags(sub, KEY_READ | KEY_WOW64_64KEY)
                && let Ok(raw) = key.get_raw_value(&q.name)
            {
                let (kind, data) = crate::regvalue::render(raw.vtype as u32, &raw.bytes);
                v.state = RegState::Present;
                v.kind = kind;
                v.data = data;
            }
            v
        })
        .collect()
}
```

（`winreg` 0.56 的 `RegValue { bytes, vtype }`：`vtype` 是 `RegType` enum，`as u32` 取得數值。若型別不同，照 winreg 文件調整。超過 5000 筆的部分以 `tracing::warn!` 記錄一次，靜態旗標可沿用 `collect.rs` 的 `first_report`。）

- [ ] **Step 4: Windows 整合測試**（`crates/agent/tests/windows.rs`）

```rust
#[test]
fn registry_values_are_read_and_guarded() {
    use protocol::{RegState, RegistryQuery};
    let q = |p: &str, n: &str| RegistryQuery { path: p.into(), name: n.into() };
    let v = endpoint_agent::windows::registry::read_values(&[
        q(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuild"),
        q(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "NoSuchValue-EM"),
        q(r"HKLM\SAM\SAM", "C"),
        q(r"hklm/sam/SAM", "C"),
        q(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword"),
    ]);
    assert_eq!(v[0].state, RegState::Present);
    assert!(v[0].data.parse::<u32>().is_ok(), "{:?}", v[0]);
    assert_eq!(v[1].state, RegState::Absent);
    assert!(v[2..].iter().all(|x| x.state == RegState::Denied), "{v:?}");
}
```

Run: `cargo test -p endpoint-agent --lib regvalue`、`cargo test -p endpoint-agent --test windows registry_values`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add -A crates/agent
git commit -m "Agent：依清單讀取 HKLM 登錄檔值（守衛在 Agent 端執行）"
```

---

### Task 3: Agent 收集安全資訊

**Files:**
- Modify: `crates/agent/Cargo.toml`（windows-sys 加 `"Win32_NetworkManagement_NetManagement"`）
- Create: `crates/agent/src/windows/security.rs`
- Modify: `crates/agent/src/windows/mod.rs`（`pub mod security;`）
- Modify: `crates/agent/src/windows/collect.rs`（`Section::Security` → `security::collect()`）
- Test: `crates/agent/src/windows/security.rs`、`crates/agent/tests/windows.rs`

**Interfaces:**
- Produces：
  - `windows::security::collect() -> SecurityInfo`：每一項各自 `Probe`，本身不會失敗。
  - `windows::security::firewall_effective(policy: Option<u32>, local: Option<u32>) -> bool`：純函式。
  - `windows::security::days_from_seconds(max_passwd_age: u32) -> u32`：純函式；`TIMEQ_FOREVER`（`u32::MAX`）回 0。

**Ruling（相對 spec §2.1）：**
- **防火牆**：spec 寫以 `INetFwPolicy2`（COM）取得實際生效狀態。改為讀登錄檔：GPO 路徑 `SOFTWARE\Policies\Microsoft\WindowsFirewall\{DomainProfile,PrivateProfile,PublicProfile}\EnableFirewall` 優先，其次是本機 `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{DomainProfile,StandardProfile,PublicProfile}\EnableFirewall`，都沒有則視為啟用。這和 COM 在 GPO 與本機設定上的結果相同，也不必另外處理 COM 初始化。代價：第三方防火牆接管時，COM 會回報 Windows 防火牆的狀態，登錄檔同樣反映 Windows 防火牆，兩者一致，所以沒有差別。
- **BitLocker**：spec 的加密百分比要另外呼叫 WMI 方法（`GetConversionStatus`），規則也用不到，這一期不收，`VolumeInfo` 不含 `percent`。代價：安全設定分頁看不到加密進度。

- [ ] **Step 1: 寫失敗的單元測試**（`security.rs`）

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_policy_overrides_local_and_defaults_on() {
        assert!(firewall_effective(None, None), "都沒設定＝預設啟用");
        assert!(!firewall_effective(None, Some(0)));
        assert!(firewall_effective(Some(1), Some(0)), "GPO 優先");
        assert!(!firewall_effective(Some(0), Some(1)));
    }

    #[test]
    fn password_age_conversion() {
        assert_eq!(days_from_seconds(u32::MAX), 0, "永不過期");
        assert_eq!(days_from_seconds(42 * 86_400), 42);
        assert_eq!(days_from_seconds(0), 0);
    }
}
```

Run: `cargo test -p endpoint-agent --lib security`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作 `security.rs`**

```rust
//! 安全設定收集：防火牆、BitLocker、Defender、密碼原則、本機管理員。每一項獨立，
//! 失敗時以 Probe::Error 回報，不影響其他項；錯誤依「同一錯誤只記一次」寫入事件記錄。

use protocol::{AccountInfo, DefenderInfo, FirewallInfo, PasswordPolicy, Probe, SecurityInfo, VolumeInfo};
use serde::Deserialize;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};

pub fn collect() -> SecurityInfo {
    SecurityInfo {
        firewall: probe("firewall", firewall),
        bitlocker: probe("bitlocker", bitlocker),
        defender: probe("defender", defender),
        password: probe("password", password_policy),
        admins: probe("admins", local_admins),
    }
}

fn probe<T>(what: &'static str, f: impl FnOnce() -> anyhow::Result<T>) -> Probe<T> {
    match f() {
        Ok(v) => {
            super::collect::recovered(what);
            Probe::Ok(v)
        }
        Err(e) => {
            let e = format!("{e:#}");
            if super::collect::first_report(what, &e) {
                tracing::warn!(item = what, error = %e, "security probe failed");
            }
            Probe::Error(protocol_clean(&e))
        }
    }
}

fn protocol_clean(s: &str) -> String {
    crate::sanitize::clean(s)
}

fn dword(path: &str, name: &str) -> Option<u32> {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(path, KEY_READ | KEY_WOW64_64KEY)
        .and_then(|k| k.get_value::<u32, _>(name))
        .ok()
}

pub fn firewall_effective(policy: Option<u32>, local: Option<u32>) -> bool {
    policy.or(local).unwrap_or(1) != 0
}

fn firewall() -> anyhow::Result<FirewallInfo> {
    const POLICY: &str = r"SOFTWARE\Policies\Microsoft\WindowsFirewall";
    const LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
    let profile = |policy_name: &str, local_name: &str| {
        firewall_effective(
            dword(&format!(r"{POLICY}\{policy_name}"), "EnableFirewall"),
            dword(&format!(r"{LOCAL}\{local_name}"), "EnableFirewall"),
        )
    };
    Ok(FirewallInfo {
        domain: profile("DomainProfile", "DomainProfile"),
        private: profile("PrivateProfile", "StandardProfile"),
        public: profile("PublicProfile", "PublicProfile"),
    })
}

#[derive(Deserialize)]
#[serde(rename = "Win32_EncryptableVolume", rename_all = "PascalCase")]
struct EncryptableVolume {
    drive_letter: Option<String>,
    protection_status: Option<u32>,
    volume_type: Option<u32>,
}

fn bitlocker() -> anyhow::Result<Vec<VolumeInfo>> {
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\CIMV2\Security\MicrosoftVolumeEncryption")?;
    let vols: Vec<EncryptableVolume> = con.query()?;
    Ok(vols
        .into_iter()
        // 0 = 作業系統磁碟、1 = 固定資料磁碟；卸除式不看
        .filter(|v| matches!(v.volume_type, Some(0 | 1)))
        .map(|v| VolumeInfo {
            drive: v.drive_letter.unwrap_or_default(),
            is_system: v.volume_type == Some(0),
            protected: v.protection_status == Some(1),
        })
        .collect())
}

#[derive(Deserialize)]
#[serde(rename = "MSFT_MpComputerStatus", rename_all = "PascalCase")]
struct MpStatus {
    #[serde(rename = "AMRunningMode")]
    am_running_mode: Option<String>,
    #[serde(rename = "AMServiceEnabled")]
    am_service_enabled: Option<bool>,
    real_time_protection_enabled: Option<bool>,
    is_tamper_protected: Option<bool>,
    antivirus_signature_last_updated: Option<wmi::WMIDateTime>,
}

fn defender() -> anyhow::Result<DefenderInfo> {
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\Microsoft\Windows\Defender")?;
    let s: MpStatus = con
        .query::<MpStatus>()?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("MSFT_MpComputerStatus returned nothing"))?;
    // 舊版 Windows 沒有 AMRunningMode：以服務是否啟用判斷
    let active = match s.am_running_mode.as_deref() {
        Some(m) => m.eq_ignore_ascii_case("Normal"),
        None => s.am_service_enabled.unwrap_or(false),
    };
    Ok(DefenderInfo {
        active,
        realtime: s.real_time_protection_enabled.unwrap_or(false),
        tamper: s.is_tamper_protected.unwrap_or(false),
        signature_updated: s.antivirus_signature_last_updated.map(|t| t.0.with_timezone(&chrono::Utc)),
    })
}

pub fn days_from_seconds(max_passwd_age: u32) -> u32 {
    if max_passwd_age == u32::MAX { 0 } else { max_passwd_age / 86_400 }
}
```

`password_policy` 與 `local_admins` 需要 FFI，寫在同檔。用 `windows-sys` 的 `NetUserModalsGet`（level 0 與 3）、`NetApiBufferFree`、`CreateWellKnownSid(WinBuiltinAdministratorsSid)`、`LookupAccountSidW`、`NetLocalGroupGetMembers`（level 2，使用 resume handle 迴圈，直到回傳值不是 `ERROR_MORE_DATA`）、`ConvertSidToStringSidW` 與 `LocalFree`。

- 每個 `unsafe` 區塊都要有註解，說明緩衝區由誰配置、由誰釋放。
- 函式簽名：`fn password_policy() -> anyhow::Result<PasswordPolicy>`、`fn local_admins() -> anyhow::Result<Vec<AccountInfo>>`。
- 回傳值不是 `NERR_Success`（0）時，回 `anyhow!("NetUserModalsGet failed: {code}")`。
- `AccountInfo.name` 取 `lgrmi2_domainandname`，SID 已不存在的成員會回傳空字串，這時名稱改用 SID 字串。

`collect.rs` 的 `first_report`／`recovered` 改為 `pub(crate)`。`Collector::collect` 的 `Section::Security` 分支回 `InventoryPayload::Security(super::security::collect())`（在 WMI 分支之前處理，就像 Software 一樣）。

- [ ] **Step 3: Windows 整合測試**

在 `collector_reports_this_machine` 的 `match p` 加上：

```rust
            InventoryPayload::Security(sec) => {
                // CI 機器不一定有 BitLocker、Defender；防火牆、密碼原則、管理員一定要成功
                assert!(matches!(sec.firewall, protocol::Probe::Ok(_)), "{:?}", sec.firewall);
                assert!(matches!(sec.password, protocol::Probe::Ok(_)), "{:?}", sec.password);
                let protocol::Probe::Ok(admins) = &sec.admins else { panic!("{:?}", sec.admins) };
                assert!(!admins.is_empty() && admins.iter().all(|a| a.sid.starts_with("S-1-")), "{admins:?}");
            }
            InventoryPayload::Registry(_) => unreachable!("registry 不經 collect"),
```

測試迴圈目前是 `for s in Section::ALL`，要跳過 `Section::Registry`（它走 `collect_registry`）。

Run: `cargo test -p endpoint-agent --lib security`、`cargo test -p endpoint-agent --test windows collector_reports`
Expected: PASS。本機不是系統管理員時，BitLocker 可能回 `Probe::Error`，這在預期內。

- [ ] **Step 4: Commit**

```bash
git add -A crates/agent
git commit -m "Agent：收集防火牆、BitLocker、Defender、密碼原則、本機管理員"
```

---

### Task 4: Agent 主迴圈——等伺服器支援才回報新區段、依清單收集登錄檔

**Files:**
- Modify: `crates/agent/src/collector.rs`、`crates/agent/src/agent.rs`
- Modify: `crates/agent/src/windows/collect.rs`（實作 `collect_registry`）
- Test: `crates/agent/tests/e2e.rs`、`crates/agent/src/agent.rs` 的 `mod tests`

**Interfaces:**
- Consumes：`CheckinResponse.registry_queries[_hash]`、`regpath::queries_hash`
- Produces：
  - `Collector::collect_registry(&self, queries: &[RegistryQuery]) -> anyhow::Result<InventoryPayload>`，預設實作回 `Ok(InventoryPayload::Registry(vec![]))`。
  - Agent 欄位：`server_supports_config: bool`、`registry_queries: Vec<RegistryQuery>`、`registry_hash: Option<String>`。
  - 行為：
    - `server_supports_config` 為 false 時，`collect_due` 只處理 `Section::LEGACY`，報到時的 `section_hashes`／`section_errors` 也只含 LEGACY。
    - 報到回應的 `registry_queries_hash` 為 `Some(h)` 時設為 true；若 `h` 與記住的不同，就更新清單並 `trigger(Section::Registry)`（下一輪收集）。
    - 上傳新區段得到 400 且訊息含 `unknown section` 時，設回 false，並記錄一次（舊伺服器降版或設定錯誤時保護）。

**Ruling（相對 spec §2.2「清單改變時當次就收集」）：** 查詢清單是在報到回應裡拿到的，而收集發生在報到之前，所以新清單在下一輪（最多一個報到間隔，預設 60 秒）才收集。代價：新規則的結果最多晚一分鐘。

- [ ] **Step 1: 寫失敗測試**（`e2e.rs`）

`Fake::collect` 新增兩個分支：

```rust
            Section::Security => InventoryPayload::Security(protocol::SecurityInfo {
                firewall: protocol::Probe::Ok(protocol::FirewallInfo { domain: true, private: true, public: false }),
                bitlocker: protocol::Probe::Error("no BitLocker".into()),
                defender: protocol::Probe::Ok(protocol::DefenderInfo { active: true, realtime: true, tamper: false, signature_updated: None }),
                password: protocol::Probe::Ok(protocol::PasswordPolicy { min_length: 8, max_age_days: 42, lockout_threshold: 0 }),
                admins: protocol::Probe::Ok(vec![protocol::AccountInfo { name: r"FAKE-PC\Administrator".into(), sid: "S-1-5-21-1-500".into() }]),
            }),
            Section::Registry => anyhow::bail!("registry is collected via collect_registry"),
```

並覆寫 `collect_registry`：依 queries 回傳每個查詢 `state = Present`、`kind = Dword`、`data = "1"`。

測試：

```rust
#[sqlx::test(migrations = false)]
async fn config_sections_start_after_server_confirms_support(pool: PgPool) {
    let e = env(pool, 1).await;
    let mut a = Agent::new(e.dir.path(), Fake::new()).unwrap();
    next(a.run_cycle().await);
    let id = a.state().device_id.unwrap();
    let sections = |e: &Env| {
        let pool = e.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT section FROM inventory_sections WHERE device_id = $1 ORDER BY section",
            )
            .bind(id)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    assert!(!sections(&e).await.contains(&"security".to_string()), "第一輪還不知道伺服器是否支援");
    next(a.run_cycle().await);
    let s = sections(&e).await;
    assert!(s.contains(&"security".to_string()) && s.contains(&"registry".to_string()), "{s:?}");
}
```

`agent.rs` 的 `mod tests` 加一個純函式測試：

```rust
    #[test]
    fn legacy_sections_only_until_supported() {
        let all = crate::agent::sections_to_collect(false);
        assert_eq!(all, protocol::Section::LEGACY.to_vec());
        assert_eq!(crate::agent::sections_to_collect(true), protocol::Section::ALL.to_vec());
    }
```

Run: `cargo test -p endpoint-agent --test e2e config_sections`、`cargo test -p endpoint-agent --lib legacy_sections`
Expected: 失敗（第二輪沒有 security 區段；`sections_to_collect` 不存在）。

- [ ] **Step 2: 實作**

`agent.rs`：

```rust
/// 伺服器確認支援前只收集第三期以前的區段：舊版伺服器看到不認識的區段會讓整個報到失敗
pub fn sections_to_collect(supported: bool) -> Vec<Section> {
    if supported { Section::ALL.to_vec() } else { Section::LEGACY.to_vec() }
}
```

- `collect_due`：`self.schedule.due(now, &self.intervals)` 的結果要過濾，只保留 `sections_to_collect(self.server_supports_config)` 內的區段。`Section::Registry` 改成呼叫 `c.collect_registry(&queries)`（`queries` 先 clone 出來，再 move 進 blocking 閉包）。
- 報到前組 `hashes` 與 `section_errors` 時，同樣只保留允許的區段（cache 裡可能還留著伺服器降版前收集的資料）。
- 報到成功後：

```rust
        if let Some(h) = &resp.registry_queries_hash {
            self.server_supports_config = true;
            if self.registry_hash.as_ref() != Some(h) {
                self.registry_queries = resp.registry_queries.clone();
                self.registry_hash = Some(h.clone());
                self.schedule.trigger(Section::Registry);
            }
        }
```

- 上傳的 `ClientError::Rejected(400, msg)` 在 `msg.contains("unknown section")` 且區段是 Security 或 Registry 時：
  - 設 `self.server_supports_config = false`，把兩個新區段從 `cache` 移除。
  - `tracing::warn!` 記錄一次（以 `error_changed` 判斷），不寫入 `state.rejected`。

`schedule.rs` 的 `interval()` 補上 `Section::Security => iv.security_secs` 與 `Section::Registry => iv.registry_secs`。

`windows/collect.rs` 實作 `collect_registry`：

```rust
    fn collect_registry(&self, queries: &[RegistryQuery]) -> anyhow::Result<InventoryPayload> {
        Ok(InventoryPayload::Registry(super::registry::read_values(queries)))
    }
```

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-agent`
Expected: 全部 PASS。`first_cycle_enrolls_and_uploads_all_sections` 仍是 5 個區段，因為第一輪還不知道伺服器是否支援。

- [ ] **Step 4: Commit**

```bash
git add -A crates/agent
git commit -m "Agent：確認伺服器支援後才回報新區段；依伺服器清單收集登錄檔"
```

---

### Task 5: 伺服器保存新區段、變更歷史、報到回應

**Files:**
- Create: `crates/server/migrations/0007_config_baseline.sql`
- Modify: `crates/server/src/inventory.rs`（`load_payload`／`write_payload`）
- Modify: `crates/server/src/diff.rs`（`items_of` 與檔頭的對照表）
- Modify: `crates/server/src/checkin.rs`（`registry_queries` 與 `registry_queries_hash`）
- Modify: `crates/server/src/db.rs`（新設定）
- Test: `crates/server/tests/inventory.rs`、`crates/server/tests/checkin.rs`、`crates/server/src/diff.rs`

**Interfaces:**
- Produces：
  - 資料表 `device_security`：`device_id` 為主鍵；`firewall`、`bitlocker`、`defender`、`password`、`admins` 皆為 jsonb；另有 `updated_at`。
  - 資料表 `device_registry`：`device_id`、`path`、`name`、`state`、`kind`、`data`，主鍵 (`device_id`, `path`, `name`)，索引 (`path`, `name`)。
  - 設定 `security_interval_secs`、`registry_interval_secs`（3600，最小 300）、`registry_max_values`（1000）。
  - `db::Settings.intervals.security_secs`／`registry_secs` 從設定讀取。
  - 報到回應：`registry_queries` 為空清單，`registry_queries_hash = Some(regpath::queries_hash(&[]))`。計畫 9 會改由規則快取提供。

- [ ] **Step 1: 寫失敗測試**

`tests/inventory.rs`：

```rust
#[sqlx::test(migrations = false)]
async fn security_and_registry_roundtrip_with_history(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let sec = |public: bool| {
        InventoryPayload::Security(protocol::SecurityInfo {
            firewall: protocol::Probe::Ok(protocol::FirewallInfo { domain: true, private: true, public }),
            bitlocker: protocol::Probe::Ok(vec![protocol::VolumeInfo { drive: "C:".into(), is_system: true, protected: true }]),
            defender: protocol::Probe::Error("inactive".into()),
            password: protocol::Probe::Ok(protocol::PasswordPolicy { min_length: 12, max_age_days: 0, lockout_threshold: 5 }),
            admins: protocol::Probe::Ok(vec![protocol::AccountInfo { name: r"PC\Administrator".into(), sid: "S-1-5-21-1-500".into() }]),
        })
    };
    assert_eq!(put(&s, &a, "security", &upload(sec(true))).await, 204);
    assert_eq!(put(&s, &a, "security", &upload(sec(false))).await, 204);
    let mut c = s.pool.acquire().await.unwrap();
    let back = endpoint_server::inventory::load_payload(&mut c, a.device_id, protocol::Section::Security)
        .await.unwrap().unwrap();
    assert_eq!(back.canonical_hash(), sec(false).canonical_hash());
    let change: (String, String, String) = sqlx::query_as(
        "SELECT item_key, old_value, new_value FROM inventory_changes WHERE device_id = $1 AND section = 'security'",
    ).bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(change, ("firewall.public".into(), "true".into(), "false".into()));

    let reg = InventoryPayload::Registry(vec![protocol::RegistryValue {
        path: r"HKLM\SOFTWARE\X".into(), name: "Y".into(),
        state: protocol::RegState::Present, kind: protocol::RegKind::Dword, data: "1".into(),
    }]);
    assert_eq!(put(&s, &a, "registry", &upload(reg.clone())).await, 204);
    let back = endpoint_server::inventory::load_payload(&mut c, a.device_id, protocol::Section::Registry)
        .await.unwrap().unwrap();
    assert_eq!(back.canonical_hash(), reg.canonical_hash());
}
```

`tests/checkin.rs`（沿用檔內既有的 checkin helper，名稱以實際為準）：

```rust
#[sqlx::test(migrations = false)]
async fn checkin_announces_config_support(pool: PgPool) {
    // 以既有 helper 報到一次後：
    // assert_eq!(resp.registry_queries_hash.as_deref(), Some(protocol::regpath::queries_hash(&[]).as_str()));
    // assert!(resp.registry_queries.is_empty());
    // assert_eq!(resp.collection_intervals.security_secs, 3600);
}
```

撰寫時照 `tests/checkin.rs` 現有的報到呼叫方式，補上上面三個斷言。

`diff.rs` 的單元測試：

```rust
    #[test]
    fn security_items_flatten_probes() {
        let p = InventoryPayload::Security(protocol::SecurityInfo {
            firewall: protocol::Probe::Ok(protocol::FirewallInfo { domain: true, private: false, public: true }),
            bitlocker: protocol::Probe::Error("x".into()),
            defender: protocol::Probe::Ok(protocol::DefenderInfo { active: true, realtime: false, tamper: true, signature_updated: None }),
            password: protocol::Probe::Ok(protocol::PasswordPolicy { min_length: 8, max_age_days: 0, lockout_threshold: 0 }),
            admins: protocol::Probe::Ok(vec![protocol::AccountInfo { name: "PC\\A".into(), sid: "S-1".into() }]),
        });
        let m = items_of(&p);
        assert_eq!(m["firewall.private"], "false");
        assert_eq!(m["bitlocker"], "error: x");
        assert_eq!(m["defender.realtime"], "false");
        assert_eq!(m["password.min_length"], "8");
        assert_eq!(m["admin:PC\\A"], "S-1");
    }
```

Run: `cargo test -p endpoint-server --test inventory security_and_registry`、`cargo test -p endpoint-server --lib diff`
Expected: FAIL（`unimplemented!` panic，或 migration 不存在）。

- [ ] **Step 2: migration**

```sql
-- 第三期：組態基準
CREATE TABLE device_security (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    firewall   JSONB NOT NULL,
    bitlocker  JSONB NOT NULL,
    defender   JSONB NOT NULL,
    password   JSONB NOT NULL,
    admins     JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_registry (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    path      TEXT NOT NULL,
    name      TEXT NOT NULL,
    state     TEXT NOT NULL CHECK (state IN ('present', 'absent', 'denied')),
    kind      TEXT NOT NULL,
    data      TEXT NOT NULL,
    PRIMARY KEY (device_id, path, name)
);
CREATE INDEX device_registry_value_idx ON device_registry (path, name);

INSERT INTO settings (key, value) VALUES
    ('security_interval_secs', '3600'),
    ('registry_interval_secs', '3600'),
    ('registry_max_values', '1000');
```

- [ ] **Step 3: 實作**

- `inventory.rs`：
  - `write_payload` 的 `Security`：`INSERT ... ON CONFLICT (device_id) DO UPDATE`，每一項以 `serde_json::to_string(&probe)` 加 `::jsonb` 寫入。
  - `write_payload` 的 `Registry`：先 `DELETE`，再用 UNNEST 批次 `INSERT`；`state`／`kind` 的字串以 `serde_json::to_value(x)?.as_str()` 取得。
  - `load_payload`：以 `::text` 讀回後 `serde_json::from_str`。`device_registry` 讀回時 `ORDER BY path, name`（`normalize` 也會排序，雜湊一致）。
- `diff.rs`：
  - `Security`：`firewall.domain`／`private`／`public`；`bitlocker:<drive>` → `protected`；`defender.active`／`realtime`／`tamper`／`signature_updated`（日期以 RFC 3339 表示，只取到日）；`password.min_length`／`max_age_days`／`lockout_threshold`；`admin:<name>` → sid。
  - `Probe::Error(e)` 時，以項目名稱為鍵，值為 `error: {e}`。
  - `Registry`：鍵為 `{path}\{name}`，值為 `{state}|{kind}|{data}`。
  - 同時更新檔頭的對照表。
- `checkin.rs`：`CheckinResponse` 補上 `registry_queries: vec![]` 與 `registry_queries_hash: Some(protocol::regpath::queries_hash(&[]))`。
- `db.rs`：`load_settings` 的 `LIKE '%_secs'` 已涵蓋新設定；`intervals` 補上 `security_secs: get("security_interval_secs", 3600, MIN_COLLECT_SECS)` 與 `registry_secs`。

- [ ] **Step 4: 執行**

Run: `cargo test --workspace`
Expected: 全部 PASS。

- [ ] **Step 5: 靜態檢查與 Commit**

Run: `cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`

```bash
git add -A crates
git commit -m "伺服器：保存 security／registry 區段與變更歷史；報到回應宣告支援"
```
