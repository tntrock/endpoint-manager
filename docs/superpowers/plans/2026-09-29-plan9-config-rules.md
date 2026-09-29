# 計畫 9：組態規則與評估 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 合規引擎新增七種組態規則，登錄檔規則所需的值經報到回應下發給 Agent，上傳的新區段觸發評估。

**Architecture:**
- `compliance/rules.rs` 新增七種 `Params`／`Check`。
- `compliance/evaluate.rs` 的 `DeviceFacts` 加入 `security`、`registry`、`services`、`agent_version`、`now`，並實作七種比對與中文摘要。
- `RuleSet` 從啟用中的登錄檔規則彙總出查詢清單與雜湊。報到回應由規則快取取得這份清單（快取最多每 5 秒確認一次 generation）。
- 建立或修改規則時，檢查查詢清單總數是否超過 `registry_max_values`。上傳時只保存清單內的值。

**Tech Stack:** Rust、sqlx、serde_json；不加新相依。

**Spec:** `docs/superpowers/specs/2026-09-29-config-baseline-design.md`（§3、§4.2、§4.3）

**前置：** 計畫 8 已合併（`protocol` 新型別與 `regpath`、Agent 收集、`device_security`／`device_registry`）。

## Global Constraints

- 使用者可見文字用繁體中文。
- 評估維持純函式：「現在時間」由呼叫端放進 `DeviceFacts.now`，不在評估時呼叫 `Utc::now()`。
- 路徑守衛使用 `protocol::regpath::check`，與 Agent 完全相同。
- 報到路徑不能每次都多查資料庫：規則快取的 generation 確認最多每 5 秒一次。
- 測試指令：`cargo test -p endpoint-server`。最後執行 clippy 與 fmt。

## Review Focus

1. 查詢清單與「上傳時只保存清單內的值」必須用同一種比對（路徑與名稱都不分大小寫），否則值會被誤丟，規則永遠是「未知」。
2. 路徑以不同寫法建立的兩條規則（`hklm\x` 與 `HKLM\X`）只算一個查詢，不能重複佔用上限。
3. 舊版 Agent（沒有 `security`／`registry`）的結果是「未知」，並註明「Agent 版本過舊」，不能算違規。
4. 數字比對：DWORD 以十進位字串回報，`expected` 也可能是 `0x...` 十六進位，兩者都要能比；非數字時 `gte`／`lte` 為「未知」。
5. 規則停用後查詢清單會變小，Agent 下一輪不再回報那些值；伺服器上殘留的舊值不能影響其他規則。

---

## File Structure

- Create: `crates/server/migrations/0008_config_rules.sql`：kind 限制加入七種新類型；新增 `template_key` 欄位。
- Modify: `crates/server/src/compliance/rules.rs`：七種 `Params`／`Check`、`KINDS`、`kind_label`、`RuleSet.registry_queries`。
- Modify: `crates/server/src/compliance/evaluate.rs`：`DeviceFacts` 新欄位、七種比對、`summarize`。
- Modify: `crates/server/src/compliance/store.rs`：`load_ruleset` 彙總查詢清單；`load_facts`／`load_facts_bulk` 載入新資料。
- Modify: `crates/server/src/compliance/mod.rs`：`RuleCache::get_throttled`、`affects_compliance`、`registry_filter`。
- Modify: `crates/server/src/compliance/admin.rs`：檢查查詢清單上限。
- Modify: `crates/server/src/checkin.rs`：由快取取得查詢清單。
- Modify: `crates/server/src/inventory.rs`：上傳 registry 時只保留清單內的值。
- Test: `crates/server/src/compliance/{rules,evaluate}.rs`（單元）、`crates/server/tests/config_rules.rs`（新增，整合）。

---

### Task 1: 七種規則的參數與驗證

**Files:**
- Create: `crates/server/migrations/0008_config_rules.sql`
- Modify: `crates/server/src/compliance/rules.rs`

**Interfaces:**
- Produces：
  - `KINDS` 新增：`registry_value`、`service_state`、`firewall`、`bitlocker`、`defender`、`password_policy`、`local_admins`。`kind_label` 依序為：登錄檔值、服務、防火牆、BitLocker、Defender、密碼原則、本機管理員。
  - `pub enum RegOp { Equals, NotEquals, Gte, Lte, Contains, Exists, NotExists }`，含 `as_str`、`parse`、`label`（等於、不等於、大於等於、小於等於、包含、存在、不存在）。
  - `Params`／`Check` 新變體（`Check` 與 `Params` 相同，多一個預先轉大寫的比對鍵）：
    - `RegistryValue { path: String /*正規化*/, name: String, op: RegOp, expected: Option<String>, absent_ok: bool }`
    - `ServiceState { name: String, require_running: bool }`
    - `Firewall { domain: bool, private: bool, public: bool }`（至少一個為 true）
    - `Bitlocker { all_fixed: bool }`
    - `Defender { realtime: bool, max_signature_age_days: Option<u32>, tamper: bool }`（至少一項）
    - `PasswordPolicy { min_length: Option<u32>, max_age_days: Option<u32>, max_lockout_threshold: Option<u32> }`（至少一項）
    - `LocalAdmins { allowed: Vec<String> }`（`Check` 版本為 `Vec<Glob>`，至少一個）
  - JSON 參數格式：
    - registry：`{"path","name","op","expected"?,"absent_ok"?}`
    - service：`{"name","require":"disabled"|"running"}`
    - firewall：`{"profiles":["domain","private","public"]}`
    - bitlocker：`{"scope":"system"|"all_fixed"}`
    - defender：`{"realtime"?:bool,"max_signature_age_days"?:u32,"tamper"?:bool}`
    - password：`{"min_length"?,"max_age_days"?,"max_lockout_threshold"?}`
    - admins：`{"allowed":[...]}`
  - `pub fn parse_number(s: &str) -> Option<u64>`：十進位或 `0x` 十六進位。
  - `impl Params { pub fn registry_query(&self) -> Option<RegistryQuery> }`

- [ ] **Step 1: 寫失敗測試**（`rules.rs` 的 `mod tests`）

```rust
    #[test]
    fn config_params_parse_and_normalize() {
        let p = Params::parse("registry_value", &json!({
            "path": "hklm/Software/Policies/X", "name": "Y", "op": "equals", "expected": "1"
        })).unwrap();
        assert_eq!(p.to_json(), json!({"path": "HKLM\\Software\\Policies\\X", "name": "Y", "op": "equals", "expected": "1"}));
        assert_eq!(p.registry_query().unwrap().path, r"HKLM\Software\Policies\X");
        let p = Params::parse("registry_value", &json!({"path": r"HKLM\A", "name": "B", "op": "exists"})).unwrap();
        assert_eq!(p.to_json(), json!({"path": r"HKLM\A", "name": "B", "op": "exists"}), "exists 不需要 expected");
        let p = Params::parse("registry_value", &json!({"path": r"HKLM\A", "name": "", "op": "equals", "expected": "x", "absent_ok": true})).unwrap();
        assert_eq!(p.to_json()["absent_ok"], true);
        assert_eq!(Params::parse("firewall", &json!({"profiles": ["public", "domain", "public"]})).unwrap().to_json(),
                   json!({"profiles": ["domain", "public"]}));
        assert_eq!(Params::parse("service_state", &json!({"name": " RemoteRegistry ", "require": "disabled"})).unwrap().to_json(),
                   json!({"name": "RemoteRegistry", "require": "disabled"}));
        assert!(Params::parse("defender", &json!({"realtime": true})).is_ok());
        assert!(Params::parse("password_policy", &json!({"min_length": 12})).is_ok());
        assert!(Params::parse("local_admins", &json!({"allowed": ["*\\Administrator"]})).is_ok());
        assert!(Params::parse("bitlocker", &json!({"scope": "all_fixed"})).is_ok());
    }

    #[test]
    fn config_params_reject_bad_input() {
        for (kind, v) in [
            ("registry_value", json!({"path": r"HKLM\SAM\SAM", "name": "x", "op": "exists"})),
            ("registry_value", json!({"path": r"HKCU\Software", "name": "x", "op": "exists"})),
            ("registry_value", json!({"path": r"HKLM\A", "name": "x", "op": "equals"})),
            ("registry_value", json!({"path": r"HKLM\A", "name": "x", "op": "gte", "expected": "abc"})),
            ("registry_value", json!({"path": r"HKLM\A", "name": "x", "op": "nope", "expected": "1"})),
            ("service_state", json!({"name": "", "require": "disabled"})),
            ("service_state", json!({"name": "x", "require": "maybe"})),
            ("firewall", json!({"profiles": []})),
            ("firewall", json!({"profiles": ["lan"]})),
            ("bitlocker", json!({"scope": "usb"})),
            ("defender", json!({})),
            ("defender", json!({"realtime": false, "tamper": false})),
            ("password_policy", json!({})),
            ("local_admins", json!({"allowed": []})),
        ] {
            assert!(Params::parse(kind, &v).is_err(), "{kind} {v}");
        }
    }

    #[test]
    fn numbers_accept_hex() {
        assert_eq!(parse_number("255"), Some(255));
        assert_eq!(parse_number("0xFF"), Some(255));
        assert_eq!(parse_number(" 0x0 "), Some(0));
        assert_eq!(parse_number("-1"), None);
        assert_eq!(parse_number("abc"), None);
    }
```

Run: `cargo test -p endpoint-server --lib rules::tests`
Expected: 編譯錯誤。

- [ ] **Step 2: migration 0008**

```sql
-- 第三期：組態規則類型；範本識別
ALTER TABLE compliance_rules DROP CONSTRAINT compliance_rules_kind_check;
ALTER TABLE compliance_rules ADD CONSTRAINT compliance_rules_kind_check CHECK (kind IN (
    'forbidden_software', 'required_software', 'software_allowlist', 'os_build', 'required_kb',
    'registry_value', 'service_state', 'firewall', 'bitlocker', 'defender', 'password_policy',
    'local_admins'));
ALTER TABLE compliance_rules ADD COLUMN template_key TEXT;
CREATE UNIQUE INDEX compliance_rules_template_key_idx ON compliance_rules (template_key)
    WHERE template_key IS NOT NULL;
```

（0004 的限制沒有命名，PostgreSQL 預設名稱是 `compliance_rules_kind_check`。先以 `\d compliance_rules` 確認實際名稱。）

- [ ] **Step 3: 實作**

- 各類型用 `#[serde(deny_unknown_fields)]` 的 Raw 結構解析，方式與既有類型相同，並沿用 `opt`／`required` 輔助函式。
- `registry_value`：
  - `path` 先 `regpath::normalize`（錯誤訊息直接回給使用者），再 `regpath::check`（失敗回 `DENIED_MESSAGE`）。
  - `name` 可為空字串（代表機碼的預設值），最多 256 字，去頭尾空白。
  - `expected`：`Exists`／`NotExists` 不看；其他必填。`Gte`／`Lte` 必須能被 `parse_number` 解析。
  - `absent_ok` 預設 false，`to_json` 只在 true 時輸出。
- `firewall`：`profiles` 去重後依 domain、private、public 的順序輸出。
- `defender`：`realtime`、`tamper` 預設 false；至少要有一項為 true 或設定了天數。
- `to_json` 與 `compile` 補上新分支；`kind()` 補上新類型。

- [ ] **Step 4: 執行並 Commit**

Run: `cargo test -p endpoint-server --lib rules::tests`
Expected: PASS。

```bash
git add -A crates/server
git commit -m "合規：七種組態規則的參數與驗證"
```

---

### Task 2: 評估與摘要

**Files:**
- Modify: `crates/server/src/compliance/evaluate.rs`

**Interfaces:**
- Produces：
  - `DeviceFacts` 新增欄位：
    - `security: Option<SecurityInfo>`
    - `registry: Option<HashMap<(String, String), RegistryValue>>`：鍵為 (`PATH` 大寫, `NAME` 大寫)。
    - `services: Option<Vec<ServiceFact>>`
    - `agent_version: Option<String>`
    - `now: DateTime<Utc>`
  - `pub struct ServiceFact { pub name: String, pub start_mode: String, pub state: String }`
  - `pub const CONFIG_AGENT_VERSION: &str = "0.3.0"`：低於這個版本且沒有新區段時，未知原因為 `agent_outdated`。
  - `pub fn registry_key(path: &str, name: &str) -> (String, String)`：轉大寫，查詢清單、上傳過濾、評估三處共用。

- [ ] **Step 1: 寫失敗測試**（加在 `evaluate.rs` 的 `mod tests`）

```rust
    fn cfg_facts() -> DeviceFacts {
        let mut reg = HashMap::new();
        let mut put = |p: &str, n: &str, state: RegState, kind: RegKind, data: &str| {
            reg.insert(registry_key(p, n), RegistryValue { path: p.into(), name: n.into(), state, kind, data: data.into() });
        };
        put(r"HKLM\A", "Dw", RegState::Present, RegKind::Dword, "5");
        put(r"HKLM\A", "Sz", RegState::Present, RegKind::String, "Hello World");
        put(r"HKLM\A", "Gone", RegState::Absent, RegKind::None, "");
        put(r"HKLM\A", "Secret", RegState::Denied, RegKind::None, "");
        DeviceFacts {
            security: Some(SecurityInfo {
                firewall: Probe::Ok(FirewallInfo { domain: true, private: true, public: false }),
                bitlocker: Probe::Ok(vec![
                    VolumeInfo { drive: "C:".into(), is_system: true, protected: true },
                    VolumeInfo { drive: "D:".into(), is_system: false, protected: false },
                ]),
                defender: Probe::Ok(DefenderInfo { active: true, realtime: true, tamper: false,
                    signature_updated: Some(Utc::now() - chrono::Duration::days(10)) }),
                password: Probe::Ok(PasswordPolicy { min_length: 8, max_age_days: 0, lockout_threshold: 5 }),
                admins: Probe::Ok(vec![
                    AccountInfo { name: r"PC\Administrator".into(), sid: "S-1-5-21-1-500".into() },
                    AccountInfo { name: r"CORP\bob".into(), sid: "S-1-5-21-2-1100".into() },
                ]),
            }),
            registry: Some(reg),
            services: Some(vec![
                ServiceFact { name: "RemoteRegistry".into(), start_mode: "Manual".into(), state: "Stopped".into() },
                ServiceFact { name: "WinDefend".into(), start_mode: "Auto".into(), state: "Running".into() },
            ]),
            ..facts(vec![])
        }
    }

    fn status(kind: &str, p: serde_json::Value) -> Option<Status> {
        one(&cfg_facts(), kind, p).map(|x| x.0)
    }

    #[test]
    fn registry_value_rules() {
        let r = |op: &str, name: &str, exp: Option<&str>| {
            let mut v = json!({"path": r"hklm\a", "name": name, "op": op});
            if let Some(e) = exp { v["expected"] = json!(e); }
            status("registry_value", v)
        };
        assert_eq!(r("equals", "Dw", Some("5")), None, "路徑、名稱不分大小寫");
        assert_eq!(r("equals", "dw", Some("0x5")), None, "十六進位");
        assert_eq!(r("gte", "Dw", Some("6")), Some(Status::Violating));
        assert_eq!(r("lte", "Dw", Some("5")), None);
        assert_eq!(r("equals", "Sz", Some("hello world")), None, "字串不分大小寫");
        assert_eq!(r("contains", "Sz", Some("WORLD")), None);
        assert_eq!(r("not_equals", "Sz", Some("Hello World")), Some(Status::Violating));
        assert_eq!(r("gte", "Sz", Some("1")), Some(Status::Unknown), "非數字");
        assert_eq!(r("equals", "Gone", Some("1")), Some(Status::Violating));
        assert_eq!(r("exists", "Gone", None), Some(Status::Violating));
        assert_eq!(r("not_exists", "Gone", None), None);
        assert_eq!(r("not_exists", "Dw", None), Some(Status::Violating));
        assert_eq!(r("equals", "Secret", Some("1")), Some(Status::Unknown), "拒絕讀取");
        assert_eq!(r("equals", "NotCollectedYet", Some("1")), Some(Status::Unknown));
        let ok = status("registry_value", json!({"path": r"HKLM\A", "name": "Gone", "op": "equals", "expected": "1", "absent_ok": true}));
        assert_eq!(ok, None, "未設定時視為符合");
    }

    #[test]
    fn service_rules() {
        assert_eq!(status("service_state", json!({"name": "remoteregistry", "require": "disabled"})), Some(Status::Violating));
        assert_eq!(status("service_state", json!({"name": "NotInstalled", "require": "disabled"})), None, "沒安裝算符合");
        assert_eq!(status("service_state", json!({"name": "WinDefend", "require": "running"})), None);
        assert_eq!(status("service_state", json!({"name": "NotInstalled", "require": "running"})), Some(Status::Violating));
        assert_eq!(status("service_state", json!({"name": "RemoteRegistry", "require": "running"})), Some(Status::Violating));
    }

    #[test]
    fn security_rules() {
        assert_eq!(status("firewall", json!({"profiles": ["domain", "private"]})), None);
        let (st, d) = one(&cfg_facts(), "firewall", json!({"profiles": ["public"]})).unwrap();
        assert_eq!((st, d["profiles_off"].clone()), (Status::Violating, json!(["public"])));
        assert_eq!(status("bitlocker", json!({"scope": "system"})), None);
        assert_eq!(status("bitlocker", json!({"scope": "all_fixed"})), Some(Status::Violating));
        assert_eq!(status("defender", json!({"realtime": true})), None);
        assert_eq!(status("defender", json!({"tamper": true})), Some(Status::Violating));
        assert_eq!(status("defender", json!({"max_signature_age_days": 7})), Some(Status::Violating));
        assert_eq!(status("defender", json!({"max_signature_age_days": 14})), None);
        assert_eq!(status("password_policy", json!({"min_length": 12})), Some(Status::Violating));
        assert_eq!(status("password_policy", json!({"max_age_days": 365})), Some(Status::Violating), "0＝永不過期");
        assert_eq!(status("password_policy", json!({"max_lockout_threshold": 10})), None);
        let (st, d) = one(&cfg_facts(), "local_admins", json!({"allowed": ["*\\administrator"]})).unwrap();
        assert_eq!((st, d["accounts"].clone()), (Status::Violating, json!(["CORP\\bob"])));
        assert_eq!(status("local_admins", json!({"allowed": ["*\\Administrator", "CORP\\*"]})), None);
    }

    #[test]
    fn missing_config_data_is_unknown_with_reason() {
        let mut f = cfg_facts();
        f.security = None;
        f.registry = None;
        f.agent_version = Some("0.2.1".into());
        let (st, d) = one(&f, "firewall", json!({"profiles": ["public"]})).unwrap();
        assert_eq!((st, d["reason"].as_str()), (Status::Unknown, Some("agent_outdated")));
        f.agent_version = Some("0.3.0".into());
        let (_, d) = one(&f, "registry_value", json!({"path": r"HKLM\A", "name": "x", "op": "exists"})).unwrap();
        assert_eq!(d["reason"], "no_data");
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.defender = Probe::Ok(DefenderInfo { active: false, realtime: false, tamper: false, signature_updated: None });
            s.bitlocker = Probe::Error("no BitLocker".into());
        }
        let (st, d) = one(&f, "defender", json!({"realtime": true})).unwrap();
        assert_eq!((st, d["reason"].as_str()), (Status::Unknown, Some("defender_inactive")));
        let (st, d) = one(&f, "bitlocker", json!({"scope": "system"})).unwrap();
        assert_eq!((st, d["reason"].as_str()), (Status::Unknown, Some("probe_error")));
    }

    #[test]
    fn config_summaries() {
        for (d, want) in [
            (json!({"reason": "agent_outdated"}), "Agent 版本過舊，未回報這項資料"),
            (json!({"reason": "not_collected"}), "Agent 尚未回報這個登錄檔值"),
            (json!({"reason": "denied"}), "不允許讀取這個登錄檔值"),
            (json!({"reason": "defender_inactive"}), "Defender 不是作用中的防毒"),
            (json!({"reason": "probe_error", "error": "x"}), "收集失敗：x"),
            (json!({"profiles_off": ["public"]}), "防火牆未啟用：公用"),
            (json!({"drives": ["D:"]}), "未加密保護：D:"),
            (json!({"reason": "no_system_volume"}), "找不到系統磁碟"),
            (json!({"accounts": ["CORP\\bob"]}), "不允許的管理員：CORP\\bob"),
            (json!({"service": "Spooler", "start_mode": "Auto", "state": "Running"}), "服務 Spooler：Auto／Running"),
            (json!({"reason": "not_installed", "service": "X"}), "服務 X 未安裝"),
            (json!({"registry": "HKLM\\A\\B", "actual": "0", "op": "equals", "expected": "1"}), "HKLM\\A\\B = 0，要求 等於 1"),
            (json!({"registry": "HKLM\\A\\B", "reason": "absent"}), "HKLM\\A\\B 未設定"),
            (json!({"failed": ["min_length"], "min_length": 8, "required_min_length": 12}), "最短長度 8，需要 12"),
            (json!({"failed": ["realtime", "signature"], "signature_age_days": 10}), "即時保護未開啟、病毒碼 10 天未更新"),
        ] {
            assert_eq!(summarize(&d), want, "{d}");
        }
    }
```

（`facts()`、`one()`、`set()` 沿用檔內既有的測試輔助函式。`facts()` 需補上新欄位，`now` 設為 `Utc::now()`。）

Run: `cargo test -p endpoint-server --lib evaluate::tests`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作**

- `check_one` 新增七個分支。細節欄位：
  - registry：違規時 `{"registry": "<path>\\<name>", "actual", "op", "expected"}`；值不存在時 `{"registry", "reason": "absent"}`。
  - service：`{"service", "start_mode", "state"}`，或 `{"reason": "not_installed", "service"}`。
  - firewall：`{"profiles_off": [...]}`
  - bitlocker：`{"drives": [...]}`，或 `{"reason": "no_system_volume"}`。
  - defender：`{"failed": [...], "signature_age_days"?}`
  - password：`{"failed": [...], "min_length", "required_min_length", ...}`，只列出失敗的項目。
  - admins：`{"accounts": [前 50 個], "total"}`
- 缺資料時：
  - `security`／`registry` 為 None：`agent_version` 低於 `CONFIG_AGENT_VERSION`（以 `cmp_version` 比較）時回 `{"reason": "agent_outdated"}`，否則回 `no_data`。
  - `Probe::Error(e)`：`{"reason": "probe_error", "error": e}`
  - 登錄檔值不在 map：`{"reason": "not_collected", "registry": ...}`
  - 被拒絕：`{"reason": "denied", "registry": ...}`
- 登錄檔比對：
  - 值的類型是 `Dword`／`Qword` 且 `expected` 能被 `parse_number` 解析時，以數值比較；其他以不分大小寫的字串比較。
  - `Gte`／`Lte` 時，任一邊不是數字就回 `{"reason": "not_numeric", ...}`（未知）。
- Defender 的天數：`(facts.now - signature_updated).num_days()`；沒有 `signature_updated` 時為未知，`reason = "signature_unknown"`。
- 服務：名稱不分大小寫；`start_mode` 為 `Disabled` 即視為停用。
- `summarize` 補上 Step 1 測試列出的所有格式。設定檔的中文名稱：domain＝網域、private＝私人、public＝公用。

- [ ] **Step 3: 執行並 Commit**

Run: `cargo test -p endpoint-server --lib evaluate`
Expected: PASS。

```bash
git add -A crates/server
git commit -m "合規：組態規則評估與摘要"
```

---

### Task 3: 讀取新事實、查詢清單彙總、報到下發、上傳過濾

**Files:**
- Modify: `crates/server/src/compliance/store.rs`、`crates/server/src/compliance/mod.rs`、`crates/server/src/compliance/rules.rs`（`RuleSet` 欄位）
- Modify: `crates/server/src/checkin.rs`、`crates/server/src/inventory.rs`
- Create: `crates/server/tests/config_rules.rs`

**Interfaces:**
- Produces：
  - `RuleSet` 新增 `registry_queries: Vec<RegistryQuery>`（去重後依路徑、名稱排序）、`registry_hash: String`、`registry_keys: HashSet<(String, String)>`；三者由 `load_ruleset` 與 `RuleSet::empty` 一起算好。
  - `RuleCache::get_throttled(&self, pool) -> Result<Arc<RuleSet>, sqlx::Error>`：距離上次確認 generation 不到 5 秒時直接回傳快取。
  - `compliance::affects_compliance` 加上 `Security`、`Registry`、`Services`。
  - `load_facts`／`load_facts_bulk` 讀 `device_security`、`device_registry`、`device_services`（name、start_mode、state），以及 `devices.agent_version`；`now = Utc::now()`。

- [ ] **Step 1: 寫失敗的整合測試**（`tests/config_rules.rs`）

測試檔開頭沿用 `tests/compliance.rs` 的 `mod common;`、`put`、`setup`、`violations` 輔助函式（複製過來）。

```rust
use endpoint_server::compliance::admin::{self, RuleInput};

fn reg_rule(path: &str, name: &str) -> RuleInput {
    RuleInput {
        name: format!("{path}\\{name}"),
        description: String::new(),
        kind: "registry_value".into(),
        severity: "high".into(),
        enabled: true,
        params: serde_json::json!({"path": path, "name": name, "op": "equals", "expected": "1"}),
        include: vec![],
        exclude: vec![],
    }
}

async fn checkin(s: &TestServer, a: &TestAgent) -> protocol::CheckinResponse {
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.3.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn registry_rule_drives_queries_evaluation_and_filtering(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let id = admin::create_rule(&s.pool, &reg_rule(r"hklm\SOFTWARE\Policies\X", "Y"), "admin").await.unwrap();
    // 同一個值、不同寫法：不重複
    admin::create_rule(&s.pool, &reg_rule(r"HKLM\software\policies\x", "y"), "admin").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let r = checkin(&s, &a).await;
    assert_eq!(r.registry_queries.len(), 1, "{:?}", r.registry_queries);
    assert_eq!(r.registry_queries_hash.as_deref(), Some(protocol::regpath::queries_hash(&r.registry_queries).as_str()));

    let v = |name: &str, data: &str| protocol::RegistryValue {
        path: r"HKLM\SOFTWARE\Policies\X".into(), name: name.into(),
        state: protocol::RegState::Present, kind: protocol::RegKind::Dword, data: data.into(),
    };
    put(&s, &a, protocol::InventoryPayload::Registry(vec![v("Y", "0"), v("NotAsked", "1")])).await;
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM device_registry WHERE device_id = $1")
        .bind(a.device_id).fetch_one(&s.pool).await.unwrap();
    assert_eq!(stored, 1, "清單外的值被丟棄");
    assert!(violations(&s, &a).await.contains(&(id, "violating".to_string())));
}

#[sqlx::test(migrations = false)]
async fn registry_value_cap_is_enforced(pool: PgPool) {
    let s = TestServer::start(pool).await;
    sqlx::query("UPDATE settings SET value = '2' WHERE key = 'registry_max_values'")
        .execute(&s.pool).await.unwrap();
    admin::create_rule(&s.pool, &reg_rule(r"HKLM\A", "1"), "admin").await.unwrap();
    admin::create_rule(&s.pool, &reg_rule(r"HKLM\A", "2"), "admin").await.unwrap();
    let err = admin::create_rule(&s.pool, &reg_rule(r"HKLM\A", "3"), "admin").await.unwrap_err();
    assert!(format!("{err:#}").contains("registry_max_values"), "{err:#}");
    // 停用的規則不佔上限
    let mut off = reg_rule(r"HKLM\A", "3");
    off.enabled = false;
    admin::create_rule(&s.pool, &off, "admin").await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn security_and_services_uploads_trigger_evaluation(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let fw = admin::create_rule(&s.pool, &RuleInput {
        kind: "firewall".into(),
        params: serde_json::json!({"profiles": ["public"]}),
        ..reg_rule(r"HKLM\A", "B")
    }, "admin").await.unwrap();
    let svc = admin::create_rule(&s.pool, &RuleInput {
        kind: "service_state".into(),
        params: serde_json::json!({"name": "RemoteRegistry", "require": "disabled"}),
        ..reg_rule(r"HKLM\A", "B")
    }, "admin").await.unwrap();
    put(&s, &a, protocol::InventoryPayload::Security(protocol::SecurityInfo {
        firewall: protocol::Probe::Ok(protocol::FirewallInfo { domain: true, private: true, public: false }),
        bitlocker: protocol::Probe::Error("x".into()),
        defender: protocol::Probe::Error("x".into()),
        password: protocol::Probe::Error("x".into()),
        admins: protocol::Probe::Error("x".into()),
    })).await;
    put(&s, &a, protocol::InventoryPayload::Services(vec![protocol::ServiceItem {
        name: "RemoteRegistry".into(), display_name: None, start_mode: "Manual".into(),
        state: "Stopped".into(), binary_path: None,
    }])).await;
    let v = violations(&s, &a).await;
    assert!(v.contains(&(fw, "violating".into())) && v.contains(&(svc, "violating".into())), "{v:?}");
}
```

Run: `cargo test -p endpoint-server --test config_rules`
Expected: FAIL。

- [ ] **Step 2: 實作**

- `rules.rs`：`RuleSet` 新增三個欄位。`RuleSet::empty()` 的清單為空，雜湊為 `queries_hash(&[])`。
- `store.rs`：
  - `load_ruleset` 建完 rules 後，走訪啟用中且 `check` 為 `Ok(Check::RegistryValue{..})` 的規則，以 `registry_key` 去重，組成 `registry_queries`（使用規則裡正規化後的路徑與名稱）、`registry_keys` 與 `registry_hash`。
  - `load_facts`：
    - 讀 `device_security`，以 `serde_json::from_str::<Probe<..>>` 還原各項。
    - 讀 `device_registry` 組成 map。
    - 讀 `device_services`。
    - `agent_version` 從 `devices` 讀取。
    - 區段是否存在由 `inventory_sections` 判斷，沒有上傳過就是 None。
  - `load_facts_bulk` 以 `= ANY($1)` 批次讀取這些資料。
- `mod.rs`：

```rust
pub struct RuleCache {
    current: RwLock<Arc<RuleSet>>,
    /// 上次確認 generation 的時間：報到路徑最多每 5 秒查一次資料庫
    checked: std::sync::Mutex<Option<std::time::Instant>>,
}

pub const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

    pub async fn get_throttled(&self, pool: &PgPool) -> Result<Arc<RuleSet>, sqlx::Error> {
        let fresh_enough = self
            .checked
            .lock()
            .expect("cache lock")
            .is_some_and(|t| t.elapsed() < CHECK_EVERY);
        if fresh_enough {
            return Ok(self.current.read().await.clone());
        }
        let r = self.get(pool).await?;
        *self.checked.lock().expect("cache lock") = Some(std::time::Instant::now());
        Ok(r)
    }
```

  既有的 `get()` 不變，上傳評估仍然每次確認，保持即時。
- `checkin.rs`：

```rust
    let rules = st.rules.get_throttled(&st.pool).await?;
    // ...
        registry_queries: rules.registry_queries.clone(),
        registry_queries_hash: Some(rules.registry_hash.clone()),
```

- `inventory.rs` 的 `upload`：`parse_upload` 之後，若 payload 是 `Registry`，以 `st.rules.get(&st.pool).await?.registry_keys` 過濾（用 `registry_key(path, name)` 比對），再交給 `store_section`。
  - 雜湊沿用 Agent 送來的完整內容雜湊。這樣 Agent 下次報到的雜湊相同，不會被要求重傳。
  - 伺服器讀回的內容是過濾後的，兩者不一致無妨，因為雜湊比對只用伺服器存的雜湊。
- `admin.rs`：`create_rule`／`update_rule` 在 `validate` 之後，如果是啟用中的 `registry_value`：
  - 在同一交易內讀出其他啟用中的 `registry_value` 規則參數（更新時排除自己），以 `registry_key` 去重，加上這一條後計數。
  - 超過 `registry_max_values`（從 settings 讀，壞值用 1000，範圍夾在 1–5000）時，回 `ensure!` 錯誤：`「登錄檔規則需要的值共 {n} 個，超過上限 {max}（可在設定 registry_max_values 調整，最高 5000）」`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 4: 全部檢查並 Commit**

Run: `cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`

```bash
git add -A crates/server
git commit -m "合規：登錄檔查詢清單下發、上傳過濾、上限檢查；新區段觸發評估"
```
