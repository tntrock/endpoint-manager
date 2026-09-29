# 計畫 10：組態基準網頁、內建範本與負載測試 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 管理員能在網頁上建立七種組態規則、從內建範本一鍵建立、查看裝置的安全設定、查詢全公司的登錄檔值；並以 30,000 台 × 1,000 個登錄檔值驗證效能。

**Architecture:**
- 沿用計畫 6 的規則表單（`web/rules.rs` 的 `RuleForm` → `form_to_input`、`params_to_form`），加入七種類型的欄位。
- 範本是內嵌的 `compliance/baseline.json`，透過 `admin::create_rule` 建立，並寫入 `template_key`。
- 裝置頁新增「安全設定」分頁（htmx 片段）。
- 新增 `/registry` 查詢頁，寫法比照軟體搜尋頁。
- loadsim 新增 `config` 指令，另附規則種子 SQL。

**Tech Stack:** Rust、axum、askama、htmx、sqlx；不加新相依。

**Spec:** `docs/superpowers/specs/2026-09-29-config-baseline-design.md`（§1.1、§4.4、§5）

**前置：** 計畫 8、9 已合併。

## Global Constraints

- 使用者可見文字用繁體中文。
- CSP 為 `default-src 'self'`：不能用 inline script 或 style。
- 權限：
  - 規則、範本只有平台管理員能建立或修改。
  - 安全設定分頁與登錄檔查詢依群組範圍顯示；範圍外的裝置回 404，也不計入統計。
- 範本不含公司特定內容。
- 範本的每個登錄檔路徑與值，都要在 Task 2 對照 Microsoft 文件（Learn）或 CIS 基準確認一次，並在 JSON 的 `source` 欄位記下出處。
- 測試指令：`cargo test -p endpoint-server`。最後執行 clippy 與 fmt。

## Review Focus

1. 範本 JSON 的每一條都要能通過 `Params::parse`；伺服器啟動時就解析範本，壞掉的範本不能等到使用者點下去才爆。
2. 用同一個範本建立兩次時，不能產生重複規則（`template_key` 唯一），重複的要略過並顯示出來。
3. 登錄檔查詢頁：群組管理員只統計自己範圍內的裝置；路徑輸入要正規化，大小寫不同也查得到。
4. 規則表單的七種類型在「新增 → 儲存 → 編輯」之後參數不變（來回轉換一致）。
5. 負載測試未達標時，要照實記錄，不能調整目標。

---

## File Structure

- Create: `crates/server/src/compliance/baseline.json`
- Create: `crates/server/src/compliance/templates.rs`：解析範本、`create_from_templates`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod templates;`）
- Modify: `crates/server/src/compliance/admin.rs`：`RuleInput` 新增 `template_key: Option<String>`
- Modify: `crates/server/src/web/rules.rs`、`crates/server/templates/rule_form.html`、`crates/server/templates/rules.html`：七種類型的表單與範本連結
- Create: `crates/server/templates/rule_templates.html`
- Modify: `crates/server/src/web/devices.rs`、`crates/server/src/web/compliance.rs`：安全設定分頁
- Create: `crates/server/templates/security_tab.html`
- Create: `crates/server/src/web/registry.rs`、`crates/server/templates/registry.html`
- Modify: `crates/server/src/web/mod.rs`、`crates/server/templates/base.html`
- Modify: `tools/loadsim/src/{lib,main}.rs`；Create: `tools/loadsim/config_rules.sql`
- Modify: `docs/loadtest.md`、`README.md`
- Create: `crates/server/tests/config_web.rs`

---

### Task 1: 規則表單支援七種類型

**Files:**
- Modify: `crates/server/src/web/rules.rs`、`crates/server/templates/rule_form.html`

**Interfaces:**
- `ParamFields` 新增欄位：
  - `reg_path`、`reg_name`、`reg_op`、`reg_expected`、`reg_absent_ok: bool`
  - `svc_name`、`svc_require`
  - `fw_domain`、`fw_private`、`fw_public`（皆為 bool）
  - `bl_scope`
  - `df_realtime: bool`、`df_days`、`df_tamper: bool`
  - `pw_min_length`、`pw_max_age`、`pw_max_lockout`
  - `admins_allowed`：textarea，每行一個
- 表單欄位名稱為 `p_` 加上上面的名稱，例如 `p_reg_path`；核取方塊送出時值為 `1`。
- `form_to_input` 與 `params_to_form` 支援七種類型，來回轉換的結果一致。

- [ ] **Step 1: 寫失敗的單元測試**（`web/rules.rs` 的 `mod tests`）

```rust
    #[test]
    fn config_kinds_roundtrip_through_form() {
        let cases = [
            ("registry_value", json!({"path": r"HKLM\SOFTWARE\X", "name": "Y", "op": "gte", "expected": "5", "absent_ok": true})),
            ("registry_value", json!({"path": r"HKLM\SOFTWARE\X", "name": "", "op": "not_exists"})),
            ("service_state", json!({"name": "RemoteRegistry", "require": "disabled"})),
            ("firewall", json!({"profiles": ["domain", "public"]})),
            ("bitlocker", json!({"scope": "all_fixed"})),
            ("defender", json!({"realtime": true, "max_signature_age_days": 7})),
            ("password_policy", json!({"min_length": 12, "max_lockout_threshold": 10})),
            ("local_admins", json!({"allowed": ["*\\Administrator", "CORP\\Domain Admins"]})),
        ];
        for (kind, params) in cases {
            let f = RuleForm {
                kind: kind.into(),
                name: "r".into(),
                severity: "high".into(),
                enabled: true,
                p: params_to_form(kind, &params),
                ..Default::default()
            };
            let input = form_to_input(&f).unwrap();
            let back = crate::compliance::rules::Params::parse(kind, &input.params).unwrap().to_json();
            assert_eq!(back, params, "{kind}");
        }
    }
```

Run: `cargo test -p endpoint-server --lib web::rules`
Expected: FAIL（新類型回「未知的規則類型」）。

- [ ] **Step 2: 實作**

- `parse_form` 認得新欄位。
- `form_to_input` 依類型組出計畫 9 定義的 JSON：
  - 數字欄位用既有的 `num()`。
  - 空的核取方塊為 false。
  - `admins_allowed` 依行切割、去頭尾空白、去掉空行。
  - 登錄檔的 `expected` 在 `exists`／`not_exists` 時不送。
- `params_to_form` 反向轉換。
- `rule_form.html` 依 `kind` 新增七個區塊：
  - 登錄檔：路徑、值名稱、比對方式（`<select>`）、期望值、「未設定時視為符合」核取方塊。提示「只能讀取 HKLM，不能讀取 SAM、SECURITY 與自動登入密碼；值名稱留空代表機碼的預設值」。
  - 服務：名稱，以及「必須停用／必須執行中」單選。
  - 防火牆：三個核取方塊。
  - BitLocker：「只看系統磁碟／所有固定磁碟」單選。
  - Defender：兩個核取方塊與天數。
  - 密碼原則：三個數字欄位，提示「只約束本機帳號；網域帳號由網域原則決定」。
  - 本機管理員：textarea，提示「每行一個，* 代表任意字元，例如 `*\Administrator`、`CORP\Domain Admins`」。
- `rules.html` 的「新增規則」連結會自動列出新類型（來自 `KINDS`）。

- [ ] **Step 3: 執行並 Commit**

Run: `cargo test -p endpoint-server --lib web::rules`、`cargo test -p endpoint-server --test compliance_web`
Expected: PASS。

```bash
git add -A crates/server
git commit -m "合規網頁：七種組態規則的表單"
```

---

### Task 2: 內建範本

**Files:**
- Create: `crates/server/src/compliance/baseline.json`、`crates/server/src/compliance/templates.rs`
- Modify: `crates/server/src/compliance/admin.rs`（`RuleInput.template_key`；`create_rule` 寫入）
- Modify: `crates/server/src/web/rules.rs`（`templates_page`、`create_from_templates`）、`crates/server/src/web/mod.rs`
- Create: `crates/server/templates/rule_templates.html`；Modify: `crates/server/templates/rules.html`（連結）
- Test: `crates/server/src/compliance/templates.rs`、`crates/server/tests/config_web.rs`

**Interfaces:**
- `baseline.json`：陣列，每個元素為 `{"key", "category", "name", "description", "severity", "kind", "params", "source"}`。
- `templates::Template`（對應 JSON 的結構）
- `templates::all() -> &'static [Template]`：第一次呼叫時解析內嵌 JSON（`OnceLock`），解析失敗就 panic（這是程式錯誤，測試會先抓到）。
- `templates::create(pool, keys: &[String], actor) -> anyhow::Result<(Vec<String> /*已建立*/, Vec<String> /*已存在而略過*/)>`
- 路由：`GET /compliance/rules/templates`、`POST /compliance/rules/templates`（平台管理員）。

- [ ] **Step 1: 寫失敗測試**

`templates.rs`：

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_parses_and_keys_are_unique() {
        let all = all();
        assert!(all.len() >= 20, "{}", all.len());
        let mut keys: Vec<&str> = all.iter().map(|t| t.key.as_str()).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), all.len(), "key 重複");
        for t in all {
            crate::compliance::rules::Params::parse(&t.kind, &t.params)
                .unwrap_or_else(|e| panic!("{}: {e}", t.key));
            assert!(crate::compliance::rules::Severity::parse(&t.severity).is_some(), "{}", t.key);
            assert!(!t.source.is_empty(), "{} 缺少出處", t.key);
        }
    }
}
```

`tests/config_web.rs`：

```rust
mod common;

use common::{TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn templates_create_rules_once(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/compliance/rules/templates").await;
    assert_eq!(st, 200);
    assert!(html.contains("防火牆") && html.contains("BitLocker"));
    let csrf = csrf_from(&html);
    let post = |keys: Vec<&'static str>| {
        let mut form: Vec<(&str, &str)> = vec![("csrf", csrf.as_str())];
        form.extend(keys.into_iter().map(|k| ("key", k)));
        let c = admin.clone();
        let url = s.web_url("/compliance/rules/templates");
        let body: Vec<(String, String)> = form.into_iter().map(|(a, b)| (a.into(), b.into())).collect();
        async move { c.post(url).form(&body).send().await.unwrap() }
    };
    let r = post(vec!["firewall_all_profiles", "bitlocker_system"]).await;
    assert_eq!(r.status(), 200);
    assert!(r.text().await.unwrap().contains("已建立 2 條"));
    let r = post(vec!["firewall_all_profiles"]).await;
    assert!(r.text().await.unwrap().contains("略過 1 條"), "重複的範本不再建立");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM compliance_rules WHERE template_key IS NOT NULL")
        .fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 2);
    let (_, html) = s.page(&admin, "/compliance/rules/templates").await;
    assert!(html.contains("已建立"), "已建立的範本有標示");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    assert_eq!(s.page(&g, "/compliance/rules/templates").await.0, 403);
}
```

（範本 key 以 `baseline.json` 實際使用的為準；測試裡的 `firewall_all_profiles`、`bitlocker_system` 必須存在於 JSON。）

Run: `cargo test -p endpoint-server --lib templates`、`cargo test -p endpoint-server --test config_web`
Expected: 編譯錯誤或 FAIL。

- [ ] **Step 2: 撰寫 `baseline.json`**

依 spec §4.4 的 24 條撰寫。每條登錄檔路徑、值名稱與期望值，都要先對照 Microsoft Learn 的原則說明（例如「Network security: LAN Manager authentication level」「SMB 1.0 停用」「WDigest」「LSA protection」「UAC」等頁面）或 CIS Microsoft Windows 11 Benchmark，把出處網址或章節編號寫進 `source`。

查不到權威出處的條目直接刪掉，並在 ledger 記一筆 Ruling，不要猜。範例：

```json
[
  {
    "key": "firewall_all_profiles",
    "category": "網路與防火牆",
    "name": "防火牆三個設定檔皆啟用",
    "description": "網域、私人、公用設定檔都必須啟用 Windows 防火牆。",
    "severity": "high",
    "kind": "firewall",
    "params": {"profiles": ["domain", "private", "public"]},
    "source": "CIS Microsoft Windows 11 Enterprise Benchmark 9.1.1 / 9.2.1 / 9.3.1"
  },
  {
    "key": "ntlmv2_only",
    "category": "帳號與密碼",
    "name": "只允許 NTLMv2",
    "description": "LmCompatibilityLevel 5：只送 NTLMv2 回應，拒絕 LM 與 NTLM。",
    "severity": "high",
    "kind": "registry_value",
    "params": {"path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "name": "LmCompatibilityLevel", "op": "gte", "expected": "5"},
    "source": "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"
  }
]
```

- [ ] **Step 3: 實作**

- `admin::RuleInput` 新增 `pub template_key: Option<String>`；既有建構處（網頁表單、測試）補上 `None`。
  - `create_rule` 的 INSERT 寫入 `template_key`。
  - 撞到唯一索引時回「這個範本已經建立過」。
- `templates::create`：
  - 逐條檢查 `SELECT 1 FROM compliance_rules WHERE template_key = $1`，存在就列入略過。
  - 否則以範本內容呼叫 `admin::create_rule`；`enabled` 為 true，範圍為全部裝置。
  - 登錄檔上限錯誤照常回報，已建立的保留。
- 網頁：
  - `templates_page`：依分類分組，每條顯示名稱、說明、嚴重度、是否已建立，並有核取方塊（`name="key"`）。
  - POST 以 `RawForm` 解析多個 `key`，建立後重新顯示頁面並附上結果訊息：「已建立 N 條、略過 M 條（已存在）」，另列出失敗原因。
- `rules.html`：平台管理員看到「從範本建立」連結。
- 路由：
  - `.route("/compliance/rules/templates", get(rules::templates_page).post(rules::create_from_templates))`
  - 這條要放在 `/compliance/rules/{id}` 之前。axum 0.8 的固定路徑優先於參數路徑，順序不影響，但寫在前面比較清楚。

- [ ] **Step 4: 執行並 Commit**

Run: `cargo test -p endpoint-server`
Expected: PASS。

```bash
git add -A crates/server
git commit -m "合規：內建組態基準範本與一鍵建立"
```

---

### Task 3: 裝置頁「安全設定」分頁與登錄檔值查詢

**Files:**
- Modify: `crates/server/src/web/devices.rs`（分頁清單加 `("security", "安全設定")`，`tab` 分派）
- Modify: `crates/server/src/web/compliance.rs`（`security_tab`）；Create: `crates/server/templates/security_tab.html`
- Create: `crates/server/src/web/registry.rs`、`crates/server/templates/registry.html`
- Modify: `crates/server/src/web/mod.rs`、`crates/server/templates/base.html`（導覽列加「登錄檔」）
- Test: `crates/server/tests/config_web.rs`

**Interfaces:**
- `GET /devices/{id}/tab/security`：範圍外回 404；沒有資料時顯示「尚未收到安全設定（Agent 版本需 0.3.0 以上）」。
- `GET /registry?path=&name=`：
  - 路徑先以 `regpath::normalize` 正規化，比對不分大小寫。
  - 列出「狀態／類型／值 → 台數」，只算範圍內使用中的裝置，最多 500 列。
  - 每列連到 `/registry/devices?path=&name=&state=&data=`，列出這些裝置（分頁）。
- `GET /registry/devices`：同樣依範圍過濾。

- [ ] **Step 1: 寫失敗的整合測試**

```rust
async fn device_with(s: &TestServer, group: &str, data: &str) -> common::TestAgent {
    let tok = s.create_group_token(group, 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    // 先建立會收集這個值的規則，上傳才不會被過濾掉
    let payload = protocol::InventoryPayload::Registry(vec![protocol::RegistryValue {
        path: r"HKLM\SOFTWARE\Policies\X".into(), name: "Y".into(),
        state: protocol::RegState::Present, kind: protocol::RegKind::Dword, data: data.into(),
    }]);
    let r = s.client(Some(&a)).put(s.url("/v1/inventory/registry"))
        .json(&protocol::InventoryUpload { schema_version: protocol::SCHEMA_VERSION, payload })
        .send().await.unwrap();
    assert_eq!(r.status(), 204);
    a
}

#[sqlx::test(migrations = false)]
async fn registry_query_is_scoped_and_case_insensitive(pool: PgPool) {
    let s = TestServer::start(pool).await;
    endpoint_server::compliance::admin::create_rule(&s.pool, &endpoint_server::compliance::admin::RuleInput {
        name: "x".into(), description: String::new(), kind: "registry_value".into(),
        severity: "low".into(), enabled: true,
        params: serde_json::json!({"path": r"HKLM\SOFTWARE\Policies\X", "name": "Y", "op": "exists"}),
        include: vec![], exclude: vec![], template_key: None,
    }, "admin").await.unwrap();
    device_with(&s, "台北", "1").await;
    device_with(&s, "高雄", "0").await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/registry?path=hklm%2Fsoftware%2Fpolicies%2Fx&name=y").await;
    assert!(html.contains(">1<") && html.contains(">0<"), "{html}");
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&g, "/registry?path=HKLM%5CSOFTWARE%5CPolicies%5CX&name=Y").await;
    assert!(!html.contains("高雄") && html.contains("共 1 台"), "{html}");
}

#[sqlx::test(migrations = false)]
async fn security_tab_shows_probes_and_errors(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let admin = s.admin_client().await;
    let tab = format!("/devices/{}/tab/security", a.device_id);
    let (_, html) = s.page(&admin, &tab).await;
    assert!(html.contains("尚未收到安全設定"));
    let payload = protocol::InventoryPayload::Security(protocol::SecurityInfo {
        firewall: protocol::Probe::Ok(protocol::FirewallInfo { domain: true, private: true, public: false }),
        bitlocker: protocol::Probe::Error("找不到 BitLocker".into()),
        defender: protocol::Probe::Ok(protocol::DefenderInfo { active: true, realtime: true, tamper: true, signature_updated: None }),
        password: protocol::Probe::Ok(protocol::PasswordPolicy { min_length: 12, max_age_days: 0, lockout_threshold: 5 }),
        admins: protocol::Probe::Ok(vec![protocol::AccountInfo { name: r"PC\Administrator".into(), sid: "S-1-5-21-1-500".into() }]),
    });
    s.client(Some(&a)).put(s.url("/v1/inventory/security"))
        .json(&protocol::InventoryUpload { schema_version: protocol::SCHEMA_VERSION, payload })
        .send().await.unwrap();
    let (_, html) = s.page(&admin, &tab).await;
    assert!(html.contains("公用") && html.contains("找不到 BitLocker") && html.contains("PC\\Administrator"), "{html}");
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &tab).await.0, 404);
}
```

Run: `cargo test -p endpoint-server --test config_web`
Expected: FAIL（404）。

- [ ] **Step 2: 實作**

- 安全設定分頁：
  - 讀 `device_security`（沿用 `store` 的解析方式）與 `inventory_sections.updated_at`（section = `security`），用表格呈現。
  - 各欄位：
    - 防火牆：三個設定檔各顯示「啟用／停用」。
    - BitLocker：每個磁碟的代號、是否系統磁碟、保護狀態。
    - Defender：作用中、即時保護、防竄改、病毒碼更新時間（以 `fmt_time` 顯示）。
    - 密碼原則：0 分別顯示為「永不過期」「不鎖定」。
    - 本機管理員：名稱與 SID。
  - `Probe::Error` 以 `<span class="error">` 顯示。
- 登錄檔查詢頁：比照 `web/software.rs`。
  - SQL 範例：`SELECT r.state, r.kind, r.data, count(*) FROM device_registry r JOIN devices d ON d.id = r.device_id AND d.status = 'active' WHERE upper(r.path) = upper($1) AND upper(r.name) = upper($2) AND ($3::bool OR d.group_id = ANY($4::bigint[])) GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 501`
  - 另外顯示「共 N 台」，並註明「只查得到有規則在收集的值」。
  - `upper(r.path)` 會讓計畫 8 的 `(path, name)` 索引用不到。migration 0009 新增 `CREATE INDEX device_registry_upper_idx ON device_registry (upper(path), upper(name));`，這一步屬於本 task。
- 導覽列：在「軟體搜尋」之後加 `<a href="/registry">登錄檔</a>`；`tests/web.rs` 的 `pages_require_login` 清單加上 `"/registry"`。

- [ ] **Step 3: 執行並 Commit**

Run: `cargo test -p endpoint-server`
Expected: PASS。

```bash
git add -A crates/server
git commit -m "網頁：裝置安全設定分頁、登錄檔值查詢"
```

---

### Task 4: 負載測試與文件

**Files:**
- Modify: `tools/loadsim/src/lib.rs`、`tools/loadsim/src/main.rs`（新增 `config` 指令）
- Create: `tools/loadsim/config_rules.sql`
- Modify: `docs/loadtest.md`、`README.md`

**Interfaces:**
- `loadsim config --server URL --root root.pem --devices devices.json [--concurrency 100] [--max-secs 900]`，每台依序：
  1. 報到，取得 `registry_queries`。
  2. 上傳 `security`（固定內容，偶數台公用防火牆關閉）。
  3. 上傳 `registry`（對清單中每個查詢回 `present`／`dword`，`data` 為裝置編號 % 2）。
  4. 以新雜湊再報到一次，確認伺服器沒有再要求重傳（沿用 `upload` 的 unverified 檢查）。
- `config_rules.sql`：建立 1,000 條 `registry_value` 規則，路徑為 `HKLM\SOFTWARE\Loadsim\K{i/100}`、名稱為 `V{i}`、比對方式 `equals`、期望值 `1`；另加防火牆與密碼原則規則各一條；最後 bump generation。

- [ ] **Step 1: 實作 loadsim**

`lib.rs` 新增 `pub async fn config(t: &Target, devices: &[Device], concurrency: usize) -> (Report, usize)`，結構比照 `upload`。

`main.rs` 新增 `"config"` 分支，印出報告；錯誤、unverified 或超過 `--max-secs` 時以非 0 結束。

Run: `cargo build --release -p loadsim`
Expected: 成功。

- [ ] **Step 2: 執行負載測試**

依 `docs/loadtest.md` 的重跑方法準備 30,000 台（`enroll`，並用 `upload` 送出基本盤點），然後：

```bash
docker exec -i em-postgres psql -U postgres -d em_load < ../../tools/loadsim/config_rules.sql
# 等 server.log 出現 "compliance recompute finished"（此時各台的值都尚未收集，全部為未知）
./loadsim heartbeat ... --rate 500 --secs 180 --max-p99-ms 100 &   # 同時量報到
./loadsim config    ... --concurrency 100                          # 三萬台上傳 1,000 個值與 security
wait
# 上傳觸發評估的 p99（方法同第二期，只看 config 期間的 compliance refresh 日誌）
```

標準（spec §1.1）：

- 上傳觸發評估的 p99 < 20ms。
- 上傳期間報到 p99 < 100ms。
- 規則上線後的全量重算 < 5 分鐘（這時值還沒收集，量的是重算本身）。
- `device_registry` 列數 = 30,000 × 1,000。

未達標時照實記錄，並用慢查詢日誌找出瓶頸。只有在修正屬於計畫範圍內的明確瓶頸時（例如缺索引），才在同一個 task 內修正並重跑；其餘寫進文件後回報。

- [ ] **Step 3: 文件**

- `docs/loadtest.md` 新增「組態基準（第三期）」一節：結果表格、環境、重跑指令。
- `README.md` 的「合規」一節補充：
  - 七種組態規則。
  - 內建範本。
  - 登錄檔讀取的限制：只能讀 HKLM，拒絕 SAM／SECURITY／自動登入密碼，上限設定 `registry_max_values`。
  - Agent 需要 0.3.0 以上。
  - 升級順序：先伺服器、後 Agent。

- [ ] **Step 4: 全部檢查並 Commit**

Run: `cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`

```bash
git add -A tools docs README.md crates
git commit -m "組態基準：負載測試與文件"
```
