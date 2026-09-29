# 計畫 6：合規管理網頁 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 管理員在網頁上管理合規規則與豁免、查看違規與趨勢、匯出 CSV。

**Architecture:** 沿用 askama 樣板與既有 handler 寫法（`AdminSession`、`check_csrf`、`RawForm` + `form_urlencoded` 解析多選欄位、錯誤回 409 純文字）。新增 `web/rules.rs`（規則增刪改與預覽）與 `web/compliance.rs`（總覽、違規清單、CSV、裝置頁合規分頁與豁免）。純函式（細節摘要、表單轉換、CSV 欄位）放在可單元測試的位置。

**Tech Stack:** Rust、axum 0.8、askama 0.16、sqlx、htmx（已內建）。`futures-util` 從 dev-dependency 提升為一般相依（已在 lockfile，axum 本來就依賴它），用於 CSV 串流。

**Spec:** `docs/superpowers/specs/2026-09-29-compliance-design.md`（§7）

**前置：** 計畫 5 已合併（`compliance::{admin, evaluate, rules, store, worker}`）。

## Global Constraints

- 所有使用者可見文字用繁體中文。
- CSP 是 `default-src 'self'`：**不能用 inline `<script>` 或 `style="..."`**。長條圖用 `<progress>`，互動用 htmx 屬性。
- 修改動作都要 `check_csrf`，寫入稽核記錄（計畫 5 的 admin 函式已處理；CSV 匯出另記 `compliance_export`）。
- 權限：看規則＝所有登入者；規則增刪改、豁免增刪＝平台管理員；違規／歷程／CSV＝依群組範圍（`Session::all_devices()` 或 `group_id = ANY(s.groups)`）。範圍外的裝置一律 404。
- 測試指令：`cargo test -p endpoint-server`；最後 `cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`。

## Review Focus

1. 群組管理員／檢視者透過任何路徑（違規清單、CSV、裝置分頁、規則頁的數字）都看不到別的群組的裝置。
2. CSV 內容以 `= + - @`、Tab、CR 開頭時必須加 `'`，否則在 Excel 會被當公式執行。
3. 規則表單送出壞參數時，回清楚的錯誤訊息，而不是 500。
4. 預覽不能讓多個管理員同時觸發全表掃描拖垮資料庫（同時只允許一個、30 秒逾時）。
5. 裝置頁「合規」分頁在沒有任何規則、沒有盤點資料時也能正常顯示。

**Rulings（相對 spec）：**
- spec §7.1 說群組管理員的趨勢「由 `device_violations` 即時聚合」——但 `device_violations` 只有目前狀態，算不出 30 天趨勢。改為：趨勢只顯示給平台管理員（來源 `compliance_daily`）；其他角色只看目前數字。代價：群組管理員沒有趨勢圖。
- spec §6.1 說通知設定在「設定頁」，但目前沒有設定頁。通知設定頁留給計畫 7，放在 `/compliance/notify`。
- 豁免到期日以「有效天數（1–365）」輸入，沿用註冊金鑰頁的寫法，不做日期選擇器。代價：無法指定精確日期。

---

## File Structure

- Modify `crates/server/Cargo.toml` — `futures-util = "0.3"` 移到 `[dependencies]`（保留 dev 也可，重複宣告時 cargo 會合併；直接移動即可）。
- Modify `crates/server/src/compliance/evaluate.rs` — `summarize(detail) -> String`。
- Modify `crates/server/src/compliance/store.rs` — `load_facts_bulk`。
- Create `crates/server/src/compliance/preview.rs` — `preview(pool, rule) -> PreviewCount`。
- Create `crates/server/src/web/rules.rs`、`templates/rules.html`、`templates/rule_form.html`。
- Create `crates/server/src/web/compliance.rs`、`templates/compliance.html`、`templates/violations.html`、`templates/compliance_tab.html`。
- Modify `crates/server/src/web/mod.rs`（路由、`pub mod`）、`crates/server/src/web/devices.rs`（分頁）、`templates/base.html`（導覽列）、`static/app.css`（`progress` 樣式、嚴重度標籤）。
- Create `crates/server/tests/compliance_web.rs`；Modify `crates/server/tests/web.rs`（`pages_require_login` 清單）。

---

### Task 1: 違規細節摘要

**Files:**
- Modify: `crates/server/src/compliance/evaluate.rs`

**Interfaces:**
- Produces: `pub fn summarize(detail: &serde_json::Value) -> String`（違規清單、裝置分頁、CSV、計畫 7 的通知共用）。

- [ ] **Step 1: 寫失敗測試**（加在 `evaluate.rs` 的 `mod tests`）

```rust
    #[test]
    fn summaries() {
        let cases = [
            (json!({"reason": "no_data"}), "尚未收到盤點資料"),
            (json!({"reason": "rule_error", "error": "x"}), "規則參數錯誤：x"),
            (json!({"reason": "missing"}), "未安裝"),
            (json!({"reason": "outdated", "software": [{"name": "Falcon", "version": "7.1"}]}), "版本過舊：Falcon 7.1"),
            (json!({"reason": "version_missing", "software": [{"name": "A", "version": null}]}), "版本不明：A"),
            (json!({"reason": "ubr_missing", "build": "22631"}), "Agent 未回報 UBR（組建 22631）"),
            (json!({"reason": "build_unparsable", "build": "abc"}), "無法解析組建號：abc"),
            (json!({"kb": "KB5031455"}), "缺少 KB5031455"),
            (json!({"build": "22631", "ubr": 4000, "min_ubr": 4317}), "組建 22631.4000，需要 22631.4317 以上"),
            (json!({"build": "19044"}), "組建 19044 低於最低支援版本"),
            (json!({"software": [{"name": "A", "version": "1"}, {"name": "B", "version": null}]}), "A 1、B"),
            (json!({"software": [{"name": "A", "version": null}], "total": 60}), "A 等 60 套"),
        ];
        for (d, want) in cases {
            assert_eq!(summarize(&d), want, "{d}");
        }
    }
```

Run: `cargo test -p endpoint-server --lib evaluate::tests::summaries`
Expected: 編譯錯誤（`summarize` 未定義）。

- [ ] **Step 2: 實作**

```rust
fn software_list(d: &Value) -> String {
    let items = d["software"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut s = items
        .iter()
        .map(|i| match i["version"].as_str() {
            Some(v) => format!("{} {v}", i["name"].as_str().unwrap_or("")),
            None => i["name"].as_str().unwrap_or("").to_string(),
        })
        .collect::<Vec<_>>()
        .join("、");
    // 白名單細節只列前 50 筆，另附總數
    if let Some(total) = d["total"].as_u64() {
        if total as usize > items.len() {
            s = format!("{s} 等 {total} 套");
        }
    }
    s
}

/// 給人看的一行摘要（網頁、CSV、通知共用）。
pub fn summarize(d: &Value) -> String {
    let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
    match d["reason"].as_str() {
        Some("no_data") => return "尚未收到盤點資料".into(),
        Some("rule_error") => return format!("規則參數錯誤：{}", s("error")),
        Some("missing") => return "未安裝".into(),
        Some("outdated") => return format!("版本過舊：{}", software_list(d)),
        Some("version_missing") => return format!("版本不明：{}", software_list(d)),
        Some("ubr_missing") => return format!("Agent 未回報 UBR（組建 {}）", s("build")),
        Some("build_unparsable") => return format!("無法解析組建號：{}", s("build")),
        _ => {}
    }
    if d.get("kb").is_some() {
        format!("缺少 {}", s("kb"))
    } else if let (Some(ubr), Some(min)) = (d["ubr"].as_u64(), d["min_ubr"].as_u64()) {
        let b = s("build");
        format!("組建 {b}.{ubr}，需要 {b}.{min} 以上")
    } else if d.get("build").is_some() {
        format!("組建 {} 低於最低支援版本", s("build"))
    } else if d.get("software").is_some() {
        software_list(d)
    } else {
        d.to_string()
    }
}
```

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --lib evaluate::tests`
Expected: 全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/compliance/evaluate.rs
git commit -m "合規：違規細節摘要"
```

---

### Task 2: 批次讀取事實與命中預覽

**Files:**
- Modify: `crates/server/src/compliance/store.rs`
- Create: `crates/server/src/compliance/preview.rs`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod preview;`）
- Test: `crates/server/tests/compliance_web.rs`（新檔，本 task 先放預覽測試）

**Interfaces:**
- Produces:
  - `store::load_facts_bulk(conn, ids: &[Uuid]) -> Result<Vec<(Uuid, DeviceFacts)>, sqlx::Error>`（不含豁免；`exempt` 為空）
  - `preview::PreviewCount { pub violating: i64, pub unknown: i64, pub devices: i64 }`
  - `preview::preview(pool: &PgPool, rule: Rule) -> Result<PreviewCount, sqlx::Error>`

- [ ] **Step 1: 寫失敗測試**

`crates/server/tests/compliance_web.rs`：

```rust
mod common;

use common::{TestAgent, TestServer, csrf_from};
use endpoint_server::compliance::rules::{Params, Rule, Severity};
use endpoint_server::web::auth::Role;
use protocol::{Arch, InventoryPayload, InventoryUpload, PatchItem, SCHEMA_VERSION, SoftwareItem};
use sqlx::PgPool;

async fn put(s: &TestServer, a: &TestAgent, p: InventoryPayload) {
    let section = p.section().as_str();
    let r = s
        .client(Some(a))
        .put(s.url(&format!("/v1/inventory/{section}")))
        .json(&InventoryUpload { schema_version: SCHEMA_VERSION, payload: p })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

fn sw(name: &str) -> SoftwareItem {
    SoftwareItem { name: name.into(), version: Some("1".into()), publisher: None, install_date: None, arch: Arch::X64 }
}

/// 在指定群組註冊一台裝置並上傳軟體與修補。
async fn device_in(s: &TestServer, group: &str, software: &[&str]) -> TestAgent {
    let tok = s.create_group_token(group, 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    put(s, &a, InventoryPayload::Software(software.iter().map(|n| sw(n)).collect())).await;
    put(s, &a, InventoryPayload::Patches(vec![PatchItem { kb: "KB1".into(), installed_on: None }])).await;
    a
}

#[sqlx::test(migrations = false)]
async fn preview_counts_matching_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    device_in(&s, "台北", &["TeamViewer 15"]).await;
    device_in(&s, "高雄", &["TeamViewer 15"]).await;
    device_in(&s, "高雄", &["7-Zip"]).await;
    let rule = |include: Vec<i64>| Rule {
        id: 0,
        name: "p".into(),
        severity: Severity::High,
        include,
        exclude: vec![],
        check: Ok(Params::parse("forbidden_software", &serde_json::json!({"name": "*TeamViewer*"})).unwrap().compile()),
    };
    let c = endpoint_server::compliance::preview::preview(&s.pool, rule(vec![])).await.unwrap();
    assert_eq!((c.violating, c.unknown, c.devices), (2, 0, 3));
    let g = s.group_id("高雄").await;
    let c = endpoint_server::compliance::preview::preview(&s.pool, rule(vec![g])).await.unwrap();
    assert_eq!(c.violating, 1);
}
```

Run: `cargo test -p endpoint-server --test compliance_web`
Expected: 編譯錯誤（`preview` 模組不存在）。

- [ ] **Step 2: 實作 `load_facts_bulk`**（`store.rs`）

```rust
type BulkDeviceRow = (Uuid, String, Option<i64>, Option<String>, Option<i32>);

/// 一次讀一批裝置的事實（預覽用；不含豁免、不加鎖）。
pub async fn load_facts_bulk(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<(Uuid, DeviceFacts)>, sqlx::Error> {
    let devices: Vec<BulkDeviceRow> = sqlx::query_as(
        "SELECT id, status, group_id, os_build, os_ubr FROM devices WHERE id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    let sections: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT device_id, section FROM inventory_sections WHERE device_id = ANY($1)")
            .bind(ids)
            .fetch_all(&mut *conn)
            .await?;
    let software: Vec<(Uuid, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT device_id, name, version, publisher FROM device_software WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    let patches: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT device_id, kb FROM device_patches WHERE device_id = ANY($1)")
            .bind(ids)
            .fetch_all(&mut *conn)
            .await?;
    let mut sw: HashMap<Uuid, Vec<SoftwareFact>> = HashMap::new();
    for (d, name, version, publisher) in software {
        sw.entry(d).or_default().push(SoftwareFact { name, version, publisher });
    }
    let mut kbs: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (d, kb) in patches {
        kbs.entry(d).or_default().push(kb);
    }
    let has = |d: Uuid, s: &str| sections.iter().any(|(x, y)| *x == d && y == s);
    Ok(devices
        .into_iter()
        .map(|(id, status, group_id, os_build, os_ubr)| {
            let facts = DeviceFacts {
                active: status == "active",
                group_id,
                os_build: has(id, "basic").then(|| os_build.unwrap_or_default()),
                os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
                software: has(id, "software").then(|| sw.remove(&id).unwrap_or_default()),
                kbs: has(id, "patches").then(|| kbs.remove(&id).unwrap_or_default()),
                exempt: vec![],
            };
            (id, facts)
        })
        .collect())
}
```

（`has` 在 1,000 台 × 5 區段內線性搜尋，約 5,000 次比較，可接受。）

- [ ] **Step 3: 實作 `preview.rs`**

```rust
//! 規則存檔前預覽「會命中幾台」：以同一個評估函式分批跑全部使用中裝置，不寫入。

use sqlx::PgPool;
use uuid::Uuid;

use super::evaluate::{Status, evaluate};
use super::rules::{Rule, RuleSet};
use super::store::load_facts_bulk;

pub const BATCH: i64 = 1000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PreviewCount {
    pub violating: i64,
    pub unknown: i64,
    pub devices: i64,
}

pub async fn preview(pool: &PgPool, rule: Rule) -> Result<PreviewCount, sqlx::Error> {
    let set = RuleSet { generation: 0, rules: vec![rule] };
    let mut count = PreviewCount::default();
    let mut cursor: Option<Uuid> = None;
    let mut conn = pool.acquire().await?;
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM devices WHERE status = 'active' AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(cursor)
        .bind(BATCH)
        .fetch_all(&mut *conn)
        .await?;
        let Some(last) = ids.last().copied() else { break };
        for (_, facts) in load_facts_bulk(&mut conn, &ids).await? {
            count.devices += 1;
            for o in evaluate(&facts, &set) {
                match o.status {
                    Status::Violating => count.violating += 1,
                    Status::Unknown => count.unknown += 1,
                    Status::Exempt => {}
                }
            }
        }
        cursor = Some(last);
        tokio::task::yield_now().await;
    }
    Ok(count)
}
```

`mod.rs` 加 `pub mod preview;`。

- [ ] **Step 4: 執行**

Run: `cargo test -p endpoint-server --test compliance_web`
Expected: PASS。

- [ ] **Step 5: Commit**

```bash
git add -A crates/server
git commit -m "合規：批次讀取事實與命中預覽"
```

---

### Task 3: 規則頁（清單、表單、新增、編輯、刪除、預覽）

**Files:**
- Create: `crates/server/src/web/rules.rs`
- Create: `crates/server/templates/rules.html`、`crates/server/templates/rule_form.html`
- Modify: `crates/server/src/web/mod.rs`、`crates/server/templates/base.html`、`crates/server/static/app.css`
- Test: `crates/server/tests/compliance_web.rs`、`crates/server/tests/web.rs`

**Interfaces:**
- Consumes: `compliance::admin::{RuleInput, create_rule, update_rule, delete_rule}`、`compliance::rules::{Params, Rule, Severity, KINDS, kind_label}`、`compliance::preview::preview`。
- Produces（路由）：
  - `GET /compliance/rules` → `rules::list`
  - `GET /compliance/rules/new?kind=…` → `rules::new_form`（平台）
  - `POST /compliance/rules` → `rules::create`（平台）
  - `GET /compliance/rules/{id}` → `rules::edit_form`（平台）
  - `POST /compliance/rules/{id}` → `rules::update`（平台）
  - `POST /compliance/rules/{id}/delete` → `rules::delete`（平台）
  - `POST /compliance/rules/preview` → `rules::preview`（平台；回 HTML 片段）
- Produces（純函式，可單元測試）：`pub fn form_to_input(f: &RuleForm) -> Result<RuleInput, String>`、`pub fn params_to_form(kind: &str, params: &Value) -> ParamFields`。

- [ ] **Step 1: 寫失敗的單元測試**（`web/rules.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn form(kind: &str, pairs: &[(&str, &str)]) -> RuleForm {
        let mut raw = format!("csrf=x&name=r&severity=high&enabled=1&kind={kind}");
        for (k, v) in pairs {
            raw.push_str(&format!("&{k}={}", crate::web::enc(v)));
        }
        parse_form(raw.as_bytes())
    }

    #[test]
    fn form_to_params_by_kind() {
        let i = form_to_input(&form("forbidden_software", &[("p_name", "*TeamViewer*"), ("p_version", "15")])).unwrap();
        assert_eq!(i.params, json!({"name": "*TeamViewer*", "publisher": "", "below_version": "15"}));
        let i = form_to_input(&form("required_software", &[("p_name", "Falcon"), ("p_version", "7")])).unwrap();
        assert_eq!(i.params["min_version"], "7");
        let i = form_to_input(&form("software_allowlist", &[("p_entries", "Office | Microsoft*\r\n\r\n| Adobe*\nNotepad++")])).unwrap();
        assert_eq!(
            i.params,
            json!({"entries": [
                {"name": "Office", "publisher": "Microsoft*"},
                {"name": "", "publisher": "Adobe*"},
                {"name": "Notepad++", "publisher": ""}
            ]})
        );
        let i = form_to_input(&form("os_build", &[("p_build", "22631"), ("p_min_ubr", "4317"), ("p_min_build", "")])).unwrap();
        assert_eq!(i.params, json!({"build": 22631, "min_ubr": 4317}));
        assert!(form_to_input(&form("os_build", &[("p_min_build", "abc")])).is_err());
        let i = form_to_input(&form("required_kb", &[("p_kb", "kb5034439")])).unwrap();
        assert_eq!(i.params, json!({"kb": "kb5034439"}), "正規化交給 Params::parse");
        let i = form_to_input(&form("required_kb", &[("include", "3"), ("include", "4"), ("exclude", "5")])).unwrap();
        assert_eq!((i.include, i.exclude, i.enabled), (vec![3, 4], vec![5], true));
    }

    #[test]
    fn params_roundtrip_to_form() {
        let f = params_to_form("software_allowlist", &json!({"entries": [{"name": "Office", "publisher": "Microsoft*"}, {"publisher": "Adobe*"}]}));
        assert_eq!(f.entries, "Office | Microsoft*\n | Adobe*");
        let f = params_to_form("os_build", &json!({"min_build": 19045}));
        assert_eq!((f.min_build.as_str(), f.build.as_str()), ("19045", ""));
        let f = params_to_form("forbidden_software", &json!({"name": "x", "below_version": "2"}));
        assert_eq!((f.name.as_str(), f.version.as_str()), ("x", "2"));
    }
}
```

Run: `cargo test -p endpoint-server --lib web::rules`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作 `web/rules.rs`**

```rust
//! 合規規則：清單（所有人可看）、新增／編輯／刪除與預覽（平台管理員）。

use std::time::Duration;

use askama::Template;
use axum::extract::{Path, Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, db_error};
use super::{forbidden, not_found, render};
use crate::AppState;
use crate::compliance::admin::{self, RuleInput};
use crate::compliance::rules::{KINDS, Params, Rule, Severity, kind_label};
use crate::error::AppError;

/// 表單原始欄位（include／exclude 可重複）。
#[derive(Debug, Default)]
pub struct RuleForm {
    pub csrf: String,
    pub name: String,
    pub description: String,
    pub kind: String,
    pub severity: String,
    pub enabled: bool,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
    pub p: ParamFields,
}

/// 各類型參數在表單上的欄位（全部是字串，方便回填）。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ParamFields {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub entries: String,
    pub min_build: String,
    pub build: String,
    pub min_ubr: String,
    pub kb: String,
}

pub fn parse_form(raw: &[u8]) -> RuleForm {
    let mut f = RuleForm::default();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.into_owned();
        match k.as_ref() {
            "csrf" => f.csrf = v,
            "name" => f.name = v,
            "description" => f.description = v,
            "kind" => f.kind = v,
            "severity" => f.severity = v,
            "enabled" => f.enabled = v == "1",
            "include" => f.include.extend(v.parse::<i64>().ok()),
            "exclude" => f.exclude.extend(v.parse::<i64>().ok()),
            "p_name" => f.p.name = v,
            "p_publisher" => f.p.publisher = v,
            "p_version" => f.p.version = v,
            "p_entries" => f.p.entries = v,
            "p_min_build" => f.p.min_build = v,
            "p_build" => f.p.build = v,
            "p_min_ubr" => f.p.min_ubr = v,
            "p_kb" => f.p.kb = v,
            _ => {}
        }
    }
    f
}

fn num(field: &str, v: &str) -> Result<Option<u32>, String> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    v.parse::<u32>().map(Some).map_err(|_| format!("{field}必須是正整數"))
}

/// 表單欄位轉成 admin 的輸入；驗證與正規化交給 Params::parse。
pub fn form_to_input(f: &RuleForm) -> Result<RuleInput, String> {
    let p = &f.p;
    let params = match f.kind.as_str() {
        "forbidden_software" => json!({"name": p.name, "publisher": p.publisher, "below_version": p.version}),
        "required_software" => json!({"name": p.name, "publisher": p.publisher, "min_version": p.version}),
        "software_allowlist" => {
            let entries: Vec<Value> = p
                .entries
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| {
                    let (name, publisher) = l.split_once('|').unwrap_or((l, ""));
                    json!({"name": name.trim(), "publisher": publisher.trim()})
                })
                .collect();
            json!({"entries": entries})
        }
        "os_build" => {
            let mut m = serde_json::Map::new();
            for (key, label, v) in [
                ("min_build", "最低組建主號", &p.min_build),
                ("build", "組建主號", &p.build),
                ("min_ubr", "最低 UBR", &p.min_ubr),
            ] {
                if let Some(n) = num(label, v)? {
                    m.insert(key.into(), json!(n));
                }
            }
            Value::Object(m)
        }
        "required_kb" => json!({"kb": p.kb}),
        other => return Err(format!("未知的規則類型：{other}")),
    };
    Ok(RuleInput {
        name: f.name.clone(),
        description: f.description.clone(),
        kind: f.kind.clone(),
        severity: f.severity.clone(),
        enabled: f.enabled,
        params,
        include: f.include.clone(),
        exclude: f.exclude.clone(),
    })
}

/// 資料庫裡的參數回填到表單欄位（編輯用）。
pub fn params_to_form(kind: &str, v: &Value) -> ParamFields {
    let s = |k: &str| match &v[k] {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let mut f = ParamFields { name: s("name"), publisher: s("publisher"), kb: s("kb"), ..Default::default() };
    f.version = if kind == "required_software" { s("min_version") } else { s("below_version") };
    f.min_build = s("min_build");
    f.build = s("build");
    f.min_ubr = s("min_ubr");
    f.entries = v["entries"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|e| {
                    let n = e["name"].as_str().unwrap_or("");
                    match e["publisher"].as_str() {
                        Some(p) => format!("{n} | {p}"),
                        None => n.to_string(),
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();
    f
}
```

注意 `params_to_form` 的測試期望 `"Office | Microsoft*\n | Adobe*"`：只有發行者時名稱為空，輸出 `" | Adobe*"`，符合上面的 `format!("{n} | {p}")`。

接著在同檔加頁面與 handler：

```rust
fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() { Ok(()) } else { Err(forbidden()) }
}

fn conflict(e: impl std::fmt::Display) -> Response {
    (StatusCode::CONFLICT, e.to_string()).into_response()
}

pub struct RuleRow {
    pub id: i64,
    pub name: String,
    pub kind: &'static str,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub enabled: bool,
    pub scope: String,
    pub violating: i64,
    pub unknown: i64,
    pub exempt: i64,
}

#[derive(Template)]
#[template(path = "rules.html")]
struct RulesPage {
    nav: Nav,
    rows: Vec<RuleRow>,
    kinds: Vec<(&'static str, &'static str)>,
}

type RuleListRow = (i64, String, String, String, bool, Option<String>, Option<String>, i64, i64, i64);

pub async fn list(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, AppError> {
    // 數字依管理員的群組範圍計算
    let rows: Vec<RuleListRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.kind, r.severity, r.enabled, \
           (SELECT string_agg(g.name, '、' ORDER BY g.name) FROM compliance_rule_groups rg \
              JOIN device_groups g ON g.id = rg.group_id WHERE rg.rule_id = r.id AND rg.mode = 'include'), \
           (SELECT string_agg(g.name, '、' ORDER BY g.name) FROM compliance_rule_groups rg \
              JOIN device_groups g ON g.id = rg.group_id WHERE rg.rule_id = r.id AND rg.mode = 'exclude'), \
           count(*) FILTER (WHERE v.status = 'violating'), \
           count(*) FILTER (WHERE v.status = 'unknown'), \
           count(*) FILTER (WHERE v.status = 'exempt') \
         FROM compliance_rules r \
         LEFT JOIN device_violations v ON v.rule_id = r.id AND EXISTS ( \
              SELECT 1 FROM devices d WHERE d.id = v.device_id \
              AND ($1::bool OR d.group_id = ANY($2::bigint[]))) \
         GROUP BY r.id ORDER BY r.name, r.id",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(|(id, name, kind, severity, enabled, include, exclude, violating, unknown, exempt)| {
            let sev = Severity::parse(&severity).unwrap_or(Severity::Medium);
            let mut scope = include.map(|g| format!("只套用：{g}")).unwrap_or_else(|| "全部裝置".into());
            if let Some(ex) = exclude {
                scope.push_str(&format!("；排除：{ex}"));
            }
            RuleRow {
                id,
                name,
                kind: kind_label(&kind),
                severity: sev.label(),
                severity_class: sev.as_str(),
                enabled,
                scope,
                violating,
                unknown,
                exempt,
            }
        })
        .collect();
    Ok(render(&RulesPage {
        nav: Nav::from(&s),
        rows,
        kinds: KINDS.iter().map(|k| (*k, kind_label(k))).collect(),
    }))
}

#[derive(Template)]
#[template(path = "rule_form.html")]
struct RuleFormPage {
    nav: Nav,
    /// None 表示新增
    id: Option<i64>,
    kind: String,
    kind_label: &'static str,
    name: String,
    description: String,
    enabled: bool,
    severities: Vec<SelectOption>,
    include: Vec<SelectOption>,
    exclude: Vec<SelectOption>,
    p: ParamFields,
}

async fn group_checks(st: &AppState, selected: &[i64]) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM device_groups ORDER BY name")
        .fetch_all(&st.pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| SelectOption { selected: selected.contains(&id), value: id.to_string(), label: name })
        .collect())
}

fn severities(current: &str) -> Vec<SelectOption> {
    Severity::ALL
        .into_iter()
        .map(|x| SelectOption { value: x.as_str().into(), label: x.label().into(), selected: x.as_str() == current })
        .collect()
}

#[derive(Deserialize)]
pub struct NewQuery {
    #[serde(default)]
    kind: String,
}

pub async fn new_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<NewQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    if !KINDS.contains(&q.kind.as_str()) {
        return Err(not_found());
    }
    Ok(render(&RuleFormPage {
        nav: Nav::from(&s),
        id: None,
        kind_label: kind_label(&q.kind),
        kind: q.kind,
        name: String::new(),
        description: String::new(),
        enabled: true,
        severities: severities("medium"),
        include: group_checks(&st, &[]).await.map_err(db_error)?,
        exclude: group_checks(&st, &[]).await.map_err(db_error)?,
        p: ParamFields::default(),
    }))
}

type RuleEditRow = (String, String, String, String, bool, String, Vec<i64>, Vec<i64>);

pub async fn edit_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<RuleEditRow> = sqlx::query_as(
        "SELECT name, description, kind, severity, enabled, params::text, \
           ARRAY(SELECT group_id FROM compliance_rule_groups WHERE rule_id = r.id AND mode = 'include'), \
           ARRAY(SELECT group_id FROM compliance_rule_groups WHERE rule_id = r.id AND mode = 'exclude') \
         FROM compliance_rules r WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(db_error)?;
    let Some((name, description, kind, severity, enabled, params, include, exclude)) = row else {
        return Err(not_found());
    };
    let params: Value = serde_json::from_str(&params).unwrap_or(Value::Null);
    Ok(render(&RuleFormPage {
        nav: Nav::from(&s),
        id: Some(id),
        kind_label: kind_label(&kind),
        p: params_to_form(&kind, &params),
        kind,
        name,
        description,
        enabled,
        severities: severities(&severity),
        include: group_checks(&st, &include).await.map_err(db_error)?,
        exclude: group_checks(&st, &exclude).await.map_err(db_error)?,
    }))
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let input = form_to_input(&f).map_err(conflict)?;
    admin::create_rule(&st.pool, &input, &s.username).await.map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/rules").into_response())
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let input = form_to_input(&f).map_err(conflict)?;
    admin::update_rule(&st.pool, id, &input, &s.username).await.map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/rules").into_response())
}

pub async fn delete(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    admin::delete_rule(&st.pool, id, &s.username).await.map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/rules").into_response())
}

/// 同時只允許一個預覽：每次都會掃過全部裝置
static PREVIEW_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
pub const PREVIEW_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn preview(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let msg = match form_to_input(&f).and_then(|i| Params::parse(&i.kind, &i.params).map(|p| (i, p))) {
        Err(e) => format!("參數有誤：{e}"),
        Ok((i, p)) => match PREVIEW_SLOT.try_acquire() {
            Err(_) => "另一個預覽正在執行，請稍後再試".into(),
            Ok(_slot) => {
                let rule = Rule {
                    id: 0,
                    name: i.name,
                    severity: Severity::Medium,
                    include: i.include,
                    exclude: i.exclude,
                    check: Ok(p.compile()),
                };
                match tokio::time::timeout(PREVIEW_TIMEOUT, crate::compliance::preview::preview(&st.pool, rule)).await {
                    Err(_) => "預覽逾時（超過 30 秒），請直接存檔，背景重算完成後再看結果".into(),
                    Ok(Err(e)) => return Err(db_error(e)),
                    Ok(Ok(c)) => format!(
                        "目前會命中 {} 台（另有 {} 台無法判斷），共評估 {} 台使用中裝置；未計入豁免。",
                        c.violating, c.unknown, c.devices
                    ),
                }
            }
        },
    };
    // 純文字片段；askama 以外的輸出要自己跳脫
    Ok(Html(format!("<p class=\"notice\">{}</p>", html_escape(&msg))).into_response())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}
```

- [ ] **Step 3: 樣板**

`templates/rules.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>合規規則</h1>
<p><a href="/compliance">← 合規總覽</a></p>
{% if nav.platform %}
<p>新增規則：{% for k in kinds %}<a href="/compliance/rules/new?kind={{ k.0 }}">{{ k.1 }}</a> {% endfor %}</p>
{% endif %}
<table>
  <tr><th>名稱</th><th>類型</th><th>嚴重度</th><th>範圍</th><th>違規</th><th>未知</th><th>豁免</th><th>狀態</th></tr>
  {% for r in rows %}
  <tr>
    <td>{% if nav.platform %}<a href="/compliance/rules/{{ r.id }}">{{ r.name }}</a>{% else %}{{ r.name }}{% endif %}</td>
    <td>{{ r.kind }}</td>
    <td><span class="sev {{ r.severity_class }}">{{ r.severity }}</span></td>
    <td>{{ r.scope }}</td>
    <td><a href="/compliance/violations?rule={{ r.id }}&status=violating">{{ r.violating }}</a></td>
    <td><a href="/compliance/violations?rule={{ r.id }}&status=unknown">{{ r.unknown }}</a></td>
    <td><a href="/compliance/violations?rule={{ r.id }}&status=exempt">{{ r.exempt }}</a></td>
    <td>{% if r.enabled %}啟用{% else %}<span class="muted">停用</span>{% endif %}</td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
```

`templates/rule_form.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>{% if id.is_some() %}編輯{% else %}新增{% endif %}規則：{{ kind_label }}</h1>
<form method="post" action="{% if let Some(i) = id %}/compliance/rules/{{ i }}{% else %}/compliance/rules{% endif %}">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <input type="hidden" name="kind" value="{{ kind }}">
  <p><label>名稱 <input name="name" value="{{ name }}" required maxlength="100" size="40"></label></p>
  <p><label>說明 <input name="description" value="{{ description }}" maxlength="1000" size="60"></label></p>
  <p><label>嚴重度 <select name="severity">{% for o in severities %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}</select></label>
     <label><input type="checkbox" name="enabled" value="1" {% if enabled %}checked{% endif %}> 啟用</label></p>

  <fieldset><legend>條件</legend>
  {% if kind == "forbidden_software" || kind == "required_software" %}
    <p><label>軟體名稱 <input name="p_name" value="{{ p.name }}" required maxlength="256" size="40" placeholder="*TeamViewer*"></label></p>
    <p><label>發行者（選填）<input name="p_publisher" value="{{ p.publisher }}" maxlength="256" size="40"></label></p>
    <p><label>{% if kind == "forbidden_software" %}只禁止低於此版本（選填）{% else %}最低版本（選填）{% endif %}
       <input name="p_version" value="{{ p.version }}" maxlength="256"></label></p>
    <p class="muted"><code>*</code> 代表任意字元，不分大小寫。</p>
  {% else if kind == "software_allowlist" %}
    <p><label>允許的軟體（每行一筆：<code>名稱樣式 | 發行者樣式</code>，任一邊可留空）<br>
       <textarea name="p_entries" rows="10" cols="70">{{ p.entries }}</textarea></label></p>
    <p class="muted">不符合任何一筆的軟體都算違規。例：<code>| Microsoft*</code> 允許所有微軟軟體。</p>
  {% else if kind == "os_build" %}
    <p><label>最低組建主號 <input name="p_min_build" value="{{ p.min_build }}" inputmode="numeric" placeholder="19045"></label>
       <span class="muted">低於此組建視為作業系統已停止支援</span></p>
    <p>或 <label>組建主號 <input name="p_build" value="{{ p.build }}" inputmode="numeric" placeholder="22631"></label>
       <label>最低 UBR <input name="p_min_ubr" value="{{ p.min_ubr }}" inputmode="numeric" placeholder="4317"></label></p>
    <p class="muted">兩種擇一。第二種只檢查該組建的電腦，例如 22631.4317 以上。</p>
  {% else if kind == "required_kb" %}
    <p><label>KB 編號 <input name="p_kb" value="{{ p.kb }}" required placeholder="KB5034439"></label></p>
    <p class="muted">每月累積更新會取代舊 KB，請用「最低組建號」規則檢查累積更新；這裡適合不走累積更新的獨立修補。</p>
  {% endif %}
  </fieldset>

  <fieldset><legend>範圍（都不勾＝全部裝置；排除優先）</legend>
    <p>只套用：{% for g in include %}<label><input type="checkbox" name="include" value="{{ g.value }}" {% if g.selected %}checked{% endif %}> {{ g.label }}</label> {% endfor %}</p>
    <p>排除：{% for g in exclude %}<label><input type="checkbox" name="exclude" value="{{ g.value }}" {% if g.selected %}checked{% endif %}> {{ g.label }}</label> {% endfor %}</p>
  </fieldset>

  <p><button>儲存</button>
     <button type="button" hx-post="/compliance/rules/preview" hx-include="closest form" hx-target="#preview">預覽命中台數</button></p>
  <div id="preview"></div>
</form>
{% if let Some(i) = id %}
<form method="post" action="/compliance/rules/{{ i }}/delete">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  <button class="danger">刪除規則（一併刪除其違規與豁免，歷程保留）</button>
</form>
{% endif %}
{% endblock %}
```

`base.html` 導覽列在「軟體搜尋」之後加 `<a href="/compliance">合規</a>`（所有登入者）。

`static/app.css` 末尾加：

```css
.sev { padding: 0 .4em; border-radius: 3px; }
.sev.high { background: #fde2e1; color: #a61b12; }
.sev.medium { background: #fff1d6; color: #8a5a00; }
.sev.low { background: #e8eef7; color: #2d4a73; }
progress { width: 12em; vertical-align: middle; }
textarea { font: inherit; }
```

- [ ] **Step 4: 路由**

`web/mod.rs`：`pub mod rules;`，並在 `web_router` 加：

```rust
        .route("/compliance/rules", get(rules::list).post(rules::create))
        .route("/compliance/rules/new", get(rules::new_form))
        .route("/compliance/rules/preview", post(rules::preview))
        .route("/compliance/rules/{id}", get(rules::edit_form).post(rules::update))
        .route("/compliance/rules/{id}/delete", post(rules::delete))
```

（`/compliance/rules/new` 與 `/compliance/rules/preview` 是固定路徑，axum 0.8 會優先於 `{id}` 比對。）

- [ ] **Step 5: 整合測試**（`tests/compliance_web.rs` 加）

```rust
#[sqlx::test(migrations = false)]
async fn rule_pages_and_permissions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/compliance/rules/new?kind=forbidden_software").await;
    assert_eq!(st, 200);
    let csrf = csrf_from(&html);
    let r = admin
        .post(s.web_url("/compliance/rules"))
        .form(&[
            ("csrf", csrf.as_str()), ("kind", "forbidden_software"), ("name", "禁止 TeamViewer"),
            ("severity", "high"), ("enabled", "1"), ("p_name", "*TeamViewer*"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let (_, html) = s.page(&admin, "/compliance/rules").await;
    assert!(html.contains("禁止 TeamViewer") && html.contains("禁止軟體"));

    // 壞參數 → 409 與中文訊息
    let r = admin
        .post(s.web_url("/compliance/rules"))
        .form(&[("csrf", csrf.as_str()), ("kind", "required_kb"), ("name", "x"), ("severity", "high"), ("p_kb", "123")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("KB 格式"));

    // 預覽
    let r = admin
        .post(s.web_url("/compliance/rules/preview"))
        .form(&[("csrf", csrf.as_str()), ("kind", "required_kb"), ("name", "x"), ("severity", "high"), ("p_kb", "KB5034439")])
        .send()
        .await
        .unwrap();
    assert!(r.text().await.unwrap().contains("共評估 0 台"));

    // 群組管理員可看清單，不能新增或編輯
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (st, html) = s.page(&g, "/compliance/rules").await;
    assert_eq!(st, 200);
    assert!(html.contains("禁止 TeamViewer") && !html.contains("/compliance/rules/new"));
    let (st, _) = s.page(&g, "/compliance/rules/new?kind=required_kb").await;
    assert_eq!(st, 403);
    let gcsrf = csrf_from(&s.page(&g, "/compliance/rules").await.1);
    let r = g
        .post(s.web_url("/compliance/rules"))
        .form(&[("csrf", gcsrf.as_str()), ("kind", "required_kb"), ("name", "x"), ("severity", "high"), ("p_kb", "KB5034439")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
```

`tests/web.rs` 的 `pages_require_login` 路徑清單加 `"/compliance"`、`"/compliance/rules"`、`"/compliance/violations"`。（`/compliance` 與 `/compliance/violations` 在 Task 4 才有路由；這一行放到 Task 4 再加也可以——若先加，本 task 執行該測試時會失敗，所以**本 task 只加 `/compliance/rules`**。）

- [ ] **Step 6: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 7: Commit**

```bash
git add -A crates/server
git commit -m "合規網頁：規則清單、表單、增刪改與命中預覽"
```

---

### Task 4: 合規總覽與違規清單

**Files:**
- Create: `crates/server/src/web/compliance.rs`
- Create: `crates/server/templates/compliance.html`、`crates/server/templates/violations.html`
- Modify: `crates/server/src/web/mod.rs`、`crates/server/tests/web.rs`
- Test: `crates/server/tests/compliance_web.rs`

**Interfaces:**
- Consumes: `compliance::worker::progress`、`compliance::evaluate::{summarize, Status}`、`compliance::rules::Severity`、`web::devices::{SelectOption, group_options, PAGE_SIZE, MAX_PAGE}`。
- Produces（路由）：`GET /compliance` → `compliance::overview`；`GET /compliance/violations` → `compliance::violations`。
- Produces：`pub struct ViolationFilter`（query 參數：`rule`、`severity`、`status`、`group`、`q`、`page`），`fn filter_sql() -> &'static str`（清單與 CSV 共用的 WHERE 條件，參數編號見下）。

- [ ] **Step 1: 寫失敗的整合測試**

```rust
async fn add_rule_via_admin(s: &TestServer, kind: &str, params: serde_json::Value) -> i64 {
    endpoint_server::compliance::admin::create_rule(
        &s.pool,
        &endpoint_server::compliance::admin::RuleInput {
            name: format!("{kind} rule"),
            description: String::new(),
            kind: kind.into(),
            severity: "high".into(),
            enabled: true,
            params,
            include: vec![],
            exclude: vec![],
        },
        "admin",
    )
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn violations_are_scoped_by_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    add_rule_via_admin(&s, "forbidden_software", serde_json::json!({"name": "*TeamViewer*"})).await;
    let taipei = device_in(&s, "台北", &["TeamViewer 15"]).await;
    let kaohsiung = device_in(&s, "高雄", &["TeamViewer 15"]).await;
    let host = |a: &TestAgent| a.device_id.to_string();

    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/compliance/violations").await;
    assert!(html.contains(&host(&taipei)) && html.contains(&host(&kaohsiung)));
    let (_, html) = s.page(&admin, "/compliance").await;
    assert!(html.contains("forbidden_software rule"), "總覽列出規則");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&g, "/compliance/violations").await;
    assert!(html.contains(&host(&taipei)) && !html.contains(&host(&kaohsiung)));
    let (_, html) = s.page(&g, "/compliance").await;
    assert!(!html.contains("近 30 天"), "趨勢只給平台管理員");
    let (_, html) = s.page(&g, "/compliance/violations?q=nomatch").await;
    assert!(!html.contains(&host(&taipei)));
}
```

裝置清單的主機名稱由 TestServer 註冊時決定（可能全都一樣），所以測試以裝置 ID 判斷——違規清單的裝置連結 `href="/devices/{id}"` 會包含 ID。

Run: `cargo test -p endpoint-server --test compliance_web violations_are_scoped`
Expected: FAIL（404）。

- [ ] **Step 2: 實作 `web/compliance.rs`（總覽與清單）**

```rust
//! 合規：總覽、違規清單、CSV 匯出、裝置頁的合規分頁與豁免。所有裝置資料都以群組範圍過濾。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use chrono::{DateTime, NaiveDate, Utc};
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav, Session};
use super::devices::{MAX_PAGE, PAGE_SIZE, SelectOption, group_options};
use super::{enc, escape_like, fmt_time, render};
use crate::AppState;
use crate::compliance::evaluate::{Status, summarize};
use crate::compliance::rules::Severity;
use crate::error::AppError;

#[derive(Deserialize, Default, Clone)]
pub struct ViolationFilter {
    #[serde(default)]
    pub rule: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub page: i64,
}

impl ViolationFilter {
    fn query_string(&self) -> String {
        format!(
            "rule={}&severity={}&status={}&group={}&q={}",
            enc(&self.rule), enc(&self.severity), enc(&self.status), enc(&self.group), enc(&self.q)
        )
    }
}

/// 清單與 CSV 共用的條件。參數：$1 all_devices、$2 groups、$3 rule(text)、$4 severity、
/// $5 status、$6 group(text)、$7 q、$8 escape_like(q)
const FILTER: &str = "($1::bool OR d.group_id = ANY($2::bigint[])) \
     AND ($3 = '' OR v.rule_id::text = $3) \
     AND ($4 = '' OR r.severity = $4) \
     AND ($5 = '' OR v.status = $5) \
     AND (CASE WHEN $6 = '' THEN true WHEN $6 = 'none' THEN d.group_id IS NULL \
               ELSE d.group_id::text = $6 END) \
     AND ($7 = '' OR d.hostname ILIKE $8)";

pub struct ViolationRow {
    pub device_id: Uuid,
    pub hostname: String,
    pub group: String,
    pub rule: String,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub since: String,
}

pub type RawViolation = (Uuid, String, Option<String>, String, String, String, String, DateTime<Utc>);

pub fn violation_select() -> String {
    format!(
        "SELECT v.device_id, d.hostname, g.name, r.name, r.severity, v.status, v.detail::text, v.since \
         FROM device_violations v \
         JOIN devices d ON d.id = v.device_id \
         JOIN compliance_rules r ON r.id = v.rule_id \
         LEFT JOIN device_groups g ON g.id = d.group_id \
         WHERE {FILTER}"
    )
}

pub fn to_row(st: &AppState, r: RawViolation) -> ViolationRow {
    let (device_id, hostname, group, rule, severity, status, detail, since) = r;
    let sev = Severity::parse(&severity).unwrap_or(Severity::Medium);
    let detail: serde_json::Value = serde_json::from_str(&detail).unwrap_or_default();
    ViolationRow {
        device_id,
        hostname,
        group: group.unwrap_or_else(|| "未分組".into()),
        rule,
        severity: sev.label(),
        severity_class: sev.as_str(),
        status: Status::parse(&status).map(Status::label).unwrap_or("?"),
        summary: summarize(&detail),
        since: fmt_time(st, Some(since)),
    }
}

fn select(options: &[(&str, &str)], current: &str) -> Vec<SelectOption> {
    options
        .iter()
        .map(|(v, l)| SelectOption { value: (*v).into(), label: (*l).into(), selected: *v == current })
        .collect()
}

#[derive(Template)]
#[template(path = "violations.html")]
struct ViolationsPage {
    nav: Nav,
    q: String,
    rules: Vec<SelectOption>,
    severities: Vec<SelectOption>,
    statuses: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<ViolationRow>,
    page: i64,
    has_next: bool,
    prev_url: String,
    next_url: String,
    csv_url: String,
}

pub async fn violations(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(f): Query<ViolationFilter>,
) -> Result<Response, AppError> {
    let page = f.page.clamp(0, MAX_PAGE);
    let sql = format!("{} ORDER BY v.since DESC, v.device_id, v.rule_id LIMIT $9 OFFSET $10", violation_select());
    let mut rows: Vec<RawViolation> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(s.all_devices())
        .bind(&s.groups)
        .bind(&f.rule)
        .bind(&f.severity)
        .bind(&f.status)
        .bind(&f.group)
        .bind(&f.q)
        .bind(escape_like(&f.q))
        .bind(PAGE_SIZE + 1)
        .bind(page * PAGE_SIZE)
        .fetch_all(&st.pool)
        .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    let rule_names: Vec<(i64, String)> = sqlx::query_as("SELECT id, name FROM compliance_rules ORDER BY name")
        .fetch_all(&st.pool)
        .await?;
    let mut rules = vec![SelectOption { value: String::new(), label: "所有規則".into(), selected: f.rule.is_empty() }];
    rules.extend(rule_names.into_iter().map(|(id, name)| SelectOption {
        selected: f.rule == id.to_string(),
        value: id.to_string(),
        label: name,
    }));
    let qs = f.query_string();
    Ok(render(&ViolationsPage {
        nav: Nav::from(&s),
        rules,
        severities: select(&[("", "所有嚴重度"), ("high", "高"), ("medium", "中"), ("low", "低")], &f.severity),
        statuses: select(&[("", "所有狀態"), ("violating", "違規"), ("unknown", "未知"), ("exempt", "豁免")], &f.status),
        groups: group_options(&st, &s, &f.group, true).await?,
        rows: rows.into_iter().map(|r| to_row(&st, r)).collect(),
        page,
        has_next,
        prev_url: format!("/compliance/violations?{qs}&page={}", page - 1),
        next_url: format!("/compliance/violations?{qs}&page={}", page + 1),
        csv_url: format!("/compliance/violations.csv?{qs}"),
        q: f.q,
    }))
}

pub struct RuleSummary {
    pub id: i64,
    pub name: String,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub violating: i64,
    pub unknown: i64,
    pub exempt: i64,
}

pub struct TrendRow {
    pub day: String,
    pub violating: i64,
}

#[derive(Template)]
#[template(path = "compliance.html")]
struct OverviewPage {
    nav: Nav,
    devices_violating: i64,
    rules: Vec<RuleSummary>,
    running: bool,
    progress_done: i64,
    progress_total: i64,
    trend: Vec<TrendRow>,
    trend_max: i64,
}

pub async fn overview(State(st): State<AppState>, AdminSession(s): AdminSession) -> Result<Response, AppError> {
    let devices_violating: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT v.device_id) FROM device_violations v JOIN devices d ON d.id = v.device_id \
         WHERE v.status = 'violating' AND ($1::bool OR d.group_id = ANY($2::bigint[]))",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_one(&st.pool)
    .await?;
    let rows: Vec<(i64, String, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT r.id, r.name, r.severity, \
           count(*) FILTER (WHERE v.status = 'violating'), \
           count(*) FILTER (WHERE v.status = 'unknown'), \
           count(*) FILTER (WHERE v.status = 'exempt') \
         FROM compliance_rules r \
         LEFT JOIN device_violations v ON v.rule_id = r.id AND EXISTS ( \
              SELECT 1 FROM devices d WHERE d.id = v.device_id \
              AND ($1::bool OR d.group_id = ANY($2::bigint[]))) \
         WHERE r.enabled GROUP BY r.id \
         ORDER BY CASE r.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, 4 DESC, r.name",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let p = crate::compliance::worker::progress(&st.pool).await?;
    let trend: Vec<(NaiveDate, i64)> = if s.all_devices() {
        sqlx::query_as(
            "SELECT day, sum(violating)::bigint FROM compliance_daily \
             WHERE day > current_date - 30 GROUP BY day ORDER BY day",
        )
        .fetch_all(&st.pool)
        .await?
    } else {
        vec![]
    };
    let trend_max = trend.iter().map(|t| t.1).max().unwrap_or(0).max(1);
    Ok(render(&OverviewPage {
        nav: Nav::from(&s),
        devices_violating,
        rules: rows
            .into_iter()
            .map(|(id, name, severity, violating, unknown, exempt)| {
                let sev = Severity::parse(&severity).unwrap_or(Severity::Medium);
                RuleSummary { id, name, severity: sev.label(), severity_class: sev.as_str(), violating, unknown, exempt }
            })
            .collect(),
        running: p.running,
        progress_done: p.done,
        progress_total: p.total,
        trend: trend.into_iter().map(|(d, v)| TrendRow { day: d.format("%m-%d").to_string(), violating: v }).collect(),
        trend_max,
    }))
}
```

- [ ] **Step 3: 樣板**

`templates/compliance.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>合規總覽</h1>
<p><a href="/compliance/rules">規則</a> · <a href="/compliance/violations?status=violating">違規清單</a></p>
<div class="cards">
  <div class="card offline">違規裝置<b>{{ devices_violating }}</b></div>
  <div class="card">啟用規則<b>{{ rules.len() }}</b></div>
</div>
{% if running %}
<p class="notice">規則已變更，正在重新評估：<progress value="{{ progress_done }}" max="{{ progress_total }}"></progress> {{ progress_done }} / {{ progress_total }} 台</p>
{% endif %}
<table>
  <tr><th>規則</th><th>嚴重度</th><th>違規</th><th>未知</th><th>豁免</th></tr>
  {% for r in rules %}
  <tr>
    <td>{{ r.name }}</td>
    <td><span class="sev {{ r.severity_class }}">{{ r.severity }}</span></td>
    <td><a href="/compliance/violations?rule={{ r.id }}&status=violating">{{ r.violating }}</a></td>
    <td><a href="/compliance/violations?rule={{ r.id }}&status=unknown">{{ r.unknown }}</a></td>
    <td><a href="/compliance/violations?rule={{ r.id }}&status=exempt">{{ r.exempt }}</a></td>
  </tr>
  {% endfor %}
</table>
{% if !trend.is_empty() %}
<h2>近 30 天違規數</h2>
<table>
  {% for t in trend %}<tr><td>{{ t.day }}</td><td><progress value="{{ t.violating }}" max="{{ trend_max }}"></progress> {{ t.violating }}</td></tr>{% endfor %}
</table>
{% endif %}
{% endblock %}
```

`templates/violations.html`：

```html
{% extends "base.html" %}
{% block content %}
<h1>違規清單</h1>
<p><a href="/compliance">← 合規總覽</a></p>
<form method="get" action="/compliance/violations">
  <input name="q" value="{{ q }}" placeholder="電腦名稱">
  <select name="rule">{% for o in rules %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}</select>
  <select name="severity">{% for o in severities %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}</select>
  <select name="status">{% for o in statuses %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}</select>
  <select name="group">{% for o in groups %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}</select>
  <button>搜尋</button>
  <a href="{{ csv_url }}">匯出 CSV</a>
</form>
<table>
  <tr><th>電腦名稱</th><th>群組</th><th>規則</th><th>嚴重度</th><th>狀態</th><th>細節</th><th>開始時間</th></tr>
  {% for v in rows %}
  <tr>
    <td><a href="/devices/{{ v.device_id }}">{{ v.hostname }}</a></td>
    <td>{{ v.group }}</td><td>{{ v.rule }}</td>
    <td><span class="sev {{ v.severity_class }}">{{ v.severity }}</span></td>
    <td>{{ v.status }}</td><td>{{ v.summary }}</td><td>{{ v.since }}</td>
  </tr>
  {% endfor %}
</table>
<div class="pager">
  {% if page > 0 %}<a href="{{ prev_url }}">上一頁</a>{% endif %}
  <span class="muted">第 {{ page + 1 }} 頁</span>
  {% if has_next %}<a href="{{ next_url }}">下一頁</a>{% endif %}
</div>
{% endblock %}
```

- [ ] **Step 4: 路由與登入檢查**

`web/mod.rs`：`pub mod compliance;`，路由加

```rust
        .route("/compliance", get(compliance::overview))
        .route("/compliance/violations", get(compliance::violations))
```

`tests/web.rs` 的 `pages_require_login` 清單加 `"/compliance"`、`"/compliance/violations"`。

- [ ] **Step 5: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 6: Commit**

```bash
git add -A crates/server
git commit -m "合規網頁：總覽與違規清單（依群組範圍）"
```

---

### Task 5: CSV 匯出

**Files:**
- Modify: `crates/server/Cargo.toml`（`futures-util` 移到 `[dependencies]`）
- Modify: `crates/server/src/web/compliance.rs`、`crates/server/src/web/mod.rs`
- Test: `crates/server/src/web/compliance.rs`（單元）、`crates/server/tests/compliance_web.rs`

**Interfaces:**
- Produces：`pub fn csv_field(s: &str) -> String`；路由 `GET /compliance/violations.csv` → `compliance::export_csv`；稽核 action `compliance_export`。

- [ ] **Step 1: 寫失敗的單元測試**（`web/compliance.rs` 底部）

```rust
#[cfg(test)]
mod tests {
    use super::csv_field;

    #[test]
    fn csv_quotes_and_neutralizes_formulas() {
        assert_eq!(csv_field("plain"), "\"plain\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("=cmd|' /C calc'!A0"), "\"'=cmd|' /C calc'!A0\"");
        for p in ["+1", "-1", "@SUM(A1)", "\tx", "\rx"] {
            assert!(csv_field(p).starts_with("\"'"), "{p:?}");
        }
        assert_eq!(csv_field("多行\n文字"), "\"多行\n文字\"");
    }
}
```

Run: `cargo test -p endpoint-server --lib web::compliance`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作**

`Cargo.toml` 的 `[dependencies]` 加 `futures-util = "0.3"`，`[dev-dependencies]` 刪掉同一行。

`web/compliance.rs`：

```rust
/// 每個欄位都加引號；以 = + - @ Tab CR 開頭時前面加 '，避免 Excel 當公式執行（CSV 注入）。
pub fn csv_field(s: &str) -> String {
    let risky = s.starts_with(['=', '+', '-', '@', '\t', '\r']);
    let body = s.replace('"', "\"\"");
    if risky { format!("\"'{body}\"") } else { format!("\"{body}\"") }
}

const CSV_BATCH: i64 = 5000;

pub async fn export_csv(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(f): Query<ViolationFilter>,
) -> Result<Response, AppError> {
    use axum::body::Body;
    use axum::http::header;
    use axum::response::IntoResponse;

    let mut conn = st.pool.acquire().await?;
    crate::audit::record(
        &mut conn,
        &s.username,
        "compliance_export",
        None,
        serde_json::json!({"rule": f.rule, "severity": f.severity, "status": f.status, "group": f.group, "q": f.q}),
    )
    .await?;
    drop(conn);

    // 以 (device_id, rule_id) 分批讀取，邊讀邊送，不把全部結果放進記憶體
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<String, std::io::Error>>(4);
    tokio::spawn(async move {
        let _ = tx.send(Ok("\u{feff}裝置ID,電腦名稱,群組,規則,嚴重度,狀態,細節,開始時間(UTC)\r\n".into())).await;
        let mut after: (Uuid, i64) = (Uuid::nil(), -1);
        loop {
            let sql = format!(
                "{} AND (v.device_id, v.rule_id) > ($9, $10) ORDER BY v.device_id, v.rule_id LIMIT $11",
                violation_select().replacen("SELECT v.device_id,", "SELECT v.device_id, v.rule_id,", 1)
            );
            let rows: Result<Vec<(Uuid, i64, String, Option<String>, String, String, String, String, DateTime<Utc>)>, _> =
                sqlx::query_as(sqlx::AssertSqlSafe(sql))
                    .bind(s.all_devices())
                    .bind(&s.groups)
                    .bind(&f.rule)
                    .bind(&f.severity)
                    .bind(&f.status)
                    .bind(&f.group)
                    .bind(&f.q)
                    .bind(escape_like(&f.q))
                    .bind(after.0)
                    .bind(after.1)
                    .bind(CSV_BATCH)
                    .fetch_all(&st.pool)
                    .await;
            let rows = match rows {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "csv export failed");
                    let _ = tx.send(Err(std::io::Error::other("database error"))).await;
                    return;
                }
            };
            let Some(last) = rows.last() else { return };
            after = (last.0, last.1);
            let mut chunk = String::new();
            for (device, _, host, group, rule, sev, status, detail, since) in &rows {
                let detail: serde_json::Value = serde_json::from_str(detail).unwrap_or_default();
                let sev = Severity::parse(sev).map(Severity::label).unwrap_or("?");
                let status = Status::parse(status).map(Status::label).unwrap_or("?");
                let fields = [
                    device.to_string(),
                    host.clone(),
                    group.clone().unwrap_or_else(|| "未分組".into()),
                    rule.clone(),
                    sev.into(),
                    status.into(),
                    summarize(&detail),
                    since.format("%Y-%m-%d %H:%M:%S").to_string(),
                ];
                chunk.push_str(&fields.iter().map(|x| csv_field(x)).collect::<Vec<_>>().join(","));
                chunk.push_str("\r\n");
            }
            if tx.send(Ok(chunk)).await.is_err() || (rows.len() as i64) < CSV_BATCH {
                return;
            }
        }
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move { rx.recv().await.map(|item| (item, rx)) });
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"violations.csv\""),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}
```

`violation_select()` 的欄位順序是 `device_id, hostname, group, rule name, severity, status, detail, since`；CSV 版用 `replacen` 在 `device_id` 後插入 `rule_id`，所以 tuple 是 `(device_id, rule_id, hostname, group, rule, severity, status, detail, since)`。若覺得 `replacen` 太脆弱，改成讓 `violation_select(with_rule_id: bool)` 接參數——兩者擇一，重點是欄位順序與 tuple 一致。

`Session` 需要 `Clone`（已有 `#[derive(Debug, Clone)]`）；`move` 進 task 的 `s`、`f`、`st` 都是 owned。

路由：`.route("/compliance/violations.csv", get(compliance::export_csv))`。

- [ ] **Step 3: 整合測試**

```rust
#[sqlx::test(migrations = false)]
async fn csv_export_is_scoped_bom_and_safe(pool: PgPool) {
    let s = TestServer::start(pool).await;
    add_rule_via_admin(&s, "forbidden_software", serde_json::json!({"name": "=*"})).await;
    let taipei = device_in(&s, "台北", &["=cmd|' /C calc'!A0"]).await;
    let kaohsiung = device_in(&s, "高雄", &["=evil"]).await;
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let r = g.get(s.web_url("/compliance/violations.csv")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.headers()["content-type"].to_str().unwrap().starts_with("text/csv"));
    let body = r.text().await.unwrap();
    assert!(body.starts_with('\u{feff}'), "BOM");
    assert!(body.contains(&taipei.device_id.to_string()));
    assert!(!body.contains(&kaohsiung.device_id.to_string()), "範圍外");
    assert!(body.contains("\"'=cmd"), "公式開頭加 '：{body}");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'compliance_export'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}
```

（細節摘要是 `summarize` 的軟體清單，含軟體名稱 `=cmd|' /C calc'!A0 1`；以 `=` 開頭，會被加 `'`。）

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server
git commit -m "合規網頁：CSV 匯出（串流、BOM、防公式注入、稽核）"
```

---

### Task 6: 裝置頁「合規」分頁與豁免

**Files:**
- Modify: `crates/server/src/web/compliance.rs`（`device_tab`、`create_exemption`、`revoke_exemption`）
- Create: `crates/server/templates/compliance_tab.html`
- Modify: `crates/server/src/web/devices.rs`（`tabs` 加一項；`tab` 分派到 `compliance::device_tab`）
- Modify: `crates/server/src/web/mod.rs`（路由）
- Test: `crates/server/tests/compliance_web.rs`

**Interfaces:**
- Consumes: `compliance::admin::{create_exemption, revoke_exemption, MAX_EXEMPTION_DAYS}`、`web::devices::device_group_in_scope`。
- Produces（路由）：`POST /devices/{id}/exemptions` → `compliance::create_exemption`；`POST /exemptions/{id}/revoke` → `compliance::revoke_exemption`。
- Produces：`pub async fn device_tab(st: &AppState, s: &Session, id: Uuid) -> Result<Response, AppError>`。

- [ ] **Step 1: 寫失敗的整合測試**

```rust
#[sqlx::test(migrations = false)]
async fn device_tab_and_exemptions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let rule = add_rule_via_admin(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    let a = device_in(&s, "台北", &[]).await;
    let tab = format!("/devices/{}/tab/compliance", a.device_id);

    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, &tab).await;
    assert_eq!(st, 200);
    assert!(html.contains("缺少 KB5031455") && html.contains("新增豁免"), "{html}");
    let (_, page) = s.page(&admin, &format!("/devices/{}", a.device_id)).await;
    assert!(page.contains("/tab/compliance"), "裝置頁有合規分頁");
    let csrf = csrf_from(&page);
    let r = admin
        .post(s.web_url(&format!("/devices/{}/exemptions", a.device_id)))
        .form(&[("csrf", csrf.as_str()), ("rule_id", &rule.to_string()), ("reason", "舊系統"), ("days", "30")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let (_, html) = s.page(&admin, &tab).await;
    assert!(html.contains("豁免") && html.contains("舊系統") && html.contains("撤銷"));

    // 群組管理員看得到分頁，但沒有豁免按鈕，POST 也被拒
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (st, html) = s.page(&g, &tab).await;
    assert_eq!(st, 200);
    assert!(!html.contains("新增豁免") && !html.contains("撤銷"));
    let gcsrf = csrf_from(&s.page(&g, "/").await.1);
    let r = g
        .post(s.web_url(&format!("/devices/{}/exemptions", a.device_id)))
        .form(&[("csrf", gcsrf.as_str()), ("rule_id", &rule.to_string()), ("reason", "x"), ("days", "1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // 範圍外的群組管理員：分頁 404
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &tab).await.0, 404);

    // 撤銷
    let ex: i64 = sqlx::query_scalar("SELECT id FROM compliance_exemptions").fetch_one(&s.pool).await.unwrap();
    let r = admin
        .post(s.web_url(&format!("/exemptions/{ex}/revoke")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM compliance_exemptions").fetch_one(&s.pool).await.unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn device_tab_without_rules_or_data(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, &format!("/devices/{}/tab/compliance", a.device_id)).await;
    assert_eq!(st, 200);
    assert!(html.contains("沒有違規"), "{html}");
}
```

Run: `cargo test -p endpoint-server --test compliance_web device_tab`
Expected: FAIL（分頁 404）。

- [ ] **Step 2: 實作**

`web/compliance.rs` 加：

```rust
use axum::extract::{Form, Path};
use axum::response::{IntoResponse, Redirect};

use super::auth::check_csrf;
use super::devices::{action_error, db_error, device_group_in_scope};
use super::login::CsrfForm;
use super::{forbidden, not_found};

pub struct ResultRow {
    pub rule: String,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub status: &'static str,
    pub summary: String,
    pub since: String,
}

pub struct ExemptionRow {
    pub id: i64,
    pub rule: String,
    pub reason: String,
    pub expires: String,
    pub created_by: String,
}

pub struct EventRow {
    pub at: String,
    pub rule: String,
    pub change: String,
    pub summary: String,
}

#[derive(Template)]
#[template(path = "compliance_tab.html")]
struct TabFragment {
    device_id: Uuid,
    csrf: String,
    platform: bool,
    results: Vec<ResultRow>,
    exemptions: Vec<ExemptionRow>,
    events: Vec<EventRow>,
    rules: Vec<SelectOption>,
    max_days: i64,
}

fn status_word(s: &str) -> &'static str {
    Status::parse(s).map(Status::label).unwrap_or("無")
}

pub async fn device_tab(st: &AppState, s: &Session, id: Uuid) -> Result<Response, AppError> {
    if device_group_in_scope(st, s, id).await?.is_none() {
        return Ok(not_found());
    }
    let results: Vec<(String, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT r.name, r.severity, v.status, v.detail::text, v.since FROM device_violations v \
         JOIN compliance_rules r ON r.id = v.rule_id WHERE v.device_id = $1 \
         ORDER BY CASE v.status WHEN 'violating' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, r.name",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let exemptions: Vec<(i64, String, String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT e.id, r.name, e.reason, e.expires_at, e.created_by FROM compliance_exemptions e \
         JOIN compliance_rules r ON r.id = e.rule_id WHERE e.device_id = $1 ORDER BY e.expires_at",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let events: Vec<(DateTime<Utc>, String, String, String, String)> = sqlx::query_as(
        "SELECT at, rule_name, from_status, to_status, detail::text FROM violation_events \
         WHERE device_id = $1 ORDER BY at DESC, id DESC LIMIT 50",
    )
    .bind(id)
    .fetch_all(&st.pool)
    .await?;
    let rules: Vec<(i64, String)> = if s.all_devices() {
        sqlx::query_as("SELECT id, name FROM compliance_rules WHERE enabled ORDER BY name")
            .fetch_all(&st.pool)
            .await?
    } else {
        vec![]
    };
    let sev = |x: &str| Severity::parse(x).unwrap_or(Severity::Medium);
    let summary = |d: &str| summarize(&serde_json::from_str(d).unwrap_or_default());
    Ok(render(&TabFragment {
        device_id: id,
        csrf: s.csrf.clone(),
        platform: s.all_devices(),
        results: results
            .into_iter()
            .map(|(rule, severity, status, detail, since)| ResultRow {
                rule,
                severity: sev(&severity).label(),
                severity_class: sev(&severity).as_str(),
                status: status_word(&status),
                summary: summary(&detail),
                since: fmt_time(st, Some(since)),
            })
            .collect(),
        exemptions: exemptions
            .into_iter()
            .map(|(id, rule, reason, expires, created_by)| ExemptionRow {
                id,
                rule,
                reason,
                expires: fmt_time(st, Some(expires)),
                created_by,
            })
            .collect(),
        events: events
            .into_iter()
            .map(|(at, rule, from, to, detail)| EventRow {
                at: fmt_time(st, Some(at)),
                rule,
                change: format!("{} → {}", status_word(&from), status_word(&to)),
                summary: summary(&detail),
            })
            .collect(),
        rules: rules
            .into_iter()
            .map(|(id, name)| SelectOption { value: id.to_string(), label: name, selected: false })
            .collect(),
        max_days: crate::compliance::admin::MAX_EXEMPTION_DAYS,
    }))
}

#[derive(Deserialize)]
pub struct ExemptionForm {
    csrf: String,
    rule_id: i64,
    reason: String,
    days: i64,
}

pub async fn create_exemption(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<Uuid>,
    Form(f): Form<ExemptionForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let days = f.days.clamp(1, crate::compliance::admin::MAX_EXEMPTION_DAYS);
    crate::compliance::admin::create_exemption(
        &st.pool,
        id,
        f.rule_id,
        &f.reason,
        Utc::now() + chrono::Duration::days(days),
        &s.username,
    )
    .await
    .map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{id}")).into_response())
}

pub async fn revoke_exemption(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<CsrfForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    if !s.all_devices() {
        return Err(forbidden());
    }
    let device: Option<Uuid> = sqlx::query_scalar("SELECT device_id FROM compliance_exemptions WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await
        .map_err(db_error)?;
    let device = device.ok_or_else(not_found)?;
    crate::compliance::admin::revoke_exemption(&st.pool, id, &s.username)
        .await
        .map_err(action_error)?;
    Ok(Redirect::to(&format!("/devices/{device}")).into_response())
}
```

（`days` 用 `clamp` 只是保險：`create_exemption` 本身會驗證範圍。表單欄位 `days` 非數字時 axum 的 `Form` 回 422，可接受。）

`templates/compliance_tab.html`：

```html
<h3>目前結果</h3>
{% if results.is_empty() %}<p class="muted">沒有違規。</p>{% else %}
<table>
  <tr><th>規則</th><th>嚴重度</th><th>狀態</th><th>細節</th><th>開始時間</th></tr>
  {% for r in results %}<tr><td>{{ r.rule }}</td><td><span class="sev {{ r.severity_class }}">{{ r.severity }}</span></td><td>{{ r.status }}</td><td>{{ r.summary }}</td><td>{{ r.since }}</td></tr>{% endfor %}
</table>
{% endif %}
<h3>豁免</h3>
{% if exemptions.is_empty() %}<p class="muted">沒有豁免。</p>{% else %}
<table>
  <tr><th>規則</th><th>原因</th><th>到期</th><th>建立者</th><th></th></tr>
  {% for e in exemptions %}
  <tr><td>{{ e.rule }}</td><td>{{ e.reason }}</td><td>{{ e.expires }}</td><td>{{ e.created_by }}</td>
    <td>{% if platform %}<form class="inline" method="post" action="/exemptions/{{ e.id }}/revoke"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="danger">撤銷</button></form>{% endif %}</td></tr>
  {% endfor %}
</table>
{% endif %}
{% if platform && !rules.is_empty() %}
<form method="post" action="/devices/{{ device_id }}/exemptions">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <select name="rule_id">{% for r in rules %}<option value="{{ r.value }}">{{ r.label }}</option>{% endfor %}</select>
  <input name="reason" required maxlength="500" placeholder="原因" size="30">
  <label>有效天數 <input name="days" type="number" min="1" max="{{ max_days }}" value="30" required></label>
  <button>新增豁免</button>
</form>
{% endif %}
<h3>最近歷程</h3>
{% if events.is_empty() %}<p class="muted">沒有歷程。</p>{% else %}
<table>
  <tr><th>時間</th><th>規則</th><th>變化</th><th>細節</th></tr>
  {% for e in events %}<tr><td>{{ e.at }}</td><td>{{ e.rule }}</td><td>{{ e.change }}</td><td>{{ e.summary }}</td></tr>{% endfor %}
</table>
{% endif %}
```

`web/devices.rs`：
- `detail` 的 `tabs` 在最前面加 `("compliance", "合規")`。
- `tab` 開頭（`device_group_in_scope` 檢查之前）加：
  ```rust
      if tab == "compliance" {
          return super::compliance::device_tab(&st, &s, id).await;
      }
  ```

`web/mod.rs` 路由：

```rust
        .route("/devices/{id}/exemptions", post(compliance::create_exemption))
        .route("/exemptions/{id}/revoke", post(compliance::revoke_exemption))
```

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 4: 全部測試與靜態檢查**

Run: `cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`
Expected: 全部通過。

- [ ] **Step 5: Commit**

```bash
git add -A crates/server
git commit -m "合規網頁：裝置頁合規分頁與豁免"
```
