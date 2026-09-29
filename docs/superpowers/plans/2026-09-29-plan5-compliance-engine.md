# 計畫 5：合規引擎 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 伺服器能依規則評估每台裝置、保存目前違規與歷程，並在上傳、裝置生命週期變更、規則／豁免變更時自動更新。

**Architecture:** 新模組 `crates/server/src/compliance/`：`matcher`（萬用字元、版本比較）與 `rules`（參數解析）、`evaluate`（純函式）不碰資料庫；`store` 負責讀事實、套用結果、寫歷程；`admin` 是規則與豁免的增刪改（含稽核）；`worker` 是背景重算、豁免到期、每日快照與歷程清理。Agent 只多收集 UBR。

**Tech Stack:** Rust、sqlx 0.9（PostgreSQL）、tokio、serde_json；不加新相依套件。

**Spec:** `docs/superpowers/specs/2026-09-29-compliance-design.md`

## Global Constraints

- 所有使用者可見文字、註解用繁體中文；程式識別字用英文。
- 不加新相依套件（本計畫範圍內）。
- sqlx 沒有開 `json` feature：jsonb 一律以 `$n::jsonb` 綁字串寫入、以 `::text` 讀出再 `serde_json::from_str`（沿用既有寫法）。
- 每個修改動作寫 `audit_log`（`crate::audit::record`）。
- 資料庫測試用 `#[sqlx::test(migrations = false)]` 並自行 `crate::db::migrate`（或 `TestServer::start`）。
- 測試指令：`cargo test -p endpoint-server`、`cargo test -p protocol`；最後跑 `cargo clippy --workspace --all-targets -- -D warnings` 與 `cargo fmt --all --check`。
- `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres`（Docker `em-postgres`）。

## Review Focus

1. 舊版 Agent（沒有 `os_ubr`）上傳 basic 時，伺服器算出的 hash 必須和 Agent 一樣，否則每次報到都被要求重傳 basic —— `os_ubr` 為 `None` 時不能出現在序列化結果中。
2. 上傳觸發的評估與背景重算同時處理同一台時，最後結果必須反映最新盤點（事實要在裝置鎖內讀取）。
3. 評估出錯（例如規則參數被手動改壞）不能讓盤點上傳失敗，也不能讓其他規則停止評估。
4. 規則停用、刪除、群組移動、除役後，不能殘留過期的違規結果。
5. 被規則引用的群組不能刪除（否則「只套用」清單變空，規則變成套用全部裝置）。

---

## File Structure

- Modify `crates/protocol/src/lib.rs` — `BasicInfo.os_ubr`。
- Modify `crates/agent/src/windows/collect.rs` — 讀 UBR。
- Modify `crates/agent/tests/e2e.rs`、`crates/server/tests/inventory.rs` — 建構 `BasicInfo` 補欄位。
- Create `crates/server/migrations/0004_compliance.sql`。
- Modify `crates/server/src/inventory.rs` — 存取 `os_ubr`；上傳後觸發評估。
- Create `crates/server/src/compliance/mod.rs` — 模組宣告、`RuleCache`、`refresh_after_upload`。
- Create `crates/server/src/compliance/matcher.rs` — `Glob`、`cmp_version`。
- Create `crates/server/src/compliance/rules.rs` — `Severity`、`Params`、`Check`、`Rule`、`RuleSet`。
- Create `crates/server/src/compliance/evaluate.rs` — `DeviceFacts`、`Status`、`Outcome`、`evaluate`。
- Create `crates/server/src/compliance/store.rs` — `load_ruleset`、`load_facts`、`refresh_device`、`refresh_device_in`、`refresh_device_fresh`。
- Create `crates/server/src/compliance/admin.rs` — 規則與豁免增刪改。
- Create `crates/server/src/compliance/worker.rs` — 重算、到期、快照、清理、`spawn`。
- Modify `crates/server/src/lib.rs` — `pub mod compliance`、`AppState.rules`、啟動 worker。
- Modify `crates/server/src/devices.rs`、`crates/server/src/groups.rs` — 生命週期觸發評估；群組被規則引用時不能刪除。
- Modify `crates/server/src/web/groups.rs`、`crates/server/templates/groups.html` — 群組頁顯示規則引用數。
- Create `crates/server/tests/compliance.rs` — 整合測試。

---

### Task 1: `os_ubr` 從 Agent 到資料庫

**Files:**
- Modify: `crates/protocol/src/lib.rs`
- Modify: `crates/agent/src/windows/collect.rs:166-178`
- Modify: `crates/agent/tests/e2e.rs:199`、`crates/server/tests/inventory.rs:126,212`
- Create: `crates/server/migrations/0004_compliance.sql`（本 task 只放 `os_ubr` 一行，Task 2 補其餘）
- Modify: `crates/server/src/inventory.rs`（`BasicRow`、`load_payload`、`write_payload`）
- Modify: `crates/agent/tests/windows.rs`（收集測試）

**Interfaces:**
- Produces: `protocol::BasicInfo { ..., os_ubr: Option<u32> }`；`devices.os_ubr INTEGER`。

- [ ] **Step 1: 寫失敗測試（protocol）**

在 `crates/protocol/src/lib.rs` 的 `mod tests` 加：

```rust
    fn basic(ubr: Option<u32>) -> InventoryPayload {
        InventoryPayload::Basic(BasicInfo {
            hostname: "PC1".into(),
            domain: None,
            is_domain_joined: false,
            os_caption: "Windows 11".into(),
            os_build: "22631".into(),
            os_ubr: ubr,
        })
    }

    /// 舊版 Agent 沒有 os_ubr：None 時不能出現在序列化結果，hash 才會和舊版一致
    #[test]
    fn basic_without_ubr_serializes_like_legacy() {
        let v = serde_json::to_value(basic(None)).unwrap();
        assert!(v["data"].get("os_ubr").is_none(), "{v}");
        let legacy: InventoryPayload = serde_json::from_value(serde_json::json!({
            "section": "basic",
            "data": {"hostname": "PC1", "domain": null, "is_domain_joined": false,
                     "os_caption": "Windows 11", "os_build": "22631"}
        }))
        .unwrap();
        assert_eq!(legacy, basic(None));
        assert_ne!(basic(Some(4317)).canonical_hash(), basic(None).canonical_hash());
    }
```

- [ ] **Step 2: 執行，確認失敗**

Run: `cargo test -p protocol basic_without_ubr`
Expected: 編譯錯誤 `struct BasicInfo has no field named os_ubr`。

- [ ] **Step 3: 加欄位**

`BasicInfo` 最後加：

```rust
    /// 月更新小版號（登錄檔 UBR）；舊版 Agent 沒有。None 時不序列化，hash 與舊版一致。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_ubr: Option<u32>,
```

- [ ] **Step 4: 執行，確認通過**

Run: `cargo test -p protocol`
Expected: 全部 PASS。

- [ ] **Step 5: 補齊所有 `BasicInfo { .. }` 建構處**

`crates/agent/tests/e2e.rs:199`、`crates/server/tests/inventory.rs:126` 與 `:212` 加 `os_ubr: None,`。

`crates/agent/src/windows/collect.rs` 的 `Section::Basic` 分支改為：

```rust
                    os_build: os.and_then(|o| o.build_number).unwrap_or_default(),
                    os_ubr: read_ubr(),
```

並在同檔加：

```rust
/// 月更新小版號，例如 22631.4317 的 4317；讀不到就不報。
fn read_ubr() -> Option<u32> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .and_then(|k| k.get_value::<u32, _>("UBR"))
        .ok()
}
```

- [ ] **Step 6: Agent 收集測試（Windows，CI 的 `agent-windows` job 會跑）**

在 `crates/agent/tests/windows.rs` 找到收集 basic 的既有測試（`grep -n "Section::Basic" crates/agent/tests/windows.rs`），在其斷言後加：

```rust
        let InventoryPayload::Basic(b) = &basic else { panic!() };
        assert!(b.os_ubr.is_some_and(|u| u > 0), "Windows 10/11 一定有 UBR: {b:?}");
```

（若既有測試變數名不同，照實際名稱調整；沒有既有 basic 測試就新增一個呼叫 `collect(Section::Basic)` 的測試。）

Run: `cargo test -p endpoint-agent --test windows`（本機非管理員時，只跑得到不需提權的測試；這個測試不需提權）
Expected: PASS。

- [ ] **Step 7: 伺服器存取 `os_ubr`（先寫失敗測試）**

`crates/server/tests/inventory.rs` 加：

```rust
#[sqlx::test(migrations = false)]
async fn basic_ubr_roundtrip(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let p = InventoryPayload::Basic(protocol::BasicInfo {
        hostname: "PC1".into(),
        domain: None,
        is_domain_joined: false,
        os_caption: "Windows 11".into(),
        os_build: "22631".into(),
        os_ubr: Some(4317),
    });
    assert_eq!(put(&s, &a, "basic", &upload(p.clone())).await, 204);
    let ubr: Option<i32> = sqlx::query_scalar("SELECT os_ubr FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(ubr, Some(4317));
    let mut c = s.pool.acquire().await.unwrap();
    let back = endpoint_server::inventory::load_payload(&mut c, a.device_id, protocol::Section::Basic)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(back.canonical_hash(), p.canonical_hash(), "讀回的內容與上傳一致");
}
```

Run: `cargo test -p endpoint-server --test inventory basic_ubr_roundtrip`
Expected: FAIL（`column "os_ubr" does not exist`）。

- [ ] **Step 8: migration 與存取**

建立 `crates/server/migrations/0004_compliance.sql`：

```sql
-- 第二期：軟體與修補合規
ALTER TABLE devices ADD COLUMN os_ubr INTEGER;
```

`inventory.rs`：
- `type BasicRow = (String, Option<String>, bool, Option<String>, Option<String>, Option<i32>);`
- `load_payload` 的 basic 查詢加 `os_ubr`，建構時 `os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),`
- `write_payload` 的 UPDATE 加 `os_ubr = $7`，`.bind(b.os_ubr.and_then(|u| i32::try_from(u).ok()))`。

Run: `cargo test -p endpoint-server --test inventory`
Expected: 全部 PASS。

- [ ] **Step 9: Commit**

```bash
git add -A crates/protocol crates/agent crates/server
git commit -m "Agent 收集月更新小版號（UBR），伺服器保存於 devices.os_ubr"
```

---

### Task 2: 合規資料表與群組刪除檢查

**Files:**
- Modify: `crates/server/migrations/0004_compliance.sql`
- Modify: `crates/server/src/groups.rs`（`usage`、`delete`）
- Modify: `crates/server/src/web/groups.rs`、`crates/server/templates/groups.html`
- Test: `crates/server/src/groups.rs` 的 `mod tests`

**Interfaces:**
- Produces: 資料表 `compliance_rules`、`compliance_rule_groups`、`compliance_exemptions`、`device_violations`、`violation_events`、`compliance_daily`、`compliance_state`；設定 `violation_history_days`。
- Produces: `groups::usage(conn, id) -> Result<(i64, i64, i64, i64), sqlx::Error>`（第 4 個是引用它的規則數）。

- [ ] **Step 1: 寫失敗測試**

`groups.rs` 的 `mod tests` 加：

```rust
    /// 被規則引用的群組不能刪除：否則「只套用」清單變空，規則會默默套用到全部裝置
    #[sqlx::test(migrations = false)]
    async fn group_referenced_by_rule_cannot_be_deleted(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let g = find_or_create(&mut c, "資訊亭").await.unwrap();
        let rule: i64 = sqlx::query_scalar(
            "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
             VALUES ('r', 'required_kb', 'high', '{\"kb\":\"KB5034439\"}', 't') RETURNING id",
        )
        .fetch_one(&mut *c)
        .await
        .unwrap();
        sqlx::query("INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, 'include')")
            .bind(rule)
            .bind(g)
            .execute(&mut *c)
            .await
            .unwrap();
        assert_eq!(usage(&mut c, g).await.unwrap().3, 1);
        let err = delete(&pool, g, "t").await.unwrap_err();
        assert!(format!("{err:#}").contains("1 條規則"), "{err:#}");
    }
```

Run: `cargo test -p endpoint-server --lib group_referenced_by_rule`
Expected: FAIL（`relation "compliance_rules" does not exist`）。

- [ ] **Step 2: 補完 migration**

在 `0004_compliance.sql` 的 `os_ubr` 之後加：

```sql
CREATE TABLE compliance_rules (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL CHECK (kind IN ('forbidden_software', 'required_software',
                                              'software_allowlist', 'os_build', 'required_kb')),
    severity    TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    params      JSONB NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- group_id 不 cascade：被引用的群組不能刪除（groups::delete 檢查）
CREATE TABLE compliance_rule_groups (
    rule_id  BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES device_groups(id),
    mode     TEXT NOT NULL CHECK (mode IN ('include', 'exclude')),
    PRIMARY KEY (rule_id, group_id)
);
CREATE INDEX compliance_rule_groups_group_idx ON compliance_rule_groups (group_id);

CREATE TABLE compliance_exemptions (
    id         BIGSERIAL PRIMARY KEY,
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id    BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    reason     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, rule_id)
);
CREATE INDEX compliance_exemptions_expires_idx ON compliance_exemptions (expires_at);

CREATE TABLE device_violations (
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id    BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    status     TEXT NOT NULL CHECK (status IN ('violating', 'unknown', 'exempt')),
    detail     JSONB NOT NULL,
    since      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, rule_id)
);
CREATE INDEX device_violations_rule_idx ON device_violations (rule_id, status);

-- 歷程；規則刪除後保留名稱與嚴重度快照。to_status / from_status 的 'none' 表示無結果
CREATE TABLE violation_events (
    id          BIGSERIAL PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id     BIGINT REFERENCES compliance_rules(id) ON DELETE SET NULL,
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status   TEXT NOT NULL,
    detail      JSONB NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX violation_events_device_idx ON violation_events (device_id, at);
CREATE INDEX violation_events_at_idx ON violation_events (at);

CREATE TABLE compliance_daily (
    day       DATE NOT NULL,
    rule_id   BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    violating INTEGER NOT NULL,
    unknown   INTEGER NOT NULL,
    exempt    INTEGER NOT NULL,
    PRIMARY KEY (day, rule_id)
);

-- 單列：generation 在規則變更時 +1；背景工作重算到 done_generation 追上為止
CREATE TABLE compliance_state (
    id              BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    generation      BIGINT NOT NULL DEFAULT 0,
    done_generation BIGINT NOT NULL DEFAULT 0,
    run_generation  BIGINT NOT NULL DEFAULT 0,
    cursor          UUID,
    started_at      TIMESTAMPTZ
);
INSERT INTO compliance_state DEFAULT VALUES;

INSERT INTO settings (key, value) VALUES ('violation_history_days', '365');
```

- [ ] **Step 3: `usage` 與 `delete`**

`groups::usage` 改回傳四元組，SQL 在最後加一個子查詢：

```rust
pub async fn usage(conn: &mut PgConnection, id: i64) -> Result<(i64, i64, i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT (SELECT count(*) FROM devices WHERE group_id = $1 AND status <> 'retired'), \
                (SELECT count(*) FROM enroll_tokens WHERE group_id = $1 \
                   AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) \
                   AND used_count < max_uses), \
                (SELECT count(*) FROM admin_groups WHERE group_id = $1), \
                (SELECT count(DISTINCT rule_id) FROM compliance_rule_groups WHERE group_id = $1)",
    )
    .bind(id)
    .fetch_one(conn)
    .await
}
```

（原 SQL 字串中的換行空白是縮排殘留，這次一併改成 `\` 續行。）更新 doc comment：「……被指派的管理員、引用它的合規規則」。

`delete`：

```rust
    let (devices, tokens, admins, rules) = usage(&mut tx, id).await?;
    anyhow::ensure!(
        devices == 0 && tokens == 0 && admins == 0 && rules == 0,
        "群組內還有 {devices} 台裝置、{tokens} 把有效金鑰、{admins} 位管理員，\
         並被 {rules} 條規則引用，無法刪除"
    );
```

`web/groups.rs`：`GroupRow` 加 `pub rules: i64`，`list` 解構四元組並填入。`groups.html`：表頭加 `<th>規則</th>`（放在「管理員」後），列加 `<td>{{ g.rules }}</td>`，刪除按鈕條件改為 `{% if g.devices == 0 && g.tokens == 0 && g.rules == 0 %}`。

- [ ] **Step 4: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS（包含新測試；既有群組頁測試仍通過）。

- [ ] **Step 5: Commit**

```bash
git add -A crates/server
git commit -m "合規資料表；被規則引用的群組不能刪除"
```

---

### Task 3: 萬用字元與版本比較

**Files:**
- Create: `crates/server/src/compliance/mod.rs`（先只有 `pub mod matcher;`）
- Create: `crates/server/src/compliance/matcher.rs`
- Modify: `crates/server/src/lib.rs`（`pub mod compliance;`）

**Interfaces:**
- Produces: `compliance::matcher::Glob::new(&str) -> Glob`、`Glob::is_match(&self, &str) -> bool`、`Glob::as_str(&self) -> &str`；`compliance::matcher::cmp_version(a: &str, b: &str) -> std::cmp::Ordering`。

- [ ] **Step 1: 寫失敗測試**

`matcher.rs`：

```rust
//! 名稱比對（`*` 萬用字元，不分大小寫）與版本比較。

use std::cmp::Ordering;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matches() {
        let cases = [
            ("Google Chrome", "google chrome", true),
            ("Google Chrome", "Google Chrome Beta", false),
            ("Google Chrome*", "Google Chrome Beta", true),
            ("*TeamViewer*", "TeamViewer 15", true),
            ("*TeamViewer*", "My teamviewer host", true),
            ("*viewer", "TeamViewer 15", false),
            ("a*b*c", "abc", true),
            ("a*b*c", "aXbYc", true),
            ("a*b*c", "acb", false),
            ("ab*ba", "aba", false),
            ("*", "", true),
            ("", "", true),
            ("", "x", false),
            ("ÄRGER*", "ärger 2", true),
            ("7-Zip*", "7-Zip 23.01 (x64)", true),
        ];
        for (pat, s, want) in cases {
            assert_eq!(Glob::new(pat).is_match(s), want, "{pat:?} vs {s:?}");
        }
    }

    #[test]
    fn version_order() {
        use Ordering::*;
        let cases = [
            ("10.0.9", "10.0.10", Less),
            ("1.2", "1.2.0", Equal),
            ("1.2.0.0", "1.2", Equal),
            ("1.0", "1.0-beta", Greater),
            ("1.0-alpha", "1.0-beta", Less),
            ("1.0-BETA", "1.0-beta", Equal),
            ("120.0.6099.130", "120.0.6099.71", Greater),
            ("2", "10", Less),
            ("", "0", Equal),
            ("99999999999999999999999", "1", Less), // 超過 u64 當文字，文字小於數字
        ];
        for (a, b, want) in cases {
            assert_eq!(cmp_version(a, b), want, "{a:?} vs {b:?}");
            assert_eq!(cmp_version(b, a), want.reverse(), "{b:?} vs {a:?}");
        }
    }
}
```

Run: `cargo test -p endpoint-server --lib matcher`
Expected: 編譯錯誤（`Glob`、`cmp_version` 未定義）。

- [ ] **Step 2: 實作**

在 `matcher.rs` 的 `#[cfg(test)]` 之前加：

```rust
/// `*` 代表任意長度字串；整串比對；不分大小寫（Unicode 小寫化）。
#[derive(Debug, Clone, PartialEq)]
pub struct Glob {
    source: String,
    parts: Vec<String>,
}

impl Glob {
    pub fn new(pattern: &str) -> Glob {
        Glob {
            source: pattern.to_string(),
            parts: pattern.to_lowercase().split('*').map(str::to_string).collect(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.source
    }

    pub fn is_match(&self, s: &str) -> bool {
        let s = s.to_lowercase();
        let (first, last) = (&self.parts[0], &self.parts[self.parts.len() - 1]);
        if self.parts.len() == 1 {
            return s == *first;
        }
        if s.len() < first.len() + last.len() || !s.starts_with(first.as_str()) || !s.ends_with(last.as_str()) {
            return false;
        }
        // 中間各段依序取最左邊的出現位置（貪婪即正確）
        let mut rest = &s[first.len()..s.len() - last.len()];
        for mid in &self.parts[1..self.parts.len() - 1] {
            match rest.find(mid.as_str()) {
                Some(i) => rest = &rest[i + mid.len()..],
                None => return false,
            }
        }
        true
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Seg {
    Num(u64),
    Text(String),
}

fn segments(v: &str) -> Vec<Seg> {
    v.split(['.', '-', '_', '+', ' '])
        .filter(|s| !s.is_empty())
        .map(|s| match s.parse::<u64>() {
            Ok(n) => Seg::Num(n),
            Err(_) => Seg::Text(s.to_lowercase()),
        })
        .collect()
}

/// 逐段比較：數字對數字比數值、文字對文字比字串（不分大小寫）、數字大於文字；段數不足補 0。
pub fn cmp_version(a: &str, b: &str) -> Ordering {
    let (a, b) = (segments(a), segments(b));
    let zero = Seg::Num(0);
    for i in 0..a.len().max(b.len()) {
        let ord = match (a.get(i).unwrap_or(&zero), b.get(i).unwrap_or(&zero)) {
            (Seg::Num(x), Seg::Num(y)) => x.cmp(y),
            (Seg::Text(x), Seg::Text(y)) => x.cmp(y),
            (Seg::Num(_), Seg::Text(_)) => Ordering::Greater,
            (Seg::Text(_), Seg::Num(_)) => Ordering::Less,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}
```

`compliance/mod.rs`：

```rust
//! 軟體與修補合規：規則、評估、違規與歷程。

pub mod matcher;
```

`lib.rs` 在 `pub mod checkin;` 後加 `pub mod compliance;`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --lib matcher`
Expected: 2 個測試 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server/src
git commit -m "合規：萬用字元與版本比較"
```

---

### Task 4: 規則參數解析

**Files:**
- Create: `crates/server/src/compliance/rules.rs`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod rules;`）

**Interfaces:**
- Consumes: `matcher::Glob`。
- Produces:
  - `pub enum Severity { Low, Medium, High }`（`Ord`，`as_str`、`parse`、`label`→「低／中／高」）。
  - `pub const KINDS: [&str; 5]`、`pub fn kind_label(kind: &str) -> &'static str`。
  - `pub enum Params`（見下）＋ `Params::parse(kind: &str, v: &serde_json::Value) -> Result<Params, String>`、`Params::to_json(&self) -> serde_json::Value`、`Params::compile(&self) -> Check`、`Params::kind(&self) -> &'static str`。
  - `pub enum Check`（見下）。
  - `pub struct Rule { pub id: i64, pub name: String, pub severity: Severity, pub include: Vec<i64>, pub exclude: Vec<i64>, pub check: Result<Check, String> }`，`Rule::applies_to(&self, group: Option<i64>) -> bool`。
  - `pub struct RuleSet { pub generation: i64, pub rules: Vec<Rule> }`，`RuleSet::empty()`。

- [ ] **Step 1: 寫失敗測試**

`rules.rs` 底部：

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_and_normalize() {
        let p = Params::parse("required_kb", &json!({"kb": " kb5034439 "})).unwrap();
        assert_eq!(p.to_json(), json!({"kb": "KB5034439"}));
        let p = Params::parse(
            "forbidden_software",
            &json!({"name": " *TeamViewer* ", "publisher": "", "below_version": null}),
        )
        .unwrap();
        assert_eq!(p.to_json(), json!({"name": "*TeamViewer*"}), "空字串視為未設定");
        let p = Params::parse("os_build", &json!({"build": 22631, "min_ubr": 4317})).unwrap();
        assert_eq!(p.to_json(), json!({"build": 22631, "min_ubr": 4317}));
        let p = Params::parse("software_allowlist", &json!({"entries": [{"publisher": "Microsoft*"}]}))
            .unwrap();
        assert_eq!(p.to_json(), json!({"entries": [{"publisher": "Microsoft*"}]}));
    }

    #[test]
    fn parse_rejects_bad_params() {
        let bad = [
            ("required_kb", json!({"kb": "5034439"})),
            ("required_kb", json!({"kb": "KB12"})),
            ("forbidden_software", json!({"name": ""})),
            ("forbidden_software", json!({"name": "x", "extra": 1})),
            ("required_software", json!({"name": "x".repeat(257)})),
            ("software_allowlist", json!({"entries": []})),
            ("software_allowlist", json!({"entries": [{}]})),
            ("os_build", json!({})),
            ("os_build", json!({"min_build": 19045, "build": 22631, "min_ubr": 1})),
            ("os_build", json!({"build": 22631})),
            ("os_build", json!({"min_build": 0})),
            ("nope", json!({})),
        ];
        for (kind, v) in bad {
            assert!(Params::parse(kind, &v).is_err(), "{kind} {v}");
        }
    }

    #[test]
    fn scope_rules() {
        let rule = |include: Vec<i64>, exclude: Vec<i64>| Rule {
            id: 1,
            name: "r".into(),
            severity: Severity::High,
            include,
            exclude,
            check: Err("x".into()),
        };
        assert!(rule(vec![], vec![]).applies_to(None), "全部裝置含未分組");
        assert!(rule(vec![], vec![2]).applies_to(Some(1)));
        assert!(!rule(vec![], vec![2]).applies_to(Some(2)));
        assert!(rule(vec![1], vec![]).applies_to(Some(1)));
        assert!(!rule(vec![1], vec![]).applies_to(Some(3)));
        assert!(!rule(vec![1], vec![]).applies_to(None), "未分組只命中沒限定群組的規則");
        assert!(!rule(vec![1], vec![1]).applies_to(Some(1)), "排除優先");
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::High > Severity::Medium && Severity::Medium > Severity::Low);
        assert_eq!(Severity::parse("medium"), Some(Severity::Medium));
        assert_eq!(Severity::parse("x"), None);
    }
}
```

Run: `cargo test -p endpoint-server --lib rules::tests`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作**

```rust
//! 規則：參數解析與驗證、編譯後的比對條件、套用範圍。

use serde::Deserialize;
use serde_json::{Value, json};

use super::matcher::Glob;

pub const MAX_PATTERN_LEN: usize = 256;

pub const KINDS: [&str; 5] = [
    "forbidden_software",
    "required_software",
    "software_allowlist",
    "os_build",
    "required_kb",
];

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "forbidden_software" => "禁止軟體",
        "required_software" => "必要軟體",
        "software_allowlist" => "軟體白名單",
        "os_build" => "最低組建號",
        "required_kb" => "必要 KB",
        _ => "未知類型",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub const ALL: [Severity; 3] = [Severity::High, Severity::Medium, Severity::Low];

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Severity> {
        Severity::ALL.into_iter().find(|x| x.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "低",
            Severity::Medium => "中",
            Severity::High => "高",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AllowEntry {
    pub name: Option<String>,
    pub publisher: Option<String>,
}

/// 已驗證、正規化（去頭尾空白、空字串視為未設定、KB 大寫）的參數。
#[derive(Debug, Clone, PartialEq)]
pub enum Params {
    Forbidden { name: String, publisher: Option<String>, below_version: Option<String> },
    Required { name: String, publisher: Option<String>, min_version: Option<String> },
    Allowlist { entries: Vec<AllowEntry> },
    MinBuild { min_build: u32 },
    PatchLevel { build: u32, min_ubr: u32 },
    RequiredKb { kb: String },
}

/// 編譯後的比對條件（萬用字元已預先處理）。
#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    Forbidden { name: Glob, publisher: Option<Glob>, below: Option<String> },
    Required { name: Glob, publisher: Option<Glob>, min: Option<String> },
    Allowlist { entries: Vec<(Option<Glob>, Option<Glob>)> },
    MinBuild { min_build: u32 },
    PatchLevel { build: u32, min_ubr: u32 },
    RequiredKb { kb: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSoftware {
    name: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
    #[serde(default)]
    below_version: Option<String>,
    #[serde(default)]
    min_version: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    publisher: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllowlist {
    entries: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBuild {
    #[serde(default)]
    min_build: Option<u32>,
    #[serde(default)]
    build: Option<u32>,
    #[serde(default)]
    min_ubr: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKb {
    kb: String,
}

/// 去頭尾空白；空字串視為未設定；超過長度上限回錯誤。
fn opt(field: &str, v: Option<String>) -> Result<Option<String>, String> {
    let v = v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    match v {
        Some(s) if s.chars().count() > MAX_PATTERN_LEN => {
            Err(format!("{field} 最多 {MAX_PATTERN_LEN} 字"))
        }
        v => Ok(v),
    }
}

fn required(field: &str, v: Option<String>) -> Result<String, String> {
    opt(field, v)?.ok_or_else(|| format!("{field} 必填"))
}

fn from<T: for<'de> Deserialize<'de>>(v: &Value) -> Result<T, String> {
    serde_json::from_value(v.clone()).map_err(|e| format!("參數格式錯誤：{e}"))
}

impl Params {
    pub fn parse(kind: &str, v: &Value) -> Result<Params, String> {
        match kind {
            "forbidden_software" | "required_software" => {
                let r: RawSoftware = from(v)?;
                let name = required("軟體名稱", r.name)?;
                let publisher = opt("發行者", r.publisher)?;
                if kind == "forbidden_software" {
                    if r.min_version.is_some() {
                        return Err("禁止軟體沒有最低版本參數".into());
                    }
                    let below_version = opt("版本", r.below_version)?;
                    Ok(Params::Forbidden { name, publisher, below_version })
                } else {
                    if r.below_version.is_some() {
                        return Err("必要軟體沒有「低於版本」參數".into());
                    }
                    let min_version = opt("最低版本", r.min_version)?;
                    Ok(Params::Required { name, publisher, min_version })
                }
            }
            "software_allowlist" => {
                let r: RawAllowlist = from(v)?;
                if r.entries.is_empty() {
                    return Err("白名單至少要有一筆".into());
                }
                let entries = r
                    .entries
                    .into_iter()
                    .map(|e| {
                        let e = AllowEntry {
                            name: opt("軟體名稱", e.name)?,
                            publisher: opt("發行者", e.publisher)?,
                        };
                        if e.name.is_none() && e.publisher.is_none() {
                            return Err("白名單每筆至少要有名稱或發行者".to_string());
                        }
                        Ok(e)
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(Params::Allowlist { entries })
            }
            "os_build" => {
                let r: RawBuild = from(v)?;
                match (r.min_build, r.build, r.min_ubr) {
                    (Some(min_build), None, None) if min_build > 0 => {
                        Ok(Params::MinBuild { min_build })
                    }
                    (None, Some(build), Some(min_ubr)) if build > 0 => {
                        Ok(Params::PatchLevel { build, min_ubr })
                    }
                    _ => Err("請填「最低組建主號」，或「組建主號＋最低 UBR」其中一種".into()),
                }
            }
            "required_kb" => {
                let r: RawKb = from(v)?;
                let kb = r.kb.trim().to_uppercase();
                let digits = kb.strip_prefix("KB").unwrap_or("");
                if !(6..=8).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("KB 格式應為 KB 加 6 到 8 位數字，例如 KB5034439".into());
                }
                Ok(Params::RequiredKb { kb })
            }
            _ => Err(format!("未知的規則類型：{kind}")),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Params::Forbidden { .. } => "forbidden_software",
            Params::Required { .. } => "required_software",
            Params::Allowlist { .. } => "software_allowlist",
            Params::MinBuild { .. } | Params::PatchLevel { .. } => "os_build",
            Params::RequiredKb { .. } => "required_kb",
        }
    }

    /// 存進資料庫的正規形式（未設定的欄位不輸出）。
    pub fn to_json(&self) -> Value {
        fn put(m: &mut serde_json::Map<String, Value>, k: &str, v: &Option<String>) {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        let mut m = serde_json::Map::new();
        match self {
            Params::Forbidden { name, publisher, below_version } => {
                m.insert("name".into(), json!(name));
                put(&mut m, "publisher", publisher);
                put(&mut m, "below_version", below_version);
            }
            Params::Required { name, publisher, min_version } => {
                m.insert("name".into(), json!(name));
                put(&mut m, "publisher", publisher);
                put(&mut m, "min_version", min_version);
            }
            Params::Allowlist { entries } => {
                let entries: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        let mut o = serde_json::Map::new();
                        put(&mut o, "name", &e.name);
                        put(&mut o, "publisher", &e.publisher);
                        Value::Object(o)
                    })
                    .collect();
                m.insert("entries".into(), json!(entries));
            }
            Params::MinBuild { min_build } => {
                m.insert("min_build".into(), json!(min_build));
            }
            Params::PatchLevel { build, min_ubr } => {
                m.insert("build".into(), json!(build));
                m.insert("min_ubr".into(), json!(min_ubr));
            }
            Params::RequiredKb { kb } => {
                m.insert("kb".into(), json!(kb));
            }
        }
        Value::Object(m)
    }

    pub fn compile(&self) -> Check {
        let g = |s: &Option<String>| s.as_deref().map(Glob::new);
        match self {
            Params::Forbidden { name, publisher, below_version } => Check::Forbidden {
                name: Glob::new(name),
                publisher: g(publisher),
                below: below_version.clone(),
            },
            Params::Required { name, publisher, min_version } => Check::Required {
                name: Glob::new(name),
                publisher: g(publisher),
                min: min_version.clone(),
            },
            Params::Allowlist { entries } => Check::Allowlist {
                entries: entries.iter().map(|e| (g(&e.name), g(&e.publisher))).collect(),
            },
            Params::MinBuild { min_build } => Check::MinBuild { min_build: *min_build },
            Params::PatchLevel { build, min_ubr } => {
                Check::PatchLevel { build: *build, min_ubr: *min_ubr }
            }
            Params::RequiredKb { kb } => Check::RequiredKb { kb: kb.clone() },
        }
    }
}

/// 已啟用的規則。check 為 Err 表示參數壞掉（例如被手動改壞），該規則對範圍內裝置一律「未知」。
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: i64,
    pub name: String,
    pub severity: Severity,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
    pub check: Result<Check, String>,
}

impl Rule {
    /// 排除優先；只套用清單為空代表全部裝置（含未分組）。
    pub fn applies_to(&self, group: Option<i64>) -> bool {
        if group.is_some_and(|g| self.exclude.contains(&g)) {
            return false;
        }
        self.include.is_empty() || group.is_some_and(|g| self.include.contains(&g))
    }
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    pub generation: i64,
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn empty() -> RuleSet {
        RuleSet { generation: -1, rules: vec![] }
    }
}
```

`mod.rs` 加 `pub mod rules;`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --lib rules::tests`
Expected: 4 個測試 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server/src/compliance
git commit -m "合規：規則參數解析、正規化與套用範圍"
```

---

### Task 5: 評估函式

**Files:**
- Create: `crates/server/src/compliance/evaluate.rs`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod evaluate;`）

**Interfaces:**
- Consumes: `rules::{Check, Rule, RuleSet}`、`matcher::cmp_version`。
- Produces:
  - `pub struct SoftwareFact { pub name: String, pub version: Option<String>, pub publisher: Option<String> }`
  - `pub struct DeviceFacts { pub active: bool, pub group_id: Option<i64>, pub os_build: Option<String>, pub os_ubr: Option<u32>, pub software: Option<Vec<SoftwareFact>>, pub kbs: Option<Vec<String>>, pub exempt: Vec<i64> }`（`os_build` 為 None 表示從未上傳 basic；`software`／`kbs` 為 None 表示從未上傳該區段）
  - `pub enum Status { Violating, Unknown, Exempt }`，`as_str`／`parse`／`label`（違規／未知／豁免）
  - `pub struct Outcome { pub rule_id: i64, pub status: Status, pub detail: serde_json::Value }`
  - `pub fn evaluate(facts: &DeviceFacts, rules: &RuleSet) -> Vec<Outcome>`
  - `pub const MAX_LISTED: usize = 50`

- [ ] **Step 1: 寫失敗測試**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::rules::{Params, Rule, RuleSet, Severity};
    use serde_json::json;

    fn sw(name: &str, version: Option<&str>, publisher: Option<&str>) -> SoftwareFact {
        SoftwareFact {
            name: name.into(),
            version: version.map(Into::into),
            publisher: publisher.map(Into::into),
        }
    }

    fn facts(software: Vec<SoftwareFact>) -> DeviceFacts {
        DeviceFacts {
            active: true,
            group_id: Some(1),
            os_build: Some("22631".into()),
            os_ubr: Some(4000),
            software: Some(software),
            kbs: Some(vec!["KB5034439".into()]),
            exempt: vec![],
        }
    }

    fn set(kind: &str, params: serde_json::Value) -> RuleSet {
        RuleSet {
            generation: 1,
            rules: vec![Rule {
                id: 7,
                name: "r".into(),
                severity: Severity::High,
                include: vec![],
                exclude: vec![],
                check: Params::parse(kind, &params).map(|p| p.compile()),
            }],
        }
    }

    fn one(f: &DeviceFacts, kind: &str, params: serde_json::Value) -> Option<(Status, serde_json::Value)> {
        let out = evaluate(f, &set(kind, params));
        assert!(out.len() <= 1);
        out.into_iter().next().map(|o| {
            assert_eq!(o.rule_id, 7);
            (o.status, o.detail)
        })
    }

    #[test]
    fn forbidden_software() {
        let f = facts(vec![sw("TeamViewer 15", Some("15.1"), Some("TeamViewer GmbH")), sw("7-Zip", Some("23.01"), None)]);
        let (st, d) = one(&f, "forbidden_software", json!({"name": "*teamviewer*"})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d, json!({"software": [{"name": "TeamViewer 15", "version": "15.1"}]}));
        assert!(one(&f, "forbidden_software", json!({"name": "*AnyDesk*"})).is_none());
        assert!(
            one(&f, "forbidden_software", json!({"name": "*TeamViewer*", "publisher": "Other*"})).is_none(),
            "發行者不符"
        );
        assert!(
            one(&f, "forbidden_software", json!({"name": "7-Zip", "publisher": "*"})).is_none(),
            "沒有發行者時不符合發行者條件"
        );
        // 版本條件：低於才算
        assert!(one(&f, "forbidden_software", json!({"name": "7-Zip", "below_version": "23.01"})).is_none());
        let (st, _) = one(&f, "forbidden_software", json!({"name": "7-Zip", "below_version": "24"})).unwrap();
        assert_eq!(st, Status::Violating);
        // 沒有版本 → 未知
        let f2 = facts(vec![sw("7-Zip", None, None)]);
        let (st, d) = one(&f2, "forbidden_software", json!({"name": "7-Zip", "below_version": "24"})).unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(d["reason"], "version_missing");
    }

    #[test]
    fn required_software() {
        let f = facts(vec![sw("CrowdStrike Falcon", Some("7.10"), None)]);
        assert!(one(&f, "required_software", json!({"name": "CrowdStrike*"})).is_none());
        let (st, d) = one(&f, "required_software", json!({"name": "Symantec*"})).unwrap();
        assert_eq!((st, d), (Status::Violating, json!({"reason": "missing"})));
        let (st, d) = one(&f, "required_software", json!({"name": "CrowdStrike*", "min_version": "7.11"})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["reason"], "outdated");
        assert!(one(&f, "required_software", json!({"name": "CrowdStrike*", "min_version": "7.9"})).is_none());
        // 一套沒版本、一套夠新 → 通過；只有沒版本 → 未知
        let f2 = facts(vec![sw("A", None, None), sw("A", Some("2"), None)]);
        assert!(one(&f2, "required_software", json!({"name": "A", "min_version": "2"})).is_none());
        let f3 = facts(vec![sw("A", None, None), sw("A", Some("1"), None)]);
        assert_eq!(one(&f3, "required_software", json!({"name": "A", "min_version": "2"})).unwrap().0, Status::Unknown);
    }

    #[test]
    fn allowlist_lists_offenders_capped() {
        let mut items: Vec<SoftwareFact> = (0..60).map(|i| sw(&format!("Game {i:02}"), None, Some("Fun Inc"))).collect();
        items.push(sw("Office", None, Some("Microsoft Corporation")));
        let f = facts(items);
        let (st, d) = one(&f, "software_allowlist", json!({"entries": [{"publisher": "Microsoft*"}]})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 60);
        assert_eq!(d["software"].as_array().unwrap().len(), MAX_LISTED);
        assert!(one(&f, "software_allowlist", json!({"entries": [{"publisher": "Microsoft*"}, {"name": "Game*"}]})).is_none());
    }

    #[test]
    fn os_build_rules() {
        let f = facts(vec![]);
        let (st, d) = one(&f, "os_build", json!({"build": 22631, "min_ubr": 4317})).unwrap();
        assert_eq!((st, d), (Status::Violating, json!({"build": "22631", "ubr": 4000, "min_ubr": 4317})));
        assert!(one(&f, "os_build", json!({"build": 22631, "min_ubr": 4000})).is_none());
        assert!(one(&f, "os_build", json!({"build": 19045, "min_ubr": 9999})).is_none(), "其他組建不受影響");
        let (st, _) = one(&f, "os_build", json!({"min_build": 26100})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(one(&f, "os_build", json!({"min_build": 19045})).is_none());
        let mut old_agent = facts(vec![]);
        old_agent.os_ubr = None;
        assert_eq!(one(&old_agent, "os_build", json!({"build": 22631, "min_ubr": 1})).unwrap().0, Status::Unknown);
        let mut weird = facts(vec![]);
        weird.os_build = Some("abc".into());
        assert_eq!(one(&weird, "os_build", json!({"min_build": 1})).unwrap().0, Status::Unknown);
    }

    #[test]
    fn required_kb_is_case_insensitive() {
        let mut f = facts(vec![]);
        f.kbs = Some(vec!["kb5034439".into()]);
        assert!(one(&f, "required_kb", json!({"kb": "KB5034439"})).is_none());
        let (st, d) = one(&f, "required_kb", json!({"kb": "KB5031455"})).unwrap();
        assert_eq!((st, d), (Status::Violating, json!({"kb": "KB5031455"})));
    }

    #[test]
    fn missing_sections_are_unknown() {
        let f = DeviceFacts { os_build: None, software: None, kbs: None, ..facts(vec![]) };
        for (kind, p) in [
            ("forbidden_software", json!({"name": "x"})),
            ("software_allowlist", json!({"entries": [{"name": "x"}]})),
            ("os_build", json!({"min_build": 1})),
            ("required_kb", json!({"kb": "KB5034439"})),
        ] {
            let (st, d) = one(&f, kind, p).unwrap();
            assert_eq!((st, d["reason"].as_str()), (Status::Unknown, Some("no_data")), "{kind}");
        }
    }

    #[test]
    fn broken_rule_is_unknown_and_others_still_run() {
        let mut rs = set("required_kb", json!({"kb": "KB5031455"}));
        rs.rules.push(Rule {
            id: 8,
            name: "broken".into(),
            severity: Severity::Low,
            include: vec![],
            exclude: vec![],
            check: Err("參數格式錯誤".into()),
        });
        let out = evaluate(&facts(vec![]), &rs);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].status, Status::Violating);
        assert_eq!(out[1].status, Status::Unknown);
        assert_eq!(out[1].detail["reason"], "rule_error");
    }

    #[test]
    fn exemption_scope_and_inactive() {
        let mut f = facts(vec![]);
        f.exempt = vec![7];
        let (st, d) = one(&f, "required_kb", json!({"kb": "KB5031455"})).unwrap();
        assert_eq!((st, d), (Status::Exempt, json!({"kb": "KB5031455"})), "豁免仍保留細節");
        let mut rs = set("required_kb", json!({"kb": "KB5031455"}));
        rs.rules[0].exclude = vec![1];
        assert!(evaluate(&facts(vec![]), &rs).is_empty(), "不在範圍內");
        let inactive = DeviceFacts { active: false, ..facts(vec![]) };
        assert!(evaluate(&inactive, &set("required_kb", json!({"kb": "KB5031455"}))).is_empty());
    }
}
```

Run: `cargo test -p endpoint-server --lib evaluate::tests`
Expected: 編譯錯誤。

- [ ] **Step 2: 實作**

```rust
//! 評估：純函式，不碰資料庫。

use std::cmp::Ordering;

use serde_json::{Value, json};

use super::matcher::{Glob, cmp_version};
use super::rules::{Check, RuleSet};

/// 細節中最多列出的軟體數
pub const MAX_LISTED: usize = 50;

#[derive(Debug, Clone, PartialEq)]
pub struct SoftwareFact {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
}

/// 評估所需的裝置事實。Option 為 None 表示從未上傳該區段（os_build 代表 basic）。
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceFacts {
    pub active: bool,
    pub group_id: Option<i64>,
    pub os_build: Option<String>,
    pub os_ubr: Option<u32>,
    pub software: Option<Vec<SoftwareFact>>,
    pub kbs: Option<Vec<String>>,
    /// 有效（未到期）豁免的規則 id
    pub exempt: Vec<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Violating,
    Unknown,
    Exempt,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Violating => "violating",
            Status::Unknown => "unknown",
            Status::Exempt => "exempt",
        }
    }

    pub fn parse(s: &str) -> Option<Status> {
        [Status::Violating, Status::Unknown, Status::Exempt]
            .into_iter()
            .find(|x| x.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Status::Violating => "違規",
            Status::Unknown => "未知",
            Status::Exempt => "豁免",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub rule_id: i64,
    pub status: Status,
    pub detail: Value,
}

fn no_data() -> Option<(Status, Value)> {
    Some((Status::Unknown, json!({"reason": "no_data"})))
}

fn listed(items: &[&SoftwareFact]) -> Value {
    Value::Array(
        items
            .iter()
            .take(MAX_LISTED)
            .map(|s| json!({"name": s.name, "version": s.version}))
            .collect(),
    )
}

fn matches(s: &SoftwareFact, name: &Glob, publisher: &Option<Glob>) -> bool {
    name.is_match(&s.name)
        && publisher
            .as_ref()
            .is_none_or(|p| s.publisher.as_deref().is_some_and(|v| p.is_match(v)))
}

fn check_one(c: &Check, f: &DeviceFacts) -> Option<(Status, Value)> {
    match c {
        Check::Forbidden { name, publisher, below } => {
            let Some(sw) = &f.software else { return no_data() };
            let hits: Vec<&SoftwareFact> = sw.iter().filter(|s| matches(s, name, publisher)).collect();
            let Some(below) = below else {
                return (!hits.is_empty()).then(|| (Status::Violating, json!({"software": listed(&hits)})));
            };
            let old: Vec<&SoftwareFact> = hits
                .iter()
                .copied()
                .filter(|s| s.version.as_deref().is_some_and(|v| cmp_version(v, below) == Ordering::Less))
                .collect();
            let unversioned: Vec<&SoftwareFact> = hits.iter().copied().filter(|s| s.version.is_none()).collect();
            if !old.is_empty() {
                Some((Status::Violating, json!({"software": listed(&old)})))
            } else if !unversioned.is_empty() {
                Some((Status::Unknown, json!({"reason": "version_missing", "software": listed(&unversioned)})))
            } else {
                None
            }
        }
        Check::Required { name, publisher, min } => {
            let Some(sw) = &f.software else { return no_data() };
            let hits: Vec<&SoftwareFact> = sw.iter().filter(|s| matches(s, name, publisher)).collect();
            if hits.is_empty() {
                return Some((Status::Violating, json!({"reason": "missing"})));
            }
            let min = min.as_ref()?;
            let ok = hits
                .iter()
                .any(|s| s.version.as_deref().is_some_and(|v| cmp_version(v, min) != Ordering::Less));
            if ok {
                None
            } else if hits.iter().any(|s| s.version.is_none()) {
                Some((Status::Unknown, json!({"reason": "version_missing", "software": listed(&hits)})))
            } else {
                Some((Status::Violating, json!({"reason": "outdated", "software": listed(&hits)})))
            }
        }
        Check::Allowlist { entries } => {
            let Some(sw) = &f.software else { return no_data() };
            let offenders: Vec<&SoftwareFact> = sw
                .iter()
                .filter(|s| {
                    !entries.iter().any(|(n, p)| {
                        n.as_ref().is_none_or(|n| n.is_match(&s.name))
                            && p.as_ref().is_none_or(|p| s.publisher.as_deref().is_some_and(|v| p.is_match(v)))
                    })
                })
                .collect();
            (!offenders.is_empty()).then(|| {
                (Status::Violating, json!({"software": listed(&offenders), "total": offenders.len()}))
            })
        }
        Check::MinBuild { min_build } => {
            let Some(build) = &f.os_build else { return no_data() };
            match build.trim().parse::<u32>() {
                Ok(b) if b < *min_build => Some((Status::Violating, json!({"build": build}))),
                Ok(_) => None,
                Err(_) => Some((Status::Unknown, json!({"reason": "build_unparsable", "build": build}))),
            }
        }
        Check::PatchLevel { build: want, min_ubr } => {
            let Some(build) = &f.os_build else { return no_data() };
            match build.trim().parse::<u32>() {
                Ok(b) if b != *want => None,
                Ok(_) => match f.os_ubr {
                    None => Some((Status::Unknown, json!({"reason": "ubr_missing", "build": build}))),
                    Some(u) if u < *min_ubr => {
                        Some((Status::Violating, json!({"build": build, "ubr": u, "min_ubr": min_ubr})))
                    }
                    Some(_) => None,
                },
                Err(_) => Some((Status::Unknown, json!({"reason": "build_unparsable", "build": build}))),
            }
        }
        Check::RequiredKb { kb } => {
            let Some(kbs) = &f.kbs else { return no_data() };
            (!kbs.iter().any(|k| k.eq_ignore_ascii_case(kb))).then(|| (Status::Violating, json!({"kb": kb})))
        }
    }
}

/// 回傳所有有結果（違規、未知、豁免）的規則；通過的規則不產生 Outcome。依規則順序。
pub fn evaluate(facts: &DeviceFacts, rules: &RuleSet) -> Vec<Outcome> {
    if !facts.active {
        return vec![];
    }
    rules
        .rules
        .iter()
        .filter(|r| r.applies_to(facts.group_id))
        .filter_map(|r| {
            let (status, detail) = match &r.check {
                Ok(c) => check_one(c, facts)?,
                Err(e) => (Status::Unknown, json!({"reason": "rule_error", "error": e})),
            };
            let status = if facts.exempt.contains(&r.id) { Status::Exempt } else { status };
            Some(Outcome { rule_id: r.id, status, detail })
        })
        .collect()
}
```

`mod.rs` 加 `pub mod evaluate;`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --lib evaluate::tests`
Expected: 8 個測試 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server/src/compliance
git commit -m "合規：評估函式（五種規則、未知、豁免、範圍）"
```

---

### Task 6: 讀取事實、套用結果、上傳時評估

**Files:**
- Create: `crates/server/src/compliance/store.rs`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod store;`、`RuleCache`、`refresh_after_upload`）
- Modify: `crates/server/src/lib.rs`（`AppState.rules`）
- Modify: `crates/server/src/inventory.rs`（`upload` 觸發）
- Create: `crates/server/tests/compliance.rs`

**Interfaces:**
- Consumes: `evaluate::{evaluate, DeviceFacts, SoftwareFact, Outcome, Status}`、`rules::{Params, Rule, RuleSet, Severity}`。
- Produces:
  - `store::load_ruleset(conn: &mut PgConnection) -> Result<RuleSet, sqlx::Error>`（先讀 generation 再讀規則）
  - `store::load_facts(conn, device_id) -> Result<Option<DeviceFacts>, sqlx::Error>`
  - `store::refresh_device_in(conn, rules: &RuleSet, device_id) -> Result<(), sqlx::Error>`（呼叫端已在交易內；會取裝置鎖）
  - `store::refresh_device(pool, rules, device_id) -> Result<(), sqlx::Error>`（自己開交易）
  - `store::refresh_device_fresh(conn, device_id) -> Result<(), sqlx::Error>`（在交易內重新載入規則再評估；給生命週期與豁免用）
  - `compliance::RuleCache::new()`、`RuleCache::get(&self, pool) -> Result<Arc<RuleSet>, sqlx::Error>`
  - `compliance::refresh_after_upload(st: &AppState, device_id) -> Result<(), sqlx::Error>`
  - `AppState.rules: Arc<compliance::RuleCache>`

**Ruling（相對 spec §5.3.1）：** spec 寫「在同一個交易內評估」。改為上傳交易 commit 後，另開交易評估：評估失敗完全不影響上傳，且兩者不共用鎖。代價：評估失敗時該裝置結果過期，直到下次上傳或重算。事實在裝置鎖內讀取，所以與背景重算並行時仍以最新盤點為準。

- [ ] **Step 1: 寫失敗的整合測試**

`crates/server/tests/compliance.rs`：

```rust
mod common;

use common::{TestAgent, TestServer};
use protocol::{Arch, InventoryPayload, InventoryUpload, PatchItem, SCHEMA_VERSION, SoftwareItem};
use sqlx::PgPool;

pub fn sw(name: &str, ver: &str) -> SoftwareItem {
    SoftwareItem {
        name: name.into(),
        version: Some(ver.into()),
        publisher: None,
        install_date: None,
        arch: Arch::X64,
    }
}

pub async fn put(s: &TestServer, a: &TestAgent, p: InventoryPayload) {
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

/// 直接寫入規則並 bump generation（admin API 在 Task 8 才有）。
pub async fn add_rule(s: &TestServer, kind: &str, params: serde_json::Value) -> i64 {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
         VALUES ($1, $2, 'high', $3::jsonb, 'test') RETURNING id",
    )
    .bind(format!("{kind} rule"))
    .bind(kind)
    .bind(params.to_string())
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE compliance_state SET generation = generation + 1")
        .execute(&s.pool)
        .await
        .unwrap();
    id
}

pub async fn violations(s: &TestServer, a: &TestAgent) -> Vec<(i64, String)> {
    sqlx::query_as("SELECT rule_id, status FROM device_violations WHERE device_id = $1 ORDER BY rule_id")
        .bind(a.device_id)
        .fetch_all(&s.pool)
        .await
        .unwrap()
}

pub async fn events(s: &TestServer, a: &TestAgent) -> Vec<(String, String)> {
    sqlx::query_as("SELECT from_status, to_status FROM violation_events WHERE device_id = $1 ORDER BY id")
        .bind(a.device_id)
        .fetch_all(&s.pool)
        .await
        .unwrap()
}

async fn setup(pool: PgPool) -> (TestServer, TestAgent) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    (s, a)
}

#[sqlx::test(migrations = false)]
async fn upload_triggers_evaluation_and_history(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = add_rule(&s, "forbidden_software", serde_json::json!({"name": "*TeamViewer*"})).await;

    put(&s, &a, InventoryPayload::Software(vec![sw("TeamViewer 15", "15.1")])).await;
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    assert_eq!(events(&s, &a).await, vec![("none".into(), "violating".into())]);

    // 版本變了但仍違規：只更新細節，不寫歷程
    put(&s, &a, InventoryPayload::Software(vec![sw("TeamViewer 15", "15.2")])).await;
    let detail: String = sqlx::query_scalar("SELECT detail::text FROM device_violations WHERE device_id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert!(detail.contains("15.2"), "{detail}");
    assert_eq!(events(&s, &a).await.len(), 1);

    put(&s, &a, InventoryPayload::Software(vec![sw("7-Zip", "23.01")])).await;
    assert!(violations(&s, &a).await.is_empty());
    assert_eq!(events(&s, &a).await[1], ("violating".into(), "none".into()));
}

#[sqlx::test(migrations = false)]
async fn broken_rule_does_not_fail_upload(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let broken = add_rule(&s, "required_kb", serde_json::json!({"oops": true})).await;
    let good = add_rule(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    put(&s, &a, InventoryPayload::Patches(vec![PatchItem { kb: "KB1".into(), installed_on: None }])).await;
    assert_eq!(
        violations(&s, &a).await,
        vec![(broken, "unknown".into()), (good, "violating".into())]
    );
}
```

Run: `cargo test -p endpoint-server --test compliance`
Expected: 兩個測試 FAIL（沒有違規被寫入）。

- [ ] **Step 2: 實作 `store.rs`**

```rust
//! 讀取裝置事實、套用評估結果、寫歷程。

use std::collections::HashMap;

use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::evaluate::{DeviceFacts, Outcome, SoftwareFact, Status, evaluate};
use super::rules::{Params, Rule, RuleSet, Severity};

type RuleRow = (i64, String, String, String, String, Vec<i64>, Vec<i64>);

/// 先讀 generation 再讀規則：若中間有人改規則，快取會帶著舊 generation，下次再重新載入。
pub async fn load_ruleset(conn: &mut PgConnection) -> Result<RuleSet, sqlx::Error> {
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&mut *conn)
        .await?;
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.severity, r.kind, r.params::text, \
                ARRAY(SELECT group_id FROM compliance_rule_groups g \
                      WHERE g.rule_id = r.id AND g.mode = 'include' ORDER BY group_id), \
                ARRAY(SELECT group_id FROM compliance_rule_groups g \
                      WHERE g.rule_id = r.id AND g.mode = 'exclude' ORDER BY group_id) \
         FROM compliance_rules r WHERE r.enabled ORDER BY r.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let rules = rows
        .into_iter()
        .map(|(id, name, severity, kind, params, include, exclude)| {
            let check = serde_json::from_str::<Value>(&params)
                .map_err(|e| e.to_string())
                .and_then(|v| Params::parse(&kind, &v))
                .map(|p| p.compile());
            if let Err(e) = &check {
                tracing::warn!(rule_id = id, error = %e, "compliance rule has invalid params");
            }
            Rule {
                id,
                name,
                severity: Severity::parse(&severity).unwrap_or(Severity::Medium),
                include,
                exclude,
                check,
            }
        })
        .collect();
    Ok(RuleSet { generation, rules })
}

type FactRow = (String, Option<i64>, Option<String>, Option<i32>);

pub async fn load_facts(conn: &mut PgConnection, id: Uuid) -> Result<Option<DeviceFacts>, sqlx::Error> {
    let row: Option<FactRow> =
        sqlx::query_as("SELECT status, group_id, os_build, os_ubr FROM devices WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((status, group_id, os_build, os_ubr)) = row else {
        return Ok(None);
    };
    let sections: Vec<String> =
        sqlx::query_scalar("SELECT section FROM inventory_sections WHERE device_id = $1")
            .bind(id)
            .fetch_all(&mut *conn)
            .await?;
    let has = |s: &str| sections.iter().any(|x| x == s);
    let software = if has("software") {
        let rows: Vec<(String, Option<String>, Option<String>)> =
            sqlx::query_as("SELECT name, version, publisher FROM device_software WHERE device_id = $1")
                .bind(id)
                .fetch_all(&mut *conn)
                .await?;
        Some(
            rows.into_iter()
                .map(|(name, version, publisher)| SoftwareFact { name, version, publisher })
                .collect(),
        )
    } else {
        None
    };
    let kbs = if has("patches") {
        Some(
            sqlx::query_scalar("SELECT kb FROM device_patches WHERE device_id = $1")
                .bind(id)
                .fetch_all(&mut *conn)
                .await?,
        )
    } else {
        None
    };
    let exempt: Vec<i64> = sqlx::query_scalar(
        "SELECT rule_id FROM compliance_exemptions WHERE device_id = $1 AND expires_at > now()",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(Some(DeviceFacts {
        active: status == "active",
        group_id,
        os_build: if has("basic") { Some(os_build.unwrap_or_default()) } else { None },
        os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
        software,
        kbs,
        exempt,
    }))
}

async fn event(
    conn: &mut PgConnection,
    device: Uuid,
    rule: (i64, &str, &str),
    from: &str,
    to: &str,
    detail: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO violation_events \
         (device_id, rule_id, rule_name, severity, from_status, to_status, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)",
    )
    .bind(device)
    .bind(rule.0)
    .bind(rule.1)
    .bind(rule.2)
    .bind(from)
    .bind(to)
    .bind(detail.to_string())
    .execute(conn)
    .await?;
    Ok(())
}

type ExistingRow = (i64, String, String, String, String);

/// 與目前的違規比對差異：新增、狀態改變寫歷程；只有細節改變時只更新違規列。
async fn apply(
    conn: &mut PgConnection,
    device: Uuid,
    rules: &RuleSet,
    outcomes: Vec<Outcome>,
) -> Result<(), sqlx::Error> {
    let existing: Vec<ExistingRow> = sqlx::query_as(
        "SELECT v.rule_id, v.status, v.detail::text, r.name, r.severity \
         FROM device_violations v JOIN compliance_rules r ON r.id = v.rule_id \
         WHERE v.device_id = $1",
    )
    .bind(device)
    .fetch_all(&mut *conn)
    .await?;
    let mut old: HashMap<i64, ExistingRow> = existing.into_iter().map(|r| (r.0, r)).collect();
    for o in outcomes {
        let rule = rules.rules.iter().find(|r| r.id == o.rule_id).expect("outcome from ruleset");
        let meta = (rule.id, rule.name.as_str(), rule.severity.as_str());
        let detail = o.detail.to_string();
        match old.remove(&o.rule_id) {
            None => {
                sqlx::query(
                    "INSERT INTO device_violations (device_id, rule_id, status, detail) \
                     VALUES ($1, $2, $3, $4::jsonb)",
                )
                .bind(device)
                .bind(o.rule_id)
                .bind(o.status.as_str())
                .bind(&detail)
                .execute(&mut *conn)
                .await?;
                event(conn, device, meta, "none", o.status.as_str(), &o.detail).await?;
            }
            Some((_, status, _, _, _)) if status != o.status.as_str() => {
                sqlx::query(
                    "UPDATE device_violations SET status = $3, detail = $4::jsonb, \
                     since = now(), updated_at = now() WHERE device_id = $1 AND rule_id = $2",
                )
                .bind(device)
                .bind(o.rule_id)
                .bind(o.status.as_str())
                .bind(&detail)
                .execute(&mut *conn)
                .await?;
                event(conn, device, meta, &status, o.status.as_str(), &o.detail).await?;
            }
            Some((_, _, old_detail, _, _)) => {
                if serde_json::from_str::<Value>(&old_detail).ok().as_ref() != Some(&o.detail) {
                    sqlx::query(
                        "UPDATE device_violations SET detail = $3::jsonb, updated_at = now() \
                         WHERE device_id = $1 AND rule_id = $2",
                    )
                    .bind(device)
                    .bind(o.rule_id)
                    .bind(&detail)
                    .execute(&mut *conn)
                    .await?;
                }
            }
        }
    }
    for (rule_id, status, detail, name, severity) in old.into_values() {
        sqlx::query("DELETE FROM device_violations WHERE device_id = $1 AND rule_id = $2")
            .bind(device)
            .bind(rule_id)
            .execute(&mut *conn)
            .await?;
        let detail: Value = serde_json::from_str(&detail).unwrap_or(Value::Null);
        event(conn, device, (rule_id, &name, &severity), &status, "none", &detail).await?;
    }
    Ok(())
}

/// 在呼叫端的交易內評估一台裝置。取裝置鎖後才讀事實，所以並行時以最新盤點為準。
pub async fn refresh_device_in(conn: &mut PgConnection, rules: &RuleSet, id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('compliance:' || $1::text))")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let Some(facts) = load_facts(conn, id).await? else {
        return Ok(());
    };
    let outcomes = evaluate(&facts, rules);
    apply(conn, id, rules, outcomes).await
}

pub async fn refresh_device(pool: &PgPool, rules: &RuleSet, id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    refresh_device_in(&mut tx, rules, id).await?;
    tx.commit().await
}

/// 重新載入規則再評估（裝置生命週期與豁免變更用，頻率低，不走快取）。
pub async fn refresh_device_fresh(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    let rules = load_ruleset(conn).await?;
    refresh_device_in(conn, &rules, id).await
}
```

`apply` 裡對已停用或已刪除規則的舊違規：因為 `outcomes` 只含啟用規則，舊列會落到最後的迴圈被刪除並寫 `→ none` 事件（規則已刪除時 CASCADE 早就刪掉違規列，不會進到這裡）。

- [ ] **Step 3: `RuleCache` 與上傳觸發**

`compliance/mod.rs`：

```rust
//! 軟體與修補合規：規則、評估、違規與歷程。

pub mod evaluate;
pub mod matcher;
pub mod rules;
pub mod store;

use std::sync::Arc;

use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::AppState;
use protocol::Section;
use rules::RuleSet;

/// 啟用中規則的快取；以 compliance_state.generation 判斷是否過期。
pub struct RuleCache {
    current: RwLock<Arc<RuleSet>>,
}

impl Default for RuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleCache {
    pub fn new() -> RuleCache {
        RuleCache { current: RwLock::new(Arc::new(RuleSet::empty())) }
    }

    pub async fn get(&self, pool: &PgPool) -> Result<Arc<RuleSet>, sqlx::Error> {
        let generation: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
            .fetch_one(pool)
            .await?;
        {
            let cur = self.current.read().await;
            if cur.generation == generation {
                return Ok(cur.clone());
            }
        }
        let mut conn = pool.acquire().await?;
        let fresh = Arc::new(store::load_ruleset(&mut conn).await?);
        *self.current.write().await = fresh.clone();
        Ok(fresh)
    }
}

/// 會影響合規結果的區段
pub fn affects_compliance(section: Section) -> bool {
    matches!(section, Section::Basic | Section::Software | Section::Patches)
}

pub async fn refresh_after_upload(st: &AppState, device_id: Uuid) -> Result<(), sqlx::Error> {
    let rules = st.rules.get(&st.pool).await?;
    store::refresh_device(&st.pool, &rules, device_id).await
}
```

`lib.rs`：`AppState` 加欄位

```rust
    /// 合規規則快取
    pub rules: Arc<compliance::RuleCache>,
```

`AppState::new` 加 `rules: Arc::new(compliance::RuleCache::new()),`。

`inventory.rs` 的 `upload`，`store_section(...).await?;` 之後：

```rust
    // 評估失敗不影響上傳：盤點已寫入，結果會在下次上傳或背景重算時補上
    if crate::compliance::affects_compliance(section) {
        if let Err(e) = crate::compliance::refresh_after_upload(&st, device.device_id).await {
            tracing::error!(device_id = %device.device_id, error = %e, "compliance evaluation failed");
        }
    }
```

（`section` 在 `spawn_blocking` 的 `move` 閉包中被移走；`Section` 是 `Copy`，所以仍可用。若編譯器抱怨，在閉包前 `let sec = section;` 再用 `sec`。）

- [ ] **Step 4: 執行**

Run: `cargo test -p endpoint-server --test compliance`
Expected: 2 個測試 PASS。

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 5: Commit**

```bash
git add -A crates/server
git commit -m "合規：套用評估結果與歷程，上傳後自動評估"
```

---

### Task 7: 裝置生命週期觸發評估

**Files:**
- Modify: `crates/server/src/devices.rs`（`approve_in`、`reject`、`retire`）
- Modify: `crates/server/src/groups.rs`（`move_device`）
- Test: `crates/server/tests/compliance.rs`

**Interfaces:**
- Consumes: `compliance::store::refresh_device_fresh`。

- [ ] **Step 1: 寫失敗測試**

`tests/compliance.rs` 加：

```rust
#[sqlx::test(migrations = false)]
async fn retire_clears_and_group_move_reevaluates(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let g = s.group_id("資訊亭").await;
    let rule = add_rule(&s, "required_kb", serde_json::json!({"kb": "KB5031455"})).await;
    sqlx::query("INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, 'exclude')")
        .bind(rule)
        .bind(g)
        .execute(&s.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE compliance_state SET generation = generation + 1").execute(&s.pool).await.unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await.len(), 1);

    endpoint_server::groups::move_device(&s.pool, a.device_id, Some(g), "t").await.unwrap();
    assert!(violations(&s, &a).await.is_empty(), "移到排除群組後違規消失");
    endpoint_server::groups::move_device(&s.pool, a.device_id, None, "t").await.unwrap();
    assert_eq!(violations(&s, &a).await.len(), 1);

    endpoint_server::devices::retire(&s.pool, a.device_id, "t").await.unwrap();
    assert!(violations(&s, &a).await.is_empty(), "除役後清除");
    assert_eq!(events(&s, &a).await.last().unwrap().1, "none");
}
```

Run: `cargo test -p endpoint-server --test compliance retire_clears`
Expected: FAIL（移動群組後違規仍在）。

- [ ] **Step 2: 實作**

- `groups::move_device`：UPDATE 成功、寫稽核之後、commit 之前：
  `crate::compliance::store::refresh_device_fresh(&mut tx, device_id).await?;`
- `devices::retire`：`revoke_certs` 之後加同一行（id）。
- `devices::reject`：`revoke_certs` 之後加同一行（pending）。待核准裝置原本就不評估，這行只是保險；保持一致。
- `devices::approve_in`：兩個 `return`／結尾路徑在 `audit::record` 之後都加 `crate::compliance::store::refresh_device_fresh(conn, <保留下來的 id>).await?;`（獨立裝置路徑是 `pending`，合併路徑是 `old`）。

鎖順序說明（寫在 `refresh_device_in` 的 doc comment 已足夠）：這些交易先鎖 devices 列，再取合規的 advisory lock；上傳評估只取 advisory lock、以一般 SELECT 讀 devices，不會互相等待成環。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server`
Expected: 全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server
git commit -m "合規：除役、核准、移動群組時重新評估"
```

---

### Task 8: 規則與豁免的增刪改

**Files:**
- Create: `crates/server/src/compliance/admin.rs`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod admin;`）
- Test: `crates/server/tests/compliance.rs`

**Interfaces:**
- Consumes: `rules::{Params, Severity}`、`store::refresh_device_fresh`、`crate::audit::record`。
- Produces:
  - `pub struct RuleInput { pub name: String, pub description: String, pub kind: String, pub severity: String, pub enabled: bool, pub params: serde_json::Value, pub include: Vec<i64>, pub exclude: Vec<i64> }`
  - `pub async fn create_rule(pool: &PgPool, input: &RuleInput, actor: &str) -> anyhow::Result<i64>`
  - `pub async fn update_rule(pool: &PgPool, id: i64, input: &RuleInput, actor: &str) -> anyhow::Result<()>`
  - `pub async fn delete_rule(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()>`
  - `pub const MAX_EXEMPTION_DAYS: i64 = 365`
  - `pub async fn create_exemption(pool: &PgPool, device_id: Uuid, rule_id: i64, reason: &str, expires_at: DateTime<Utc>, actor: &str) -> anyhow::Result<i64>`
  - `pub async fn revoke_exemption(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()>`
  - 稽核 action：`rule_create`、`rule_update`、`rule_delete`、`exemption_create`、`exemption_revoke`。

**Ruling（相對 spec §2.6／§5.3.2）：** spec 寫豁免變更也 bump generation 觸發全部重算。豁免只影響一台裝置，改為在同一交易內只重新評估該台。代價：無（結果相同、成本低很多）。

- [ ] **Step 1: 寫失敗測試**

```rust
use endpoint_server::compliance::admin::{self, RuleInput};

fn input(kind: &str, params: serde_json::Value) -> RuleInput {
    RuleInput {
        name: "禁止遠端桌面軟體".into(),
        description: String::new(),
        kind: kind.into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
    }
}

#[sqlx::test(migrations = false)]
async fn rule_crud_validates_and_audits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let g = s.group_id("資訊亭").await;
    let bad = RuleInput { include: vec![g], exclude: vec![g], ..input("required_kb", serde_json::json!({"kb": "KB5034439"})) };
    assert!(admin::create_rule(&s.pool, &bad, "admin").await.is_err(), "同一群組不能同時只套用又排除");
    assert!(admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "x"})), "admin").await.is_err());
    let blank = RuleInput { name: "  ".into(), ..input("required_kb", serde_json::json!({"kb": "KB5034439"})) };
    assert!(admin::create_rule(&s.pool, &blank, "admin").await.is_err());

    let before: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state").fetch_one(&s.pool).await.unwrap();
    let id = admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": " kb5034439"})), "admin")
        .await
        .unwrap();
    let params: String = sqlx::query_scalar("SELECT params::text FROM compliance_rules WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(params, r#"{"kb": "KB5034439"}"#, "存正規化後的參數");
    let mut upd = input("required_kb", serde_json::json!({"kb": "KB5034439"}));
    upd.include = vec![g];
    admin::update_rule(&s.pool, id, &upd, "admin").await.unwrap();
    let groups: Vec<(i64, String)> = sqlx::query_as("SELECT group_id, mode FROM compliance_rule_groups WHERE rule_id = $1")
        .bind(id)
        .fetch_all(&s.pool)
        .await
        .unwrap();
    assert_eq!(groups, vec![(g, "include".into())]);
    admin::delete_rule(&s.pool, id, "admin").await.unwrap();
    let after: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state").fetch_one(&s.pool).await.unwrap();
    assert_eq!(after, before + 3);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_log WHERE action LIKE 'rule_%' ORDER BY id",
    )
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert_eq!(actions, ["rule_create", "rule_update", "rule_delete"]);
    assert!(admin::update_rule(&s.pool, id, &upd, "admin").await.is_err(), "已刪除");
}

#[sqlx::test(migrations = false)]
async fn exemption_marks_exempt_and_revoke_restores(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "KB5031455"})), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);

    let soon = chrono::Utc::now() + chrono::Duration::days(30);
    assert!(admin::create_exemption(&s.pool, a.device_id, rule, " ", soon, "admin").await.is_err(), "原因必填");
    let too_far = chrono::Utc::now() + chrono::Duration::days(400);
    assert!(admin::create_exemption(&s.pool, a.device_id, rule, "ok", too_far, "admin").await.is_err());
    let past = chrono::Utc::now() - chrono::Duration::minutes(1);
    assert!(admin::create_exemption(&s.pool, a.device_id, rule, "ok", past, "admin").await.is_err());

    let ex = admin::create_exemption(&s.pool, a.device_id, rule, "舊系統相容性", soon, "admin").await.unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "exempt".into())]);
    admin::revoke_exemption(&s.pool, ex, "admin").await.unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action LIKE 'exemption_%'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
}
```

注意：`exemption_marks_exempt...` 裡 `create_rule` 之後直接上傳，靠的是上傳時 `RuleCache` 依 generation 重新載入，不需要背景重算。

Run: `cargo test -p endpoint-server --test compliance`
Expected: 編譯錯誤（`admin` 不存在）。

- [ ] **Step 2: 實作 `admin.rs`**

```rust
//! 規則與豁免的增刪改（權限由網頁層檢查）。每個動作寫入稽核記錄。

use anyhow::{Context, ensure};
use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::rules::{Params, Severity};
use super::store::refresh_device_fresh;
use crate::audit;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_DESCRIPTION_LEN: usize = 1000;
pub const MAX_REASON_LEN: usize = 500;
pub const MAX_EXEMPTION_DAYS: i64 = 365;

#[derive(Debug, Clone)]
pub struct RuleInput {
    pub name: String,
    pub description: String,
    pub kind: String,
    pub severity: String,
    pub enabled: bool,
    pub params: serde_json::Value,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
}

struct Valid {
    name: String,
    description: String,
    severity: Severity,
    params: Params,
}

fn validate(i: &RuleInput) -> anyhow::Result<Valid> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "規則名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    let description = i.description.trim().to_string();
    ensure!(description.chars().count() <= MAX_DESCRIPTION_LEN, "說明最多 {MAX_DESCRIPTION_LEN} 字");
    let severity = Severity::parse(&i.severity).context("嚴重度無效")?;
    let params = Params::parse(&i.kind, &i.params).map_err(anyhow::Error::msg)?;
    ensure!(
        !i.include.iter().any(|g| i.exclude.contains(g)),
        "同一個群組不能同時「只套用」又「排除」"
    );
    Ok(Valid { name, description, severity, params })
}

async fn bump(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE compliance_state SET generation = generation + 1")
        .execute(conn)
        .await?;
    Ok(())
}

async fn write_groups(conn: &mut PgConnection, id: i64, i: &RuleInput) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM compliance_rule_groups WHERE rule_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    for (groups, mode) in [(&i.include, "include"), (&i.exclude, "exclude")] {
        for g in groups {
            sqlx::query("INSERT INTO compliance_rule_groups (rule_id, group_id, mode) VALUES ($1, $2, $3)")
                .bind(id)
                .bind(g)
                .bind(mode)
                .execute(&mut *conn)
                .await
                .map_err(|_| anyhow::anyhow!("群組不存在：{g}"))?;
        }
    }
    Ok(())
}

pub async fn create_rule(pool: &PgPool, i: &RuleInput, actor: &str) -> anyhow::Result<i64> {
    let v = validate(i)?;
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, description, kind, severity, enabled, params, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7) RETURNING id",
    )
    .bind(&v.name)
    .bind(&v.description)
    .bind(v.params.kind())
    .bind(v.severity.as_str())
    .bind(i.enabled)
    .bind(v.params.to_json().to_string())
    .bind(actor)
    .fetch_one(&mut *tx)
    .await?;
    write_groups(&mut tx, id, i).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "rule_create",
        Some(&v.name),
        json!({"id": id, "kind": v.params.kind(), "params": v.params.to_json(),
               "include": i.include, "exclude": i.exclude, "enabled": i.enabled}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_rule(pool: &PgPool, id: i64, i: &RuleInput, actor: &str) -> anyhow::Result<()> {
    let v = validate(i)?;
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE compliance_rules SET name = $2, description = $3, kind = $4, severity = $5, \
         enabled = $6, params = $7::jsonb, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&v.name)
    .bind(&v.description)
    .bind(v.params.kind())
    .bind(v.severity.as_str())
    .bind(i.enabled)
    .bind(v.params.to_json().to_string())
    .execute(&mut *tx)
    .await?
    .rows_affected();
    ensure!(n == 1, "規則不存在");
    write_groups(&mut tx, id, i).await?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "rule_update",
        Some(&v.name),
        json!({"id": id, "kind": v.params.kind(), "params": v.params.to_json(),
               "include": i.include, "exclude": i.exclude, "enabled": i.enabled}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_rule(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM compliance_rules WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let name = name.context("規則不存在")?;
    bump(&mut tx).await?;
    audit::record(&mut tx, actor, "rule_delete", Some(&name), json!({"id": id})).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn create_exemption(
    pool: &PgPool,
    device_id: Uuid,
    rule_id: i64,
    reason: &str,
    expires_at: DateTime<Utc>,
    actor: &str,
) -> anyhow::Result<i64> {
    let reason = reason.trim();
    ensure!(
        !reason.is_empty() && reason.chars().count() <= MAX_REASON_LEN,
        "豁免原因必填，最多 {MAX_REASON_LEN} 字"
    );
    let now = Utc::now();
    ensure!(
        expires_at > now && expires_at <= now + Duration::days(MAX_EXEMPTION_DAYS),
        "到期日須在今天之後、{MAX_EXEMPTION_DAYS} 天之內"
    );
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_exemptions (device_id, rule_id, reason, expires_at, created_by) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (device_id, rule_id) DO UPDATE SET reason = EXCLUDED.reason, \
           expires_at = EXCLUDED.expires_at, created_by = EXCLUDED.created_by, created_at = now() \
         RETURNING id",
    )
    .bind(device_id)
    .bind(rule_id)
    .bind(reason)
    .bind(expires_at)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| anyhow::anyhow!("裝置或規則不存在"))?;
    audit::record(
        &mut tx,
        actor,
        "exemption_create",
        Some(&device_id.to_string()),
        json!({"id": id, "rule_id": rule_id, "reason": reason, "expires_at": expires_at}),
    )
    .await?;
    refresh_device_fresh(&mut tx, device_id).await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn revoke_exemption(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let row: Option<(Uuid, i64)> =
        sqlx::query_as("DELETE FROM compliance_exemptions WHERE id = $1 RETURNING device_id, rule_id")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let (device_id, rule_id) = row.context("豁免不存在")?;
    audit::record(
        &mut tx,
        actor,
        "exemption_revoke",
        Some(&device_id.to_string()),
        json!({"id": id, "rule_id": rule_id}),
    )
    .await?;
    refresh_device_fresh(&mut tx, device_id).await?;
    tx.commit().await?;
    Ok(())
}
```

`mod.rs` 加 `pub mod admin;`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --test compliance`
Expected: 全部 PASS。

- [ ] **Step 4: Commit**

```bash
git add -A crates/server
git commit -m "合規：規則與豁免的增刪改（驗證、稽核）"
```

---

### Task 9: 背景工作——全量重算、豁免到期、每日快照、歷程清理

**Files:**
- Create: `crates/server/src/compliance/worker.rs`
- Modify: `crates/server/src/compliance/mod.rs`（`pub mod worker;`）
- Modify: `crates/server/src/lib.rs`（`serve` 啟動 worker）
- Test: `crates/server/tests/compliance.rs`

**Interfaces:**
- Consumes: `store::{load_ruleset, refresh_device, refresh_device_fresh}`。
- Produces:
  - `pub const BATCH: i64 = 1000`
  - `pub async fn recompute_step(pool: &PgPool) -> Result<bool, sqlx::Error>`（處理一批；回傳是否還有工作）
  - `pub async fn recompute_all(pool: &PgPool) -> Result<(), sqlx::Error>`
  - `pub async fn expire_exemptions(pool: &PgPool) -> Result<u64, sqlx::Error>`
  - `pub async fn snapshot_daily(pool: &PgPool, day: chrono::NaiveDate) -> Result<(), sqlx::Error>`
  - `pub async fn cleanup_history(pool: &PgPool) -> Result<u64, sqlx::Error>`
  - `pub struct Progress { pub running: bool, pub done: i64, pub total: i64 }`、`pub async fn progress(pool: &PgPool) -> Result<Progress, sqlx::Error>`（計畫 6 的網頁用）
  - `pub fn spawn(pool: PgPool)`

- [ ] **Step 1: 寫失敗測試**

```rust
use endpoint_server::compliance::worker;

#[sqlx::test(migrations = false)]
async fn recompute_applies_rule_changes_to_all_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let mut agents = vec![];
    for _ in 0..3 {
        let a = s.enroll_ok(&tok, None, None).await;
        put(&s, &a, InventoryPayload::Patches(vec![])).await;
        agents.push(a);
    }
    let id = admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "KB5031455"})), "admin")
        .await
        .unwrap();
    for a in &agents {
        assert!(violations(&s, a).await.is_empty(), "還沒重算");
    }
    worker::recompute_all(&s.pool).await.unwrap();
    for a in &agents {
        assert_eq!(violations(&s, a).await, vec![(id, "violating".into())]);
    }
    let p = worker::progress(&s.pool).await.unwrap();
    assert!(!p.running);

    // 停用 → 重算後清除並寫解除事件
    let mut off = input("required_kb", serde_json::json!({"kb": "KB5031455"}));
    off.enabled = false;
    admin::update_rule(&s.pool, id, &off, "admin").await.unwrap();
    assert!(worker::progress(&s.pool).await.unwrap().running);
    worker::recompute_all(&s.pool).await.unwrap();
    for a in &agents {
        assert!(violations(&s, a).await.is_empty());
        assert_eq!(events(&s, a).await.last().unwrap(), &("violating".to_string(), "none".to_string()));
    }
}

#[sqlx::test(migrations = false)]
async fn recompute_restarts_when_rules_change_midway(pool: PgPool) {
    let (s, a) = setup(pool).await;
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "KB5031455"})), "admin")
        .await
        .unwrap();
    // 模擬跑到一半（cursor 已越過這台）時規則又改了
    sqlx::query(
        "UPDATE compliance_state SET run_generation = generation, \
         cursor = 'ffffffff-ffff-ffff-ffff-ffffffffffff'",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let second = admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "KB5031456"})), "admin")
        .await
        .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    let v = violations(&s, &a).await;
    assert_eq!(v.len(), 2, "從頭重算，兩條規則都套用：{v:?}");
    assert_eq!(v[1].0, second);
    let (g, done): (i64, i64) = sqlx::query_as("SELECT generation, done_generation FROM compliance_state")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, done);
}

#[sqlx::test(migrations = false)]
async fn expired_exemption_is_removed_and_reevaluated(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "KB5031455"})), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    admin::create_exemption(&s.pool, a.device_id, rule, "暫時", chrono::Utc::now() + chrono::Duration::days(1), "admin")
        .await
        .unwrap();
    assert_eq!(violations(&s, &a).await, vec![(rule, "exempt".into())]);
    sqlx::query("UPDATE compliance_exemptions SET expires_at = now() - interval '1 second'")
        .execute(&s.pool)
        .await
        .unwrap();
    assert_eq!(worker::expire_exemptions(&s.pool).await.unwrap(), 1);
    assert_eq!(violations(&s, &a).await, vec![(rule, "violating".into())]);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = 'exemption_expire'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = false)]
async fn daily_snapshot_and_history_cleanup(pool: PgPool) {
    let (s, a) = setup(pool).await;
    let rule = admin::create_rule(&s.pool, &input("required_kb", serde_json::json!({"kb": "KB5031455"})), "admin")
        .await
        .unwrap();
    put(&s, &a, InventoryPayload::Patches(vec![])).await;
    let today = chrono::Utc::now().date_naive();
    worker::snapshot_daily(&s.pool, today).await.unwrap();
    worker::snapshot_daily(&s.pool, today).await.unwrap();
    let row: (i32, i32, i32) = sqlx::query_as(
        "SELECT violating, unknown, exempt FROM compliance_daily WHERE day = $1 AND rule_id = $2",
    )
    .bind(today)
    .bind(rule)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(row, (1, 0, 0));

    sqlx::query("UPDATE violation_events SET at = now() - interval '400 days'")
        .execute(&s.pool)
        .await
        .unwrap();
    assert_eq!(worker::cleanup_history(&s.pool).await.unwrap(), 1);
}
```

Run: `cargo test -p endpoint-server --test compliance`
Expected: 編譯錯誤（`worker` 不存在）。

- [ ] **Step 2: 實作 `worker.rs`**

```rust
//! 背景工作：規則變更後全量重算、豁免到期、每日快照、歷程清理。

use std::time::{Duration, Instant};

use chrono::NaiveDate;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use super::store::{load_ruleset, refresh_device, refresh_device_fresh};

pub const BATCH: i64 = 1000;
pub const DEFAULT_HISTORY_DAYS: i64 = 365;

type StateRow = (i64, i64, i64, Option<Uuid>);

/// 處理一批：generation 追上 done_generation 就沒事做；run_generation 落後代表規則在
/// 重算途中又變了，從頭再來。
// ponytail: 假設只有一個伺服器實例；多實例時改用 pg_try_advisory_lock 選一個執行者
pub async fn recompute_step(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let (generation, done, run, cursor): StateRow = sqlx::query_as(
        "SELECT generation, done_generation, run_generation, cursor FROM compliance_state",
    )
    .fetch_one(pool)
    .await?;
    if generation == done {
        return Ok(false);
    }
    let cursor = if run == generation {
        cursor
    } else {
        sqlx::query(
            "UPDATE compliance_state SET run_generation = $1, cursor = NULL, started_at = now()",
        )
        .bind(generation)
        .execute(pool)
        .await?;
        None
    };
    let mut conn = pool.acquire().await?;
    let rules = load_ruleset(&mut conn).await?;
    drop(conn);
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM devices WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id LIMIT $2",
    )
    .bind(cursor)
    .bind(BATCH)
    .fetch_all(pool)
    .await?;
    for id in &ids {
        refresh_device(pool, &rules, *id).await?;
    }
    if (ids.len() as i64) < BATCH {
        // 用 run_generation（不是現在的 generation）：途中又有變更時 done 仍落後，下一輪從頭來
        sqlx::query(
            "UPDATE compliance_state SET done_generation = $1, cursor = NULL WHERE run_generation = $1",
        )
        .bind(generation)
        .execute(pool)
        .await?;
    } else {
        sqlx::query("UPDATE compliance_state SET cursor = $2 WHERE run_generation = $1")
            .bind(generation)
            .bind(ids.last())
            .execute(pool)
            .await?;
    }
    Ok(true)
}

pub async fn recompute_all(pool: &PgPool) -> Result<(), sqlx::Error> {
    while recompute_step(pool).await? {
        tokio::task::yield_now().await;
    }
    Ok(())
}

pub struct Progress {
    pub running: bool,
    pub done: i64,
    pub total: i64,
}

pub async fn progress(pool: &PgPool) -> Result<Progress, sqlx::Error> {
    let (running, done, total): (bool, i64, i64) = sqlx::query_as(
        "SELECT s.generation <> s.done_generation, \
                CASE WHEN s.run_generation = s.generation AND s.cursor IS NOT NULL \
                     THEN (SELECT count(*) FROM devices WHERE id <= s.cursor) ELSE 0 END, \
                (SELECT count(*) FROM devices) \
         FROM compliance_state s",
    )
    .fetch_one(pool)
    .await?;
    Ok(Progress { running, done, total })
}

/// 刪除到期豁免並重新評估那些裝置。回傳處理筆數。
pub async fn expire_exemptions(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let expired: Vec<(i64, Uuid, i64)> = sqlx::query_as(
        "SELECT id, device_id, rule_id FROM compliance_exemptions WHERE expires_at <= now() ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    let mut n = 0;
    for (id, device, rule) in expired {
        let mut tx = pool.begin().await?;
        let gone = sqlx::query("DELETE FROM compliance_exemptions WHERE id = $1 AND expires_at <= now()")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if gone == 1 {
            crate::audit::record(
                &mut tx,
                "system",
                "exemption_expire",
                Some(&device.to_string()),
                json!({"id": id, "rule_id": rule}),
            )
            .await?;
            refresh_device_fresh(&mut tx, device).await?;
            n += 1;
        }
        tx.commit().await?;
    }
    Ok(n)
}

pub async fn snapshot_daily(pool: &PgPool, day: NaiveDate) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO compliance_daily (day, rule_id, violating, unknown, exempt) \
         SELECT $1, rule_id, count(*) FILTER (WHERE status = 'violating'), \
                count(*) FILTER (WHERE status = 'unknown'), count(*) FILTER (WHERE status = 'exempt') \
         FROM device_violations GROUP BY rule_id \
         ON CONFLICT (day, rule_id) DO UPDATE SET violating = EXCLUDED.violating, \
           unknown = EXCLUDED.unknown, exempt = EXCLUDED.exempt",
    )
    .bind(day)
    .execute(pool)
    .await?;
    Ok(())
}

/// 保留天數設定：壞值用預設，夾在 30–3650。
pub async fn history_days(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM settings WHERE key = 'violation_history_days'")
            .fetch_optional(pool)
            .await?;
    Ok(raw
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(DEFAULT_HISTORY_DAYS)
        .clamp(30, 3650))
}

pub async fn cleanup_history(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let days = history_days(pool).await?;
    let events = sqlx::query("DELETE FROM violation_events WHERE at < now() - make_interval(days => $1)")
        .bind(days as i32)
        .execute(pool)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM compliance_daily WHERE day < (now() - make_interval(days => $1))::date")
        .bind(days as i32)
        .execute(pool)
        .await?;
    Ok(events)
}

pub fn spawn(pool: PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        let mut last_expire: Option<Instant> = None;
        let mut last_hourly: Option<Instant> = None;
        loop {
            tick.tick().await;
            if let Err(e) = recompute_all(&pool).await {
                tracing::error!(error = %e, "compliance recompute failed");
            }
            if last_expire.is_none_or(|t| t.elapsed() >= Duration::from_secs(300)) {
                last_expire = Some(Instant::now());
                if let Err(e) = expire_exemptions(&pool).await {
                    tracing::error!(error = %e, "exemption expiry failed");
                }
            }
            if last_hourly.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
                last_hourly = Some(Instant::now());
                let today = chrono::Utc::now().date_naive();
                if let Err(e) = snapshot_daily(&pool, today).await {
                    tracing::error!(error = %e, "compliance snapshot failed");
                }
                if let Err(e) = cleanup_history(&pool).await {
                    tracing::error!(error = %e, "violation history cleanup failed");
                }
            }
        }
    });
}
```

`recompute_all` 完成時加一行 `tracing::info!`，記錄這一輪處理的裝置數與耗時（負載測試要看這個數字）：在 `recompute_step` 的「完成」分支印 `tracing::info!(generation, elapsed_secs = ..., "compliance recompute finished")`，耗時用 `started_at` 算：把完成分支的 UPDATE 改為 `... RETURNING extract(epoch FROM now() - started_at)::float8` 並 `fetch_optional`。

`mod.rs` 加 `pub mod worker;`。`lib.rs` 的 `serve` 在分割區維護的 `tokio::spawn` 之後加 `compliance::worker::spawn(pool.clone());`。

- [ ] **Step 3: 執行**

Run: `cargo test -p endpoint-server --test compliance`
Expected: 全部 PASS。

- [ ] **Step 4: 全部測試與靜態檢查**

Run: `cargo test --workspace`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --all --check`
Expected: 全部通過；有 fmt 差異就 `cargo fmt --all` 後再檢查。

- [ ] **Step 5: Commit**

```bash
git add -A crates/server
git commit -m "合規：背景重算、豁免到期、每日快照與歷程清理"
```
