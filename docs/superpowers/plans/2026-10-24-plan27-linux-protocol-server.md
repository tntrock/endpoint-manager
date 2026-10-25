# 計畫 27：Linux Agent——通訊協定與伺服器 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 讓伺服器認得 Linux 裝置：記錄作業系統類型、接收新的 `accounts` 區段、讓 Linux 裝置不進入合規／派送／Windows Update，並讓腳本有語言、指令只派給作業系統相符的裝置。

**Architecture:**
- protocol：`OsFamily`、`ScriptLanguage`、`Arch::Other`、`Section::Accounts`（不放進 Windows 的區段清單）、`AccountsInfo`。所有新欄位缺少時等於舊行為，舊版 Windows agent 不用改。
- server：migration 0022 加 `devices.os_family`、`scripts.language`、`command_runs.script_language`／`skipped_os`、`device_accounts`。Linux 判斷集中在少數地方：報到回應、合規事實（`active = false`）、派送／更新頁的 `TARGET`、指令展開。
- 這份計畫**不含** Linux agent 本身（計畫 28）和後台畫面（計畫 29）。Windows agent 只做兩個小改動：改用 `Section::WINDOWS`、拒絕非 PowerShell 腳本。

**Tech Stack:** 既有依賴，不新增套件。

**Spec:** `docs/superpowers/specs/2026-10-24-linux-agent-design.md`（§2、§3、§4.4 arch、§4.6 資料型別與儲存、§5.1）

## Global Constraints
- 使用者可見文字與註解用繁體中文，風格同既有程式碼。
- 新的協定欄位一律 `#[serde(default)]`；`os_family` 為 `None` 時不能出現在序列化結果（`skip_serializing_if = "Option::is_none"`，比照 `BasicInfo::os_ubr`）。
- `devices.os_family` 只允許 `windows`／`linux`，NOT NULL DEFAULT `windows`。`scripts.language` 只允許 `powershell`／`sh`，NOT NULL DEFAULT `powershell`。
- 既有 Windows 裝置的合規結果、派送與更新統計、報到回應內容都不能改變（§1.1 算失敗的情況）。
- 測試指令：`cargo test -p protocol`、`cargo test -p endpoint-server --test <名稱>`、`cargo test -p endpoint-agent`；完整：`cargo test --workspace -j 4`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --check`。Docker Desktop 要先開，`em-postgres` 在跑。

## Review Focus
1. 報到時 Linux 裝置的 `deployments_hash`／`update_policy_hash`／`registry_queries_hash` 是**空清單的 hash**，而不是 `None`（`None` 對 agent 的意思是「伺服器不支援」，語意不同）。
2. 同一台裝置的 `os_family` 從 windows 變 linux（重灌）後，下一次重算合規就清掉它的違規，派送頁也不再算它。
3. 群組指令展開時，略過數只算「使用中、作業系統不符」的裝置，不包含已停用或重複的裝置。
4. 舊版 agent 送來沒有 `language` 的 `ScriptSpec`、舊資料庫的腳本列都當成 PowerShell。
5. `accounts` 區段的 diff 和 hash 對同樣內容、不同順序的輸入是穩定的（`normalize` 要排序三個清單）。

---

### Task 1：通訊協定新型別

**Files:**
- Modify: `crates/protocol/src/lib.rs`
- Modify: `crates/protocol/src/command.rs`
- Modify: `crates/agent/src/agent.rs:41`、`crates/agent/src/schedule.rs:38,106,114`、`crates/agent/src/windows/commands.rs:44`、`crates/agent/tests/windows.rs:193`（`Section::ALL` → `Section::WINDOWS`）
- Modify: `crates/agent/src/commands/logic.rs`、`crates/agent/src/commands/worker.rs:204-207`
- Test: 同檔案的 `#[cfg(test)]`

**Interfaces:**
- Produces（`protocol`）：
  - `enum OsFamily { Windows, Linux }`，serde lowercase，`as_str()`／`parse(&str) -> Option<OsFamily>`。
  - `EnrollRequest.os_family: Option<OsFamily>`、`CheckinRequest.os_family: Option<OsFamily>`，兩者 `#[serde(default, skip_serializing_if = "Option::is_none")]`。
  - `Arch::Other`（`as_str() == "other"`，`parse` 認得）。
  - `Section::Accounts`（`as_str() == "accounts"`）；`Section::ALL: [Section; 8]` 含全部；新增 `Section::WINDOWS: [Section; 7]`（現在的 ALL）與 `Section::LINUX: [Section; 5] = [Basic, Hardware, Software, Services, Accounts]`；`parse` 用 `ALL`。`LEGACY` 不變。
  - `struct AccountsInfo { users: Vec<LocalUser>, system_user_count: u32, privileged: Vec<PrivilegeEntry>, sudoers_unparsed: Vec<String> }`
  - `struct LocalUser { name: String, uid: u32, shell: String, locked: Option<bool>, password_changed: Option<chrono::NaiveDate> }`
  - `struct PrivilegeEntry { principal: String, kind: PrincipalKind, source: String }`、`enum PrincipalKind { User, Group }`（lowercase）
  - 以上都 derive `Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize`。
  - `InventoryPayload::Accounts(AccountsInfo)`：`section()`、`normalize()`（三個 Vec 都 sort）、`validate()`（筆數 = users + privileged + sudoers_unparsed）。
  - `protocol::command::ScriptLanguage { PowerShell, Sh }`，serde 名稱 `powershell`／`sh`，`Default = PowerShell`，`as_str()`／`parse(&str) -> Option<ScriptLanguage>`；`ScriptSpec.language: ScriptLanguage`（`#[serde(default)]`，一律序列化）。
- Produces（agent）：`commands::logic::NATIVE_LANGUAGE: ScriptLanguage`（`cfg(windows)` = PowerShell，其他 = Sh）。

- [ ] **Step 1：寫失敗的測試（protocol）**

```rust
#[test]
fn os_family_absent_serializes_like_legacy() {
    let r = CheckinRequest { os_family: None, /* 其他欄位用既有測試的值 */ };
    assert!(serde_json::to_value(&r).unwrap().get("os_family").is_none());
    let linux = CheckinRequest { os_family: Some(OsFamily::Linux), ..r.clone() };
    assert_eq!(serde_json::to_value(&linux).unwrap()["os_family"], "linux");
}

#[test]
fn section_lists() {
    assert_eq!(Section::parse("accounts"), Some(Section::Accounts));
    assert!(!Section::WINDOWS.contains(&Section::Accounts));
    assert!(!Section::LINUX.contains(&Section::Registry));
    assert_eq!(Section::ALL.len(), 8);
}

#[test]
fn accounts_hash_ignores_order() {
    // 同樣的 users／privileged／sudoers_unparsed，順序相反 → canonical_hash 相同
}

#[test]
fn arch_other_round_trips() {
    assert_eq!(Arch::parse("other"), Some(Arch::Other));
}
```

`command.rs`：

```rust
#[test]
fn script_spec_without_language_is_powershell() {
    let s: ScriptSpec = serde_json::from_value(json!({"sha256": "…", "content": "x", "timeout_minutes": 5})).unwrap();
    assert_eq!(s.language, ScriptLanguage::PowerShell);
}
```

- [ ] **Step 2：執行 `cargo test -p protocol`，確認編譯失敗（型別不存在）**

- [ ] **Step 3：實作 protocol 型別（Interfaces 列出的全部）**

- [ ] **Step 4：Windows agent 改用 `Section::WINDOWS`，`EnrollRequest`／`CheckinRequest` 填 `os_family: None`（agent.rs:244、:364，及 server/loadsim/測試裡所有建構這兩個 struct 的地方）**

用 `cargo build --workspace --all-targets` 找出所有編譯錯誤逐一補上。

- [ ] **Step 5：寫失敗的測試（agent）**

`crates/agent/src/commands/logic.rs` 或 worker 測試：語言不是 `NATIVE_LANGUAGE` 的腳本回報 `Failed`，輸出為「這台電腦的作業系統不支援 sh 腳本，未執行」（語言名稱用 `as_str()`），而且沒有寫出任何腳本檔。

- [ ] **Step 6：在 `worker.rs` 的 `script()` 開頭，雜湊檢查之前先檢查語言**

- [ ] **Step 7：`cargo test -p protocol && cargo test -p endpoint-agent`，全部通過**

- [ ] **Step 8：Commit**

```bash
git add crates/protocol crates/agent crates/server crates/loadsim
git commit -m "feat(protocol): os family, accounts section, script language"
```

---

### Task 2：migration 與作業系統類型的記錄

**Files:**
- Create: `crates/server/migrations/0022_linux.sql`
- Modify: `crates/server/src/enroll.rs:129`、`crates/server/src/checkin.rs:66-98`
- Test: `crates/server/tests/checkin.rs`、`crates/server/tests/enroll.rs`

**Interfaces:**
- Consumes：Task 1 的 `OsFamily`。
- Produces：`devices.os_family`、`device_accounts`、`scripts.language`、`command_runs.script_language`、`command_runs.skipped_os`（後面 Task 3、6 使用）。

migration 內容：

```sql
-- Linux Agent 第一版
ALTER TABLE devices ADD COLUMN os_family TEXT NOT NULL DEFAULT 'windows'
    CHECK (os_family IN ('windows', 'linux'));
CREATE INDEX devices_os_family_idx ON devices (os_family) WHERE os_family <> 'windows';

CREATE TABLE device_accounts (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE scripts ADD COLUMN language TEXT NOT NULL DEFAULT 'powershell'
    CHECK (language IN ('powershell', 'sh'));
ALTER TABLE command_runs ADD COLUMN script_language TEXT
    CHECK (script_language IN ('powershell', 'sh'));
UPDATE command_runs SET script_language = 'powershell' WHERE action = 'script';
-- 名稱不能用 command_runs_script_language_check：那是上面欄位 CHECK 自動產生的名稱
ALTER TABLE command_runs ADD CONSTRAINT command_runs_script_has_language
    CHECK ((action = 'script') = (script_language IS NOT NULL));
ALTER TABLE command_runs ADD COLUMN skipped_os INT NOT NULL DEFAULT 0 CHECK (skipped_os >= 0);
```

- [ ] **Step 1：寫失敗的測試**

`tests/enroll.rs`：`enroll_records_os_family`：送 `os_family: Some(Linux)` 註冊 → `SELECT os_family FROM devices` 為 `linux`；不送 → `windows`。（`enroll_with_csr` 加一個 `os_family: Option<OsFamily>` 參數，或另寫一個 helper；既有呼叫傳 `None`。）

`tests/checkin.rs`：
- `checkin_updates_os_family_when_changed`：windows 裝置報到時帶 `Some(Linux)` → 變 `linux`；之後不帶（None）→ **維持** `linux`（None 不覆寫）。
- `linux_checkin_gets_empty_assignments`：建立一個對該群組生效的派送和更新原則、一條登錄檔規則；把裝置設成 linux；報到回應：`deployments` 空、`deployments_hash == Some(assignments_hash(&[]))`、`update_policy` None、`update_policy_hash == Some(update_policy_hash(None))`、`registry_queries` 空、`registry_queries_hash == Some(queries_hash(&[]))`、`package_source` None；同群組的 windows 裝置照常拿到。
- `linux_checkin_still_gets_commands`：對 linux 裝置建立 `collect` 指令 → 報到回應有這筆。

- [ ] **Step 2：執行 `cargo test -p endpoint-server --test enroll --test checkin`，確認失敗**

- [ ] **Step 3：實作**
  - enroll：INSERT 加 `os_family`（`req.os_family.unwrap_or(OsFamily::Windows).as_str()`）。重新註冊（`reenroll_of`）沿用同一個寫法。
  - checkin：`SELECT group_id, status, os_family`；`req.os_family` 是 `Some` 且不同時 `UPDATE devices SET os_family = $2 WHERE id = $1`（只在不同時寫，避免每次報到多一次寫入）。Linux 時照 Review Focus 1 回傳空值的 hash；`commands` 照常。

- [ ] **Step 4：測試通過，加上 `cargo test -p endpoint-server --test deploy --test updates --test branch` 確認 Windows 行為沒變**

- [ ] **Step 5：Commit** `feat(server): record device os family; linux check-in gets no windows assignments`

---

### Task 3：`accounts` 區段的儲存與差異

**Files:**
- Modify: `crates/server/src/inventory.rs`（`load_payload`、`write_payload`）
- Modify: `crates/server/src/diff.rs`（`items_of`）
- Test: `crates/server/tests/inventory.rs`、`crates/server/src/diff.rs` 的 tests

**Interfaces:**
- Consumes：Task 1 的 `AccountsInfo`、Task 2 的 `device_accounts`。
- Produces：`load_payload(.., Section::Accounts)` 回傳 `InventoryPayload::Accounts`（計畫 29 的裝置頁會用）。

- [ ] **Step 1：寫失敗的測試**
  - `tests/inventory.rs::accounts_section_round_trips`：上傳 `accounts`（2 個 users、1 筆 privileged、1 行 unparsed）→ `device_accounts` 有一列；同內容再傳一次不寫 `inventory_changes`；改一個 user 的 `locked` → 產生一筆 updated 變更。
  - `diff.rs`：`accounts_items_are_keyed`：`items_of` 的 key 分別是 `user|<name>`、`priv|<principal>|<kind>|<source>`、`unparsed|<line>`；user 的 value 包含 uid、shell、locked、password_changed。

- [ ] **Step 2：確認失敗**

- [ ] **Step 3：實作**：`write_payload` 用 `INSERT … ON CONFLICT (device_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`；`load_payload` 讀 `data` 反序列化，沒有列就 None（比照其他區段）。diff 的 key 照 Step 1。

- [ ] **Step 4：測試通過**

- [ ] **Step 5：Commit** `feat(server): store and diff accounts section`

---

### Task 4：合規排除 Linux 裝置

**Files:**
- Modify: `crates/server/src/compliance/store.rs:156,208,438,482`
- Test: `crates/server/tests/compliance.rs`

**Interfaces:**
- Consumes：`devices.os_family`。
- 做法：`load_facts`／`load_facts_bulk` 多讀 `os_family`，`active: status == "active" && os_family == "windows"`。`evaluate.rs` 已經對 `!active` 不產生任何結果（`evaluate.rs:779`），預覽（`evaluate.rs:369`）也一樣，不用改 evaluate。

- [ ] **Step 1：寫失敗的測試**
  - `linux_device_has_no_violations`：建立一條所有裝置都會違反的規則（例如 required software 不存在），一台 windows、一台 linux（同群組）→ 重算後只有 windows 有違規；`compliance_daily` 的 violating 為 1。
  - `device_switching_to_linux_clears_violations`：先是 windows 有違規 → 改成 linux → 重算 → `device_violations` 沒有這台。違規歷程的結尾跟「裝置停用」的處理相同（照現有 inactive 的行為，不新增事件類型）。
  - `preview_skips_linux`：規則預覽的違反台數不含 linux。

- [ ] **Step 2：確認失敗**

- [ ] **Step 3：實作**（上面的做法）

- [ ] **Step 4：`cargo test -p endpoint-server --test compliance --test compliance_web --test config_rules`，全部通過**

- [ ] **Step 5：Commit** `feat(server): exclude linux devices from compliance`

---

### Task 5：派送與 Windows Update 頁面排除 Linux 裝置

**Files:**
- Modify: `crates/server/src/web/deployments.rs:21`（`TARGET`）
- Modify: `crates/server/src/web/updates.rs:20`（`TARGET`）、`:682`、`:693`
- Test: `crates/server/tests/deploy_web.rs`、`crates/server/tests/updates_web.rs`

**Interfaces:**
- 做法：兩個 `TARGET` 常數開頭的 `v.status = 'active'` 改成 `v.status = 'active' AND v.os_family = 'windows'`。`updates.rs:682、693` 的統計查詢（不經過 `TARGET`）同樣加上條件。自動暫停（`deploy/api.rs::auto_pause`）只看已回報的 `deployment_status`，Linux 不會回報，**不用改**。

- [ ] **Step 1：寫失敗的測試**
  - `deploy_web::linux_devices_not_counted`：群組有 2 台 windows、1 台 linux，派送到這個群組 → 派送清單和詳細頁的目標數是 2；詳細頁的裝置清單沒有 linux 那台。
  - `updates_web::linux_devices_not_counted`：同樣的情境，更新原則清單與詳細頁的台數是 2。

- [ ] **Step 2：確認失敗**

- [ ] **Step 3：實作**

- [ ] **Step 4：`cargo test -p endpoint-server --test deploy_web --test updates_web --test deploy --test updates`，全部通過**

- [ ] **Step 5：Commit** `feat(server): linux devices are not deployment or update targets`

---

### Task 6：腳本語言與依作業系統展開指令

**Files:**
- Modify: `crates/server/src/commands/scripts.rs`（`ScriptInput`、`create_script`；`update_script` 不接受改語言）
- Modify: `crates/server/src/commands/runs.rs`（`ScriptSnapshot`、`create_run`）
- Modify: `crates/server/src/commands/api.rs:30-75`（`pending_for`）
- Modify: `crates/server/src/web/scripts.rs`（表單只需要能把 `language` 欄位傳進 `ScriptInput`；畫面在計畫 29）
- Test: `crates/server/tests/commands.rs`

**Interfaces:**
- Consumes：Task 1 的 `ScriptLanguage`、Task 2 的欄位。
- Produces：
  - `ScriptInput.language: ScriptLanguage`（新增；`update_script` 忽略這個欄位）。
  - `create_run` 回傳值改成 `(run_id, count, skipped)`：`anyhow::Result<(i64, i64, i64)>`；呼叫端（`web/commands.rs`、測試、loadsim）一併更新，網頁暫時不顯示 skipped（計畫 29）。
  - 必要作業系統：`script` → 腳本語言對應（powershell→windows、sh→linux）；`apply` → windows；其他動作 → 不限。

- [ ] **Step 1：寫失敗的測試**
  - `script_language_is_stored`：建立 sh 腳本 → `scripts.language = 'sh'`；`update_script` 帶不同語言 → 語言不變。
  - `group_run_skips_mismatched_os`：群組 2 台 windows（其中 1 台 `status = 'retired'`）、2 台 linux；跑 sh 腳本 → count = 2、skipped = 1（只算使用中的 windows）、`command_runs.skipped_os = 1`、`script_language = 'sh'`。
  - `group_run_with_no_matching_os_is_rejected`：群組只有 windows，跑 sh 腳本 → `CmdError::Invalid`，訊息「群組內沒有作業系統相符的使用中裝置」，沒有建立 run。
  - `device_run_with_mismatched_os_is_rejected`：對 linux 裝置跑 PowerShell 腳本、對 linux 裝置下 `apply` → `CmdError::Invalid`，訊息「這台裝置是 Linux，不支援這個動作」（Windows 裝置 + sh：「這台裝置是 Windows，不支援 sh 腳本」——實作者可以統一成一個格式，但必須說出裝置的作業系統）。
  - `collect_goes_to_all_os`：群組混合時 `collect` 的 count = 全部使用中裝置、skipped = 0。
  - `pending_for_carries_language`：linux 裝置報到拿到的 `ScriptSpec.language == Sh`。

- [ ] **Step 2：確認失敗**

- [ ] **Step 3：實作**
  - `create_script` INSERT 加 `language`。
  - `create_run`：讀腳本時一起讀 `language`，存進 `command_runs.script_language`。裝置目標的查詢多讀 `os_family`，不符時回 Invalid（在範圍檢查**之後**，群組管理員不能用這個錯誤探測範圍外的裝置）。群組目標：

```sql
INSERT INTO command_targets (run_id, device_id)
SELECT $1, id FROM devices
 WHERE status = 'active' AND group_id = $2 AND ($3::text IS NULL OR os_family = $3)
```

    skipped = 同群組 `status = 'active' AND os_family <> $3` 的台數（`$3` 為 NULL 時是 0），`UPDATE command_runs SET skipped_os = …`。count = 0 時：skipped > 0 回 Invalid（上面的訊息），否則維持現有的「群組內沒有使用中的裝置」。稽核紀錄的 json 加 `"skipped_os"`。
  - `pending_for`：SELECT 加 `r.script_language`，`ScriptLanguage::parse` 失敗時當成 PowerShell。

- [ ] **Step 4：`cargo test -p endpoint-server --test commands --test commands_web` 與 `cargo test -p loadsim`，全部通過**

- [ ] **Step 5：完整檢查**

```bash
cargo test --workspace -j 4
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

全部通過。

- [ ] **Step 6：Commit** `feat(server): script language and os-aware command targets`

---

## 之後的計畫（不在這份裡）
- **計畫 28（Linux agent）**：`crates/agent/src/linux/`（收集器 §4、sh 執行 §5.2、資料目錄與 configure §6）、`main.rs` Linux 入口、systemd unit、deb／rpm／tar.gz 打包、CI Linux 工作與 Release 資產。
- **計畫 29（後台與文件）**：裝置列表作業系統篩選、Linux 裝置頁分頁與「帳號與權限」、腳本頁語言欄位、指令詳細頁略過數、軟體頁作業系統篩選（預設 Windows）、`EM_AGENT_DEB`／`EM_AGENT_RPM` 下載路由與金鑰頁 Linux 安裝區塊、README「Linux Agent」一節。
