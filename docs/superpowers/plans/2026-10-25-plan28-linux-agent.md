# 計畫 28：Linux Agent——收集、指令、安裝與打包 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 做出可以裝在任何 x86_64 Linux 發行版上的 `endpoint-agent`：收集基本資訊、硬體、軟體、服務、帳號與權限，執行遠端指令和 sh 腳本，並打包成 deb、rpm、tar.gz。

**Architecture:**
- 平台差異改成由實作宣告，不用 `cfg` 切換共用邏輯：`Collector` 多 `sections()`／`os_family()`，`CommandHost` 多 `language()`／`shutdown_args()`／`shutdown_label()`，都有 Windows 的預設值。這樣測試用的假實作在任何平台都維持原本行為（計畫 27 的 CI 失敗就是 `cfg` 造成的）。
- 解析程式（`/etc/os-release`、`/proc`、dpkg、rpm、systemctl、passwd／group／shadow／sudoers）放在不受平台限制的 `crate::linux_parse`，Windows 上也能跑單元測試。讀檔、執行指令、systemd 相關的部分放在 `#[cfg(target_os = "linux")] crate::linux`。
- 打包用 `cargo-deb`、`cargo-generate-rpm`（CI 安裝的工具，不是相依套件），systemd unit 和維護腳本放在 `packaging/linux/`。

**Tech Stack:** 既有依賴，加上 `libc`（Linux 專用：`statvfs`、`kill`、`umask`；已在 Cargo.lock 中，MIT/Apache-2.0）。

**Spec:** `docs/superpowers/specs/2026-10-24-linux-agent-design.md`（§4、§5、§6、§7.1、§7.2 的 configure、§9）

## Global Constraints
- 使用者可見文字與註解用繁體中文，風格同既有程式碼。
- 目標：`x86_64-unknown-linux-musl` 靜態執行檔；不做 aarch64、不做 OpenRC。
- 資料目錄 `/var/lib/endpoint-manager`（`EM_AGENT_DIR` 可覆寫），權限 0700、擁有者 root；agent 啟動時 `umask(0o077)`，金鑰與狀態檔一律 0600。
- 外部指令用完整路徑，`/usr/bin/<名稱>` 找不到時改試 `/bin/<名稱>`，都沒有就當作不支援；每個外部指令逾時 60 秒。
- 絕對不能回報 `/etc/shadow` 的密碼欄位內容（連長度、雜湊演算法都不行），解析完只保留布林值與日期。
- Windows agent 的行為、序列化、測試結果都不能改變。
- 測試指令：Windows 上 `cargo test -p endpoint-agent`；Linux 專用程式碼在 WSL（Ubuntu）內：`wsl -e bash -lc "cd /mnt/d/Claude/endpoint-manager && CARGO_TARGET_DIR=\$HOME/em-target cargo test -p endpoint-agent --lib"`；完整：`cargo test --workspace -j 4`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo fmt --check`，CI 的 Linux 工作也必須通過。
- WSL 裡需要先有 Rust 工具鏈（rustup stable）與 `musl-tools`；沒有就回報 BLOCKED，不要自己安裝。

## Review Focus
1. sudoers 裡看不懂的寫法（別名、`Defaults`、帶條件的權限行、include 迴圈）必須進 `sudoers_unparsed`，不能默默略過；include 最多三層，循環 include 不能無窮遞迴。
2. 沒有 dpkg 也沒有 rpm、沒有 systemd、`/sys/class/dmi` 讀不到（VM、容器）時，該區段回空值並寫 `section_errors` 的說明，agent 照常報到，不能整輪失敗。
3. sh 腳本逾時時整個程序群組都要結束（腳本開的背景子程序也是），之後 agent 不會卡住。
4. 套件移除（不是升級）才清註冊資料；`apt install` 新版 deb 升級時資料目錄保留、服務重新啟動。
5. 同一個主體從多個來源取得 root（例如在 sudo 群組又寫在 sudoers 裡），每個來源各一筆；非 root 的 UID 0 一定列出。

---

### Task 1：平台差異改由實作宣告

**Files:**
- Modify: `crates/agent/src/collector.rs`、`crates/agent/src/agent.rs`（`sections_to_collect`、enroll／check-in 的 `os_family`）、`crates/agent/src/schedule.rs`（`Schedule::due`）
- Modify: `crates/agent/src/commands/worker.rs`（`CommandHost`、`run`、`script`）、`crates/agent/src/commands/logic.rs`（刪除 `NATIVE_LANGUAGE`；新增 `script_file_name`、`script_body`）
- Modify: `crates/agent/src/windows/commands.rs`（`collect_all` 用 `Section::WINDOWS`，不受影響）
- Modify: `crates/agent/src/deploy/worker.rs`（`run_process` 在 unix 上用程序群組）、`crates/agent/Cargo.toml`（`[target.'cfg(unix)'.dependencies] libc = "0.2"`）
- Modify: `crates/agent/src/sanitize.rs`（accounts 三個清單合計不超過 `MAX_ITEMS`）
- Modify: `crates/agent/tests/e2e.rs`（撤掉計畫 27 CI 修正：`command()` 不再改 `os_family`，`approved_script` 的 language 改回 `Default::default()`）
- Test: 同檔案的 tests、`crates/agent/tests/e2e.rs`

**Interfaces:**
- Produces：
  - `trait Collector` 新增預設方法 `fn sections(&self) -> &'static [Section] { &Section::WINDOWS }`、`fn os_family(&self) -> Option<OsFamily> { None }`。
  - `pub fn sections_to_collect(platform: &[Section], supported: bool) -> Vec<Section>`：supported → `platform` 全部；否則 `platform` 中屬於 `Section::LEGACY` 的。
  - `Schedule::due(&self, now: Instant, iv: &CollectionIntervals, sections: &[Section]) -> Vec<Section>`。
  - `trait CommandHost` 新增預設方法：`fn language(&self) -> ScriptLanguage { ScriptLanguage::PowerShell }`、`fn shutdown_args(&self, reboot: bool, delay_minutes: u32) -> String { logic::shutdown_args(reboot, delay_minutes) }`、`fn shutdown_label(&self) -> &'static str { "shutdown.exe" }`。
  - `logic::script_file_name(lang: ScriptLanguage, id: i64) -> String`（PowerShell → `"{id}.ps1"`，Sh → `"{id}.sh"`）、`logic::script_body(lang: ScriptLanguage, content: &str) -> String`（PowerShell 前加 `\u{feff}`，Sh 原樣）。
  - 啟動時清殘留腳本（`leftover_scripts_are_removed_on_start`）要同時清 `.ps1` 和 `.sh`。
  - worker 的錯誤文字：「這台電腦的作業系統不支援 {lang} 腳本，未執行」改用 `host.language()` 比較；「無法執行 PowerShell：{e}」改成「無法執行 {lang} 腳本：{e}」（`lang` 用 `as_str()`）；關機的回報文字 `format!("{} {args}", host.shutdown_label())`。
  - `run_process`：`#[cfg(unix)]` 時 `process_group(0)`；逾時先對群組送 SIGTERM（`libc::kill(-pgid, SIGTERM)`），等 10 秒還沒結束就 SIGKILL 整個群組，再 `child.kill()`。

- [ ] **Step 1：寫失敗的測試**
  - `logic.rs`：`script_file_names_and_bodies`：`script_file_name(Sh, 7) == "7.sh"`、`script_body(PowerShell, "x") == "\u{feff}x"`、`script_body(Sh, "x") == "x"`。
  - `agent.rs`：`sections_follow_platform`：`sections_to_collect(&Section::LINUX, true) == Section::LINUX`；`sections_to_collect(&Section::LINUX, false)` 不含 `Accounts`；`sections_to_collect(&Section::WINDOWS, false) == Section::LEGACY`。
  - `worker.rs`（或 e2e 的 commands 模組）：一個 `language()` 回 Sh 的假 host 收到 Sh 腳本 → 寫出 `scripts/<id>.sh`，內容沒有 BOM，`run_script` 被呼叫；收到 PowerShell 腳本 → 失敗「這台電腦的作業系統不支援 powershell 腳本，未執行」。
  - `deploy/worker.rs`，`#[cfg(unix)]`：`timeout_kills_process_group`：用 `/bin/sh -c "sleep 300 & echo $! > <tmp>/pid; wait"`、逾時 1 秒 → 回 `TimedOut`，12 秒內 `<tmp>/pid` 裡的程序已不存在（`libc::kill(pid, 0)` 回 -1）。這個測試只會在 CI 的 Linux 和 WSL 上跑。
  - `sanitize.rs`：`accounts_total_is_capped`：三個清單合計超過 `MAX_ITEMS` 時，sanitize 後合計 = `MAX_ITEMS`，而且 `validate()` 通過。

- [ ] **Step 2：確認失敗**（Windows：`cargo test -p endpoint-agent`；unix 測試：WSL 指令，見 Global Constraints）

- [ ] **Step 3：實作 Interfaces 列出的全部**；撤掉 e2e 的計畫 27 修正

- [ ] **Step 4：`cargo test -p endpoint-agent`（Windows）與 WSL 的 `--lib` 都通過；`cargo test --workspace -j 4`、clippy、fmt 通過**

- [ ] **Step 5：Commit** `refactor(agent): platform hooks on Collector and CommandHost`

---

### Task 2：系統資訊的解析與讀取（識別、心跳、basic、hardware）

**Files:**
- Create: `crates/agent/src/linux_parse/mod.rs`、`crates/agent/src/linux_parse/system.rs`
- Create: `crates/agent/src/linux/mod.rs`（只先放 `pub mod exec; pub mod system;`）、`crates/agent/src/linux/exec.rs`、`crates/agent/src/linux/system.rs`
- Modify: `crates/agent/src/lib.rs`（`pub mod linux_parse;`、`#[cfg(target_os = "linux")] pub mod linux;`）
- Test: `linux_parse/system.rs` 的 tests（測試資料用字串常數）

**Interfaces:**
- Produces（`linux_parse::system`，純函式）：
  - `os_caption(os_release: &str) -> Option<String>`：`PRETTY_NAME`；沒有就 `NAME` + 空白 + `VERSION`；值去掉成對的 `"` 或 `'`。
  - `boot_time(proc_stat: &str) -> Option<DateTime<Utc>>`：`btime` 行。
  - `mem_total_mb(meminfo: &str) -> Option<u64>`：`MemTotal` kB → MB（整數除法）。
  - `cpu_model(cpuinfo: &str) -> Option<String>`：第一個 `model name`。
  - `real_mounts(proc_mounts: &str) -> Vec<String>`：回掛載點；排除檔案系統類型 `tmpfs devtmpfs proc sysfs cgroup cgroup2 overlay squashfs devpts mqueue debugfs tracefs securityfs pstore bpf autofs hugetlbfs fusectl configfs binfmt_misc efivarfs ramfs nsfs rpc_pipefs`，以及掛載點以 `/snap/` 開頭的；`\040` 這類八進位跳脫要還原；同一掛載點只留一次。
  - `ip_addresses(ip_o_addr: &str) -> Vec<String>`：解析 `ip -o addr show` 的輸出，取 `inet`／`inet6` 後的位址（去掉 `/前綴`），排除 `lo`、`127.0.0.0/8`、`::1`、`fe80::/10`。
  - `first_user(who: &str) -> Option<String>`：`who` 輸出第一個不是 `root` 的使用者名稱。
- Produces（`linux::exec`）：`run_capture(program: &str, args: &[&str], timeout: Duration) -> anyhow::Result<String>`：先找 `/usr/bin/<program>`、再 `/bin/<program>`（program 本身含 `/` 時直接用），都沒有回 `Err` 且錯誤可用 `is_not_found(&anyhow::Error) -> bool` 判斷；非 0 結束碼回 `Err`（含 stderr 前 200 字）；逾時 kill 後回 `Err`。常數 `pub const CMD_TIMEOUT: Duration = Duration::from_secs(60)`。
- Produces（`linux::system`）：`identity() -> anyhow::Result<Identity>`、`heartbeat() -> anyhow::Result<Heartbeat>`、`basic() -> BasicInfo`、`hardware() -> anyhow::Result<HardwareInfo>`。來源照規格 §4.1–§4.3（hostname 讀 `/proc/sys/kernel/hostname`，核心版本讀 `/proc/sys/kernel/osrelease`；DMI 讀不到就 None；MAC 讀 `/sys/class/net/*/address`，排除 `lo` 與全 0；磁碟用 `libc::statvfs`）。`domain` None、`is_domain_joined` false、`os_ubr` None。

- [ ] **Step 1：寫失敗的測試**（`linux_parse::system`）
  - `os_caption_prefers_pretty_name`：`PRETTY_NAME="Ubuntu 24.04.1 LTS"` → `Ubuntu 24.04.1 LTS`；只有 `NAME="Rocky Linux"`、`VERSION="9.4 (Blue Onyx)"` → `Rocky Linux 9.4 (Blue Onyx)`；兩者都沒有 → None。
  - `boot_time_reads_btime`：`btime 1729700000` → 對應的 UTC 時間。
  - `meminfo_and_cpu`：`MemTotal:       16318412 kB` → 15935；cpuinfo 有兩個 `model name` 時取第一個。
  - `real_mounts_filters_virtual`：輸入含 `/`（ext4）、`/boot/efi`（vfat）、`/proc`、`/run`（tmpfs）、`/snap/core/1`（squashfs）、`/mnt/my\040disk`（ext4）、重複的 `/` → `["/", "/boot/efi", "/mnt/my disk"]`。
  - `ip_addresses_skip_loopback_and_link_local`：含 `lo`、`eth0 inet 10.0.0.5/24`、`eth0 inet6 fe80::1/64`、`eth0 inet6 2001:db8::5/64` → `["10.0.0.5", "2001:db8::5"]`。
  - `first_user_skips_root`：`root pts/0 …` 與 `alice tty2 …` → `alice`；空字串 → None。

- [ ] **Step 2：確認失敗**（Windows：`cargo test -p endpoint-agent --lib linux_parse`）

- [ ] **Step 3：實作 `linux_parse::system`；再實作 `linux::exec` 與 `linux::system`（只在 Linux 編譯）**

- [ ] **Step 4：Windows 上 `--lib linux_parse` 通過；WSL 上 `cargo test -p endpoint-agent --lib` 與 `cargo clippy -p endpoint-agent --all-targets -- -D warnings` 通過**；在 WSL 執行一個暫時的 `#[test] #[ignore]` 或 `cargo run --example` 都不要留下——改為在 `linux::system` 加一個 `#[cfg(test)]` 測試 `reads_this_machine`：`identity()` 成功且 hostname 非空、`basic().os_caption` 非空、`hardware()` 成功且 `ram_mb > 0`（WSL 與 CI 都有這些檔案）。

- [ ] **Step 5：Commit** `feat(agent): linux system information`

---

### Task 3：軟體與服務

**Files:**
- Create: `crates/agent/src/linux_parse/packages.rs`、`crates/agent/src/linux_parse/services.rs`
- Create: `crates/agent/src/linux/packages.rs`、`crates/agent/src/linux/services.rs`
- Test: 兩個 `linux_parse` 檔案的 tests

**Interfaces:**
- Consumes：Task 2 的 `linux::exec::{run_capture, is_not_found, CMD_TIMEOUT}`。
- Produces（純函式）：
  - `packages::parse_dpkg(out: &str) -> Vec<SoftwareItem>`：輸入是 `dpkg-query -W -f='${Status}\t${Package}\t${Version}\t${Maintainer}\t${Architecture}\n'`，只收 Status 為 `install ok installed` 的。
  - `packages::parse_rpm(out: &str) -> Vec<SoftwareItem>`：輸入是 `rpm -qa --qf '%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{ARCH}\n'`；EPOCH 為 `(none)` 時不加前綴，否則 `EPOCH:VERSION-RELEASE`；VENDOR 為 `(none)` 時 None；INSTALLTIME（epoch 秒）轉成 `YYYY-MM-DD`（UTC）。
  - `packages::arch_of(s: &str) -> Arch`：`amd64`、`x86_64` → `X64`；`i386`、`i486`、`i586`、`i686` → `X86`；其他 → `Other`。
  - `services::parse(units: &str, unit_files: &str) -> Vec<ServiceItem>`：`units` 是 `systemctl list-units --type=service --all --no-legend --plain --no-pager`（欄位：UNIT LOAD ACTIVE SUB DESCRIPTION…），`unit_files` 是 `systemctl list-unit-files --type=service --no-legend --no-pager`（UNIT STATE [PRESET]）。合併成每個 unit 一筆：`name` = unit 名稱、`display_name` = DESCRIPTION（可能含空白）、`start_mode` = unit file 的 STATE（沒有就 `"unknown"`）、`state` = `"{ACTIVE}/{SUB}"`（只在 unit file 出現、沒有載入的 → `"inactive/dead"`）、`binary_path` = None。範本 unit（名稱含 `@.service`）不列。
- Produces（Linux）：`linux::packages::collect() -> (Vec<SoftwareItem>, Option<String>)` 回清單與 section 錯誤說明；`linux::services::collect() -> (Vec<ServiceItem>, Option<String>)`。說明文字照規格：「此發行版的套件系統不支援」、「沒有 systemd，不收集服務」。

- [ ] **Step 1：寫失敗的測試**
  - `dpkg_only_installed`：三行（`install ok installed`、`deinstall ok config-files`、`install ok installed` 且架構 `all`）→ 兩筆，第二筆 `arch == Arch::Other`，`publisher` 為 Maintainer。
  - `rpm_epoch_vendor_date`：`bash\t(none)\t5.1.8-9.el9\tRocky Enterprise Software Foundation\t1729700000\tx86_64` → version `5.1.8-9.el9`、date `2024-10-23`、arch X64；`openssl\t1\t3.0.7-27.el9\t(none)\t…\tx86_64` → version `1:3.0.7-27.el9`、publisher None。
  - `arch_mapping`：`i686` → X86、`noarch` → Other、`aarch64` → Other。
  - `services_merge`：`ssh.service loaded active running OpenBSD Secure Shell server` 加 unit file `ssh.service enabled enabled` → `start_mode "enabled"`、`state "active/running"`、`display_name "OpenBSD Secure Shell server"`；只在 unit file 的 `foo.service disabled enabled` → `state "inactive/dead"`；`getty@.service` 不列。

- [ ] **Step 2：確認失敗**

- [ ] **Step 3：實作**（Linux 端：dpkg 優先；兩者都 `is_not_found` → 空清單 + 說明；其他錯誤 → `Err` 往上丟，由收集器記成 section 錯誤）

- [ ] **Step 4：Windows `--lib linux_parse` 與 WSL `--lib` 通過；WSL 加 `reads_this_machine_packages`：`packages::collect()` 回非空清單、錯誤為 None（WSL Ubuntu 有 dpkg；CI ubuntu runner 也有）**

- [ ] **Step 5：Commit** `feat(agent): linux packages and services`

---

### Task 4：帳號與管理權限

**Files:**
- Create: `crates/agent/src/linux_parse/accounts.rs`
- Create: `crates/agent/src/linux/accounts.rs`
- Test: `linux_parse/accounts.rs` 的 tests

**Interfaces:**
- Produces（純函式，`linux_parse::accounts`）：
  - `uid_min(login_defs: &str) -> u32`：`UID_MIN` 數值，沒有或無法解析 → 1000。
  - `users(passwd: &str, shadow: Option<&str>, uid_min: u32) -> (Vec<LocalUser>, u32)`：回可登入帳號與系統帳號數。不列的條件：shell 的檔名（最後一段）是 `nologin`、`false`、`sync`、`halt`、`shutdown`，或 `uid < uid_min` 且名稱不是 `root`。`locked`：shadow 密碼欄以 `!` 或 `*` 開頭 → true，其他 → false，shadow 沒有這個帳號或 `shadow` 為 None → None。`password_changed`：shadow 第三欄（天數）轉成 `1970-01-01 + n 天`，空或 0 → None。
  - `uid_zero(passwd: &str) -> Vec<String>`：所有 UID 0 的帳號名稱。
  - `admin_group_members(group: &str) -> Vec<(String, String)>`：回 `(成員, "group:<群組名>")`，只看 `sudo`、`wheel`、`admin`。
  - `struct SudoersFile { name: String, content: String }`；`sudoers(files: &[SudoersFile]) -> (Vec<PrivilegeEntry>, Vec<String>)`：只處理已經讀進來的檔案內容（include 由 Linux 端讀檔時展開）。每個有效行：`使用者 主機=…` → kind User，`%群組 主機=…` → kind Group，主體可以是逗號分隔的多個名稱；`source` = `"sudoers:<name>"`。進 unparsed（原文，最多 50 行、每行最多 200 字元）：`User_Alias`／`Runas_Alias`／`Host_Alias`／`Cmnd_Alias` 定義行、主體是別名（全大寫）或以 `+`、`#數字`、`%#`、`%:` 開頭的行、沒有 `=` 的非指令行。略過：`Defaults` 開頭、註解（`#` 後不是 `include`／`includedir`）、空行、`#include`／`@include`／`#includedir`／`@includedir`。行尾 `\` 接續下一行。
  - `include_targets(content: &str) -> Vec<Include>`，`enum Include { File(String), Dir(String) }`：回這個檔案裡的 include 指令。
- Produces（Linux，`linux::accounts`）：`collect() -> AccountsInfo`：讀 `/etc/login.defs`、`/etc/passwd`、`/etc/shadow`（讀不到 → None）、`/etc/group`、`/etc/sudoers` 與它的 include；`privileged` = UID 0（source `"uid0"`）＋ 群組成員（kind User）＋ sudoers。include 規則：`*Dir` 底下的檔案依名稱排序，略過名稱含 `.` 或以 `~` 結尾的；最多三層；同一個實際路徑（`canonicalize`）只讀一次；讀不到的檔案在 `sudoers_unparsed` 放一行「無法讀取 <路徑>：<原因>」。`/etc/sudoers` 本身讀不到也一樣處理。

- [ ] **Step 1：寫失敗的測試**
  - `users_filters_and_reads_shadow`：passwd 含 `root:x:0:0::/root:/bin/bash`、`daemon:x:1:1::/:/usr/sbin/nologin`、`alice:x:1000:1000::/home/alice:/bin/bash`、`bob:x:1001:1001::/home/bob:/bin/zsh`、`svc:x:999:999::/:/bin/bash`；shadow 含 `root:*:19000:…`、`alice:$6$abc$hash:19500:…`、`bob:!$6$x:0:…` → users 依序 root（locked true、changed 2022-01-08）、alice（false、2023-05-22）、bob（true、None）；系統帳號數 2。
  - `shadow_secrets_never_leak`：上面結果 `format!("{:?}", users)` 與 `serde_json::to_string` 都不含 `$6$`、`abc`、`hash`。
  - `uid_zero_lists_impostors`：`root` 和 `toor:x:0:0::/:/bin/sh` → `["root", "toor"]`。
  - `group_members`：`sudo:x:27:alice,bob`、`wheel:x:10:`、`adm:x:4:carol` → `[("alice","group:sudo"),("bob","group:sudo")]`。
  - `sudoers_parses_common_lines`：檔案 `sudoers` 內容：

```
Defaults env_reset
# comment
root ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
alice,bob ALL=(ALL) NOPASSWD: ALL
User_Alias ADMINS = carol, dave
ADMINS ALL=(ALL) ALL
%sudo   ALL=(ALL:ALL) \
        ALL
#includedir /etc/sudoers.d
```

    → privileged：root(User)、admin(Group)、alice(User)、bob(User)、sudo(Group)，source 都是 `sudoers:sudoers`；unparsed：`User_Alias ADMINS = carol, dave`、`ADMINS ALL=(ALL) ALL`。
  - `sudoers_unparsed_is_capped`：60 行別名 → unparsed 50 行；一行 300 字 → 截成 200 字元。
  - `include_targets`：`#includedir /etc/sudoers.d`、`@include /etc/sudoers.local` → `[Dir("/etc/sudoers.d"), File("/etc/sudoers.local")]`。

- [ ] **Step 2：確認失敗**

- [ ] **Step 3：實作 `linux_parse::accounts`，再實作 `linux::accounts::collect`**（Review Focus 1：include 層數與 canonicalize 去重）

- [ ] **Step 4：Windows `--lib linux_parse` 通過；WSL `--lib` 通過，加 Linux 測試 `include_loop_terminates`：在暫存目錄建兩個互相 include 的檔案，呼叫 `linux::accounts` 內部讀取 include 的函式（實作者自訂名稱，以目錄為參數），在三層內結束且每個檔案只讀一次**

- [ ] **Step 5：Commit** `feat(agent): linux accounts and privileges`

---

### Task 5：Linux 收集器、指令執行、資料目錄與入口

**Files:**
- Create: `crates/agent/src/linux/collect.rs`、`crates/agent/src/linux/commands.rs`、`crates/agent/src/linux/install.rs`
- Modify: `crates/agent/src/linux/mod.rs`（`agent_dir`、`run`、`run_foreground`）、`crates/agent/src/main.rs`（`#[cfg(target_os = "linux")] fn main`；其他非 Windows 平台維持「不支援」）
- Test: 各檔案的 `#[cfg(test)]`（只在 Linux 跑）

**Interfaces:**
- Consumes：Task 1 的 `Collector::{sections, os_family}`、`CommandHost::{language, shutdown_args, shutdown_label}`、`run_process`；Task 2–4 的收集函式。
- Produces：
  - `linux::collect::LinuxCollector`：`impl Collector`，`sections()` = `&Section::LINUX`，`os_family()` = `Some(OsFamily::Linux)`；`collect(Section::Accounts)` 回 `InventoryPayload::Accounts`；software／services 在「不支援」時回 `Err(anyhow!(說明))`：現有的 `Agent` 會把它放進報到的 `section_errors`、不上傳該區段，後台（計畫 29）把這段文字當成說明顯示，不當成錯誤。這比規格 §4.4「空清單 + 說明」少上傳一個空清單，結果相同（伺服器本來就沒有這台的軟體資料）；`collect(Patches｜Security｜Registry)` 回 `Err("Linux 不收集這個區段")`。
  - `linux::commands::LinuxHost { triggers: mpsc::Sender<Section> }`：`impl CommandHost`；`language()` = Sh；`shutdown_label()` = `"shutdown"`；`shutdown_args(reboot, d)` = `"{-r｜-h} {now｜+d} \"<訊息>\""`，訊息與 Windows 相同（`logic::shutdown_args` 裡的文字抽成共用函式 `logic::shutdown_message(reboot, delay) -> String`）；`shutdown()` 執行 `/bin/sh -c "/sbin/shutdown <args>"`（args 只由固定文字與數字組成）；`apply_now()` 不做事；`collect_all()` 送出 `Section::LINUX`；`run_script(path, timeout)`：`chmod 0700`，內容第一行以 `#!` 開頭 → 程式 `/usr/bin/env`、參數 `-i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 HOME=/root <path>`；否則參數最後改成 `/bin/sh <path>`；交給 `run_process(.., capture = true)`。工作目錄是資料目錄（unit 的 `WorkingDirectory`），不是規格 §5.2 寫的 `scripts/`：`run_process` 沒有設定工作目錄的參數，為這點加參數不值得；兩者都是只有 root 能進的目錄。
  - `linux::agent_dir() -> PathBuf`：`EM_AGENT_DIR` 或 `/var/lib/endpoint-manager`。
  - `linux::install::configure(data: &Path, server_url, token, root_ca) -> anyhow::Result<()>`：`prepare_data_dir`（不存在就建立；存在但擁有者不是目前的 uid → 錯誤「資料目錄擁有者不正確：<路徑>」；權限設成 0700）後呼叫既有的 `config::apply_install_config`，成功後執行 `systemctl start endpoint-agent`（`systemctl` 不存在或失敗只印警告，不讓 configure 失敗）。`unconfigure(data)` 刪除整個資料目錄（不存在不算錯）。
  - `linux::run_foreground() -> anyhow::Result<()>`：`umask(0o077)`、初始化 tracing（輸出到 stderr，systemd journal 會收）、收到 SIGTERM 或 Ctrl+C 時停止；只啟動報到迴圈與指令 worker（不啟動派送與更新原則 worker）。
  - `main.rs`（Linux）：`run`、`configure [--server-url URL] [--token TOKEN] [--root-ca BASE64]`、`unconfigure`；其他子命令印用法並以非 0 結束。

- [ ] **Step 1：寫失敗的測試**（Linux）
  - `linux::commands`：`shutdown_args_linux`：`(true, 0)` → `-r now "IT 部門即將重新開機。"`；`(false, 5)` → `-h +5 "IT 部門排定在 5 分鐘後關機，請儲存您的工作。"`。
  - `script_runs_with_clean_env`：寫一個 `echo "$FOO|$PATH"; exit 4` 的檔案，在 `FOO=x` 的環境下呼叫 `run_script` → 結束碼 4、輸出 `|/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`。
  - `shebang_script_uses_interpreter`：`#!/bin/sh` 開頭、內容 `echo $0` → 輸出就是腳本路徑（證明是直接執行檔案）。
  - `linux::install`：`configure_creates_private_dir`：暫存目錄下的 `data` 不存在 → configure（用測試用的 root CA base64，參考 `config.rs` 的既有測試）後 `data` 權限 `0o700`；`unconfigure` 後目錄不存在。
  - `linux::collect`：`linux_collector_declares_linux`：`sections() == Section::LINUX`、`os_family() == Some(Linux)`、`collect(Section::Registry)` 是 `Err`。
  - Windows 端：`commands::logic` 的既有 `shutdown_arguments` 測試在抽出 `shutdown_message` 後仍通過。

- [ ] **Step 2：確認失敗**（WSL）

- [ ] **Step 3：實作**

- [ ] **Step 4：WSL 上 `cargo test -p endpoint-agent`（含 e2e，需要 DB：WSL 連 Windows 的 `em-postgres`，`DATABASE_URL` 用 Windows 主機位址；連不上就只跑 `--lib` 並在報告說明）與 clippy 通過；Windows 上 `cargo test --workspace -j 4`、clippy、fmt 通過**

- [ ] **Step 5：在 WSL 手動冒煙**：`CARGO_TARGET_DIR=$HOME/em-target cargo build -p endpoint-agent`，`EM_AGENT_DIR=/tmp/em-smoke sudo -E $HOME/em-target/debug/endpoint-agent run` 在沒有 config 時以清楚的錯誤結束（不是 panic）；結果寫進報告。

- [ ] **Step 6：Commit** `feat(agent): linux collector, command host and entry point`

---

### Task 6：打包與 CI

**Files:**
- Create: `packaging/linux/endpoint-agent.service`、`packaging/linux/postinst`、`packaging/linux/prerm`、`packaging/linux/postrm`、`packaging/linux/INSTALL.txt`、`packaging/linux/build.sh`
- Modify: `crates/agent/Cargo.toml`（`[package.metadata.deb]`、`[package.metadata.generate-rpm]`）
- Modify: `.github/workflows/ci.yml`（新增 `agent-linux` 工作）
- Test: CI 工作本身

**Interfaces:**
- unit 檔內容（照規格 §7.1）：

```ini
[Unit]
Description=Endpoint Manager Agent
After=network-online.target
Wants=network-online.target
# 還沒執行 configure 就不啟動
ConditionPathExists=/var/lib/endpoint-manager/config.json

[Service]
ExecStart=/usr/bin/endpoint-agent run
WorkingDirectory=/var/lib/endpoint-manager
Restart=always
RestartSec=10
Nice=10
# 不能開 NoNewPrivileges：腳本要以 root 執行任意指令

[Install]
WantedBy=multi-user.target
```

- 維護腳本（deb；rpm 用同樣邏輯寫進 `generate-rpm` 的 `post_install_script`／`pre_uninstall_script`）：
  - 安裝與升級後：`systemctl daemon-reload`、`systemctl enable endpoint-agent`；**升級**時（deb：`$1 = configure` 且 `$2` 非空；rpm：`$1 >= 2`）`systemctl try-restart endpoint-agent`。
  - 移除前，**只有真正移除**時（deb prerm：`$1 = remove`；rpm preun：`$1 = 0`）：`systemctl stop endpoint-agent`、`endpoint-agent unconfigure`、`systemctl disable endpoint-agent`。
  - 每個 `systemctl` 呼叫都加 `|| true`（容器裡沒有 systemd 也要能安裝與移除）。
  - deb `postrm purge`：不需要額外動作（unconfigure 已刪資料目錄），檔案存在只為了 lintian 不報錯——不需要就不要建立，實作者決定。
- 檔案位置：deb `/usr/bin/endpoint-agent`、`/lib/systemd/system/endpoint-agent.service`；rpm `/usr/bin/endpoint-agent`、`/usr/lib/systemd/system/endpoint-agent.service`。
- 產出檔名：`endpoint-agent_<版本>_amd64.deb`、`endpoint-agent-<版本>-1.x86_64.rpm`、`endpoint-agent-<版本>-x86_64-linux.tar.gz`（內容：`endpoint-agent`、`endpoint-agent.service`、`INSTALL.txt`）。
- `packaging/linux/build.sh`：在 Linux 上依序 `cargo build --release -p endpoint-agent --target x86_64-unknown-linux-musl`、`cargo deb -p endpoint-agent --no-build --target x86_64-unknown-linux-musl`、`cargo generate-rpm -p crates/agent --target x86_64-unknown-linux-musl`、打包 tar.gz，最後把三個檔案和各自的 `.sha256`（`sha256sum` 的輸出格式）放到 `target/linux-release/`。
- `INSTALL.txt`：繁體中文，十行內：安裝、註冊（`sudo endpoint-agent configure --server-url … --token … --root-ca …`，從後台金鑰頁複製）、移除、非 systemd 系統以 `endpoint-agent run` 手動啟動。
- CI `agent-linux`（`ubuntu-latest`）：安裝 `musl-tools`、`rustup target add x86_64-unknown-linux-musl`、`cargo install cargo-deb cargo-generate-rpm --locked`（用 `taiki-e/install-action` 有就用它），執行 `packaging/linux/build.sh`；接著驗證：
  1. `file target/x86_64-unknown-linux-musl/release/endpoint-agent` 含 `statically linked`。
  2. `sudo dpkg -i` deb → `/usr/bin/endpoint-agent` 存在、`systemctl is-enabled endpoint-agent` 為 `enabled`、`systemctl is-active` **不是** `active`（還沒 configure）。
  3. 再 `sudo dpkg -i` 同一個 deb（模擬升級）成功。
  4. `sudo mkdir -p /var/lib/endpoint-manager && sudo touch /var/lib/endpoint-manager/config.json` 後 `sudo dpkg -r endpoint-agent` → `/var/lib/endpoint-manager` 不存在、`/usr/bin/endpoint-agent` 不存在。
  5. `docker run --rm -v $PWD/target/linux-release:/pkg rockylinux:9 bash -c "rpm -i /pkg/*.rpm && test -x /usr/bin/endpoint-agent && rpm -e endpoint-agent && test ! -e /usr/bin/endpoint-agent"`。
  6. 上傳 `target/linux-release/` 為 artifact `agent-linux`。

- [ ] **Step 1：寫 unit 檔、維護腳本、INSTALL.txt、Cargo metadata、build.sh**
- [ ] **Step 2：在 WSL 執行 `bash packaging/linux/build.sh`（需要 `cargo-deb`、`cargo-generate-rpm`；沒有就安裝到 WSL 的使用者目錄：`cargo install --locked`），確認三個檔案與 `.sha256` 產生；`dpkg-deb -c` 列出的路徑符合上面的位置**
- [ ] **Step 3：加入 CI 工作**
- [ ] **Step 4：Commit** `build(agent): linux packages and CI job`；推上 PR 分支後 CI 的 `agent-linux` 必須通過（由 controller 確認）

---

### Task 7：真機驗證（controller 執行，不派 subagent）

- [ ] **Step 1**：從 CI artifact 取得 deb 與 rpm。
- [ ] **Step 2**：在 WSL Ubuntu（Debian 系列）與一個 RHEL 系列環境（WSL 的 AlmaLinux／Rocky 發行版，或 VM）各走一次規格 §1.2：安裝 → 從後台貼註冊指令（伺服器用 `D:\Claude\em-demo` 的展示環境）→ 後台看得到基本資訊、硬體、軟體、服務、帳號與權限 → 執行一支 sh 腳本拿回結束碼和輸出 → 重開機指令（在 WSL 上只確認 `shutdown` 被呼叫並回報，不真的重開）。
- [ ] **Step 3**：結果（截圖或文字）寫進 PR 說明；發現的問題回到對應任務修正。

## 之後的計畫
- **計畫 29（後台與文件）**：裝置列表作業系統篩選、Linux 裝置頁分頁與「帳號與權限」、腳本頁語言欄位（拒絕不認得的語言值）、指令詳細頁略過數、軟體頁作業系統篩選（預設 Windows）、`EM_AGENT_DEB`／`EM_AGENT_RPM` 下載與金鑰頁 Linux 安裝區塊、README「Linux Agent」一節，然後發新版。
