# Linux Agent 第一版 設計

日期：2026-10-24。狀態：等使用者審閱（已經過一次 builder check）。

已和使用者確認的事：
- 發行版不設限，機房伺服器和個人電腦都可能安裝。
- 第一版只做**盤點**和**遠端指令（含 sh 腳本）**。
- 加上**本機帳號與管理權限**，只要「看得到」，不從後台控制。
- 管理者通常一台一台用 SSH 登入安裝，沒有 Ansible 這類集中派送工具。
- 安裝流程用現有的 `configure` 指令，參數由後台組成一行，複製貼上即可。不做 `curl | sudo sh`。
- 安裝包跟 MSI 一樣由伺服器提供下載。

標「（設計者決定）」的項目是我做的決定，使用者沒有特別表示意見，審閱時可以推翻。

## 1. 目的

讓同一套 Endpoint Manager 也能管理 Linux 機器：後台看得到它的軟硬體、服務、帳號和誰有 root 權限，也能對它重新收集、重開機、關機，或執行核准過的 sh 腳本。

### 1.1 範圍

**做：**
- Linux agent：x86_64 靜態執行檔（musl），用 systemd 常駐，以 root 身分執行。
- 安裝包：deb、rpm、tar.gz，放在 GitHub Release；deb、rpm 也可以放到伺服器上，由後台下載（§7.2）。
- 盤點：基本資訊、硬體、軟體（dpkg／rpm）、服務（systemd）、帳號與管理權限（新區段 `accounts`）。
- 遠端指令：`collect`、`reboot`、`shutdown`，以及 sh 腳本。
- 伺服器：裝置的作業系統類型；合規、派送、Windows Update 原則都排除 Linux 裝置；後台顯示與篩選。

**不做：**
- Linux 的合規規則、套件派送（deb/rpm）、更新管理、組態控制。
- 從後台鎖定帳號、改 sudo 權限等任何寫入動作。
- LDAP、AD（SSSD）網域帳號的列舉。
- ARM（aarch64）版本。之後要加只是多一個編譯目標。
- 非 systemd 的服務管理（例如 Alpine 的 OpenRC）：只在 README 提供手動啟動的方式。
- 一行安裝腳本（`curl … | sudo sh`）。
- 伺服器的 arm64 映像。

**算失敗的情況（即使功能都能動）：**
- 現有 Windows 裝置的合規結果、派送狀態或 Windows Update 狀態，因為這次的修改而改變。
- agent 平常吃太多資源，例如每次收集都讓 CPU 長時間滿載。
- 回報內容含有密碼雜湊或其他秘密。

### 1.2 成功標準

- 在一台 Debian/Ubuntu 系列和一台 RHEL 系列（Rocky、Alma 或 Fedora）上，各自走完整個流程：安裝套件 → 貼上註冊指令 → 後台出現裝置，看得到基本資訊、硬體、軟體、服務、帳號與管理權限 → 執行一支 sh 腳本，拿回結束碼和輸出 → 重開機指令生效。
- 現有測試全部通過，CI 的 Windows 工作照常產出 MSI 和 exe。
- 已有的 Windows 裝置報到 p99 和合規重算時間跟這次之前相比沒有變差（用現有的 loadsim 量）。

## 2. 作業系統類型

- 新增裝置欄位 `devices.os_family`：`windows`／`linux`，NOT NULL，預設 `windows`（既有的裝置全部是 Windows）。
- agent 在註冊（`EnrollRequest`）和每次報到（`CheckinRequest`）時帶上 `os_family`。欄位沒有出現就當成 `windows`，所以舊版 Windows agent 不用改，序列化結果也跟舊版一樣（`skip_serializing_if`，比照 `os_ubr` 的做法）。
- 報到時，如果回報值和資料庫不同就更新。（設計者決定：同一台硬體重灌成另一個系統時，資料不會停在舊值。）

## 3. 伺服器怎麼對待 Linux 裝置

原則：**Linux 裝置不是合規、派送、Windows Update 原則的對象**，在每個統計和畫面上都不能被算成「待處理」、「失敗」或「不合規」。

- **報到回應**：Linux 裝置的 `deployments`、`update_policy`、`registry_queries` 一律回空，hash 也照空值計算。`commands` 照常下發。`package_source` 回 `None`。
- **要求收集的區段**：只要求 Linux 有支援的區段（`basic`、`hardware`、`software`、`services`、`accounts`）。不要求 `patches`、`security`、`registry`。
- **合規**：Linux 裝置不參與評估，不會產生違規、違規歷程、每日快照的筆數。合規總覽的分母不含 Linux 裝置。裝置頁的合規區塊顯示「Linux 裝置不適用合規規則」。
- **派送**：派送的目標統計、自動暫停的失敗率分母、派送詳細頁的裝置清單，全部排除 Linux 裝置。
- **Windows Update 原則**：狀態統計和詳細頁全部排除 Linux 裝置。
- **群組**：Linux 裝置可以放進任何現有群組，群組權限照舊。

實作提示：派送和更新頁的 SQL 用同一個 `{TARGET}` 條件組合，加在那裡就能一次涵蓋。合規相關要看 `compliance/worker.rs`（挑選裝置）、`compliance/store.rs`（評估與總覽）、`compliance/preview.rs`。

## 4. 盤點

所有收集都是讀檔或執行唯讀指令，不修改系統。外部指令用完整路徑（`/usr/bin/…`），在 `PATH` 找不到時改試 `/bin`，都找不到就當作不支援。

### 4.1 識別與心跳（`Identity`、`Heartbeat`）

| 欄位 | 來源 |
|---|---|
| hostname | `uname` 的 nodename |
| smbios_uuid | `/sys/class/dmi/id/product_uuid`（需要 root）；讀不到就 None |
| bios_serial | `/sys/class/dmi/id/product_serial`；讀不到就 None |
| mac_addresses | `/sys/class/net/*/address`，排除 `lo` 和全 0 |
| boot_time | `/proc/stat` 的 `btime` |
| logged_on_user | `who` 第一個非 root 的互動使用者；沒有就 None（設計者決定） |
| ip_addresses | 跟 Windows 一樣是 IPv4/IPv6 位址清單，排除 loopback |

### 4.2 `basic`

- `os_caption`：`/etc/os-release` 的 `PRETTY_NAME`，沒有就用 `NAME` + `VERSION`。
- `os_build`：核心版本（`uname -r`）。
- `os_ubr`：None。
- `domain`、`is_domain_joined`：第一版固定 None／false。（設計者決定：判斷 SSSD/realmd 加入網域的方式各發行版不一樣，等有需要再做。）

### 4.3 `hardware`

- manufacturer／model：`/sys/class/dmi/id/sys_vendor`、`product_name`。
- cpu：`/proc/cpuinfo` 第一個 `model name`。
- ram_mb：`/proc/meminfo` 的 `MemTotal`。
- disks：`/proc/mounts` 裡的實體檔案系統（排除 tmpfs、proc、overlay、squashfs 等虛擬檔案系統，以及 snap 的掛載），用 `statvfs` 算容量和剩餘。`name` 用掛載點。

### 4.4 `software`

- 有 `dpkg-query` 就讀 dpkg；否則有 `rpm` 就讀 rpm。兩個都有時只讀 dpkg（設計者決定）。
- 兩個都沒有：回報空清單，並在 `section_errors` 寫「此發行版的套件系統不支援」，後台顯示這段文字，不當成錯誤。
- 欄位對應：

| SoftwareItem | dpkg | rpm |
|---|---|---|
| name | Package | NAME |
| version | Version | VERSION-RELEASE（有 EPOCH 時加 `EPOCH:` 前綴） |
| publisher | Maintainer | VENDOR |
| install_date | None | INSTALLTIME 轉成日期 |
| arch | Architecture | ARCH |

- `arch` 的對應：`amd64`、`x86_64` → `x64`；`i386`、`i686` → `x86`；其他（`all`、`noarch`、`aarch64` 等）→ 新增的 `Arch::Other`。伺服器要能存、能顯示 `other`。（設計者決定：不為每種 Linux 架構各開一個值。）
- 只列已安裝的套件（dpkg 的狀態是 `install ok installed`）。

### 4.5 `services`

- `systemctl list-units --type=service --all` 加上 `list-unit-files --type=service`，合併成每個服務一筆。
- ServiceItem 對應：name = unit 名稱；display_name = Description；start_mode = UnitFileState（enabled／disabled／static／masked…，原樣）；state = ActiveState/SubState，例如 `active/running`；binary_path = None。
- 沒有 systemd：回空清單，`section_errors` 寫「沒有 systemd，不收集服務」。

### 4.6 `accounts`（新區段，第一版只有 Linux 收集）

新的 `Section::Accounts` 和 `InventoryPayload::Accounts(AccountsInfo)`。伺服器新資料表，比照其他區段的寫法（hash 相同就不寫、diff 進 `inventory_changes`）。

```
AccountsInfo {
  users: Vec<LocalUser>,
  system_user_count: u32,
  privileged: Vec<PrivilegeEntry>,
  sudoers_unparsed: Vec<String>,
}
LocalUser { name, uid, shell, locked: Option<bool>, password_changed: Option<NaiveDate> }
PrivilegeEntry { principal, kind, source }
  kind: "user" | "group"
  source: "uid0" | "group:sudo" | "group:wheel" | "group:admin" | "sudoers:<檔名>"
```

**users**：
- 讀 `/etc/passwd`。shell 是 `nologin`、`false`、`sync`、`halt`、`shutdown` 的不列，只計入 `system_user_count`。
- 另外 UID 小於 `/etc/login.defs` 的 `UID_MIN`（預設 1000）而且不是 root 的帳號，就算 shell 可登入也只計數。（設計者決定：系統帳號太多會淹沒真人帳號。）
- `locked`、`password_changed`：讀 `/etc/shadow`。密碼欄位以 `!` 或 `*` 開頭就是鎖定；第三欄（自 1970-01-01 起的天數）轉成日期。讀不到 shadow 就是 None。
- **絕對不能**回報 shadow 的密碼欄位內容，連長度和雜湊演算法都不行。程式裡解析完只保留布林值和日期。

**privileged**（誰能取得 root）：
- `/etc/passwd` 裡 UID 0 的所有帳號（root 也列，非 root 的 UID 0 在後台用警示樣式顯示）。
- `/etc/group` 裡 `sudo`、`wheel`、`admin` 群組的成員，各列一筆 kind=user；群組本身不列。
- `/etc/sudoers` 和 `/etc/sudoers.d/*`（照 sudo 的規則，略過檔名有 `.` 或以 `~` 結尾的檔案）：
  - 會解析的寫法：`使用者 主機=…`、`%群組 主機=…`，主體是單一名稱或逗號分隔的名稱。
  - 不解析：`User_Alias` 等別名、`#include`／`@include` 以外的指令、`Defaults`、註解、空行。`#include`／`@include`／`#includedir`／`@includedir` 要跟著讀，最多三層。
  - 別名定義的行和看不懂的權限行，放進 `sudoers_unparsed`（原文，最多 50 行、每行最多 200 字），後台顯示「以下設定無法判讀，請人工檢查」。**不能默默略過。**
  - 讀不到 sudoers（權限不足或檔案不存在）：`sudoers_unparsed` 放一行說明原因。
- 同一個主體從多個來源取得權限時，每個來源各一筆。

**限制**（README 要寫清楚）：網域帳號（LDAP、SSSD）不在這些檔案裡，看不到；sudoers 裡用網域群組的話，群組名稱會列出來，但看不到成員。

### 4.7 收集頻率與資源

- 頻率沿用伺服器的 `collection_intervals`。`accounts` 使用 `security_secs` 的間隔（設計者決定：不新增設定）。
- 外部指令都要有逾時（60 秒），逾時就當作該區段錯誤，記到 `section_errors`。
- 除了 `basic`、`accounts` 之外都不用監看檔案變化。（Windows 的 regwatch 沒有 Linux 版。）

## 5. 遠端指令

| 動作 | Linux 行為 |
|---|---|
| `collect` | 跟 Windows 一樣，重新收集所有支援的區段 |
| `apply` | 不適用：Linux 裝置不建立 target（跟 §5.1 語言不符的處理相同），單台就拒絕（422）。指令詳細頁顯示略過的台數 |
| `reboot`／`shutdown` | `/sbin/shutdown -r｜-h +<分鐘> "<訊息>"`；延遲 0 就用 `now`。先回報結果再執行，跟 Windows 一樣 |
| `script` | 見下方 |

### 5.1 腳本語言

- `scripts` 資料表新增 `language`：`powershell`／`sh`，NOT NULL，預設 `powershell`。既有的腳本全部是 `powershell`，核准狀態不變。
- 建立後不能改語言。（設計者決定：改語言等於換一支腳本，請另外建立。）
- 執行時只對**作業系統相符**的裝置建立 `command_targets`：PowerShell 只派給 Windows，sh 只派給 Linux。
  - 對單台裝置下指令時語言不符：直接拒絕（422），訊息寫明原因。
  - 對群組下指令：只展開相符的裝置，指令詳細頁顯示「略過 N 台作業系統不相符的裝置」（略過數存在 `command_runs`）。展開後一台都沒有：拒絕建立（422）。
  - 現在沒有確認頁（表單直接建立再轉到詳細頁），這次**不新增確認頁**；建立表單上用一行說明文字預先告知會略過不相符的裝置。（設計者決定：事後顯示略過數已足夠，避免新增兩段式流程。）
- 協定 `ScriptSpec` 新增 `language`，缺少時當成 `powershell`（舊版 agent 相容）。Windows agent 收到 sh 腳本、Linux agent 收到 PowerShell 腳本時，都回報失敗，不執行。
- 核准、雙人核准、sha256 比對、逾時、輸出上限全部沿用。

### 5.2 Linux 怎麼執行 sh 腳本

- 腳本存成 root 才能讀的暫存檔，執行 `/bin/sh <檔案>`。第一行是 `#!` 的話，改成直接執行檔案（先 `chmod 0700`），讓 `#!/bin/bash` 這類寫法生效。
- 新的程序群組（`setsid`）；逾時就對整個群組送 SIGTERM，10 秒後 SIGKILL。對應 Windows 的 Job Object。
- 工作目錄是 agent 資料目錄底下的 `scripts/`；環境變數只保留 `PATH`（固定成 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`）、`LANG=C.UTF-8`、`HOME=/root`。（設計者決定：不繼承 systemd 的環境。）
- stdout、stderr 合併擷取，沿用現有的 64 KiB 上限和 NUL 過濾。
- 結束後刪除暫存檔。

## 6. agent 程式結構

- 現在的 `crates/agent/src/windows/` 是 Windows 專屬；新增平行的 `linux/`，實作同樣的介面：`Collector`、`CommandHost`、資料目錄、`configure`／`unconfigure`、主迴圈。
- 判斷邏輯（排程、狀態、指令去重、退避）維持共用，不複製。
- `main.rs` 的 `#[cfg(not(windows))]` 現在只印錯誤訊息，改成 `#[cfg(target_os = "linux")]` 的完整入口；其他平台（macOS 等）維持「不支援」。
- 派送和更新原則的背景工作在 Linux 上不啟動。
- 子命令跟 Windows 一樣：`run`（前景執行，systemd 用這個）、`configure`、`unconfigure`。Linux 不需要 `service` 子命令。
- 資料目錄 `/var/lib/endpoint-manager`，權限 0700、擁有者 root。金鑰、憑證檔 0600。沿用 Windows 版的成對寫入與崩潰復原做法。

## 7. 安裝與註冊

### 7.1 安裝包

| 檔案 | 內容 |
|---|---|
| `endpoint-agent_<版本>_amd64.deb` | `/usr/bin/endpoint-agent`、`/lib/systemd/system/endpoint-agent.service` |
| `endpoint-agent-<版本>-1.x86_64.rpm` | 同上（rpm 的 unit 路徑 `/usr/lib/systemd/system/`） |
| `endpoint-agent-<版本>-x86_64-linux.tar.gz` | 執行檔、unit 檔、README 摘錄（手動安裝和非 systemd 系統用） |

- 安裝後：`systemctl daemon-reload`、`enable`，**還沒 configure 就不啟動**（unit 用 `ConditionPathExists=` 指向 `configure` 寫出的 `config.json`；實際向伺服器註冊是在 `run` 裡進行，所以不能用 `state.json`）。
- 升級：重新啟動服務，保留資料目錄。
- 移除（`apt remove`／`rpm -e`，不是升級時）：停止服務，執行 `endpoint-agent unconfigure`。Windows 版的 `unconfigure` 會刪掉整個資料目錄，Linux 版也一樣（金鑰、憑證、狀態都在裡面，留著沒有意義）；`apt purge` 不需要額外動作。（設計者決定。）
- unit 檔：`Restart=always`、`RestartSec=10`，加上合理的限制（`NoNewPrivileges` 不能開，因為腳本要以 root 執行任意指令；其餘 hardening 選項由實作者判斷，前提是不影響盤點和腳本）。
- 打包工具由實作者選（例如 `cargo-deb`、`cargo-generate-rpm`），但必須通過 `deny.toml` 的授權檢查。

### 7.2 註冊指令

- `endpoint-agent configure --server-url URL --token TOKEN --root-ca BASE64` 跟 Windows 參數一樣。成功後啟動服務（`systemctl start`）。
- **安裝包由伺服器提供，跟 MSI 範本一樣**（使用者決定）：
  - 新設定 `EM_AGENT_DEB`、`EM_AGENT_RPM`，各指向伺服器本機的一個檔案，管理者從 Release 下載後放上去，跟 `EM_AGENT_MSI` 相同。沒設定時，後台對應的下載按鈕不顯示，並說明要設定哪個變數。
  - 後台新增兩個下載路由（需登入、跟 MSI 下載同樣的權限），直接回傳檔案，不做任何修改（金鑰不寫進套件，靠下面的註冊指令）。
  - 伺服器啟動時檢查檔案存在、可讀；讀不到跟 MSI 範本一樣回 503 並記錄。不需要解析套件內容。
  - 管理者在自己的電腦下載，再用 `scp` 複製到 Linux 機器，所以機房的機器不需要對外網路，也不需要信任私有根憑證去下載。
- 後台建立裝置金鑰的頁面：除了現有的「下載 Windows 安裝檔」，金鑰顯示頁多一個「Linux 安裝」區塊，列出：
  1. deb 和 rpm 的下載按鈕（上面的路由）。
  2. 安裝指令（`sudo apt install ./…deb` 或 `sudo dnf install ./…rpm`）。
  3. 完整的 `sudo endpoint-agent configure …` 指令，金鑰和根憑證都已經填好，有複製按鈕。
- 金鑰還是只顯示這一次，跟現在一樣。
- 這行指令含金鑰，會留在 shell history。後台的說明要提醒：註冊後作廢金鑰，或在指令前加空白（bash 的 `HISTCONTROL=ignorespace`）。

## 8. 後台畫面

- 裝置列表：新增「作業系統」篩選（全部／Windows／Linux），作業系統欄位旁加一個小圖示或標籤。
- 裝置頁（Linux）：
  - 只顯示有資料的分頁：概要、硬體、軟體、服務、帳號與權限、指令。
  - 修補、安全設定、登錄檔、派送、Windows Update 分頁不顯示。
  - 「帳號與權限」分頁：上面是管理權限名單（主體、類型、來源；非 root 的 UID 0 用警示樣式），中間是可登入的帳號（名稱、UID、shell、鎖定、密碼最後修改），最後是 `sudoers_unparsed`（有內容才顯示）和系統帳號數量。
- 腳本頁：新增語言欄位和篩選；建立表單要選語言，預設 PowerShell。
- 指令詳細頁：顯示略過的作業系統不符裝置數（§5.1）。
- 軟體頁（跨裝置彙總的 `web/software.rs` 和相關搜尋、計數）：新增「作業系統」篩選，**預設 Windows**，可切換 Linux 或全部。（設計者決定：Linux 的套件數量很大，預設混在一起會改變 Windows 管理者現有的畫面，違反 §1.1。）
- 樣式沿用 UI 第一階段的設計系統，不新增 CSS 框架或 JS 套件。

## 9. 測試與 CI

- 單元測試：`/etc/os-release`、`/proc/*`、`passwd`、`group`、`shadow`、`sudoers`（包含別名、include、看不懂的行）、dpkg/rpm 輸出的解析，用固定的測試資料，不依賴執行環境。
- shadow 解析的測試要確認：輸出裡找不到原本的密碼欄位字串。
- 伺服器測試：Linux 裝置不出現在合規、派送、更新的統計裡；Windows 裝置的結果不變；腳本語言相符的展開與拒絕。
- agent e2e：現有的 `crates/agent/tests/e2e.rs` 在 Linux runner 上跑得起來的部分照跑，加上 Linux 收集器和 sh 腳本的流程。
- CI：
  - 新增 Linux 工作，建置 `x86_64-unknown-linux-musl` 的 agent，產出 deb、rpm、tar.gz，上傳成 artifact。
  - 打包後在 CI 裡實際用 `dpkg -i`（ubuntu runner）安裝一次，確認檔案位置和 `unconfigure` 的移除流程。rpm 可以在容器裡驗。
  - Release 加上這三個檔案和各自的 `.sha256`。
- 真機驗證（§1.2）由實作者用 WSL 或 VM 完成，結果記在 PR。

## 10. 留給實作者的事

- 各模組怎麼切、函式怎麼命名。
- 新資料表的欄位細節和 migration 編號，前提是符合 §2–§5 的行為。
- deb／rpm 打包工具的選擇（需通過授權檢查）。
- systemd unit 的 hardening 細節（§7.1 的限制內）。
- e2e 測試裡哪些在 Linux 上跳過，要在 PR 說明原因。
- README：新增「Linux Agent」一節（安裝、註冊、移除、限制、非 systemd 的手動啟動方式）。
