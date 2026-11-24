# 擴增錯誤設定偵測

日期：2026-11-24
來源：`docs/roadmap.md` 第 4 項。

## 1. 目標與原則

現有的「組態基準範本」用登錄檔與安全設定檢查一部分 Windows 設定，例如 SMBv1、SMB 簽章、LLMNR、NLA、WDigest、UAC。這份規格補上**目前看不到**的錯誤設定：共用資料夾、對外開放的服務、遠端登入、可被提權的權限、帳號。

原則：

- **只回報判斷結果，不上傳內容**。例如只回報「這個共用所有人可寫入」，不上傳檔案清單；帳號只回報「沒有密碼」，不讀密碼雜湊。
- **每一類都是合規規則**：沿用現有的違規、豁免、歷程、通知、報告、CSV。不另做一套頁面。
- **每條規則都能設例外**，並在說明裡寫出常見的正常情況，例如印表機共用、IT 刻意開放的軟體散布共用。
- **先做風險高、收集便宜的**。

## 2. 規則的平台

目前只有容器規則評估 Linux 裝置（`Check::linux_only`），其他規則只評估 Windows。這份規格的規則有的只適用一邊、有的兩邊都適用，所以改成每種規則宣告適用平台：

| 平台 | 規則 |
|---|---|
| Windows | 現有的 Windows 規則、服務路徑沒加引號、防火牆全開規則、遠端桌面使用者、Windows 帳號旗標 |
| Linux | 容器規則、多餘的 UID 0 帳號、sshd 設定 |
| 兩邊 | 開放的共用、對外開放的服務、權限過寬、帳號（各平台判斷的項目不同） |

規則編輯頁顯示「適用於：Windows／Linux／兩者」。不適用的裝置不評估，也不算「未知」。

## 3. 第一期：現有資料就能判斷（只改伺服器）

不需要升級 Agent。

### 3.1 服務路徑沒加引號（`unquoted_service_path`，Windows，高）

- **資料**：服務區段已有 `binary_path`。
- **條件**：
  - 路徑沒有用引號包起來。
  - 執行檔路徑（到第一個 `.exe` 為止）含有空白。
  - 不在 `%SystemRoot%`、`C:\Windows` 底下（系統服務由 Windows 管理，一般使用者無法在那裡建立檔案）。
- **意義**：例如 `C:\Program Files\My App\svc.exe`，有權限在 `C:\` 建立 `Program.exe` 的人可以讓服務以 SYSTEM 身分執行它。
- **例外**：服務名稱萬用字元清單。
- **細節**：服務名稱與路徑。

### 3.2 多餘的 UID 0 帳號（`extra_root_account`，Linux，高）

- **資料**：帳號區段的特權清單裡，`source` 是 `uid0` 的項目。
- **條件**：除了 `root` 之外還有 UID 0 的帳號。
- **例外**：帳號名稱清單（例如某些設備廠商的維護帳號）。

### 3.3 組態基準範本新增項目

都是現有的「登錄檔值」規則，加進 `baseline.json`：

| 名稱 | 機碼與值 | 條件 | 嚴重度 |
|---|---|---|---|
| 停用「一律以提高的權限安裝」 | `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` `AlwaysInstallElevated` | 不等於 1（沒設定視為符合） | 高 |
| WinRM 不允許 Basic 驗證 | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service` `AllowBasic` | 不等於 1 | 高 |
| WinRM 不允許未加密的流量 | 同上，`AllowUnencryptedTraffic` | 不等於 1 | 高 |
| 不使用自動登入 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` `AutoAdminLogon` | 不等於 1 | 中 |
| 限制匿名存取具名管道與共用 | `HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters` `RestrictNullSessAccess` | 等於 1（沒設定視為符合，Windows 預設是 1） | 中 |

- **自動登入只判斷「有沒有開」，不讀密碼**：`DefaultPassword` 在 Agent 的拒絕清單裡，不會被讀取。「有沒有存密碼」需要 Agent 只回報存在與否，放在第四期。
- **範本更新**：已經套用過範本的伺服器，範本頁會列出新的項目，管理員自行決定是否加入。

## 4. 第二期：開放的共用（`shares` 區段）

新區段 `shares`，Windows 與 Linux 都有。需要伺服器在 `supported_sections` 宣告才收集。間隔沿用「安全設定」（預設每小時）。

### 4.1 收集

每個共用回報：

| 欄位 | 說明 |
|---|---|
| `name` | 共用名稱 |
| `path` | 本機路徑 |
| `kind` | `smb`（Windows）、`samba`、`nfs` |
| `anonymous` | 不登入就能做什麼：`none`、`read`、`write` |
| `all_users` | 網域或本機所有使用者能做什麼：`none`、`read`、`write` |
| `no_root_squash` | 只有 NFS：遠端的 root 在這裡也是 root |
| `clients` | 只有 NFS：允許的來源，例如 `*`、`10.0.0.0/8` |

**權限在 Agent 端判斷，只上傳結論**，不上傳 ACL。

- **Windows**：
  - `NetShareEnum`（層級 502）取得共用與共用權限。略過管理用共用（`C$`、`ADMIN$`、`IPC$` 這類特殊共用）與印表機共用。
  - 實際權限 = 共用權限與 NTFS 權限的交集：讀共用資料夾本身的 NTFS ACL。
  - 「所有使用者」：Everyone、Authenticated Users、Users、Domain Users。
  - 「匿名」：Anonymous Logon；Guests 與 Everyone 在 Guest 帳號啟用時也算（`EveryoneIncludesAnonymous` 為 1 時 Everyone 也算）。
  - 寫入：有寫入資料或新增檔案的權限；讀取：有讀取資料的權限。
- **Linux Samba**：讀 `testparm -s` 的實際設定。
  - `guest ok`（或 `public`）= yes：匿名可讀；再加上可寫入（`writable`、`write ok` = yes，或 `read only` = no）：匿名可寫。
  - 沒有 `valid users`：所有使用者，讀寫同上。
  - 略過 `printable = yes` 的印表機共用與 `[global]`。
  - 沒有安裝 Samba 時不回報。
- **Linux NFS**：讀 `/etc/exports` 與 `/etc/exports.d/*.exports`。
  - 來源是 `*` 或沒有限制：匿名（NFS 預設不驗證使用者身分）；`rw`：可寫入。
  - 來源是網段或主機：`all_users`，`clients` 列出來源。
  - `no_root_squash` 單獨回報。

### 4.2 規則：開放的共用（`open_share`，兩邊）

- **參數**：
  - 對象：匿名、所有使用者（可複選）。
  - 權限：寫入，或讀取以上。
  - NFS 的 `no_root_squash` 也算違規（勾選）。
  - 例外：共用名稱萬用字元清單。
- **範本**：
  - 「匿名或所有使用者可寫入的共用」（高）。
  - 「匿名可讀取的共用」（中）。
- **常見的正常情況**（寫在規則說明）：IT 的軟體散布共用（通常只能讀）、部門共用資料夾（所有人可寫入是刻意的）。用例外設定排除。

### 4.3 後台

裝置頁新增「共用」卡片：列出共用名稱、路徑、匿名與所有使用者的權限。在「安全」分頁裡，不另開分頁。

## 5. 第三期：對外開放的服務與遠端登入（`exposure` 區段）

新區段 `exposure`，兩邊都有，間隔沿用「安全設定」。

### 5.1 收集

- **監聽中的連接埠**：只回報不是只監聽在本機（127.0.0.0/8、::1）的。
  - 每筆：通訊協定（TCP／UDP）、位址、連接埠、程式名稱（不含參數）。
  - Windows：`GetExtendedTcpTable`、`GetExtendedUdpTable`（含擁有的 PID）。
  - Linux：`/proc/net/tcp`、`tcp6`、`udp`、`udp6`，以 socket inode 對到 `/proc/<pid>/fd` 找程式。
  - 最多 500 筆。
- **Windows 防火牆全開規則**：讀登錄檔裡的防火牆規則（本機與群組原則兩處）。找出「允許、輸入、啟用、任何遠端位址、任何本機連接埠、沒有限定程式或服務」的規則，只回報規則名稱。
- **Linux sshd**：`sshd -T` 的 `permitrootlogin`、`passwordauthentication`、`permitemptypasswords`、`port`。沒有安裝 sshd 時不回報。
- **Windows 遠端桌面**：是否開啟（`fDenyTSConnections`），以及 Remote Desktop Users 群組的成員。

### 5.2 規則

- **對外開放的服務**（`exposed_service`，兩邊）：
  - 預設清單：Telnet（23）、FTP（21）、VNC（5900–5903）、Redis（6379）、MongoDB（27017）、Elasticsearch（9200）、MySQL（3306）、PostgreSQL（5432）、Memcached（11211）。可以勾選，也可以加自訂的連接埠。
  - 選項「只算監聽在所有介面（`0.0.0.0`、`::`）的」：資料庫只綁定內部網卡時可以不算。
  - 例外：程式名稱萬用字元清單。
  - 嚴重度預設高。
- **防火牆全開規則**（`firewall_allow_all`，Windows，高）：例外是規則名稱萬用字元清單。
- **sshd 設定**（`ssh_config`，Linux）：
  - 勾選：不允許 root 以密碼登入（`prohibit-password` 視為符合）、不允許 root 登入、不允許密碼登入、不允許空密碼。
  - 範本：「不允許空密碼」與「root 不能用密碼登入」（高）。
- **遠端桌面使用者**（`rdp_users`，Windows）：Remote Desktop Users 群組只允許清單內的成員（萬用字元），跟現有的「本機管理員」規則相同的寫法。遠端桌面沒開時視為符合。

### 5.3 後台

- 裝置頁「安全」分頁新增「監聽中的連接埠」表格。
- 新增 `/exposure` 頁：依「連接埠＋程式」彙整全部裝置，看得到哪些電腦開了什麼，點進去是裝置清單。跟 `/containers` 的映像頁相同的作法。

## 6. 第四期：權限過寬與帳號

### 6.1 權限過寬（`permissions` 區段）

檢查比較慢，間隔沿用「硬體」（預設每天）。

- **Windows**：
  - 服務執行檔與所在資料夾，一般使用者可寫入（Everyone、Authenticated Users、Users、Interactive 有寫入、修改或完全控制）。
  - 以 SYSTEM 執行的排程工作，執行的程式一般使用者可寫入：讀 `C:\Windows\System32\Tasks` 底下的工作定義（XML）。
- **Linux**：
  - `/etc` 底下所有人可寫入的一般檔案（不跟隨符號連結，不跨檔案系統）。
  - `/etc/shadow`、`/etc/gshadow` 一般使用者可讀。
  - 非預期的 SUID／SGID 程式：系統執行檔目錄（`/usr/bin`、`/usr/sbin`、`/bin`、`/sbin`、`/usr/local/bin`、`/usr/local/sbin`）裡，不屬於任何套件的（批次以 `dpkg -S` 或 `rpm -qf` 比對）。
- **回報**：每筆是種類、路徑、名稱（服務或排程工作）、給了誰。最多 200 筆。
- **規則**：權限過寬（`weak_permissions`，兩邊，高），例外是路徑萬用字元清單。

### 6.2 帳號

- **Windows 本機帳號**：帳號區段改成 Windows 也回報。
  - 每個本機帳號：名稱、是否停用、密碼永不過期、不需要密碼（`UF_PASSWD_NOTREQD`）、最後登入時間。
  - 另外回報「自動登入有沒有存密碼」：只回報是否存在，不讀內容。
- **Linux 補兩個欄位**：
  - 帳號：密碼欄位是空的（只回報是或否，不上傳雜湊）。
  - sudo 規則：免密碼而且可以執行任何指令（`NOPASSWD: ALL`）。
- **規則**：帳號設定（`account_flags`，兩邊），勾選：
  - 不允許沒有密碼的帳號（Windows 不需要密碼、Linux 空密碼）（高）。
  - Guest 帳號必須停用（Windows）（中）。
  - 不允許密碼永不過期（Windows，可設例外帳號）（低）。
  - 不允許 sudo 免密碼執行任何指令（Linux，可設例外帳號或群組）（中）。
  - 自動登入不能存密碼（Windows）（高）。

## 7. 相容性

- 新區段都要伺服器在 `supported_sections` 宣告才收集，舊版伺服器不受影響。
- 舊版 Agent 沒有新區段：依賴新區段的規則在這些裝置上是「未知」，裝置頁提示「Agent 版本太舊，無法檢查」。
- 帳號區段新增的欄位用 `serde(default)`，舊版 Agent 送來的資料照常接收。

## 8. 分期

1. **只改伺服器**：規則適用平台、服務路徑沒加引號、多餘的 UID 0 帳號、範本新增五個登錄檔項目。
2. **共用**：`shares` 區段、開放的共用規則、裝置頁卡片。
3. **對外服務與遠端登入**：`exposure` 區段、四種規則、`/exposure` 頁。
4. **權限過寬與帳號**：`permissions` 區段、Windows 帳號、Linux 帳號補欄位、兩種規則。

每期各自一個 PR，各期都能單獨上線。

## 9. 測試

- **伺服器**：
  - 每種規則的判斷：純函式，含例外、適用平台、資料不足時的「未知」。
  - 整合測試：上傳區段資料後產生違規、豁免後消失、規則編輯頁顯示適用平台。
- **Agent**：
  - 解析是純函式，各平台都能測：`testparm -s`、`/etc/exports`、`/proc/net/tcp`、`sshd -T`、防火牆規則字串、排程工作 XML、`dpkg -S` 輸出。
  - Windows 權限判斷：以測試建立的資料夾與 ACL 驗證「所有人可寫入」的判斷（在 Windows CI 上跑）。
  - Windows 監聽連接埠：測試自己開一個監聽，確認讀得到。

## 10. 偵測不到的情況（README 要寫）

- 只看本機設定，不測試實際能不能連進來（不做主動掃描，見 roadmap 的延後項目）。
- 共用權限只判斷幾個「大群組」，不判斷個別帳號（例如某個離職員工的帳號仍有權限）。
- Windows 的第三方 SMB／NFS 伺服器、Linux 上 Samba 與 NFS 以外的共用（例如 WebDAV）不檢查。

## 11. 實作與規格的差異

- **第一期**：
  - 範本除了五個登錄檔項目，也加入「服務路徑要加引號」與「Linux：只有 root 是 UID 0」兩條，共 29 條。
  - 帳號區段上傳後也會重新評估合規（原本只有容器等區段會）。
  - 適用平台依規則種類決定；參數壞掉的規則跟以前一樣只對 Windows 顯示「未知」。
- **第二期**：
  - **權限用 SDDL 判斷**：Windows 把共用與資料夾的安全描述元轉成 SDDL 字串，判斷是純函式，各平台都能測試。
  - **「所有使用者」多了 Network（S-1-5-2）**：從網路連進來的使用者都有這個身分。
  - **能改權限或擁有者（WRITE_DAC、WRITE_OWNER）也算可寫入**：可以自己加上寫入權限。
  - **共用沒有安全描述元**時等於所有人完全控制；讀不到資料夾權限時只看共用權限，並記在 `errors`。
  - **Samba 不檢查 `[homes]`**（只有帳號本人能用）與 `print$`；`[global]` 的設定當成各共用的預設值。
  - **Linux 的共用卡片放在「帳號與權限」分頁**：Linux 裝置沒有「安全設定」分頁。
  - **讀取失敗**：沒有找到違規、但有來源讀取失敗（例如 `testparm` 失敗）時是「未知」。
  - 範本加兩條：「沒有匿名或所有使用者可寫入的共用」（高，含 no_root_squash）、「沒有匿名可讀取的共用」（中），共 31 條。
- **第三期**：
  - **規則參數**：對外開放的服務以內建服務代號（`telnet`、`mysql`……）加自訂連接埠設定，連接埠不分 TCP、UDP。
  - **讀取失敗**：各規則只看和自己有關的錯誤（連接埠、防火牆、sshd、遠端桌面）。沒有違規但相關資料讀不到時是「未知」。
  - **防火牆全開規則**也排除限定 UWP 應用程式（`PFN`、`AppPkgId`）或驗證使用者（`LUAuth`）的規則。
  - **遠端桌面使用者**與「本機管理員」共用比對方式（`*-500` 這類 SID 樣式）。
  - **對外服務頁**放在側欄「資產」底下（`/exposure`），可篩選連接埠或程式、只看高風險服務；明細以「連接埠＋協定＋程式」為單位列出裝置與監聽位址。
  - 範本加三條：「沒有對外開放的高風險服務」、「沒有全開的防火牆規則」、「Linux：sshd 不允許空密碼、root 不能用密碼登入」，共 34 條。
