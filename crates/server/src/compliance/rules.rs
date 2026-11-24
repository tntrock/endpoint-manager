//! 規則：參數解析與驗證、編譯後的比對條件、套用範圍。

use serde::Deserialize;
use serde_json::{Value, json};

use super::matcher::Glob;

pub const MAX_PATTERN_LEN: usize = 256;

pub const KINDS: [&str; 28] = [
    "forbidden_software",
    "required_software",
    "software_allowlist",
    "os_build",
    "required_kb",
    "registry_value",
    "service_state",
    "firewall",
    "bitlocker",
    "defender",
    "password_policy",
    "local_admins",
    "patch_age",
    "reboot_pending",
    "update_policy",
    "dual_homed",
    "forbidden_image",
    "container_privilege",
    "unpinned_image",
    "unquoted_service_path",
    "extra_root_account",
    "open_share",
    "exposed_service",
    "firewall_allow_all",
    "ssh_config",
    "rdp_users",
    "account_flags",
    "weak_permissions",
];

/// 對外開放的服務：內建的服務與連接埠（錯誤設定規格 §5.2）
pub const SERVICE_PRESETS: [(&str, &str, &[u16]); 9] = [
    ("telnet", "Telnet", &[23]),
    ("ftp", "FTP", &[21]),
    ("vnc", "VNC", &[5900, 5901, 5902, 5903]),
    ("redis", "Redis", &[6379]),
    ("mongodb", "MongoDB", &[27017]),
    ("elasticsearch", "Elasticsearch", &[9200]),
    ("mysql", "MySQL", &[3306]),
    ("postgresql", "PostgreSQL", &[5432]),
    ("memcached", "Memcached", &[11211]),
];

/// 自訂連接埠最多幾個
pub const MAX_CUSTOM_PORTS: usize = 50;

/// 多重連線規則：回溯天數上限
pub const MAX_LOOKBACK_DAYS: u32 = 90;
/// 多重連線規則：最短持續時間上限（秒）
pub const MAX_MIN_DURATION_SECS: u32 = 86_400;
/// 多重連線規則：例外清單各自的上限
pub const MAX_EXCEPTIONS: usize = 50;

pub fn kind_label(kind: &str) -> &'static str {
    match kind {
        "forbidden_software" => "禁止軟體",
        "required_software" => "必要軟體",
        "software_allowlist" => "軟體白名單",
        "os_build" => "最低組建號",
        "required_kb" => "必要 KB",
        "registry_value" => "登錄檔值",
        "service_state" => "服務",
        "firewall" => "防火牆",
        "bitlocker" => "BitLocker",
        "defender" => "Defender",
        "password_policy" => "密碼原則",
        "local_admins" => "本機管理員",
        "patch_age" => "太久沒更新",
        "reboot_pending" => "待重開機太久",
        "update_policy" => "更新原則衝突",
        "dual_homed" => "多重連線",
        "forbidden_image" => "禁止映像",
        "container_privilege" => "容器權限",
        "unpinned_image" => "映像未固定版本",
        "unquoted_service_path" => "服務路徑沒加引號",
        "extra_root_account" => "多餘的 UID 0 帳號",
        "open_share" => "開放的共用",
        "exposed_service" => "對外開放的服務",
        "firewall_allow_all" => "防火牆全開規則",
        "ssh_config" => "sshd 設定",
        "rdp_users" => "遠端桌面使用者",
        "account_flags" => "帳號設定",
        "weak_permissions" => "權限過寬",
        _ => "未知類型",
    }
}

/// 規則適用的作業系統（錯誤設定規格 §2）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    Both,
}

impl Platform {
    pub fn covers(self, linux: bool) -> bool {
        match self {
            Platform::Windows => !linux,
            Platform::Linux => linux,
            Platform::Both => true,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Platform::Windows => "Windows",
            Platform::Linux => "Linux",
            Platform::Both => "Windows、Linux",
        }
    }
}

/// 依規則種類決定適用的作業系統；不認得的種類跟舊版一樣只對 Windows
pub fn kind_platform(kind: &str) -> Platform {
    match kind {
        "forbidden_image" | "container_privilege" | "unpinned_image" | "extra_root_account" => {
            Platform::Linux
        }
        "open_share" | "exposed_service" | "account_flags" | "weak_permissions" => Platform::Both,
        "ssh_config" => Platform::Linux,
        _ => Platform::Windows,
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
    Forbidden {
        name: String,
        publisher: Option<String>,
        below_version: Option<String>,
    },
    Required {
        name: String,
        publisher: Option<String>,
        min_version: Option<String>,
    },
    Allowlist {
        entries: Vec<AllowEntry>,
    },
    MinBuild {
        min_build: u32,
    },
    PatchLevel {
        build: u32,
        min_ubr: u32,
    },
    RequiredKb {
        kb: String,
    },
    RegistryValue {
        /// 已正規化（`HKLM\...`）
        path: String,
        name: String,
        op: RegOp,
        expected: Option<String>,
        absent_ok: bool,
    },
    ServiceState {
        name: String,
        require_running: bool,
    },
    Firewall {
        domain: bool,
        private: bool,
        public: bool,
    },
    Bitlocker {
        all_fixed: bool,
    },
    Defender {
        realtime: bool,
        max_signature_age_days: Option<u32>,
        tamper: bool,
    },
    PasswordPolicy {
        min_length: Option<u32>,
        max_age_days: Option<u32>,
        max_lockout_threshold: Option<u32>,
    },
    LocalAdmins {
        allowed: Vec<String>,
    },
    PatchAge {
        max_days: u32,
    },
    RebootPending {
        max_days: u32,
    },
    UpdatePolicy,
    DualHomed(DualHomedParams),
    ForbiddenImage {
        /// 映像（萬用字元）
        image: String,
        running_only: bool,
    },
    ContainerPrivilege {
        privileged: bool,
        host_network: bool,
        /// 掛載容器執行環境的 socket（docker.sock 等）
        runtime_socket: bool,
        /// 例外映像（萬用字元）
        except_images: Vec<String>,
    },
    UnpinnedImage {
        except_images: Vec<String>,
    },
    UnquotedServicePath {
        /// 例外服務名稱（萬用字元）
        except_services: Vec<String>,
    },
    ExtraRootAccount {
        /// 例外帳號（萬用字元）
        except_accounts: Vec<String>,
    },
    OpenShare(OpenShareParams),
    ExposedService {
        /// 內建服務的代號（[`SERVICE_PRESETS`]）
        services: Vec<String>,
        /// 自訂連接埠
        ports: Vec<u16>,
        /// 只算監聽在所有介面的
        any_interface_only: bool,
        /// 例外程式（萬用字元）
        except_processes: Vec<String>,
    },
    FirewallAllowAll {
        /// 例外規則名稱（萬用字元）
        except_rules: Vec<String>,
    },
    SshConfig(SshParams),
    RdpUsers {
        allowed: Vec<String>,
    },
    AccountFlags {
        checks: AccountChecks,
        /// 例外帳號（萬用字元；群組寫 `%群組`）
        except_accounts: Vec<String>,
    },
    WeakPermissions {
        /// 例外路徑或名稱（萬用字元）
        except_paths: Vec<String>,
    },
}

/// 帳號設定規則：勾選的項目（錯誤設定規格 §6.2）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AccountChecks {
    /// 不允許沒有密碼的帳號（Windows 不需要密碼、Linux 空密碼）
    pub no_password: bool,
    /// Guest 帳號必須停用（Windows）
    pub guest_disabled: bool,
    /// 不允許密碼永不過期（Windows）
    pub password_expires: bool,
    /// 不允許 sudo 免密碼執行任何指令（Linux）
    pub sudo_nopasswd: bool,
    /// 自動登入不能存密碼（Windows）
    pub no_autologon_password: bool,
}

impl AccountChecks {
    /// (參數名稱, 是否勾選)
    pub fn fields(&self) -> [(&'static str, bool); 5] {
        [
            ("no_password", self.no_password),
            ("guest_disabled", self.guest_disabled),
            ("password_expires", self.password_expires),
            ("sudo_nopasswd", self.sudo_nopasswd),
            ("no_autologon_password", self.no_autologon_password),
        ]
    }
}

/// sshd 設定規則：勾選的項目（錯誤設定規格 §5.2）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SshParams {
    /// root 不能以密碼登入（`prohibit-password` 視為符合）
    pub no_root_password: bool,
    /// root 完全不能登入
    pub no_root_login: bool,
    /// 不允許密碼登入
    pub no_password: bool,
    /// 不允許空密碼
    pub no_empty_passwords: bool,
}

/// 開放的共用（錯誤設定規格 §4.2）
#[derive(Debug, Clone, PartialEq)]
pub struct OpenShareParams {
    /// 匿名（不登入）
    pub anonymous: bool,
    /// 所有使用者
    pub all_users: bool,
    /// 只算可寫入（false：可讀取以上）
    pub write_only: bool,
    /// NFS 的 no_root_squash 也算
    pub no_root_squash: bool,
    /// 例外共用名稱或路徑（萬用字元）
    pub except_shares: Vec<String>,
}

/// 多重連線規則的參數（網路規格 §5.3）
#[derive(Debug, Clone, PartialEq)]
pub struct DualHomedParams {
    /// 這段期間內出現過一次就算違規
    pub lookback_days: u32,
    /// 短於這個值的期間不計
    pub min_duration_secs: u32,
    /// 網卡名稱（萬用字元）
    pub exclude_interfaces: Vec<String>,
    /// 已正規化的網段
    pub exclude_cidrs: Vec<String>,
    /// 只抓「公司網路＋外部網路」（條件 2）
    pub only_cross_site: bool,
}

/// 登錄檔值的比對方式
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegOp {
    Equals,
    NotEquals,
    Gte,
    Lte,
    Contains,
    Exists,
    NotExists,
}

impl RegOp {
    pub const ALL: [RegOp; 7] = [
        RegOp::Equals,
        RegOp::NotEquals,
        RegOp::Gte,
        RegOp::Lte,
        RegOp::Contains,
        RegOp::Exists,
        RegOp::NotExists,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RegOp::Equals => "equals",
            RegOp::NotEquals => "not_equals",
            RegOp::Gte => "gte",
            RegOp::Lte => "lte",
            RegOp::Contains => "contains",
            RegOp::Exists => "exists",
            RegOp::NotExists => "not_exists",
        }
    }

    pub fn parse(s: &str) -> Option<RegOp> {
        RegOp::ALL.into_iter().find(|o| o.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            RegOp::Equals => "等於",
            RegOp::NotEquals => "不等於",
            RegOp::Gte => "大於等於",
            RegOp::Lte => "小於等於",
            RegOp::Contains => "包含",
            RegOp::Exists => "存在",
            RegOp::NotExists => "不存在",
        }
    }

    /// 需要期望值的比對方式
    pub fn needs_expected(self) -> bool {
        !matches!(self, RegOp::Exists | RegOp::NotExists)
    }
}

/// 十進位或 `0x` 十六進位的非負整數
pub fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// 登錄檔值的比對鍵：路徑與名稱都不分大小寫。查詢清單、上傳過濾、評估三處共用。
pub fn registry_key(path: &str, name: &str) -> (String, String) {
    (path.to_uppercase(), name.to_uppercase())
}

/// 編譯後的比對條件（萬用字元已預先處理）。
#[derive(Debug, Clone, PartialEq)]
pub enum Check {
    Forbidden {
        name: Glob,
        publisher: Option<Glob>,
        below: Option<String>,
    },
    Required {
        name: Glob,
        publisher: Option<Glob>,
        min: Option<String>,
    },
    Allowlist {
        entries: Vec<(Option<Glob>, Option<Glob>)>,
    },
    MinBuild {
        min_build: u32,
    },
    PatchLevel {
        build: u32,
        min_ubr: u32,
    },
    RequiredKb {
        kb: String,
    },
    RegistryValue {
        path: String,
        name: String,
        /// `registry_key(path, name)`
        key: (String, String),
        op: RegOp,
        expected: Option<String>,
        absent_ok: bool,
    },
    ServiceState {
        name: String,
        require_running: bool,
    },
    Firewall {
        domain: bool,
        private: bool,
        public: bool,
    },
    Bitlocker {
        all_fixed: bool,
    },
    Defender {
        realtime: bool,
        max_signature_age_days: Option<u32>,
        tamper: bool,
    },
    PasswordPolicy {
        min_length: Option<u32>,
        max_age_days: Option<u32>,
        max_lockout_threshold: Option<u32>,
    },
    LocalAdmins {
        allowed: Vec<Glob>,
    },
    PatchAge {
        max_days: u32,
    },
    RebootPending {
        max_days: u32,
    },
    UpdatePolicy,
    DualHomed {
        lookback_days: u32,
        min_duration_secs: u32,
        exclude_interfaces: Vec<Glob>,
        exclude_cidrs: Vec<(std::net::IpAddr, u8)>,
        only_cross_site: bool,
    },
    ForbiddenImage {
        image: Glob,
        running_only: bool,
    },
    ContainerPrivilege {
        privileged: bool,
        host_network: bool,
        runtime_socket: bool,
        except_images: Vec<Glob>,
    },
    UnpinnedImage {
        except_images: Vec<Glob>,
    },
    UnquotedServicePath {
        except_services: Vec<Glob>,
    },
    ExtraRootAccount {
        except_accounts: Vec<Glob>,
    },
    OpenShare {
        anonymous: bool,
        all_users: bool,
        write_only: bool,
        no_root_squash: bool,
        except_shares: Vec<Glob>,
    },
    ExposedService {
        /// (連接埠, 顯示名稱)
        ports: Vec<(u16, String)>,
        any_interface_only: bool,
        except_processes: Vec<Glob>,
    },
    FirewallAllowAll {
        except_rules: Vec<Glob>,
    },
    SshConfig(SshParams),
    RdpUsers {
        allowed: Vec<Glob>,
    },
    AccountFlags {
        checks: AccountChecks,
        except_accounts: Vec<Glob>,
    },
    WeakPermissions {
        except_paths: Vec<Glob>,
    },
}

impl Check {
    /// 規則適用的作業系統
    pub fn platform(&self) -> Platform {
        match self {
            Check::ForbiddenImage { .. }
            | Check::ContainerPrivilege { .. }
            | Check::UnpinnedImage { .. }
            | Check::ExtraRootAccount { .. } => Platform::Linux,
            Check::OpenShare { .. }
            | Check::ExposedService { .. }
            | Check::AccountFlags { .. }
            | Check::WeakPermissions { .. } => Platform::Both,
            Check::SshConfig(_) => Platform::Linux,
            _ => Platform::Windows,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawForbiddenImage {
    image: Option<String>,
    #[serde(default = "default_true")]
    running_only: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrivilege {
    #[serde(default)]
    privileged: bool,
    #[serde(default)]
    host_network: bool,
    #[serde(default)]
    runtime_socket: bool,
    #[serde(default)]
    except_images: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnpinned {
    #[serde(default)]
    except_images: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUnquoted {
    #[serde(default)]
    except_services: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExtraRoot {
    #[serde(default)]
    except_accounts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExposed {
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    ports: Vec<u32>,
    #[serde(default)]
    any_interface_only: bool,
    #[serde(default)]
    except_processes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFirewallAll {
    #[serde(default)]
    except_rules: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSsh {
    #[serde(default)]
    no_root_password: bool,
    #[serde(default)]
    no_root_login: bool,
    #[serde(default)]
    no_password: bool,
    #[serde(default)]
    no_empty_passwords: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWeakPermissions {
    #[serde(default)]
    except_paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccountFlags {
    #[serde(default)]
    no_password: bool,
    #[serde(default)]
    guest_disabled: bool,
    #[serde(default)]
    password_expires: bool,
    #[serde(default)]
    sudo_nopasswd: bool,
    #[serde(default)]
    no_autologon_password: bool,
    #[serde(default)]
    except_accounts: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRdpUsers {
    #[serde(default)]
    allowed: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOpenShare {
    #[serde(default)]
    anonymous: bool,
    #[serde(default)]
    all_users: bool,
    /// `write`（預設）或 `read`
    #[serde(default)]
    access: Option<String>,
    #[serde(default)]
    no_root_squash: bool,
    #[serde(default)]
    except_shares: Vec<String>,
}

/// 例外映像：去空白、去重；最多 MAX_EXCEPTIONS 個
fn image_exceptions(v: Vec<String>) -> Result<Vec<String>, String> {
    exceptions("例外映像", v)
}

/// 例外清單：去空白、去重；最多 MAX_EXCEPTIONS 個
fn exceptions(field: &str, v: Vec<String>) -> Result<Vec<String>, String> {
    if v.len() > MAX_EXCEPTIONS {
        return Err(format!("例外最多 {MAX_EXCEPTIONS} 個"));
    }
    let mut out = vec![];
    for i in v {
        if let Some(i) = opt(field, Some(i))?
            && !out.contains(&i)
        {
            out.push(i);
        }
    }
    Ok(out)
}

fn default_lookback() -> u32 {
    7
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDualHomed {
    #[serde(default = "default_lookback")]
    lookback_days: u32,
    #[serde(default)]
    min_duration_secs: u32,
    #[serde(default)]
    exclude_interfaces: Vec<String>,
    #[serde(default)]
    exclude_cidrs: Vec<String>,
    #[serde(default)]
    only_cross_site: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDays {
    max_days: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEmpty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRegistry {
    path: String,
    #[serde(default)]
    name: String,
    op: String,
    #[serde(default)]
    expected: Option<String>,
    #[serde(default)]
    absent_ok: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawService {
    name: String,
    require: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFirewall {
    profiles: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBitlocker {
    scope: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDefender {
    #[serde(default)]
    realtime: bool,
    #[serde(default)]
    max_signature_age_days: Option<u32>,
    #[serde(default)]
    tamper: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPassword {
    #[serde(default)]
    min_length: Option<u32>,
    #[serde(default)]
    max_age_days: Option<u32>,
    #[serde(default)]
    max_lockout_threshold: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAdmins {
    allowed: Vec<String>,
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
                    Ok(Params::Forbidden {
                        name,
                        publisher,
                        below_version,
                    })
                } else {
                    if r.below_version.is_some() {
                        return Err("必要軟體沒有「低於版本」參數".into());
                    }
                    let min_version = opt("最低版本", r.min_version)?;
                    Ok(Params::Required {
                        name,
                        publisher,
                        min_version,
                    })
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
            "registry_value" => {
                let r: RawRegistry = from(v)?;
                let path = protocol::regpath::normalize(&r.path)?;
                let path = protocol::regpath::check(&path, &r.name)?;
                let name = r.name.trim().to_string();
                if name.chars().count() > MAX_PATTERN_LEN {
                    return Err(format!("值名稱最多 {MAX_PATTERN_LEN} 字"));
                }
                let op = RegOp::parse(&r.op).ok_or("比對方式無效")?;
                let expected = if op.needs_expected() {
                    let e = opt("期望值", r.expected)?.ok_or("期望值必填")?;
                    if matches!(op, RegOp::Gte | RegOp::Lte) && parse_number(&e).is_none() {
                        return Err(
                            "大於等於／小於等於的期望值必須是數字（可用 0x 十六進位）".into()
                        );
                    }
                    Some(e)
                } else {
                    None
                };
                Ok(Params::RegistryValue {
                    path,
                    name,
                    op,
                    expected,
                    absent_ok: r.absent_ok,
                })
            }
            "service_state" => {
                let r: RawService = from(v)?;
                let name = required("服務名稱", Some(r.name))?;
                let require_running = match r.require.as_str() {
                    "disabled" => false,
                    "running" => true,
                    _ => return Err("服務要求必須是 disabled 或 running".into()),
                };
                Ok(Params::ServiceState {
                    name,
                    require_running,
                })
            }
            "firewall" => {
                let r: RawFirewall = from(v)?;
                let has = |p: &str| r.profiles.iter().any(|x| x == p);
                if r.profiles.is_empty()
                    || r.profiles
                        .iter()
                        .any(|p| !matches!(p.as_str(), "domain" | "private" | "public"))
                {
                    return Err("防火牆設定檔須為 domain、private、public 其中至少一個".into());
                }
                Ok(Params::Firewall {
                    domain: has("domain"),
                    private: has("private"),
                    public: has("public"),
                })
            }
            "bitlocker" => {
                let r: RawBitlocker = from(v)?;
                let all_fixed = match r.scope.as_str() {
                    "system" => false,
                    "all_fixed" => true,
                    _ => return Err("BitLocker 範圍必須是 system 或 all_fixed".into()),
                };
                Ok(Params::Bitlocker { all_fixed })
            }
            "defender" => {
                let r: RawDefender = from(v)?;
                if !r.realtime && !r.tamper && r.max_signature_age_days.is_none() {
                    return Err("Defender 規則至少要勾選一項".into());
                }
                Ok(Params::Defender {
                    realtime: r.realtime,
                    max_signature_age_days: r.max_signature_age_days,
                    tamper: r.tamper,
                })
            }
            "password_policy" => {
                let r: RawPassword = from(v)?;
                if r.min_length.is_none()
                    && r.max_age_days.is_none()
                    && r.max_lockout_threshold.is_none()
                {
                    return Err("密碼原則至少要填一項".into());
                }
                Ok(Params::PasswordPolicy {
                    min_length: r.min_length,
                    max_age_days: r.max_age_days,
                    max_lockout_threshold: r.max_lockout_threshold,
                })
            }
            "local_admins" => {
                let r: RawAdmins = from(v)?;
                let allowed = r
                    .allowed
                    .into_iter()
                    .map(|a| opt("允許的成員", Some(a)))
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                if allowed.is_empty() {
                    return Err("至少要有一個允許的成員".into());
                }
                Ok(Params::LocalAdmins { allowed })
            }
            "patch_age" | "reboot_pending" => {
                let r: RawDays = from(v)?;
                let max = if kind == "patch_age" { 365 } else { 90 };
                if !(1..=max).contains(&r.max_days) {
                    return Err(format!("天數必須是 1–{max}"));
                }
                Ok(if kind == "patch_age" {
                    Params::PatchAge {
                        max_days: r.max_days,
                    }
                } else {
                    Params::RebootPending {
                        max_days: r.max_days,
                    }
                })
            }
            "update_policy" => {
                let _: RawEmpty = from(v)?;
                Ok(Params::UpdatePolicy)
            }
            "dual_homed" => {
                let r: RawDualHomed = from(v)?;
                if !(1..=MAX_LOOKBACK_DAYS).contains(&r.lookback_days) {
                    return Err(format!("回溯天數必須是 1–{MAX_LOOKBACK_DAYS}"));
                }
                if r.min_duration_secs > MAX_MIN_DURATION_SECS {
                    return Err(format!("最短持續時間最多 {MAX_MIN_DURATION_SECS} 秒"));
                }
                if r.exclude_interfaces.len() > MAX_EXCEPTIONS
                    || r.exclude_cidrs.len() > MAX_EXCEPTIONS
                {
                    return Err(format!("例外最多 {MAX_EXCEPTIONS} 個"));
                }
                let mut exclude_interfaces = vec![];
                for n in r.exclude_interfaces {
                    if let Some(n) = opt("例外網卡", Some(n))?
                        && !exclude_interfaces.contains(&n)
                    {
                        exclude_interfaces.push(n);
                    }
                }
                let mut exclude_cidrs = vec![];
                for c in r.exclude_cidrs {
                    if c.trim().is_empty() {
                        continue;
                    }
                    let c = crate::branch::sites::parse_cidr(&c).map_err(|e| e.to_string())?;
                    let c = crate::branch::sites::cidr_string(&c);
                    if !exclude_cidrs.contains(&c) {
                        exclude_cidrs.push(c);
                    }
                }
                Ok(Params::DualHomed(DualHomedParams {
                    lookback_days: r.lookback_days,
                    min_duration_secs: r.min_duration_secs,
                    exclude_interfaces,
                    exclude_cidrs,
                    only_cross_site: r.only_cross_site,
                }))
            }
            "forbidden_image" => {
                let r: RawForbiddenImage = from(v)?;
                Ok(Params::ForbiddenImage {
                    image: required("映像", r.image)?,
                    running_only: r.running_only,
                })
            }
            "container_privilege" => {
                let r: RawPrivilege = from(v)?;
                if !r.privileged && !r.host_network && !r.runtime_socket {
                    return Err("容器權限規則至少要勾選一項".into());
                }
                Ok(Params::ContainerPrivilege {
                    privileged: r.privileged,
                    host_network: r.host_network,
                    runtime_socket: r.runtime_socket,
                    except_images: image_exceptions(r.except_images)?,
                })
            }
            "unpinned_image" => {
                let r: RawUnpinned = from(v)?;
                Ok(Params::UnpinnedImage {
                    except_images: image_exceptions(r.except_images)?,
                })
            }
            "unquoted_service_path" => {
                let r: RawUnquoted = from(v)?;
                Ok(Params::UnquotedServicePath {
                    except_services: exceptions("例外服務", r.except_services)?,
                })
            }
            "extra_root_account" => {
                let r: RawExtraRoot = from(v)?;
                Ok(Params::ExtraRootAccount {
                    except_accounts: exceptions("例外帳號", r.except_accounts)?,
                })
            }
            "exposed_service" => {
                let r: RawExposed = from(v)?;
                let mut services = vec![];
                for s in r.services {
                    let s = s.trim().to_string();
                    if s.is_empty() || services.contains(&s) {
                        continue;
                    }
                    if !SERVICE_PRESETS.iter().any(|(k, _, _)| *k == s) {
                        return Err(format!("不認得的服務：{s}"));
                    }
                    services.push(s);
                }
                if r.ports.len() > MAX_CUSTOM_PORTS {
                    return Err(format!("自訂連接埠最多 {MAX_CUSTOM_PORTS} 個"));
                }
                let mut ports = vec![];
                for p in r.ports {
                    let p = u16::try_from(p)
                        .ok()
                        .filter(|p| *p > 0)
                        .ok_or_else(|| format!("連接埠必須是 1–65535：{p}"))?;
                    if !ports.contains(&p) {
                        ports.push(p);
                    }
                }
                if services.is_empty() && ports.is_empty() {
                    return Err("至少要選一個服務或填一個連接埠".into());
                }
                Ok(Params::ExposedService {
                    services,
                    ports,
                    any_interface_only: r.any_interface_only,
                    except_processes: exceptions("例外程式", r.except_processes)?,
                })
            }
            "firewall_allow_all" => {
                let r: RawFirewallAll = from(v)?;
                Ok(Params::FirewallAllowAll {
                    except_rules: exceptions("例外規則", r.except_rules)?,
                })
            }
            "ssh_config" => {
                let r: RawSsh = from(v)?;
                if !(r.no_root_password || r.no_root_login || r.no_password || r.no_empty_passwords)
                {
                    return Err("sshd 設定規則至少要勾選一項".into());
                }
                Ok(Params::SshConfig(SshParams {
                    no_root_password: r.no_root_password,
                    no_root_login: r.no_root_login,
                    no_password: r.no_password,
                    no_empty_passwords: r.no_empty_passwords,
                }))
            }
            "weak_permissions" => {
                let r: RawWeakPermissions = from(v)?;
                Ok(Params::WeakPermissions {
                    except_paths: exceptions("例外路徑", r.except_paths)?,
                })
            }
            "account_flags" => {
                let r: RawAccountFlags = from(v)?;
                let checks = AccountChecks {
                    no_password: r.no_password,
                    guest_disabled: r.guest_disabled,
                    password_expires: r.password_expires,
                    sudo_nopasswd: r.sudo_nopasswd,
                    no_autologon_password: r.no_autologon_password,
                };
                if !checks.fields().iter().any(|(_, on)| *on) {
                    return Err("帳號設定規則至少要勾選一項".into());
                }
                Ok(Params::AccountFlags {
                    checks,
                    except_accounts: exceptions("例外帳號", r.except_accounts)?,
                })
            }
            "rdp_users" => {
                let r: RawRdpUsers = from(v)?;
                Ok(Params::RdpUsers {
                    allowed: exceptions("允許的成員", r.allowed)?,
                })
            }
            "open_share" => {
                let r: RawOpenShare = from(v)?;
                if !r.anonymous && !r.all_users && !r.no_root_squash {
                    return Err("開放的共用規則至少要勾選一項".into());
                }
                let write_only = match r.access.as_deref().map(str::trim) {
                    None | Some("") | Some("write") => true,
                    Some("read") => false,
                    Some(other) => return Err(format!("不認得的權限：{other}")),
                };
                Ok(Params::OpenShare(OpenShareParams {
                    anonymous: r.anonymous,
                    all_users: r.all_users,
                    write_only,
                    no_root_squash: r.no_root_squash,
                    except_shares: exceptions("例外共用", r.except_shares)?,
                }))
            }
            _ => Err(format!("未知的規則類型：{kind}")),
        }
    }

    /// 登錄檔規則需要 Agent 讀取的值
    pub fn registry_query(&self) -> Option<protocol::RegistryQuery> {
        match self {
            Params::RegistryValue { path, name, .. } => Some(protocol::RegistryQuery {
                path: path.clone(),
                name: name.clone(),
            }),
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Params::Forbidden { .. } => "forbidden_software",
            Params::Required { .. } => "required_software",
            Params::Allowlist { .. } => "software_allowlist",
            Params::MinBuild { .. } | Params::PatchLevel { .. } => "os_build",
            Params::RequiredKb { .. } => "required_kb",
            Params::RegistryValue { .. } => "registry_value",
            Params::ServiceState { .. } => "service_state",
            Params::Firewall { .. } => "firewall",
            Params::Bitlocker { .. } => "bitlocker",
            Params::Defender { .. } => "defender",
            Params::PasswordPolicy { .. } => "password_policy",
            Params::LocalAdmins { .. } => "local_admins",
            Params::PatchAge { .. } => "patch_age",
            Params::RebootPending { .. } => "reboot_pending",
            Params::UpdatePolicy => "update_policy",
            Params::DualHomed(_) => "dual_homed",
            Params::ForbiddenImage { .. } => "forbidden_image",
            Params::ContainerPrivilege { .. } => "container_privilege",
            Params::UnpinnedImage { .. } => "unpinned_image",
            Params::UnquotedServicePath { .. } => "unquoted_service_path",
            Params::ExtraRootAccount { .. } => "extra_root_account",
            Params::OpenShare(_) => "open_share",
            Params::ExposedService { .. } => "exposed_service",
            Params::FirewallAllowAll { .. } => "firewall_allow_all",
            Params::SshConfig(_) => "ssh_config",
            Params::RdpUsers { .. } => "rdp_users",
            Params::AccountFlags { .. } => "account_flags",
            Params::WeakPermissions { .. } => "weak_permissions",
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
            Params::Forbidden {
                name,
                publisher,
                below_version,
            } => {
                m.insert("name".into(), json!(name));
                put(&mut m, "publisher", publisher);
                put(&mut m, "below_version", below_version);
            }
            Params::Required {
                name,
                publisher,
                min_version,
            } => {
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
            Params::RegistryValue {
                path,
                name,
                op,
                expected,
                absent_ok,
            } => {
                m.insert("path".into(), json!(path));
                m.insert("name".into(), json!(name));
                m.insert("op".into(), json!(op.as_str()));
                put(&mut m, "expected", expected);
                if *absent_ok {
                    m.insert("absent_ok".into(), json!(true));
                }
            }
            Params::ServiceState {
                name,
                require_running,
            } => {
                m.insert("name".into(), json!(name));
                let r = if *require_running {
                    "running"
                } else {
                    "disabled"
                };
                m.insert("require".into(), json!(r));
            }
            Params::Firewall {
                domain,
                private,
                public,
            } => {
                let profiles: Vec<&str> =
                    [("domain", domain), ("private", private), ("public", public)]
                        .into_iter()
                        .filter(|(_, on)| **on)
                        .map(|(n, _)| n)
                        .collect();
                m.insert("profiles".into(), json!(profiles));
            }
            Params::Bitlocker { all_fixed } => {
                let scope = if *all_fixed { "all_fixed" } else { "system" };
                m.insert("scope".into(), json!(scope));
            }
            Params::Defender {
                realtime,
                max_signature_age_days,
                tamper,
            } => {
                if *realtime {
                    m.insert("realtime".into(), json!(true));
                }
                if let Some(d) = max_signature_age_days {
                    m.insert("max_signature_age_days".into(), json!(d));
                }
                if *tamper {
                    m.insert("tamper".into(), json!(true));
                }
            }
            Params::PasswordPolicy {
                min_length,
                max_age_days,
                max_lockout_threshold,
            } => {
                for (k, v) in [
                    ("min_length", min_length),
                    ("max_age_days", max_age_days),
                    ("max_lockout_threshold", max_lockout_threshold),
                ] {
                    if let Some(v) = v {
                        m.insert(k.into(), json!(v));
                    }
                }
            }
            Params::LocalAdmins { allowed } => {
                m.insert("allowed".into(), json!(allowed));
            }
            Params::PatchAge { max_days } | Params::RebootPending { max_days } => {
                m.insert("max_days".into(), json!(max_days));
            }
            Params::UpdatePolicy => {}
            Params::DualHomed(p) => {
                m.insert("lookback_days".into(), json!(p.lookback_days));
                if p.min_duration_secs > 0 {
                    m.insert("min_duration_secs".into(), json!(p.min_duration_secs));
                }
                if !p.exclude_interfaces.is_empty() {
                    m.insert("exclude_interfaces".into(), json!(p.exclude_interfaces));
                }
                if !p.exclude_cidrs.is_empty() {
                    m.insert("exclude_cidrs".into(), json!(p.exclude_cidrs));
                }
                if p.only_cross_site {
                    m.insert("only_cross_site".into(), json!(true));
                }
            }
            Params::ForbiddenImage {
                image,
                running_only,
            } => {
                m.insert("image".into(), json!(image));
                m.insert("running_only".into(), json!(running_only));
            }
            Params::ContainerPrivilege {
                privileged,
                host_network,
                runtime_socket,
                except_images,
            } => {
                for (k, on) in [
                    ("privileged", privileged),
                    ("host_network", host_network),
                    ("runtime_socket", runtime_socket),
                ] {
                    if *on {
                        m.insert(k.into(), json!(true));
                    }
                }
                if !except_images.is_empty() {
                    m.insert("except_images".into(), json!(except_images));
                }
            }
            Params::UnpinnedImage { except_images } => {
                if !except_images.is_empty() {
                    m.insert("except_images".into(), json!(except_images));
                }
            }
            Params::UnquotedServicePath { except_services } => {
                if !except_services.is_empty() {
                    m.insert("except_services".into(), json!(except_services));
                }
            }
            Params::ExtraRootAccount { except_accounts } => {
                if !except_accounts.is_empty() {
                    m.insert("except_accounts".into(), json!(except_accounts));
                }
            }
            Params::ExposedService {
                services,
                ports,
                any_interface_only,
                except_processes,
            } => {
                if !services.is_empty() {
                    m.insert("services".into(), json!(services));
                }
                if !ports.is_empty() {
                    m.insert("ports".into(), json!(ports));
                }
                if *any_interface_only {
                    m.insert("any_interface_only".into(), json!(true));
                }
                if !except_processes.is_empty() {
                    m.insert("except_processes".into(), json!(except_processes));
                }
            }
            Params::FirewallAllowAll { except_rules } => {
                if !except_rules.is_empty() {
                    m.insert("except_rules".into(), json!(except_rules));
                }
            }
            Params::SshConfig(p) => {
                for (k, on) in [
                    ("no_root_password", p.no_root_password),
                    ("no_root_login", p.no_root_login),
                    ("no_password", p.no_password),
                    ("no_empty_passwords", p.no_empty_passwords),
                ] {
                    if on {
                        m.insert(k.into(), json!(true));
                    }
                }
            }
            Params::RdpUsers { allowed } => {
                m.insert("allowed".into(), json!(allowed));
            }
            Params::AccountFlags {
                checks,
                except_accounts,
            } => {
                for (k, on) in checks.fields() {
                    if on {
                        m.insert(k.into(), json!(true));
                    }
                }
                if !except_accounts.is_empty() {
                    m.insert("except_accounts".into(), json!(except_accounts));
                }
            }
            Params::WeakPermissions { except_paths } => {
                if !except_paths.is_empty() {
                    m.insert("except_paths".into(), json!(except_paths));
                }
            }
            Params::OpenShare(p) => {
                for (k, on) in [
                    ("anonymous", p.anonymous),
                    ("all_users", p.all_users),
                    ("no_root_squash", p.no_root_squash),
                ] {
                    if on {
                        m.insert(k.into(), json!(true));
                    }
                }
                m.insert(
                    "access".into(),
                    json!(if p.write_only { "write" } else { "read" }),
                );
                if !p.except_shares.is_empty() {
                    m.insert("except_shares".into(), json!(p.except_shares));
                }
            }
        }
        Value::Object(m)
    }

    pub fn compile(&self) -> Check {
        let g = |s: &Option<String>| s.as_deref().map(Glob::new);
        match self {
            Params::Forbidden {
                name,
                publisher,
                below_version,
            } => Check::Forbidden {
                name: Glob::new(name),
                publisher: g(publisher),
                below: below_version.clone(),
            },
            Params::Required {
                name,
                publisher,
                min_version,
            } => Check::Required {
                name: Glob::new(name),
                publisher: g(publisher),
                min: min_version.clone(),
            },
            Params::Allowlist { entries } => Check::Allowlist {
                entries: entries
                    .iter()
                    .map(|e| (g(&e.name), g(&e.publisher)))
                    .collect(),
            },
            Params::MinBuild { min_build } => Check::MinBuild {
                min_build: *min_build,
            },
            Params::PatchLevel { build, min_ubr } => Check::PatchLevel {
                build: *build,
                min_ubr: *min_ubr,
            },
            Params::RequiredKb { kb } => Check::RequiredKb { kb: kb.clone() },
            Params::RegistryValue {
                path,
                name,
                op,
                expected,
                absent_ok,
            } => Check::RegistryValue {
                path: path.clone(),
                name: name.clone(),
                key: registry_key(path, name),
                op: *op,
                expected: expected.clone(),
                absent_ok: *absent_ok,
            },
            Params::ServiceState {
                name,
                require_running,
            } => Check::ServiceState {
                name: name.clone(),
                require_running: *require_running,
            },
            Params::Firewall {
                domain,
                private,
                public,
            } => Check::Firewall {
                domain: *domain,
                private: *private,
                public: *public,
            },
            Params::Bitlocker { all_fixed } => Check::Bitlocker {
                all_fixed: *all_fixed,
            },
            Params::Defender {
                realtime,
                max_signature_age_days,
                tamper,
            } => Check::Defender {
                realtime: *realtime,
                max_signature_age_days: *max_signature_age_days,
                tamper: *tamper,
            },
            Params::PasswordPolicy {
                min_length,
                max_age_days,
                max_lockout_threshold,
            } => Check::PasswordPolicy {
                min_length: *min_length,
                max_age_days: *max_age_days,
                max_lockout_threshold: *max_lockout_threshold,
            },
            Params::LocalAdmins { allowed } => Check::LocalAdmins {
                allowed: allowed.iter().map(|a| Glob::new(a)).collect(),
            },
            Params::PatchAge { max_days } => Check::PatchAge {
                max_days: *max_days,
            },
            Params::RebootPending { max_days } => Check::RebootPending {
                max_days: *max_days,
            },
            Params::UpdatePolicy => Check::UpdatePolicy,
            Params::DualHomed(p) => Check::DualHomed {
                lookback_days: p.lookback_days,
                min_duration_secs: p.min_duration_secs,
                exclude_interfaces: p.exclude_interfaces.iter().map(|n| Glob::new(n)).collect(),
                exclude_cidrs: p
                    .exclude_cidrs
                    .iter()
                    .filter_map(|c| crate::branch::sites::parse_cidr(c).ok())
                    .collect(),
                only_cross_site: p.only_cross_site,
            },
            Params::ForbiddenImage {
                image,
                running_only,
            } => Check::ForbiddenImage {
                image: Glob::new(image),
                running_only: *running_only,
            },
            Params::ContainerPrivilege {
                privileged,
                host_network,
                runtime_socket,
                except_images,
            } => Check::ContainerPrivilege {
                privileged: *privileged,
                host_network: *host_network,
                runtime_socket: *runtime_socket,
                except_images: except_images.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::UnpinnedImage { except_images } => Check::UnpinnedImage {
                except_images: except_images.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::UnquotedServicePath { except_services } => Check::UnquotedServicePath {
                except_services: except_services.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::ExtraRootAccount { except_accounts } => Check::ExtraRootAccount {
                except_accounts: except_accounts.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::ExposedService {
                services,
                ports,
                any_interface_only,
                except_processes,
            } => {
                let mut list: Vec<(u16, String)> = vec![];
                for (key, label, ps) in SERVICE_PRESETS {
                    if services.iter().any(|s| s == key) {
                        list.extend(ps.iter().map(|p| (*p, label.to_string())));
                    }
                }
                for p in ports {
                    if !list.iter().any(|(x, _)| x == p) {
                        list.push((*p, format!("連接埠 {p}")));
                    }
                }
                Check::ExposedService {
                    ports: list,
                    any_interface_only: *any_interface_only,
                    except_processes: except_processes.iter().map(|i| Glob::new(i)).collect(),
                }
            }
            Params::FirewallAllowAll { except_rules } => Check::FirewallAllowAll {
                except_rules: except_rules.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::SshConfig(p) => Check::SshConfig(*p),
            Params::RdpUsers { allowed } => Check::RdpUsers {
                allowed: allowed.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::AccountFlags {
                checks,
                except_accounts,
            } => Check::AccountFlags {
                checks: *checks,
                except_accounts: except_accounts.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::WeakPermissions { except_paths } => Check::WeakPermissions {
                except_paths: except_paths.iter().map(|i| Glob::new(i)).collect(),
            },
            Params::OpenShare(p) => Check::OpenShare {
                anonymous: p.anonymous,
                all_users: p.all_users,
                write_only: p.write_only,
                no_root_squash: p.no_root_squash,
                except_shares: p.except_shares.iter().map(|i| Glob::new(i)).collect(),
            },
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
    /// 啟用中登錄檔規則需要 Agent 讀取的值（不分大小寫去重、排序）
    pub registry_queries: Vec<protocol::RegistryQuery>,
    pub registry_hash: String,
    /// registry_key(path, name) 的集合：上傳時只保存這些值
    pub registry_keys: std::collections::HashSet<(String, String)>,
}

impl RuleSet {
    pub fn new(generation: i64, rules: Vec<Rule>) -> RuleSet {
        let mut keys = std::collections::HashSet::new();
        let mut queries = vec![];
        for r in &rules {
            if let Ok(Check::RegistryValue {
                path, name, key, ..
            }) = &r.check
                && keys.insert(key.clone())
            {
                queries.push(protocol::RegistryQuery {
                    path: path.clone(),
                    name: name.clone(),
                });
            }
        }
        queries.sort_by_key(|q| registry_key(&q.path, &q.name));
        RuleSet {
            generation,
            rules,
            registry_hash: protocol::regpath::queries_hash(&queries),
            registry_queries: queries,
            registry_keys: keys,
        }
    }

    pub fn empty() -> RuleSet {
        RuleSet::new(-1, vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_params_parse_and_normalize() {
        let p = Params::parse(
            "registry_value",
            &json!({"path": "hklm/Software/Policies/X", "name": "Y", "op": "equals", "expected": "1"}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"path": "HKLM\\Software\\Policies\\X", "name": "Y", "op": "equals", "expected": "1"})
        );
        assert_eq!(
            p.registry_query().unwrap().path,
            r"HKLM\Software\Policies\X"
        );
        let p = Params::parse(
            "registry_value",
            &json!({"path": r"HKLM\A", "name": "B", "op": "exists", "expected": "ignored"}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"path": r"HKLM\A", "name": "B", "op": "exists"}),
            "exists 不需要 expected"
        );
        let p = Params::parse(
            "registry_value",
            &json!({"path": r"HKLM\A", "name": "", "op": "equals", "expected": "x", "absent_ok": true}),
        )
        .unwrap();
        assert_eq!(p.to_json()["absent_ok"], true);
        assert_eq!(
            Params::parse(
                "firewall",
                &json!({"profiles": ["public", "domain", "public"]})
            )
            .unwrap()
            .to_json(),
            json!({"profiles": ["domain", "public"]})
        );
        assert_eq!(
            Params::parse(
                "service_state",
                &json!({"name": " RemoteRegistry ", "require": "disabled"})
            )
            .unwrap()
            .to_json(),
            json!({"name": "RemoteRegistry", "require": "disabled"})
        );
        assert_eq!(
            Params::parse("defender", &json!({"realtime": true}))
                .unwrap()
                .to_json(),
            json!({"realtime": true})
        );
        assert_eq!(
            Params::parse("password_policy", &json!({"min_length": 12}))
                .unwrap()
                .to_json(),
            json!({"min_length": 12})
        );
        assert_eq!(
            Params::parse(
                "local_admins",
                &json!({"allowed": [" *\\Administrator ", ""]})
            )
            .unwrap()
            .to_json(),
            json!({"allowed": ["*\\Administrator"]})
        );
        assert_eq!(
            Params::parse("bitlocker", &json!({"scope": "all_fixed"}))
                .unwrap()
                .to_json(),
            json!({"scope": "all_fixed"})
        );
        for k in [
            "registry_value",
            "service_state",
            "firewall",
            "bitlocker",
            "defender",
            "password_policy",
            "local_admins",
        ] {
            assert!(KINDS.contains(&k), "{k}");
            assert_ne!(kind_label(k), "未知類型", "{k}");
        }
    }

    #[test]
    fn update_params() {
        for (kind, v, ok) in [
            ("patch_age", json!({"max_days": 0}), false),
            ("patch_age", json!({"max_days": 1}), true),
            ("patch_age", json!({"max_days": 365}), true),
            ("patch_age", json!({"max_days": 366}), false),
            ("patch_age", json!({}), false),
            ("reboot_pending", json!({"max_days": 90}), true),
            ("reboot_pending", json!({"max_days": 91}), false),
            ("update_policy", json!({}), true),
        ] {
            let r = Params::parse(kind, &v);
            assert_eq!(r.is_ok(), ok, "{kind} {v}");
            if let Ok(p) = r {
                assert_eq!(p.kind(), kind);
                assert_eq!(Params::parse(kind, &p.to_json()).unwrap(), p, "往返");
            }
        }
        for k in ["patch_age", "reboot_pending", "update_policy"] {
            assert!(KINDS.contains(&k), "{k}");
            assert_ne!(kind_label(k), "未知類型", "{k}");
        }
    }

    #[test]
    fn dual_homed_params() {
        let p = Params::parse(
            "dual_homed",
            &json!({
                "lookback_days": 14,
                "min_duration_secs": 30,
                "exclude_interfaces": [" *Npcap* ", "", "*Npcap*"],
                "exclude_cidrs": ["192.168.56.1/24", " ", "192.168.56.0/24"],
                "only_cross_site": true
            }),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({
                "lookback_days": 14,
                "min_duration_secs": 30,
                "exclude_interfaces": ["*Npcap*"],
                "exclude_cidrs": ["192.168.56.0/24"],
                "only_cross_site": true
            })
        );
        assert_eq!(p.kind(), "dual_homed");
        assert_eq!(
            Params::parse("dual_homed", &p.to_json()).unwrap(),
            p,
            "往返"
        );
        // 預設 7 天，其他都不設
        let d = Params::parse("dual_homed", &json!({})).unwrap();
        assert_eq!(d.to_json(), json!({"lookback_days": 7}));
        assert!(matches!(
            d.compile(),
            Check::DualHomed {
                lookback_days: 7,
                ..
            }
        ));
        for bad in [
            json!({"lookback_days": 0}),
            json!({"lookback_days": 91}),
            json!({"min_duration_secs": 86_401}),
            json!({"exclude_cidrs": ["10.0.0.0/33"]}),
            json!({"exclude_cidrs": ["nope"]}),
            json!({"exclude_interfaces": ["x".repeat(MAX_PATTERN_LEN + 1)]}),
            json!({"exclude_interfaces": vec!["a"; MAX_EXCEPTIONS + 1]}),
            json!({"unknown": 1}),
        ] {
            assert!(Params::parse("dual_homed", &bad).is_err(), "{bad}");
        }
        assert!(KINDS.contains(&"dual_homed"));
        assert_eq!(kind_label("dual_homed"), "多重連線");
    }

    #[test]
    fn container_params() {
        let p = Params::parse("forbidden_image", &json!({"image": " *xmrig* "})).unwrap();
        assert_eq!(
            p.to_json(),
            json!({"image": "*xmrig*", "running_only": true})
        );
        assert_eq!(p.kind(), "forbidden_image");
        assert!(p.compile().platform() == Platform::Linux);
        let p = Params::parse(
            "container_privilege",
            &json!({"privileged": true, "except_images": [" portainer/* ", "", "portainer/*"]}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"privileged": true, "except_images": ["portainer/*"]})
        );
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p, "往返");
        assert!(p.compile().platform() == Platform::Linux);
        let p = Params::parse("unpinned_image", &json!({})).unwrap();
        assert_eq!((p.kind(), p.to_json()), ("unpinned_image", json!({})));
        assert!(p.compile().platform() == Platform::Linux);
        assert!(
            Params::parse("dual_homed", &json!({}))
                .unwrap()
                .compile()
                .platform()
                == Platform::Windows
        );
        for (kind, bad) in [
            ("forbidden_image", json!({})),
            ("forbidden_image", json!({"image": "  "})),
            ("container_privilege", json!({})),
            (
                "container_privilege",
                json!({"privileged": false, "host_network": false}),
            ),
            (
                "container_privilege",
                json!({"privileged": true, "except_images": vec!["a"; MAX_EXCEPTIONS + 1]}),
            ),
            (
                "unpinned_image",
                json!({"except_images": ["x".repeat(MAX_PATTERN_LEN + 1)]}),
            ),
            ("unpinned_image", json!({"tag": "latest"})),
        ] {
            assert!(Params::parse(kind, &bad).is_err(), "{kind} {bad}");
        }
        for k in ["forbidden_image", "container_privilege", "unpinned_image"] {
            assert!(KINDS.contains(&k));
            assert_ne!(kind_label(k), "未知類型");
        }
    }

    #[test]
    fn exposure_params() {
        let p = Params::parse(
            "exposed_service",
            &json!({"services": ["mysql", " vnc ", "mysql", ""], "ports": [8080, 8080],
                    "any_interface_only": true, "except_processes": ["mysqld"]}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"services": ["mysql", "vnc"], "ports": [8080], "any_interface_only": true,
                   "except_processes": ["mysqld"]})
        );
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p, "往返");
        let Check::ExposedService { ports, .. } = p.compile() else {
            unreachable!()
        };
        assert_eq!(ports.len(), 6, "VNC 四個、MySQL、自訂：{ports:?}");
        assert!(ports.contains(&(8080, "連接埠 8080".to_string())));
        assert_eq!(p.compile().platform(), Platform::Both);
        // 自訂連接埠和內建的重複：用內建的名稱
        let p = Params::parse(
            "exposed_service",
            &json!({"services": ["redis"], "ports": [6379]}),
        )
        .unwrap();
        let Check::ExposedService { ports, .. } = p.compile() else {
            unreachable!()
        };
        assert_eq!(ports, [(6379, "Redis".to_string())]);
        for bad in [
            json!({}),
            json!({"services": ["gopher"]}),
            json!({"ports": [0]}),
            json!({"ports": [70000]}),
            json!({"ports": vec![1; MAX_CUSTOM_PORTS + 1]}),
        ] {
            assert!(Params::parse("exposed_service", &bad).is_err(), "{bad}");
        }

        let p = Params::parse("firewall_allow_all", &json!({"except_rules": ["Lab*"]})).unwrap();
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);
        assert_eq!(p.compile().platform(), Platform::Windows);
        assert_eq!(
            Params::parse("firewall_allow_all", &json!({}))
                .unwrap()
                .to_json(),
            json!({})
        );

        let p = Params::parse(
            "ssh_config",
            &json!({"no_empty_passwords": true, "no_root_password": true}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"no_root_password": true, "no_empty_passwords": true})
        );
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);
        assert_eq!(p.compile().platform(), Platform::Linux);
        assert!(Params::parse("ssh_config", &json!({})).is_err());
        let p = Params::parse(
            "ssh_config",
            &json!({"no_root_login": true, "no_password": true}),
        )
        .unwrap();
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);

        let p = Params::parse(
            "rdp_users",
            &json!({"allowed": [" *-544 ", "CORP\\helpdesk"]}),
        )
        .unwrap();
        assert_eq!(p.to_json(), json!({"allowed": ["*-544", "CORP\\helpdesk"]}));
        assert_eq!(p.compile().platform(), Platform::Windows);
        assert_eq!(
            Params::parse("rdp_users", &json!({})).unwrap().to_json(),
            json!({"allowed": []})
        );
        let p = Params::parse(
            "account_flags",
            &json!({"no_password": true, "sudo_nopasswd": true, "except_accounts": [" %ops "]}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"no_password": true, "sudo_nopasswd": true, "except_accounts": ["%ops"]})
        );
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);
        assert_eq!(p.compile().platform(), Platform::Both);
        assert!(
            Params::parse("account_flags", &json!({"except_accounts": ["x"]}))
                .unwrap_err()
                .contains("至少")
        );
        assert_eq!(kind_platform("account_flags"), Platform::Both);
        let p = Params::parse(
            "weak_permissions",
            &json!({"except_paths": [r" C:\Vendor\* ", "/usr/local/bin/x"]}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"except_paths": [r"C:\Vendor\*", "/usr/local/bin/x"]})
        );
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);
        assert_eq!(p.compile().platform(), Platform::Both);
        assert_eq!(
            Params::parse("weak_permissions", &json!({}))
                .unwrap()
                .to_json(),
            json!({})
        );
        assert_eq!(kind_platform("weak_permissions"), Platform::Both);
        assert_eq!(kind_platform("ssh_config"), Platform::Linux);
        assert_eq!(kind_platform("exposed_service"), Platform::Both);
        assert_eq!(kind_platform("rdp_users"), Platform::Windows);
    }

    #[test]
    fn open_share_params() {
        let p = Params::parse(
            "open_share",
            &json!({"anonymous": true, "all_users": false, "except_shares": [" dist ", ""]}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"anonymous": true, "access": "write", "except_shares": ["dist"]})
        );
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p, "往返");
        assert_eq!(p.compile().platform(), Platform::Both);
        assert_eq!(kind_platform("open_share"), Platform::Both);
        let p = Params::parse("open_share", &json!({"all_users": true, "access": "read"})).unwrap();
        assert_eq!(p.to_json(), json!({"all_users": true, "access": "read"}));
        let p = Params::parse("open_share", &json!({"no_root_squash": true})).unwrap();
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);
        for bad in [
            json!({}),
            json!({"anonymous": false}),
            json!({"anonymous": true, "access": "full"}),
            json!({"anonymous": true, "x": 1}),
        ] {
            assert!(Params::parse("open_share", &bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn misconfig_params_and_platforms() {
        let p = Params::parse(
            "unquoted_service_path",
            &json!({"except_services": [" Vendor* ", "Vendor*", ""]}),
        )
        .unwrap();
        assert_eq!(p.to_json(), json!({"except_services": ["Vendor*"]}));
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p, "往返");
        assert_eq!(p.compile().platform(), Platform::Windows);
        let p = Params::parse("extra_root_account", &json!({})).unwrap();
        assert_eq!((p.kind(), p.to_json()), ("extra_root_account", json!({})));
        assert_eq!(p.compile().platform(), Platform::Linux);
        let p = Params::parse("extra_root_account", &json!({"except_accounts": ["toor"]})).unwrap();
        assert_eq!(Params::parse(p.kind(), &p.to_json()).unwrap(), p);
        for (kind, bad) in [
            ("unquoted_service_path", json!({"x": 1})),
            (
                "extra_root_account",
                json!({"except_accounts": vec!["a"; MAX_EXCEPTIONS + 1]}),
            ),
        ] {
            assert!(Params::parse(kind, &bad).is_err(), "{kind} {bad}");
        }
        // 種類與編譯後的規則對同一個平台
        for k in KINDS {
            assert_ne!(kind_label(k), "未知類型");
        }
        assert_eq!(kind_platform("extra_root_account"), Platform::Linux);
        assert_eq!(kind_platform("unquoted_service_path"), Platform::Windows);
        assert_eq!(kind_platform("bogus"), Platform::Windows);
        assert!(Platform::Both.covers(true) && Platform::Both.covers(false));
        assert!(Platform::Windows.covers(false) && !Platform::Windows.covers(true));
        assert!(Platform::Linux.covers(true) && !Platform::Linux.covers(false));
        assert_eq!(Platform::Both.label(), "Windows、Linux");
        assert_eq!(Platform::Linux.label(), "Linux");
        assert_eq!(Platform::Windows.label(), "Windows");
    }

    #[test]
    fn config_params_reject_bad_input() {
        for (kind, v) in [
            (
                "registry_value",
                json!({"path": r"HKLM\SAM\SAM", "name": "x", "op": "exists"}),
            ),
            (
                "registry_value",
                json!({"path": r"HKCU\Software", "name": "x", "op": "exists"}),
            ),
            (
                "registry_value",
                json!({"path": r"HKLM\A", "name": "x", "op": "equals"}),
            ),
            (
                "registry_value",
                json!({"path": r"HKLM\A", "name": "x", "op": "gte", "expected": "abc"}),
            ),
            (
                "registry_value",
                json!({"path": r"HKLM\A", "name": "x", "op": "nope", "expected": "1"}),
            ),
            ("service_state", json!({"name": "", "require": "disabled"})),
            ("service_state", json!({"name": "x", "require": "maybe"})),
            ("firewall", json!({"profiles": []})),
            ("firewall", json!({"profiles": ["lan"]})),
            ("bitlocker", json!({"scope": "usb"})),
            ("defender", json!({})),
            ("defender", json!({"realtime": false, "tamper": false})),
            ("password_policy", json!({})),
            ("local_admins", json!({"allowed": []})),
            ("local_admins", json!({"allowed": ["  "]})),
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

    #[test]
    fn parse_and_normalize() {
        let p = Params::parse("required_kb", &json!({"kb": " kb5034439 "})).unwrap();
        assert_eq!(p.to_json(), json!({"kb": "KB5034439"}));
        let p = Params::parse(
            "forbidden_software",
            &json!({"name": " *TeamViewer* ", "publisher": "", "below_version": null}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"name": "*TeamViewer*"}),
            "空字串視為未設定"
        );
        let p = Params::parse("os_build", &json!({"build": 22631, "min_ubr": 4317})).unwrap();
        assert_eq!(p.to_json(), json!({"build": 22631, "min_ubr": 4317}));
        let p = Params::parse(
            "software_allowlist",
            &json!({"entries": [{"publisher": "Microsoft*"}]}),
        )
        .unwrap();
        assert_eq!(
            p.to_json(),
            json!({"entries": [{"publisher": "Microsoft*"}]})
        );
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
            (
                "os_build",
                json!({"min_build": 19045, "build": 22631, "min_ubr": 1}),
            ),
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
        assert!(
            !rule(vec![1], vec![]).applies_to(None),
            "未分組只命中沒限定群組的規則"
        );
        assert!(!rule(vec![1], vec![1]).applies_to(Some(1)), "排除優先");
    }

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::High > Severity::Medium && Severity::Medium > Severity::Low);
        assert_eq!(Severity::parse("medium"), Some(Severity::Medium));
        assert_eq!(Severity::parse("x"), None);
    }
}
