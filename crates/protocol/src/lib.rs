//! Agent 與伺服器之間的共用訊息格式。

pub mod branch;
pub mod command;
pub mod deploy;
pub mod matcher;
pub mod regpath;
pub mod signing;
pub mod timefmt;
pub mod update;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_STRING_LEN: usize = 1024;
pub const MAX_ITEMS: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Section {
    Basic,
    Hardware,
    Software,
    Patches,
    Services,
    Security,
    Registry,
    Accounts,
    Containers,
    Network,
}

impl Section {
    pub const ALL: [Section; 10] = [
        Section::Basic,
        Section::Hardware,
        Section::Software,
        Section::Patches,
        Section::Services,
        Section::Security,
        Section::Registry,
        Section::Accounts,
        Section::Containers,
        Section::Network,
    ];

    /// Windows Agent 回報的區段
    pub const WINDOWS: [Section; 8] = [
        Section::Basic,
        Section::Hardware,
        Section::Software,
        Section::Patches,
        Section::Services,
        Section::Security,
        Section::Registry,
        Section::Network,
    ];

    /// Linux Agent 回報的區段
    pub const LINUX: [Section; 7] = [
        Section::Basic,
        Section::Hardware,
        Section::Software,
        Section::Services,
        Section::Accounts,
        Section::Containers,
        Section::Network,
    ];

    /// 第三期以前就有的區段：新版 Agent 在確認伺服器支援前只回報這些
    /// （舊版伺服器看到不認識的區段會讓整個報到失敗）
    pub const LEGACY: [Section; 5] = [
        Section::Basic,
        Section::Hardware,
        Section::Software,
        Section::Patches,
        Section::Services,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Section::Basic => "basic",
            Section::Hardware => "hardware",
            Section::Software => "software",
            Section::Patches => "patches",
            Section::Services => "services",
            Section::Security => "security",
            Section::Registry => "registry",
            Section::Accounts => "accounts",
            Section::Containers => "containers",
            Section::Network => "network",
        }
    }

    pub fn parse(s: &str) -> Option<Section> {
        Section::ALL.into_iter().find(|x| x.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Windows,
    Linux,
}

impl OsFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            OsFamily::Windows => "windows",
            OsFamily::Linux => "linux",
        }
    }

    pub fn parse(s: &str) -> Option<OsFamily> {
        [OsFamily::Windows, OsFamily::Linux]
            .into_iter()
            .find(|f| f.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub schema_version: u32,
    pub enroll_token: String,
    pub csr_pem: String,
    pub hostname: String,
    pub smbios_uuid: Option<String>,
    pub bios_serial: Option<String>,
    pub mac_addresses: Vec<String>,
    /// 舊版 Agent 沒有；缺少視為 windows，None 時不序列化
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_family: Option<OsFamily>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub device_id: Uuid,
    /// 裝置憑證 + 中繼 CA + 根 CA，PEM 串接
    pub certificate_chain_pem: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckinRequest {
    pub schema_version: u32,
    pub agent_version: String,
    #[serde(with = "timefmt::rfc3339")]
    pub boot_time: OffsetDateTime,
    pub logged_on_user: Option<String>,
    pub ip_addresses: Vec<String>,
    pub section_hashes: BTreeMap<Section, String>,
    pub section_errors: BTreeMap<Section, String>,
    /// 舊版 Agent 沒有；缺少視為 windows，None 時不序列化
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_family: Option<OsFamily>,
    /// Agent 本機設定的信任簽章公鑰（Base64）。伺服器只用來顯示與預先檢查
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signing_keys: Vec<String>,
    /// 本機事件日誌的 ID：重新安裝或日誌損毀時換新，伺服器用它分辨「序號歸零」與重送
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal_id: Option<Uuid>,
    /// 本機暫存的事件，最舊的在前，最多 [`MAX_EVENTS_PER_CHECKIN`] 筆。
    /// 只在伺服器表明支援（[`CheckinResponse::supports_events`]）後才送
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<AgentEvent>,
}

/// 每次報到最多送幾筆事件
pub const MAX_EVENTS_PER_CHECKIN: usize = 200;

/// Agent 在本機記下的事件（網路規格 §4.2）
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    /// 同一個日誌內遞增
    pub seq: u64,
    /// 端點的時間
    #[serde(with = "timefmt::rfc3339")]
    pub at: OffsetDateTime,
    /// [`AgentEvent::NET_UP`] 等
    pub kind: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl AgentEvent {
    /// Agent 啟動時的完整網卡清單（data 是 [`NetworkInfo`]）：伺服器以它為重播的起點
    pub const NET_SNAPSHOT: &'static str = "net.snapshot";
    /// 網卡啟用或新出現（data 是 [`NetInterface`]）
    pub const NET_UP: &'static str = "net.up";
    /// 網卡停用或消失（data 只有 name 與 kind）
    pub const NET_DOWN: &'static str = "net.down";
    /// 位址、閘道等改變（data 是 [`NetInterface`]）
    pub const NET_CHANGED: &'static str = "net.changed";
    /// 本機日誌超過上限刪掉了最舊的事件（data 是 `{"count": n}`）
    pub const JOURNAL_DROPPED: &'static str = "journal.dropped";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CollectionIntervals {
    pub software_secs: u32,
    pub patches_secs: u32,
    pub services_secs: u32,
    pub hardware_secs: u32,
    /// 舊版伺服器沒有這兩個欄位：預設每小時
    #[serde(default = "default_hourly")]
    pub security_secs: u32,
    #[serde(default = "default_hourly")]
    pub registry_secs: u32,
}

fn default_hourly() -> u32 {
    3600
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckinResponse {
    pub next_checkin_seconds: u32,
    pub request_sections: Vec<Section>,
    pub collection_intervals: CollectionIntervals,
    pub renew_certificate: bool,
    /// 伺服器要 Agent 讀取的登錄檔值（由啟用中的登錄檔規則彙總）
    #[serde(default)]
    pub registry_queries: Vec<RegistryQuery>,
    /// 查詢清單的雜湊；有這個欄位表示伺服器支援 security／registry 區段
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_queries_hash: Option<String>,
    /// 這台該執行的派送（期望狀態）
    #[serde(default)]
    pub deployments: Vec<deploy::Assignment>,
    /// 指派清單的雜湊；沒有代表伺服器不支援派送，Agent 不做任何派送
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployments_hash: Option<String>,
    /// 這台該套用的 Windows Update 原則；None 表示不受管
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_policy: Option<update::UpdatePolicy>,
    /// 原則的雜湊；沒有代表伺服器不支援，Agent 完全不動 WU 設定
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_policy_hash: Option<String>,
    /// 這台待執行的遠端指令（收到結果前每次報到都會重送）
    #[serde(default)]
    pub commands: Vec<command::Command>,
    /// 這台該向哪台分點快取下載套件；None 表示直接向中央下載
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_source: Option<branch::PackageSource>,
    /// 伺服器認得的區段名稱。用字串而不是 `Section`：舊版 Agent 看到不認得的值也不會解析失敗。
    /// 第三期以後新增的區段（containers 起），Agent 只在這裡列出時才回報。
    #[serde(default)]
    pub supported_sections: Vec<String>,
    /// 伺服器接受報到請求裡的 `events`；舊版伺服器沒有這個欄位
    #[serde(default)]
    pub supports_events: bool,
    /// 伺服器已存下的最大事件序號：Agent 收到後才刪除本機日誌中序號不大於它的事件
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events_ack: Option<u64>,
}

impl CheckinResponse {
    /// 伺服器是否認得這個區段
    pub fn supports(&self, s: Section) -> bool {
        self.supported_sections.iter().any(|x| x == s.as_str())
    }
}

impl Section {
    /// 需要伺服器在 [`CheckinResponse::supported_sections`] 明確列出才回報的區段
    pub fn needs_announcement(self) -> bool {
        matches!(self, Section::Containers | Section::Network)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BasicInfo {
    pub hostname: String,
    pub domain: Option<String>,
    pub is_domain_joined: bool,
    pub os_caption: String,
    pub os_build: String,
    /// 月更新小版號（登錄檔 UBR）；舊版 Agent 沒有。None 時不序列化，hash 與舊版一致。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_ubr: Option<u32>,
    /// Agent 在哪裡執行；舊版 Agent 沒有。None 時不序列化，hash 與舊版一致。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs_in: Option<RunsIn>,
}

/// Agent 的執行環境
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RunsIn {
    /// [`RunsIn::HOST`]、[`RunsIn::CONTAINER`]、[`RunsIn::WSL`]；用字串，新種類不會讓舊版伺服器解析失敗
    pub kind: String,
    /// host：虛擬化平台（`systemd-detect-virt --vm` 的名稱，`none` 是實體機）；
    /// container：容器種類（docker、podman、lxc…）；wsl：版本（1、2）。None 表示判斷不出來
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl RunsIn {
    pub const HOST: &'static str = "host";
    pub const CONTAINER: &'static str = "container";
    pub const WSL: &'static str = "wsl";

    pub fn new(kind: &str, detail: Option<&str>) -> RunsIn {
        RunsIn {
            kind: kind.to_string(),
            detail: detail.map(str::to_string),
        }
    }

    /// 容器或 WSL：硬體識別碼屬於所在的主機，不能拿來比對裝置
    pub fn is_guest(&self) -> bool {
        self.kind == RunsIn::CONTAINER || self.kind == RunsIn::WSL
    }
}

/// 由 DMI／WMI 的製造商與型號判斷虛擬化平台，名稱與 `systemd-detect-virt --vm` 相同。
/// 看不出是虛擬機時回 `none`（實體機）。
pub fn vm_from_vendor(manufacturer: &str, model: &str) -> &'static str {
    let m = manufacturer.to_ascii_lowercase();
    let p = model.to_ascii_lowercase();
    let has = |s: &str| m.contains(s) || p.contains(s);
    if has("vmware") {
        "vmware"
    } else if has("virtualbox") || m.contains("innotek") {
        "oracle"
    } else if m.contains("microsoft") && p.contains("virtual") {
        "microsoft"
    } else if has("qemu") {
        "qemu"
    } else if has("kvm") || p.contains("standard pc") {
        "kvm"
    } else if has("xen") {
        "xen"
    } else if has("parallels") {
        "parallels"
    } else if m.contains("amazon ec2") {
        "amazon"
    } else if m.contains("google") && p.contains("compute engine") {
        "google"
    } else if has("bochs") {
        "bochs"
    } else {
        "none"
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Disk {
    pub name: String,
    pub size_bytes: u64,
    pub free_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub cpu: Option<String>,
    pub ram_mb: u64,
    pub disks: Vec<Disk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X64,
    X86,
    /// 安裝在使用者層級（HKU）
    User,
    /// 其他架構（Linux 的 arm64 等）
    Other,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
            Arch::User => "user",
            Arch::Other => "other",
        }
    }

    pub fn parse(s: &str) -> Option<Arch> {
        [Arch::X64, Arch::X86, Arch::User, Arch::Other]
            .into_iter()
            .find(|a| a.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SoftwareItem {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub arch: Arch,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PatchItem {
    pub kb: String,
    pub installed_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ServiceItem {
    pub name: String,
    pub display_name: Option<String>,
    pub start_mode: String,
    pub state: String,
    pub binary_path: Option<String>,
}

/// Agent 端一次最多讀取的登錄檔值（硬上限；伺服器的設定上限不會超過這個數字）
pub const MAX_REGISTRY_VALUES: usize = 5000;

/// 單一項安全資訊的收集結果：失敗時帶錯誤訊息，不影響其他項
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Probe<T> {
    Ok(T),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FirewallInfo {
    pub domain: bool,
    pub private: bool,
    pub public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct VolumeInfo {
    pub drive: String,
    pub is_system: bool,
    pub protected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DefenderInfo {
    /// Defender 是作用中的防毒（被第三方防毒取代時為 false）
    pub active: bool,
    pub realtime: bool,
    pub tamper: bool,
    #[serde(with = "timefmt::rfc3339_option", default)]
    pub signature_updated: Option<OffsetDateTime>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: u32,
    /// 0 表示永不過期
    pub max_age_days: u32,
    /// 0 表示不鎖定
    pub lockout_threshold: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountInfo {
    pub name: String,
    pub sid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SecurityInfo {
    pub firewall: Probe<FirewallInfo>,
    pub bitlocker: Probe<Vec<VolumeInfo>>,
    pub defender: Probe<DefenderInfo>,
    pub password: Probe<PasswordPolicy>,
    pub admins: Probe<Vec<AccountInfo>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RegistryQuery {
    pub path: String,
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegState {
    Present,
    Absent,
    /// 被 Agent 的拒絕清單擋下，沒有讀取
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegKind {
    Dword,
    Qword,
    String,
    ExpandString,
    MultiString,
    Binary,
    Other,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RegistryValue {
    pub path: String,
    pub name: String,
    pub state: RegState,
    pub kind: RegKind,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LocalUser {
    pub name: String,
    pub uid: u32,
    pub shell: String,
    /// None = 讀不到（沒有 shadow 權限）
    pub locked: Option<bool>,
    #[serde(with = "timefmt::date_option", default)]
    pub password_changed: Option<time::Date>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrincipalKind {
    User,
    Group,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PrivilegeEntry {
    pub principal: String,
    pub kind: PrincipalKind,
    /// 來源檔，例如 /etc/sudoers.d/foo
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountsInfo {
    pub users: Vec<LocalUser>,
    /// 不列出的系統帳號數量
    pub system_user_count: u32,
    pub privileged: Vec<PrivilegeEntry>,
    /// 解析不了的 sudoers 行
    pub sudoers_unparsed: Vec<String>,
}

/// 每台最多回報的容器數（執行中的優先）
pub const MAX_CONTAINERS: usize = 500;

/// 主機上的容器執行環境與容器（Linux）
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContainersInfo {
    pub runtimes: Vec<RuntimeInfo>,
    pub containers: Vec<ContainerItem>,
    /// 超過 [`MAX_CONTAINERS`] 被截斷
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RuntimeInfo {
    /// docker | podman（之後加入 containerd、lxc、incus）
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// 指令存在但讀取失敗（例如 daemon 沒有啟動）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// 一個容器。不含環境變數、啟動參數與標籤（常含密碼）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContainerItem {
    pub runtime: String,
    /// 前 12 碼
    pub id: String,
    pub name: String,
    /// 原樣，例如 `nginx:1.27`、`registry.example.com/app@sha256:…`
    pub image: String,
    /// 映像 ID（`sha256:…`）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,
    /// running | paused | restarting | exited | created | dead…（執行環境的原始值，小寫）
    pub state: String,
    /// healthy | unhealthy | starting
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
    #[serde(with = "timefmt::rfc3339_option", default)]
    pub created_at: Option<time::OffsetDateTime>,
    #[serde(with = "timefmt::rfc3339_option", default)]
    pub started_at: Option<time::OffsetDateTime>,
    #[serde(with = "timefmt::rfc3339_option", default)]
    pub finished_at: Option<time::OffsetDateTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<String>,
    /// 讀不到時 None
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_network: Option<bool>,
    /// `0.0.0.0:8080->80/tcp`
    #[serde(default)]
    pub ports: Vec<String>,
    /// bind mount 的主機路徑
    #[serde(default)]
    pub host_mounts: Vec<String>,
    /// rootless Podman 的使用者
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
}

impl ContainerItem {
    /// 執行中（含暫停與重新啟動中）
    pub fn is_running(&self) -> bool {
        matches!(self.state.as_str(), "running" | "paused" | "restarting")
    }
}

/// 每台最多回報的網卡數
pub const MAX_INTERFACES: usize = 256;

/// 每張網卡（network 區段）
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub interfaces: Vec<NetInterface>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NetInterface {
    /// Windows 的別名（「乙太網路」）或 Linux 的 eth0
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// [`NetInterface::ETHERNET`] 等。用字串：之後新增種類時舊版伺服器也能解析
    pub kind: String,
    pub up: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// CIDR 寫法：10.1.2.3/24
    #[serde(default)]
    pub addresses: Vec<String>,
    /// 這張網卡上的預設閘道
    #[serde(default)]
    pub gateways: Vec<String>,
    #[serde(default)]
    pub dns: Vec<String>,
    /// Wi-Fi 才有，讀不到就 None
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
}

impl NetInterface {
    pub const ETHERNET: &'static str = "ethernet";
    pub const WIFI: &'static str = "wifi";
    pub const CELLULAR: &'static str = "cellular";
    pub const VPN: &'static str = "vpn";
    pub const VIRTUAL: &'static str = "virtual";
    pub const LOOPBACK: &'static str = "loopback";
    pub const OTHER: &'static str = "other";

    /// 啟用中、有預設閘道、不是虛擬／VPN／loopback 的網卡（多重連線條件 1 的「對外路徑」）
    pub fn is_uplink(&self) -> bool {
        self.up
            && !self.gateways.is_empty()
            && !matches!(
                self.kind.as_str(),
                Self::VIRTUAL | Self::LOOPBACK | Self::VPN
            )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "section", content = "data", rename_all = "lowercase")]
pub enum InventoryPayload {
    Basic(BasicInfo),
    Hardware(HardwareInfo),
    Software(Vec<SoftwareItem>),
    Patches(Vec<PatchItem>),
    Services(Vec<ServiceItem>),
    Security(SecurityInfo),
    Registry(Vec<RegistryValue>),
    Accounts(AccountsInfo),
    Containers(ContainersInfo),
    Network(NetworkInfo),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InventoryUpload {
    pub schema_version: u32,
    #[serde(flatten)]
    pub payload: InventoryPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RenewRequest {
    pub csr_pem: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RenewResponse {
    pub certificate_chain_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("string too long: {len} chars")]
    StringTooLong { len: usize },
    #[error("too many items: {count}")]
    TooManyItems { count: usize },
    /// PostgreSQL 的 text／jsonb 都不接受 U+0000；Agent 需先移除。
    #[error("string contains NUL character")]
    NulCharacter,
}

impl InventoryPayload {
    pub fn section(&self) -> Section {
        match self {
            InventoryPayload::Basic(_) => Section::Basic,
            InventoryPayload::Hardware(_) => Section::Hardware,
            InventoryPayload::Software(_) => Section::Software,
            InventoryPayload::Patches(_) => Section::Patches,
            InventoryPayload::Services(_) => Section::Services,
            InventoryPayload::Security(_) => Section::Security,
            InventoryPayload::Registry(_) => Section::Registry,
            InventoryPayload::Accounts(_) => Section::Accounts,
            InventoryPayload::Containers(_) => Section::Containers,
            InventoryPayload::Network(_) => Section::Network,
        }
    }

    /// 排序所有清單，讓相同內容產生相同的序列化結果。
    pub fn normalize(&mut self) {
        match self {
            InventoryPayload::Basic(_) => {}
            InventoryPayload::Hardware(h) => h.disks.sort(),
            InventoryPayload::Software(v) => v.sort(),
            InventoryPayload::Patches(v) => v.sort(),
            InventoryPayload::Services(v) => v.sort(),
            InventoryPayload::Security(s) => {
                if let Probe::Ok(v) = &mut s.bitlocker {
                    v.sort();
                }
                if let Probe::Ok(v) = &mut s.admins {
                    v.sort();
                }
            }
            InventoryPayload::Registry(v) => v.sort(),
            InventoryPayload::Accounts(a) => {
                a.users.sort();
                a.privileged.sort();
                a.sudoers_unparsed.sort();
            }
            InventoryPayload::Containers(c) => {
                c.runtimes.sort();
                c.containers.sort();
                for x in &mut c.containers {
                    x.ports.sort();
                    x.host_mounts.sort();
                }
            }
            // DNS 的順序有意義（先問哪一台），不排序
            InventoryPayload::Network(n) => {
                n.interfaces.sort();
                for i in &mut n.interfaces {
                    i.addresses.sort();
                    i.gateways.sort();
                }
            }
        }
    }

    /// 正規化後 JSON 的 SHA-256（小寫 hex）。Agent 與伺服器都用這個函式。
    pub fn canonical_hash(&self) -> String {
        let mut c = self.clone();
        c.normalize();
        let bytes = serde_json::to_vec(&c).expect("payload serializes");
        hex::encode(Sha256::digest(&bytes))
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        let count = match self {
            InventoryPayload::Basic(_) => 1,
            InventoryPayload::Hardware(h) => h.disks.len(),
            InventoryPayload::Software(v) => v.len(),
            InventoryPayload::Patches(v) => v.len(),
            InventoryPayload::Services(v) => v.len(),
            InventoryPayload::Security(_) => 1,
            InventoryPayload::Registry(v) => {
                if v.len() > MAX_REGISTRY_VALUES {
                    return Err(ValidationError::TooManyItems { count: v.len() });
                }
                v.len()
            }
            InventoryPayload::Accounts(a) => {
                a.users.len() + a.privileged.len() + a.sudoers_unparsed.len()
            }
            InventoryPayload::Containers(c) => {
                if c.containers.len() > MAX_CONTAINERS {
                    return Err(ValidationError::TooManyItems {
                        count: c.containers.len(),
                    });
                }
                c.runtimes.len()
                    + c.containers
                        .iter()
                        .map(|x| 1 + x.ports.len() + x.host_mounts.len())
                        .sum::<usize>()
            }
            InventoryPayload::Network(n) => {
                if n.interfaces.len() > MAX_INTERFACES {
                    return Err(ValidationError::TooManyItems {
                        count: n.interfaces.len(),
                    });
                }
                n.interfaces
                    .iter()
                    .map(|i| 1 + i.addresses.len() + i.gateways.len() + i.dns.len())
                    .sum::<usize>()
            }
        };
        if count > MAX_ITEMS {
            return Err(ValidationError::TooManyItems { count });
        }
        validate_strings(self)
    }
}

/// 檢查任意可序列化值中所有字串（含 map key）不超過 MAX_STRING_LEN 字元、不含 NUL。
pub fn validate_strings<T: Serialize>(value: &T) -> Result<(), ValidationError> {
    fn walk(v: &serde_json::Value) -> Result<(), ValidationError> {
        match v {
            serde_json::Value::String(s) => check(s),
            serde_json::Value::Array(a) => a.iter().try_for_each(walk),
            serde_json::Value::Object(o) => o.iter().try_for_each(|(k, v)| {
                check(k)?;
                walk(v)
            }),
            _ => Ok(()),
        }
    }
    fn check(s: &str) -> Result<(), ValidationError> {
        if s.contains(' ') {
            return Err(ValidationError::NulCharacter);
        }
        let len = s.chars().count();
        if len > MAX_STRING_LEN {
            Err(ValidationError::StringTooLong { len })
        } else {
            Ok(())
        }
    }
    walk(&serde_json::to_value(value).expect("value serializes"))
}

/// 64 位十六進位字元（套件以 sha256 為檔名，格式不對的不能拿來組路徑）
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// 寫入 `<path>.tmp` 並 fsync 後再 rename：斷電時不會留下寫一半或內容為零的檔案。
/// 暫存檔一律重新建立（不沿用可能被他人預先建立、帶著其他擁有者的檔案）。
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkin(os_family: Option<OsFamily>) -> CheckinRequest {
        CheckinRequest {
            schema_version: SCHEMA_VERSION,
            agent_version: "1".into(),
            boot_time: OffsetDateTime::UNIX_EPOCH,
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: BTreeMap::new(),
            section_errors: BTreeMap::new(),
            os_family,
            signing_keys: vec![],
            journal_id: None,
            events: vec![],
        }
    }

    #[test]
    fn events_are_optional_on_the_wire() {
        // 沒有事件時不序列化，舊版伺服器看到的請求與以前相同
        let v = serde_json::to_value(checkin(None)).unwrap();
        assert!(v.get("events").is_none() && v.get("journal_id").is_none());
        let mut r = checkin(None);
        r.journal_id = Some(Uuid::nil());
        r.events = vec![AgentEvent {
            seq: 7,
            at: OffsetDateTime::UNIX_EPOCH,
            kind: AgentEvent::NET_UP.into(),
            data: serde_json::json!({"name": "eth0"}),
        }];
        let back: CheckinRequest =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        // 舊版伺服器的回應：不支援事件，沒有確認
        let resp: CheckinResponse = serde_json::from_value(serde_json::json!({
            "next_checkin_seconds": 60, "request_sections": [], "renew_certificate": false,
            "collection_intervals": {"software_secs": 1, "patches_secs": 1,
                                     "services_secs": 1, "hardware_secs": 1}
        }))
        .unwrap();
        assert!(!resp.supports_events && resp.events_ack.is_none());
    }

    #[test]
    fn os_family_absent_serializes_like_legacy() {
        let r = checkin(None);
        assert!(serde_json::to_value(&r).unwrap().get("os_family").is_none());
        let linux = checkin(Some(OsFamily::Linux));
        assert_eq!(serde_json::to_value(&linux).unwrap()["os_family"], "linux");
        assert_eq!(OsFamily::parse("windows"), Some(OsFamily::Windows));
    }

    #[test]
    fn section_lists() {
        assert_eq!(Section::parse("accounts"), Some(Section::Accounts));
        assert!(!Section::WINDOWS.contains(&Section::Accounts));
        assert!(!Section::LINUX.contains(&Section::Registry));
        assert_eq!(Section::ALL.len(), 10);
        assert!(!Section::WINDOWS.contains(&Section::Containers));
        assert!(Section::WINDOWS.contains(&Section::Network));
        assert!(Section::LINUX.contains(&Section::Network));
        assert!(Section::Network.needs_announcement());
        assert_eq!(Section::parse("network"), Some(Section::Network));
    }

    fn accounts(rev: bool) -> InventoryPayload {
        let mut users = vec![
            LocalUser {
                name: "a".into(),
                uid: 1000,
                shell: "/bin/sh".into(),
                locked: None,
                password_changed: None,
            },
            LocalUser {
                name: "b".into(),
                uid: 1001,
                shell: "/bin/sh".into(),
                locked: Some(true),
                password_changed: Some(time::macros::date!(2026 - 01 - 02)),
            },
        ];
        let mut privileged = vec![
            PrivilegeEntry {
                principal: "a".into(),
                kind: PrincipalKind::User,
                source: "/etc/sudoers".into(),
            },
            PrivilegeEntry {
                principal: "wheel".into(),
                kind: PrincipalKind::Group,
                source: "/etc/sudoers".into(),
            },
        ];
        let mut un = vec!["x".to_string(), "y".to_string()];
        if rev {
            users.reverse();
            privileged.reverse();
            un.reverse();
        }
        InventoryPayload::Accounts(AccountsInfo {
            users,
            system_user_count: 3,
            privileged,
            sudoers_unparsed: un,
        })
    }

    #[test]
    fn accounts_hash_ignores_order() {
        assert_eq!(
            accounts(false).canonical_hash(),
            accounts(true).canonical_hash()
        );
        assert_eq!(accounts(false).section(), Section::Accounts);
        accounts(false).validate().unwrap();
    }

    #[test]
    fn arch_other_round_trips() {
        assert_eq!(Arch::parse("other"), Some(Arch::Other));
        assert_eq!(Arch::Other.as_str(), "other");
    }

    fn sw(name: &str, ver: &str) -> SoftwareItem {
        SoftwareItem {
            name: name.into(),
            version: Some(ver.into()),
            publisher: None,
            install_date: None,
            arch: Arch::X64,
        }
    }

    fn basic(ubr: Option<u32>) -> InventoryPayload {
        InventoryPayload::Basic(BasicInfo {
            hostname: "PC1".into(),
            domain: None,
            is_domain_joined: false,
            os_caption: "Windows 11".into(),
            os_build: "22631".into(),
            os_ubr: ubr,
            runs_in: None,
        })
    }

    #[test]
    fn runs_in_is_optional_and_hashed() {
        let mut b = match basic(None) {
            InventoryPayload::Basic(b) => b,
            _ => unreachable!(),
        };
        b.runs_in = Some(RunsIn::new(RunsIn::CONTAINER, Some("docker")));
        let p = InventoryPayload::Basic(b);
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["data"]["runs_in"]["kind"], "container");
        assert_ne!(p.canonical_hash(), basic(None).canonical_hash());
        let back: InventoryPayload = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
        let host = RunsIn::new(RunsIn::HOST, None);
        assert!(!host.is_guest());
        assert!(RunsIn::new(RunsIn::WSL, Some("2")).is_guest());
        assert!(serde_json::to_value(&host).unwrap().get("detail").is_none());
    }

    #[test]
    fn vm_vendor_table() {
        for (mf, model, want) in [
            ("VMware, Inc.", "VMware7,1", "vmware"),
            ("innotek GmbH", "VirtualBox", "oracle"),
            ("Microsoft Corporation", "Virtual Machine", "microsoft"),
            ("Microsoft Corporation", "Surface Laptop 5", "none"),
            ("QEMU", "Standard PC (Q35 + ICH9, 2009)", "qemu"),
            ("Red Hat", "KVM", "kvm"),
            ("", "Standard PC (i440FX + PIIX, 1996)", "kvm"),
            ("Xen", "HVM domU", "xen"),
            (
                "Parallels Software International Inc.",
                "Parallels Virtual Platform",
                "parallels",
            ),
            ("Amazon EC2", "m5.large", "amazon"),
            ("Google", "Google Compute Engine", "google"),
            ("Bochs", "Bochs", "bochs"),
            ("Dell Inc.", "OptiPlex 7090", "none"),
        ] {
            assert_eq!(vm_from_vendor(mf, model), want, "{mf} / {model}");
        }
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
        assert_ne!(
            basic(Some(4317)).canonical_hash(),
            basic(None).canonical_hash()
        );
    }

    #[test]
    fn old_checkin_response_still_parses_and_new_fields_default() {
        let v = serde_json::json!({
            "next_checkin_seconds": 60, "request_sections": ["basic"],
            "collection_intervals": {"software_secs": 1, "patches_secs": 1,
                                     "services_secs": 1, "hardware_secs": 1},
            "renew_certificate": false
        });
        let r: CheckinResponse = serde_json::from_value(v).unwrap();
        assert!(r.registry_queries.is_empty() && r.registry_queries_hash.is_none());
        assert_eq!(
            (
                r.collection_intervals.security_secs,
                r.collection_intervals.registry_secs
            ),
            (3600, 3600)
        );
        // 0.11.0 以前的伺服器沒有 supported_sections：不支援任何需要宣告的區段
        assert!(r.supported_sections.is_empty() && !r.supports(Section::Containers));
        let mut r = r;
        r.supported_sections = vec!["containers".into(), "future".into()];
        assert!(r.supports(Section::Containers));
        assert!(
            Section::Containers.needs_announcement() && !Section::Accounts.needs_announcement()
        );
        assert_eq!(Section::parse("containers"), Some(Section::Containers));
    }

    fn container(name: &str) -> ContainerItem {
        ContainerItem {
            runtime: "docker".into(),
            id: "0123456789ab".into(),
            name: name.into(),
            image: "nginx".into(),
            image_id: None,
            state: "running".into(),
            health: None,
            created_at: None,
            started_at: None,
            finished_at: None,
            restart_policy: None,
            privileged: None,
            host_network: None,
            ports: vec!["b".into(), "a".into()],
            host_mounts: vec![],
            owner: None,
        }
    }

    fn nic(name: &str, kind: &str, gw: bool) -> NetInterface {
        NetInterface {
            name: name.into(),
            description: None,
            kind: kind.into(),
            up: true,
            mac: None,
            addresses: vec!["10.0.0.9/24".into(), "10.0.0.2/24".into()],
            gateways: if gw { vec!["10.0.0.1".into()] } else { vec![] },
            dns: vec!["8.8.8.8".into(), "1.1.1.1".into()],
            ssid: None,
        }
    }

    #[test]
    fn network_normalize_limits_and_uplink() {
        let p = |v: Vec<NetInterface>| InventoryPayload::Network(NetworkInfo { interfaces: v });
        let a = p(vec![nic("a", "ethernet", true), nic("b", "wifi", false)]);
        let mut b0 = nic("a", "ethernet", true);
        b0.addresses.reverse();
        let b = p(vec![nic("b", "wifi", false), b0]);
        assert_eq!(a.canonical_hash(), b.canonical_hash());
        // DNS 順序不同就是不同的設定
        let mut c0 = nic("a", "ethernet", true);
        c0.dns.reverse();
        let c = p(vec![c0, nic("b", "wifi", false)]);
        assert_ne!(a.canonical_hash(), c.canonical_hash());
        assert_eq!(a.section(), Section::Network);
        assert_eq!(a.validate(), Ok(()));
        let too_many = p((0..=MAX_INTERFACES)
            .map(|i| nic(&i.to_string(), "ethernet", false))
            .collect());
        assert!(matches!(
            too_many.validate(),
            Err(ValidationError::TooManyItems { .. })
        ));

        assert!(nic("a", NetInterface::ETHERNET, true).is_uplink());
        assert!(nic("a", NetInterface::CELLULAR, true).is_uplink());
        assert!(!nic("a", NetInterface::ETHERNET, false).is_uplink());
        assert!(!nic("a", NetInterface::VPN, true).is_uplink());
        assert!(!nic("a", NetInterface::VIRTUAL, true).is_uplink());
        let mut down = nic("a", NetInterface::WIFI, true);
        down.up = false;
        assert!(!down.is_uplink());
    }

    #[test]
    fn containers_normalize_and_limits() {
        let p = |v: Vec<ContainerItem>| {
            InventoryPayload::Containers(ContainersInfo {
                runtimes: vec![],
                containers: v,
                truncated: false,
            })
        };
        // 順序不同、連接埠順序不同，hash 相同
        let a = p(vec![container("x"), container("y")]);
        let mut y = container("y");
        y.ports.reverse();
        let b = p(vec![y, container("x")]);
        assert_eq!(a.canonical_hash(), b.canonical_hash());
        assert_eq!(a.section(), Section::Containers);
        assert_eq!(a.validate(), Ok(()));
        let too_many = p((0..=MAX_CONTAINERS)
            .map(|i| container(&i.to_string()))
            .collect());
        assert!(matches!(
            too_many.validate(),
            Err(ValidationError::TooManyItems { .. })
        ));
        let mut stopped = container("s");
        stopped.state = "exited".into();
        assert!(container("r").is_running() && !stopped.is_running());
        // 沒有選填欄位時不序列化
        let v = serde_json::to_value(container("x")).unwrap();
        assert!(v.get("health").is_none() && v.get("owner").is_none(), "{v}");
    }

    #[test]
    fn security_probe_serializes_as_ok_or_error() {
        let p: Probe<FirewallInfo> = Probe::Error("boom".into());
        assert_eq!(
            serde_json::to_value(&p).unwrap(),
            serde_json::json!({"error": "boom"})
        );
        let p = Probe::Ok(FirewallInfo {
            domain: true,
            private: false,
            public: true,
        });
        assert_eq!(serde_json::to_value(&p).unwrap()["ok"]["private"], false);
        assert_eq!(
            serde_json::to_value(RegKind::ExpandString).unwrap(),
            "expand_string"
        );
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

    #[test]
    fn hash_is_independent_of_item_order() {
        let a = InventoryPayload::Software(vec![sw("A", "1"), sw("B", "2")]);
        let b = InventoryPayload::Software(vec![sw("B", "2"), sw("A", "1")]);
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn hash_changes_when_version_changes() {
        let a = InventoryPayload::Software(vec![sw("A", "1")]);
        let b = InventoryPayload::Software(vec![sw("A", "2")]);
        assert_ne!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let h = InventoryPayload::Patches(vec![]).canonical_hash();
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn validate_rejects_long_string() {
        let p = InventoryPayload::Software(vec![sw(&"x".repeat(MAX_STRING_LEN + 1), "1")]);
        assert_eq!(
            p.validate(),
            Err(ValidationError::StringTooLong {
                len: MAX_STRING_LEN + 1
            })
        );
    }

    #[test]
    fn validate_rejects_nul() {
        let p = InventoryPayload::Software(vec![sw("bad\0name", "1")]);
        assert_eq!(p.validate(), Err(ValidationError::NulCharacter));
    }

    #[test]
    fn validate_counts_chars_not_bytes() {
        // 1024 個中文字 = 3072 bytes，仍應通過
        let p = InventoryPayload::Software(vec![sw(&"軟".repeat(MAX_STRING_LEN), "1")]);
        assert_eq!(p.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_too_many_items() {
        let items = (0..=MAX_ITEMS).map(|i| sw(&i.to_string(), "1")).collect();
        assert_eq!(
            InventoryPayload::Software(items).validate(),
            Err(ValidationError::TooManyItems {
                count: MAX_ITEMS + 1
            })
        );
    }

    #[test]
    fn upload_serializes_with_section_tag() {
        let u = InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: InventoryPayload::Patches(vec![PatchItem {
                kb: "KB500".into(),
                installed_on: None,
            }]),
        };
        let v = serde_json::to_value(&u).unwrap();
        assert_eq!(v["section"], "patches");
        assert_eq!(v["data"][0]["kb"], "KB500");
        assert_eq!(v["schema_version"], 1);
    }

    #[test]
    fn section_parse_roundtrip() {
        for s in Section::ALL {
            assert_eq!(Section::parse(s.as_str()), Some(s));
        }
        assert_eq!(Section::parse("nope"), None);
    }
}
