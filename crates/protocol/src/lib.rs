//! Agent 與伺服器之間的共用訊息格式。

pub mod deploy;
pub mod matcher;
pub mod regpath;
pub mod update;

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
}

impl Section {
    pub const ALL: [Section; 7] = [
        Section::Basic,
        Section::Hardware,
        Section::Software,
        Section::Patches,
        Section::Services,
        Section::Security,
        Section::Registry,
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
        }
    }

    pub fn parse(s: &str) -> Option<Section> {
        Section::ALL.into_iter().find(|x| x.as_str() == s)
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
    pub boot_time: DateTime<Utc>,
    pub logged_on_user: Option<String>,
    pub ip_addresses: Vec<String>,
    pub section_hashes: BTreeMap<Section, String>,
    pub section_errors: BTreeMap<Section, String>,
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
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::X86 => "x86",
            Arch::User => "user",
        }
    }

    pub fn parse(s: &str) -> Option<Arch> {
        [Arch::X64, Arch::X86, Arch::User]
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
    pub signature_updated: Option<DateTime<Utc>>,
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

#[cfg(test)]
mod tests {
    use super::*;

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
