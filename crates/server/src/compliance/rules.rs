//! 規則：參數解析與驗證、編譯後的比對條件、套用範圍。

use serde::Deserialize;
use serde_json::{Value, json};

use super::matcher::Glob;

pub const MAX_PATTERN_LEN: usize = 256;

pub const KINDS: [&str; 15] = [
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
];

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
