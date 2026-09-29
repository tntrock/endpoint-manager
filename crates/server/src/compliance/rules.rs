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
        RuleSet {
            generation: -1,
            rules: vec![],
        }
    }
}

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
