//! 評估：純函式，不碰資料庫。

use std::cmp::Ordering;
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use protocol::{Probe, RegKind, RegState, RegistryValue, SecurityInfo};
use serde_json::{Value, json};

use super::matcher::{Glob, cmp_version};
pub use super::rules::registry_key;
use super::rules::{Check, RegOp, RuleSet, parse_number};

/// 支援 security／registry 區段的最低 Agent 版本：更舊的版本沒有這些資料時，未知原因寫「版本過舊」
pub const CONFIG_AGENT_VERSION: &str = "0.3.0";

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
    pub security: Option<SecurityInfo>,
    /// 鍵為 registry_key(path, name)
    pub registry: Option<HashMap<(String, String), RegistryValue>>,
    pub services: Option<Vec<ServiceFact>>,
    pub agent_version: Option<String>,
    /// Agent 回報的 Windows Update 狀態（None：從未回報）
    pub update_status: Option<UpdateFact>,
    /// 評估時的「現在」（病毒碼天數用）：由呼叫端提供，評估本身維持純函式
    pub now: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UpdateFact {
    /// applied／conflict／error／unmanaged
    pub state: String,
    pub detail: String,
    pub reboot_pending: bool,
    pub reboot_pending_since: Option<DateTime<Utc>>,
    pub last_patch_date: Option<chrono::NaiveDate>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceFact {
    pub name: String,
    pub start_mode: String,
    pub state: String,
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

fn older(s: &SoftwareFact, than: &str) -> bool {
    s.version
        .as_deref()
        .is_some_and(|v| cmp_version(v, than) == Ordering::Less)
}

/// security／registry 區段沒有資料：Agent 太舊就註明版本過舊，否則是尚未收到
fn missing_config(f: &DeviceFacts) -> Option<(Status, Value)> {
    let outdated = f
        .agent_version
        .as_deref()
        .is_none_or(|v| cmp_version(v, CONFIG_AGENT_VERSION) == Ordering::Less);
    if outdated {
        Some((Status::Unknown, json!({"reason": "agent_outdated"})))
    } else {
        no_data()
    }
}

/// 取出 security 區段的某一項；沒資料或收集失敗時回對應的「未知」結果
fn probe<'a, T>(
    f: &'a DeviceFacts,
    pick: impl FnOnce(&'a SecurityInfo) -> &'a Probe<T>,
) -> Result<&'a T, Option<(Status, Value)>> {
    let Some(sec) = &f.security else {
        return Err(missing_config(f));
    };
    match pick(sec) {
        Probe::Ok(v) => Ok(v),
        Probe::Error(e) => Err(Some((
            Status::Unknown,
            json!({"reason": "probe_error", "error": e}),
        ))),
    }
}

fn service_detail(s: &ServiceFact) -> (Status, Value) {
    (
        Status::Violating,
        json!({"service": s.name, "start_mode": s.start_mode, "state": s.state}),
    )
}

fn registry_check(
    v: &RegistryValue,
    label: &str,
    op: RegOp,
    expected: Option<&str>,
    absent_ok: bool,
) -> Option<(Status, Value)> {
    match v.state {
        RegState::Denied => {
            return Some((
                Status::Unknown,
                json!({"reason": "denied", "registry": label}),
            ));
        }
        RegState::Absent => {
            return match op {
                RegOp::NotExists => None,
                RegOp::Exists => Some((
                    Status::Violating,
                    json!({"registry": label, "reason": "absent"}),
                )),
                _ if absent_ok => None,
                _ => Some((
                    Status::Violating,
                    json!({"registry": label, "reason": "absent"}),
                )),
            };
        }
        RegState::Present => {}
    }
    let expected = expected.unwrap_or("");
    let numeric = matches!(v.kind, RegKind::Dword | RegKind::Qword);
    let nums = (parse_number(&v.data), parse_number(expected));
    let ok = match op {
        RegOp::Exists => true,
        RegOp::NotExists => false,
        RegOp::Contains => v.data.to_lowercase().contains(&expected.to_lowercase()),
        RegOp::Gte | RegOp::Lte => {
            let (Some(a), Some(b)) = nums else {
                return Some((
                    Status::Unknown,
                    json!({"reason": "not_numeric", "registry": label, "actual": v.data}),
                ));
            };
            if op == RegOp::Gte { a >= b } else { a <= b }
        }
        RegOp::Equals | RegOp::NotEquals => {
            let same = match nums {
                (Some(a), Some(b)) if numeric => a == b,
                _ => {
                    v.data.eq_ignore_ascii_case(expected)
                        || v.data.to_lowercase() == expected.to_lowercase()
                }
            };
            if op == RegOp::Equals { same } else { !same }
        }
    };
    if ok {
        return None;
    }
    let mut d = json!({"registry": label, "op": op.as_str(), "actual": v.data});
    if op.needs_expected() {
        d["expected"] = json!(expected);
    }
    Some((Status::Violating, d))
}

fn check_one(c: &Check, f: &DeviceFacts) -> Option<(Status, Value)> {
    match c {
        Check::PatchAge { max_days } => {
            let Some(u) = &f.update_status else {
                return no_data();
            };
            let Some(last) = u.last_patch_date else {
                return Some((Status::Unknown, json!({"reason": "no_patch_date"})));
            };
            let days = (f.now.date_naive() - last).num_days();
            (days > i64::from(*max_days)).then(|| {
                (
                    Status::Violating,
                    json!({"last_patch_date": last.to_string(), "days": days}),
                )
            })
        }
        Check::RebootPending { max_days } => {
            let Some(u) = &f.update_status else {
                return no_data();
            };
            // 沒有起始時間無法判斷天數：不算違規
            let since = u.reboot_pending_since.filter(|_| u.reboot_pending)?;
            let days = (f.now - since).num_days();
            (days > i64::from(*max_days)).then(|| {
                (
                    Status::Violating,
                    json!({"reboot_pending_since": since.to_rfc3339(), "days": days}),
                )
            })
        }
        Check::UpdatePolicy => {
            let Some(u) = &f.update_status else {
                return no_data();
            };
            matches!(u.state.as_str(), "conflict" | "error").then(|| {
                (
                    Status::Violating,
                    json!({"update_state": u.state, "update_detail": u.detail}),
                )
            })
        }
        Check::RegistryValue {
            path,
            name,
            key,
            op,
            expected,
            absent_ok,
        } => {
            let Some(reg) = &f.registry else {
                return missing_config(f);
            };
            let label = format!("{path}\\{name}");
            let Some(v) = reg.get(key) else {
                return Some((
                    Status::Unknown,
                    json!({"reason": "not_collected", "registry": label}),
                ));
            };
            registry_check(v, &label, *op, expected.as_deref(), *absent_ok)
        }
        Check::ServiceState {
            name,
            require_running,
        } => {
            let Some(services) = &f.services else {
                return no_data();
            };
            let svc = services.iter().find(|s| s.name.eq_ignore_ascii_case(name));
            let disabled = |s: &ServiceFact| s.start_mode.eq_ignore_ascii_case("Disabled");
            match (svc, require_running) {
                (None, false) => None,
                (None, true) => Some((
                    Status::Violating,
                    json!({"reason": "not_installed", "service": name}),
                )),
                (Some(s), false) => (!disabled(s)).then(|| service_detail(s)),
                (Some(s), true) => (disabled(s) || !s.state.eq_ignore_ascii_case("Running"))
                    .then(|| service_detail(s)),
            }
        }
        Check::Firewall {
            domain,
            private,
            public,
        } => {
            let fw = match probe(f, |s| &s.firewall) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let off: Vec<&str> = [
                ("domain", *domain, fw.domain),
                ("private", *private, fw.private),
                ("public", *public, fw.public),
            ]
            .into_iter()
            .filter(|(_, required, on)| *required && !on)
            .map(|(n, _, _)| n)
            .collect();
            (!off.is_empty()).then(|| (Status::Violating, json!({"profiles_off": off})))
        }
        Check::Bitlocker { all_fixed } => {
            let vols = match probe(f, |s| &s.bitlocker) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let in_scope: Vec<_> = vols.iter().filter(|v| *all_fixed || v.is_system).collect();
            if in_scope.is_empty() {
                return Some((Status::Violating, json!({"reason": "no_system_volume"})));
            }
            let bad: Vec<&str> = in_scope
                .iter()
                .filter(|v| !v.protected)
                .map(|v| v.drive.as_str())
                .collect();
            (!bad.is_empty()).then(|| (Status::Violating, json!({"drives": bad})))
        }
        Check::Defender {
            realtime,
            max_signature_age_days,
            tamper,
        } => {
            let d = match probe(f, |s| &s.defender) {
                Ok(v) => v,
                Err(u) => return u,
            };
            if !d.active {
                return Some((Status::Unknown, json!({"reason": "defender_inactive"})));
            }
            let mut failed = vec![];
            let mut detail = serde_json::Map::new();
            if *realtime && !d.realtime {
                failed.push("realtime");
            }
            if *tamper && !d.tamper {
                failed.push("tamper");
            }
            // 病毒碼日期未知不能蓋掉其他已確定的違規：先看其他項，全部通過才回報未知
            let mut signature_unknown = false;
            if let Some(max) = max_signature_age_days {
                match d.signature_updated {
                    None => signature_unknown = true,
                    Some(updated) => {
                        let age = (f.now - updated).num_days().max(0);
                        if age > i64::from(*max) {
                            failed.push("signature");
                            detail.insert("signature_age_days".into(), json!(age));
                        }
                    }
                }
            }
            if failed.is_empty() {
                return signature_unknown
                    .then(|| (Status::Unknown, json!({"reason": "signature_unknown"})));
            }
            detail.insert("failed".into(), json!(failed));
            Some((Status::Violating, Value::Object(detail)))
        }
        Check::PasswordPolicy {
            min_length,
            max_age_days,
            max_lockout_threshold,
        } => {
            let p = match probe(f, |s| &s.password) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let mut failed = vec![];
            let mut detail = serde_json::Map::new();
            if let Some(req) = min_length
                && p.min_length < *req
            {
                failed.push("min_length");
                detail.insert("min_length".into(), json!(p.min_length));
                detail.insert("required_min_length".into(), json!(req));
            }
            // 0 = 永不過期、不鎖定：一律算不符合
            if let Some(req) = max_age_days
                && (p.max_age_days == 0 || p.max_age_days > *req)
            {
                failed.push("max_age_days");
                detail.insert("max_age_days".into(), json!(p.max_age_days));
                detail.insert("required_max_age_days".into(), json!(req));
            }
            if let Some(req) = max_lockout_threshold
                && (p.lockout_threshold == 0 || p.lockout_threshold > *req)
            {
                failed.push("lockout_threshold");
                detail.insert("lockout_threshold".into(), json!(p.lockout_threshold));
                detail.insert("required_lockout_threshold".into(), json!(req));
            }
            if failed.is_empty() {
                return None;
            }
            detail.insert("failed".into(), json!(failed));
            Some((Status::Violating, Value::Object(detail)))
        }
        Check::LocalAdmins { allowed } => {
            let admins = match probe(f, |s| &s.admins) {
                Ok(v) => v,
                Err(u) => return u,
            };
            let bad: Vec<&str> = admins
                .iter()
                .filter(|a| !allowed.iter().any(|g| g.is_match(&a.name)))
                .map(|a| a.name.as_str())
                .collect();
            (!bad.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"accounts": bad.iter().take(MAX_LISTED).collect::<Vec<_>>(), "total": bad.len()}),
                )
            })
        }
        Check::Forbidden {
            name,
            publisher,
            below,
        } => {
            let Some(sw) = &f.software else {
                return no_data();
            };
            let hits: Vec<&SoftwareFact> =
                sw.iter().filter(|s| matches(s, name, publisher)).collect();
            let Some(below) = below else {
                return (!hits.is_empty())
                    .then(|| (Status::Violating, json!({"software": listed(&hits)})));
            };
            let old: Vec<&SoftwareFact> =
                hits.iter().copied().filter(|s| older(s, below)).collect();
            let unversioned: Vec<&SoftwareFact> = hits
                .iter()
                .copied()
                .filter(|s| s.version.is_none())
                .collect();
            if !old.is_empty() {
                Some((Status::Violating, json!({"software": listed(&old)})))
            } else if !unversioned.is_empty() {
                Some((
                    Status::Unknown,
                    json!({"reason": "version_missing", "software": listed(&unversioned)}),
                ))
            } else {
                None
            }
        }
        Check::Required {
            name,
            publisher,
            min,
        } => {
            let Some(sw) = &f.software else {
                return no_data();
            };
            let hits: Vec<&SoftwareFact> =
                sw.iter().filter(|s| matches(s, name, publisher)).collect();
            if hits.is_empty() {
                return Some((Status::Violating, json!({"reason": "missing"})));
            }
            let min = min.as_ref()?;
            let ok = hits.iter().any(|s| s.version.is_some() && !older(s, min));
            if ok {
                None
            } else if hits.iter().any(|s| s.version.is_none()) {
                Some((
                    Status::Unknown,
                    json!({"reason": "version_missing", "software": listed(&hits)}),
                ))
            } else {
                Some((
                    Status::Violating,
                    json!({"reason": "outdated", "software": listed(&hits)}),
                ))
            }
        }
        Check::Allowlist { entries } => {
            let Some(sw) = &f.software else {
                return no_data();
            };
            let offenders: Vec<&SoftwareFact> = sw
                .iter()
                .filter(|s| {
                    !entries.iter().any(|(n, p)| {
                        n.as_ref().is_none_or(|n| n.is_match(&s.name))
                            && p.as_ref().is_none_or(|p| {
                                s.publisher.as_deref().is_some_and(|v| p.is_match(v))
                            })
                    })
                })
                .collect();
            (!offenders.is_empty()).then(|| {
                (
                    Status::Violating,
                    json!({"software": listed(&offenders), "total": offenders.len()}),
                )
            })
        }
        Check::MinBuild { min_build } => {
            let Some(build) = &f.os_build else {
                return no_data();
            };
            match build.trim().parse::<u32>() {
                Ok(b) if b < *min_build => Some((Status::Violating, json!({"build": build}))),
                Ok(_) => None,
                Err(_) => Some((
                    Status::Unknown,
                    json!({"reason": "build_unparsable", "build": build}),
                )),
            }
        }
        Check::PatchLevel {
            build: want,
            min_ubr,
        } => {
            let Some(build) = &f.os_build else {
                return no_data();
            };
            match build.trim().parse::<u32>() {
                Ok(b) if b != *want => None,
                Ok(_) => match f.os_ubr {
                    None => Some((
                        Status::Unknown,
                        json!({"reason": "ubr_missing", "build": build}),
                    )),
                    Some(u) if u < *min_ubr => Some((
                        Status::Violating,
                        json!({"build": build, "ubr": u, "min_ubr": min_ubr}),
                    )),
                    Some(_) => None,
                },
                Err(_) => Some((
                    Status::Unknown,
                    json!({"reason": "build_unparsable", "build": build}),
                )),
            }
        }
        Check::RequiredKb { kb } => {
            let Some(kbs) = &f.kbs else {
                return no_data();
            };
            (!kbs.iter().any(|k| k.eq_ignore_ascii_case(kb)))
                .then(|| (Status::Violating, json!({"kb": kb})))
        }
    }
}

fn software_list(d: &Value) -> String {
    let items = d["software"].as_array().map(Vec::as_slice).unwrap_or(&[]);
    let mut s = items
        .iter()
        .map(|i| {
            let name = i["name"].as_str().unwrap_or("");
            match i["version"].as_str() {
                Some(v) => format!("{name} {v}"),
                None => name.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("、");
    // 白名單細節只列前 50 筆，另附總數
    if let Some(total) = d["total"].as_u64()
        && total as usize > items.len()
    {
        s = format!("{s} 等 {total} 套");
    }
    s
}

/// 給人看的一行摘要（網頁、CSV、通知共用）。
pub fn summarize(d: &Value) -> String {
    let s = |k: &str| d[k].as_str().unwrap_or("").to_string();
    match d["reason"].as_str() {
        Some("no_data") => return "尚未收到盤點資料".into(),
        Some("rule_error") => return format!("規則參數錯誤：{}", s("error")),
        Some("missing") => return "未安裝".into(),
        Some("outdated") => return format!("版本過舊：{}", software_list(d)),
        Some("version_missing") => return format!("版本不明：{}", software_list(d)),
        Some("ubr_missing") => return format!("Agent 未回報 UBR（組建 {}）", s("build")),
        Some("build_unparsable") => return format!("無法解析組建號：{}", s("build")),
        Some("agent_outdated") => return "Agent 版本過舊，未回報這項資料".into(),
        Some("not_collected") => return "Agent 尚未回報這個登錄檔值".into(),
        Some("denied") => return "不允許讀取這個登錄檔值".into(),
        Some("defender_inactive") => return "Defender 不是作用中的防毒".into(),
        Some("probe_error") => return format!("收集失敗：{}", s("error")),
        Some("not_numeric") => return format!("{} = {}，不是數字", s("registry"), s("actual")),
        Some("signature_unknown") => return "無法取得病毒碼更新時間".into(),
        Some("no_system_volume") => return "找不到系統磁碟".into(),
        Some("not_installed") => return format!("服務 {} 未安裝", s("service")),
        Some("absent") => return format!("{} 未設定", s("registry")),
        Some("no_patch_date") => return "沒有可判讀的更新安裝日期".into(),
        _ => {}
    }
    let days = d["days"].as_i64().unwrap_or_default();
    if d.get("last_patch_date").is_some() {
        return format!("最後裝更新：{}（{days} 天前）", s("last_patch_date"));
    }
    if d.get("reboot_pending_since").is_some() {
        return format!("待重開機已 {days} 天");
    }
    if let Some(state) = d["update_state"].as_str() {
        let what = if state == "conflict" {
            "原則被改動"
        } else {
            "原則套用失敗"
        };
        return format!("{what}：{}", s("update_detail"));
    }
    let list = |k: &str| {
        d[k].as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("、")
            })
            .unwrap_or_default()
    };
    if d.get("registry").is_some() {
        let op = super::rules::RegOp::parse(&s("op"))
            .map(|o| o.label())
            .unwrap_or("");
        return if d.get("expected").is_some() {
            format!(
                "{} = {}，要求 {op} {}",
                s("registry"),
                s("actual"),
                s("expected")
            )
        } else {
            format!("{} 存在，要求 {op}", s("registry"))
        };
    }
    if d.get("profiles_off").is_some() {
        let names: Vec<&str> = d["profiles_off"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let zh: Vec<&str> = names
            .iter()
            .map(|n| match *n {
                "domain" => "網域",
                "private" => "私人",
                "public" => "公用",
                other => other,
            })
            .collect();
        return format!("防火牆未啟用：{}", zh.join("、"));
    }
    if d.get("drives").is_some() {
        return format!("未加密保護：{}", list("drives"));
    }
    if d.get("accounts").is_some() {
        return format!("不允許的管理員：{}", list("accounts"));
    }
    if d.get("service").is_some() {
        return format!("服務 {}：{}／{}", s("service"), s("start_mode"), s("state"));
    }
    if let Some(failed) = d["failed"].as_array() {
        let n = |k: &str| d[k].as_u64().map(|v| v.to_string()).unwrap_or_default();
        let parts: Vec<String> = failed
            .iter()
            .filter_map(|x| x.as_str())
            .map(|f| match f {
                "realtime" => "即時保護未開啟".to_string(),
                "tamper" => "防竄改未開啟".to_string(),
                "signature" => format!("病毒碼 {} 天未更新", n("signature_age_days")),
                "min_length" => format!(
                    "最短長度 {}，需要 {}",
                    n("min_length"),
                    n("required_min_length")
                ),
                "max_age_days" => {
                    let a = n("max_age_days");
                    let a = if a == "0" {
                        "永不過期".to_string()
                    } else {
                        format!("{a} 天")
                    };
                    format!(
                        "密碼最長使用 {a}，需要 {} 天以內",
                        n("required_max_age_days")
                    )
                }
                "lockout_threshold" => {
                    let a = n("lockout_threshold");
                    let a = if a == "0" {
                        "不鎖定".to_string()
                    } else {
                        format!("{a} 次")
                    };
                    format!(
                        "鎖定門檻 {a}，需要 {} 次以內",
                        n("required_lockout_threshold")
                    )
                }
                other => other.to_string(),
            })
            .collect();
        return parts.join("、");
    }
    if d.get("kb").is_some() {
        format!("缺少 {}", s("kb"))
    } else if let (Some(ubr), Some(min)) = (d["ubr"].as_u64(), d["min_ubr"].as_u64()) {
        let b = s("build");
        format!("組建 {b}.{ubr}，需要 {b}.{min} 以上")
    } else if d.get("build").is_some() {
        format!("組建 {} 低於最低支援版本", s("build"))
    } else if d.get("software").is_some() {
        software_list(d)
    } else {
        d.to_string()
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
            let status = if facts.exempt.contains(&r.id) {
                Status::Exempt
            } else {
                status
            };
            Some(Outcome {
                rule_id: r.id,
                status,
                detail,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::rules::{Params, Rule, RuleSet, Severity};
    use chrono::Utc;
    use protocol::{
        AccountInfo, DefenderInfo, FirewallInfo, PasswordPolicy, Probe, RegKind, RegState,
        RegistryValue, SecurityInfo, VolumeInfo,
    };
    use serde_json::json;
    use std::collections::HashMap;

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
            security: None,
            registry: None,
            services: None,
            agent_version: Some("0.3.0".into()),
            update_status: None,
            now: Utc::now(),
        }
    }

    fn cfg_facts() -> DeviceFacts {
        let mut reg = HashMap::new();
        let mut put = |p: &str, n: &str, state: RegState, kind: RegKind, data: &str| {
            reg.insert(
                registry_key(p, n),
                RegistryValue {
                    path: p.into(),
                    name: n.into(),
                    state,
                    kind,
                    data: data.into(),
                },
            );
        };
        put(r"HKLM\A", "Dw", RegState::Present, RegKind::Dword, "5");
        put(
            r"HKLM\A",
            "Sz",
            RegState::Present,
            RegKind::String,
            "Hello World",
        );
        put(r"HKLM\A", "Gone", RegState::Absent, RegKind::None, "");
        put(r"HKLM\A", "Secret", RegState::Denied, RegKind::None, "");
        DeviceFacts {
            security: Some(SecurityInfo {
                firewall: Probe::Ok(FirewallInfo {
                    domain: true,
                    private: true,
                    public: false,
                }),
                bitlocker: Probe::Ok(vec![
                    VolumeInfo {
                        drive: "C:".into(),
                        is_system: true,
                        protected: true,
                    },
                    VolumeInfo {
                        drive: "D:".into(),
                        is_system: false,
                        protected: false,
                    },
                ]),
                defender: Probe::Ok(DefenderInfo {
                    active: true,
                    realtime: true,
                    tamper: false,
                    signature_updated: Some(Utc::now() - chrono::Duration::days(10)),
                }),
                password: Probe::Ok(PasswordPolicy {
                    min_length: 8,
                    max_age_days: 0,
                    lockout_threshold: 5,
                }),
                admins: Probe::Ok(vec![
                    AccountInfo {
                        name: r"PC\Administrator".into(),
                        sid: "S-1-5-21-1-500".into(),
                    },
                    AccountInfo {
                        name: r"CORP\bob".into(),
                        sid: "S-1-5-21-2-1100".into(),
                    },
                ]),
            }),
            registry: Some(reg),
            services: Some(vec![
                ServiceFact {
                    name: "RemoteRegistry".into(),
                    start_mode: "Manual".into(),
                    state: "Stopped".into(),
                },
                ServiceFact {
                    name: "WinDefend".into(),
                    start_mode: "Auto".into(),
                    state: "Running".into(),
                },
            ]),
            ..facts(vec![])
        }
    }

    fn status(kind: &str, p: serde_json::Value) -> Option<Status> {
        one(&cfg_facts(), kind, p).map(|x| x.0)
    }

    #[test]
    fn registry_value_rules() {
        let r = |op: &str, name: &str, exp: Option<&str>| {
            let mut v = json!({"path": r"hklm\a", "name": name, "op": op});
            if let Some(e) = exp {
                v["expected"] = json!(e);
            }
            status("registry_value", v)
        };
        assert_eq!(r("equals", "Dw", Some("5")), None, "路徑、名稱不分大小寫");
        assert_eq!(r("equals", "dw", Some("0x5")), None, "十六進位");
        assert_eq!(r("gte", "Dw", Some("6")), Some(Status::Violating));
        assert_eq!(r("lte", "Dw", Some("5")), None);
        assert_eq!(
            r("equals", "Sz", Some("hello world")),
            None,
            "字串不分大小寫"
        );
        assert_eq!(r("contains", "Sz", Some("WORLD")), None);
        assert_eq!(
            r("not_equals", "Sz", Some("Hello World")),
            Some(Status::Violating)
        );
        assert_eq!(r("gte", "Sz", Some("1")), Some(Status::Unknown), "非數字");
        assert_eq!(r("equals", "Gone", Some("1")), Some(Status::Violating));
        assert_eq!(r("exists", "Gone", None), Some(Status::Violating));
        assert_eq!(r("not_exists", "Gone", None), None);
        assert_eq!(r("not_exists", "Dw", None), Some(Status::Violating));
        assert_eq!(
            r("equals", "Secret", Some("1")),
            Some(Status::Unknown),
            "拒絕讀取"
        );
        assert_eq!(
            r("equals", "NotCollectedYet", Some("1")),
            Some(Status::Unknown)
        );
        let ok = status(
            "registry_value",
            json!({"path": r"HKLM\A", "name": "Gone", "op": "equals", "expected": "1", "absent_ok": true}),
        );
        assert_eq!(ok, None, "未設定時視為符合");
    }

    #[test]
    fn service_rules() {
        let s =
            |name: &str, req: &str| status("service_state", json!({"name": name, "require": req}));
        assert_eq!(s("remoteregistry", "disabled"), Some(Status::Violating));
        assert_eq!(s("NotInstalled", "disabled"), None, "沒安裝算符合");
        assert_eq!(s("WinDefend", "running"), None);
        assert_eq!(s("NotInstalled", "running"), Some(Status::Violating));
        assert_eq!(s("RemoteRegistry", "running"), Some(Status::Violating));
    }

    #[test]
    fn security_rules() {
        assert_eq!(
            status("firewall", json!({"profiles": ["domain", "private"]})),
            None
        );
        let (st, d) = one(&cfg_facts(), "firewall", json!({"profiles": ["public"]})).unwrap();
        assert_eq!(
            (st, d["profiles_off"].clone()),
            (Status::Violating, json!(["public"]))
        );
        assert_eq!(status("bitlocker", json!({"scope": "system"})), None);
        assert_eq!(
            status("bitlocker", json!({"scope": "all_fixed"})),
            Some(Status::Violating)
        );
        assert_eq!(status("defender", json!({"realtime": true})), None);
        assert_eq!(
            status("defender", json!({"tamper": true})),
            Some(Status::Violating)
        );
        assert_eq!(
            status("defender", json!({"max_signature_age_days": 7})),
            Some(Status::Violating)
        );
        assert_eq!(
            status("defender", json!({"max_signature_age_days": 14})),
            None
        );
        assert_eq!(
            status("password_policy", json!({"min_length": 12})),
            Some(Status::Violating)
        );
        assert_eq!(
            status("password_policy", json!({"max_age_days": 365})),
            Some(Status::Violating),
            "0＝永不過期"
        );
        assert_eq!(
            status("password_policy", json!({"max_lockout_threshold": 10})),
            None
        );
        let (st, d) = one(
            &cfg_facts(),
            "local_admins",
            json!({"allowed": ["*\\administrator"]}),
        )
        .unwrap();
        assert_eq!(
            (st, d["accounts"].clone()),
            (Status::Violating, json!(["CORP\\bob"]))
        );
        assert_eq!(
            status(
                "local_admins",
                json!({"allowed": ["*\\Administrator", "CORP\\*"]})
            ),
            None
        );
    }

    /// 病毒碼日期未知時，已確定的其他違規仍要回報違規，不能被蓋成未知
    #[test]
    fn defender_known_failure_beats_unknown_signature() {
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.defender = Probe::Ok(DefenderInfo {
                active: true,
                realtime: false,
                tamper: true,
                signature_updated: None,
            });
        }
        let r = one(
            &f,
            "defender",
            json!({"realtime": true, "max_signature_age_days": 7}),
        );
        assert_eq!(r.map(|x| x.0), Some(Status::Violating));
        let r = one(
            &f,
            "defender",
            json!({"tamper": true, "max_signature_age_days": 7}),
        );
        assert_eq!(
            r.map(|x| x.0),
            Some(Status::Unknown),
            "其他項都通過時才是未知"
        );
    }

    /// 範圍「所有固定磁碟」卻一個磁碟都沒有：和「系統磁碟」範圍一樣算違規
    #[test]
    fn bitlocker_without_volumes_is_violating_for_both_scopes() {
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.bitlocker = Probe::Ok(vec![]);
        }
        for scope in ["system", "all_fixed"] {
            let r = one(&f, "bitlocker", json!({ "scope": scope }));
            assert_eq!(r.map(|x| x.0), Some(Status::Violating), "{scope}");
        }
    }

    #[test]
    fn missing_config_data_is_unknown_with_reason() {
        let mut f = cfg_facts();
        f.security = None;
        f.registry = None;
        f.agent_version = Some("0.2.1".into());
        let (st, d) = one(&f, "firewall", json!({"profiles": ["public"]})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("agent_outdated"))
        );
        f.agent_version = Some("0.3.0".into());
        let (_, d) = one(
            &f,
            "registry_value",
            json!({"path": r"HKLM\A", "name": "x", "op": "exists"}),
        )
        .unwrap();
        assert_eq!(d["reason"], "no_data");
        let mut f = cfg_facts();
        if let Some(s) = f.security.as_mut() {
            s.defender = Probe::Ok(DefenderInfo {
                active: false,
                realtime: false,
                tamper: false,
                signature_updated: None,
            });
            s.bitlocker = Probe::Error("no BitLocker".into());
        }
        let (st, d) = one(&f, "defender", json!({"realtime": true})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("defender_inactive"))
        );
        let (st, d) = one(&f, "bitlocker", json!({"scope": "system"})).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("probe_error"))
        );
    }

    #[test]
    fn config_summaries() {
        for (d, want) in [
            (
                json!({"reason": "agent_outdated"}),
                "Agent 版本過舊，未回報這項資料",
            ),
            (
                json!({"reason": "not_collected"}),
                "Agent 尚未回報這個登錄檔值",
            ),
            (json!({"reason": "denied"}), "不允許讀取這個登錄檔值"),
            (
                json!({"reason": "defender_inactive"}),
                "Defender 不是作用中的防毒",
            ),
            (
                json!({"reason": "probe_error", "error": "x"}),
                "收集失敗：x",
            ),
            (
                json!({"reason": "not_numeric", "registry": "HKLM\\A\\B", "actual": "abc"}),
                "HKLM\\A\\B = abc，不是數字",
            ),
            (
                json!({"reason": "signature_unknown"}),
                "無法取得病毒碼更新時間",
            ),
            (json!({"profiles_off": ["public"]}), "防火牆未啟用：公用"),
            (json!({"drives": ["D:"]}), "未加密保護：D:"),
            (json!({"reason": "no_system_volume"}), "找不到系統磁碟"),
            (
                json!({"accounts": ["CORP\\bob"]}),
                "不允許的管理員：CORP\\bob",
            ),
            (
                json!({"service": "Spooler", "start_mode": "Auto", "state": "Running"}),
                "服務 Spooler：Auto／Running",
            ),
            (
                json!({"reason": "not_installed", "service": "X"}),
                "服務 X 未安裝",
            ),
            (
                json!({"registry": "HKLM\\A\\B", "actual": "0", "op": "equals", "expected": "1"}),
                "HKLM\\A\\B = 0，要求 等於 1",
            ),
            (
                json!({"registry": "HKLM\\A\\B", "op": "not_exists"}),
                "HKLM\\A\\B 存在，要求 不存在",
            ),
            (
                json!({"registry": "HKLM\\A\\B", "reason": "absent"}),
                "HKLM\\A\\B 未設定",
            ),
            (
                json!({"failed": ["min_length"], "min_length": 8, "required_min_length": 12}),
                "最短長度 8，需要 12",
            ),
            (
                json!({"failed": ["realtime", "signature"], "signature_age_days": 10}),
                "即時保護未開啟、病毒碼 10 天未更新",
            ),
        ] {
            assert_eq!(summarize(&d), want, "{d}");
        }
    }

    fn set(kind: &str, params: serde_json::Value) -> RuleSet {
        RuleSet::new(
            1,
            vec![Rule {
                id: 7,
                name: "r".into(),
                severity: Severity::High,
                include: vec![],
                exclude: vec![],
                check: Params::parse(kind, &params).map(|p| p.compile()),
            }],
        )
    }

    #[test]
    fn summaries() {
        let cases = [
            (json!({"reason": "no_data"}), "尚未收到盤點資料"),
            (
                json!({"reason": "rule_error", "error": "x"}),
                "規則參數錯誤：x",
            ),
            (json!({"reason": "missing"}), "未安裝"),
            (
                json!({"reason": "outdated", "software": [{"name": "Falcon", "version": "7.1"}]}),
                "版本過舊：Falcon 7.1",
            ),
            (
                json!({"reason": "version_missing", "software": [{"name": "A", "version": null}]}),
                "版本不明：A",
            ),
            (
                json!({"reason": "ubr_missing", "build": "22631"}),
                "Agent 未回報 UBR（組建 22631）",
            ),
            (
                json!({"reason": "build_unparsable", "build": "abc"}),
                "無法解析組建號：abc",
            ),
            (json!({"kb": "KB5031455"}), "缺少 KB5031455"),
            (
                json!({"build": "22631", "ubr": 4000, "min_ubr": 4317}),
                "組建 22631.4000，需要 22631.4317 以上",
            ),
            (json!({"build": "19044"}), "組建 19044 低於最低支援版本"),
            (
                json!({"software": [{"name": "A", "version": "1"}, {"name": "B", "version": null}]}),
                "A 1、B",
            ),
            (
                json!({"software": [{"name": "A", "version": null}], "total": 60}),
                "A 等 60 套",
            ),
        ];
        for (d, want) in cases {
            assert_eq!(summarize(&d), want, "{d}");
        }
    }

    fn one(
        f: &DeviceFacts,
        kind: &str,
        params: serde_json::Value,
    ) -> Option<(Status, serde_json::Value)> {
        let out = evaluate(f, &set(kind, params));
        assert!(out.len() <= 1);
        out.into_iter().next().map(|o| {
            assert_eq!(o.rule_id, 7);
            (o.status, o.detail)
        })
    }

    fn upd(state: &str) -> UpdateFact {
        UpdateFact {
            state: state.into(),
            detail: String::new(),
            reboot_pending: false,
            reboot_pending_since: None,
            last_patch_date: None,
        }
    }

    #[test]
    fn patch_age() {
        let mut f = facts(vec![]);
        let p = json!({"max_days": 30});
        assert_eq!(one(&f, "patch_age", p.clone()).unwrap().0, Status::Unknown);
        f.update_status = Some(upd("applied"));
        let (st, d) = one(&f, "patch_age", p.clone()).unwrap();
        assert_eq!(
            (st, d["reason"].as_str()),
            (Status::Unknown, Some("no_patch_date"))
        );
        let today = f.now.date_naive();
        f.update_status.as_mut().unwrap().last_patch_date =
            Some(today - chrono::Duration::days(30));
        assert_eq!(one(&f, "patch_age", p.clone()), None, "剛好 30 天不算");
        f.update_status.as_mut().unwrap().last_patch_date =
            Some(today - chrono::Duration::days(31));
        let (st, d) = one(&f, "patch_age", p).unwrap();
        assert_eq!((st, d["days"].as_i64()), (Status::Violating, Some(31)));
        assert!(summarize(&d).contains("31 天前"), "{}", summarize(&d));
    }

    #[test]
    fn reboot_pending() {
        let mut f = facts(vec![]);
        let p = json!({"max_days": 7});
        assert_eq!(
            one(&f, "reboot_pending", p.clone()).unwrap().0,
            Status::Unknown
        );
        f.update_status = Some(upd("applied"));
        assert_eq!(one(&f, "reboot_pending", p.clone()), None);
        let u = f.update_status.as_mut().unwrap();
        u.reboot_pending = true;
        assert_eq!(
            one(&f, "reboot_pending", p.clone()),
            None,
            "沒有起始時間不判違規"
        );
        f.update_status.as_mut().unwrap().reboot_pending_since =
            Some(f.now - chrono::Duration::days(6));
        assert_eq!(one(&f, "reboot_pending", p.clone()), None);
        f.update_status.as_mut().unwrap().reboot_pending_since =
            Some(f.now - chrono::Duration::days(8));
        let (st, d) = one(&f, "reboot_pending", p).unwrap();
        assert_eq!((st, d["days"].as_i64()), (Status::Violating, Some(8)));
        assert!(
            summarize(&d).contains("待重開機已 8 天"),
            "{}",
            summarize(&d)
        );
    }

    #[test]
    fn update_policy_state() {
        let mut f = facts(vec![]);
        assert_eq!(
            one(&f, "update_policy", json!({})).unwrap().0,
            Status::Unknown
        );
        for ok in ["applied", "unmanaged"] {
            f.update_status = Some(upd(ok));
            assert_eq!(one(&f, "update_policy", json!({})), None, "{ok}");
        }
        let mut u = upd("conflict");
        u.detail = "DeferQualityUpdates".into();
        f.update_status = Some(u);
        let (st, d) = one(&f, "update_policy", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(summarize(&d).contains("原則被改動：DeferQualityUpdates"));
        f.update_status = Some(upd("error"));
        let (st, d) = one(&f, "update_policy", json!({})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(summarize(&d).contains("原則套用失敗"));
    }

    #[test]
    fn forbidden_software() {
        let f = facts(vec![
            sw("TeamViewer 15", Some("15.1"), Some("TeamViewer GmbH")),
            sw("7-Zip", Some("23.01"), None),
        ]);
        let (st, d) = one(&f, "forbidden_software", json!({"name": "*teamviewer*"})).unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(
            d,
            json!({"software": [{"name": "TeamViewer 15", "version": "15.1"}]})
        );
        assert!(one(&f, "forbidden_software", json!({"name": "*AnyDesk*"})).is_none());
        assert!(
            one(
                &f,
                "forbidden_software",
                json!({"name": "*TeamViewer*", "publisher": "Other*"})
            )
            .is_none(),
            "發行者不符"
        );
        assert!(
            one(
                &f,
                "forbidden_software",
                json!({"name": "7-Zip", "publisher": "*"})
            )
            .is_none(),
            "沒有發行者時不符合發行者條件"
        );
        // 版本條件：低於才算
        assert!(
            one(
                &f,
                "forbidden_software",
                json!({"name": "7-Zip", "below_version": "23.01"})
            )
            .is_none()
        );
        let (st, _) = one(
            &f,
            "forbidden_software",
            json!({"name": "7-Zip", "below_version": "24"}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        // 沒有版本 → 未知
        let f2 = facts(vec![sw("7-Zip", None, None)]);
        let (st, d) = one(
            &f2,
            "forbidden_software",
            json!({"name": "7-Zip", "below_version": "24"}),
        )
        .unwrap();
        assert_eq!(st, Status::Unknown);
        assert_eq!(d["reason"], "version_missing");
    }

    #[test]
    fn required_software() {
        let f = facts(vec![sw("CrowdStrike Falcon", Some("7.10"), None)]);
        assert!(one(&f, "required_software", json!({"name": "CrowdStrike*"})).is_none());
        let (st, d) = one(&f, "required_software", json!({"name": "Symantec*"})).unwrap();
        assert_eq!((st, d), (Status::Violating, json!({"reason": "missing"})));
        let (st, d) = one(
            &f,
            "required_software",
            json!({"name": "CrowdStrike*", "min_version": "7.11"}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["reason"], "outdated");
        assert!(
            one(
                &f,
                "required_software",
                json!({"name": "CrowdStrike*", "min_version": "7.9"})
            )
            .is_none()
        );
        // 一套沒版本、一套夠新 → 通過；只有沒版本或太舊 → 未知
        let f2 = facts(vec![sw("A", None, None), sw("A", Some("2"), None)]);
        assert!(
            one(
                &f2,
                "required_software",
                json!({"name": "A", "min_version": "2"})
            )
            .is_none()
        );
        let f3 = facts(vec![sw("A", None, None), sw("A", Some("1"), None)]);
        assert_eq!(
            one(
                &f3,
                "required_software",
                json!({"name": "A", "min_version": "2"})
            )
            .unwrap()
            .0,
            Status::Unknown
        );
    }

    #[test]
    fn allowlist_lists_offenders_capped() {
        let mut items: Vec<SoftwareFact> = (0..60)
            .map(|i| sw(&format!("Game {i:02}"), None, Some("Fun Inc")))
            .collect();
        items.push(sw("Office", None, Some("Microsoft Corporation")));
        let f = facts(items);
        let (st, d) = one(
            &f,
            "software_allowlist",
            json!({"entries": [{"publisher": "Microsoft*"}]}),
        )
        .unwrap();
        assert_eq!(st, Status::Violating);
        assert_eq!(d["total"], 60);
        assert_eq!(d["software"].as_array().unwrap().len(), MAX_LISTED);
        assert!(
            one(
                &f,
                "software_allowlist",
                json!({"entries": [{"publisher": "Microsoft*"}, {"name": "Game*"}]})
            )
            .is_none()
        );
    }

    #[test]
    fn os_build_rules() {
        let f = facts(vec![]);
        let (st, d) = one(&f, "os_build", json!({"build": 22631, "min_ubr": 4317})).unwrap();
        assert_eq!(
            (st, d),
            (
                Status::Violating,
                json!({"build": "22631", "ubr": 4000, "min_ubr": 4317})
            )
        );
        assert!(one(&f, "os_build", json!({"build": 22631, "min_ubr": 4000})).is_none());
        assert!(
            one(&f, "os_build", json!({"build": 19045, "min_ubr": 9999})).is_none(),
            "其他組建不受影響"
        );
        let (st, _) = one(&f, "os_build", json!({"min_build": 26100})).unwrap();
        assert_eq!(st, Status::Violating);
        assert!(one(&f, "os_build", json!({"min_build": 19045})).is_none());
        let mut old_agent = facts(vec![]);
        old_agent.os_ubr = None;
        assert_eq!(
            one(
                &old_agent,
                "os_build",
                json!({"build": 22631, "min_ubr": 1})
            )
            .unwrap()
            .0,
            Status::Unknown
        );
        let mut weird = facts(vec![]);
        weird.os_build = Some("abc".into());
        assert_eq!(
            one(&weird, "os_build", json!({"min_build": 1})).unwrap().0,
            Status::Unknown
        );
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
        let f = DeviceFacts {
            os_build: None,
            software: None,
            kbs: None,
            ..facts(vec![])
        };
        for (kind, p) in [
            ("forbidden_software", json!({"name": "x"})),
            ("software_allowlist", json!({"entries": [{"name": "x"}]})),
            ("os_build", json!({"min_build": 1})),
            ("required_kb", json!({"kb": "KB5034439"})),
        ] {
            let (st, d) = one(&f, kind, p).unwrap();
            assert_eq!(
                (st, d["reason"].as_str()),
                (Status::Unknown, Some("no_data")),
                "{kind}"
            );
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
        assert_eq!(
            (st, d),
            (Status::Exempt, json!({"kb": "KB5031455"})),
            "豁免仍保留細節"
        );
        let mut rs = set("required_kb", json!({"kb": "KB5031455"}));
        rs.rules[0].exclude = vec![1];
        assert!(evaluate(&facts(vec![]), &rs).is_empty(), "不在範圍內");
        let inactive = DeviceFacts {
            active: false,
            ..facts(vec![])
        };
        assert!(evaluate(&inactive, &set("required_kb", json!({"kb": "KB5031455"}))).is_empty());
    }
}
