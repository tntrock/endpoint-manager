//! 評估：純函式，不碰資料庫。

use std::cmp::Ordering;

use serde_json::{Value, json};

use super::matcher::{Glob, cmp_version};
use super::rules::{Check, RuleSet};

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

fn check_one(c: &Check, f: &DeviceFacts) -> Option<(Status, Value)> {
    match c {
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
        _ => {}
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
    use serde_json::json;

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
        }
    }

    fn set(kind: &str, params: serde_json::Value) -> RuleSet {
        RuleSet {
            generation: 1,
            rules: vec![Rule {
                id: 7,
                name: "r".into(),
                severity: Severity::High,
                include: vec![],
                exclude: vec![],
                check: Params::parse(kind, &params).map(|p| p.compile()),
            }],
        }
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
