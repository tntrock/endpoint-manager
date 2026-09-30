//! 決定這一輪要對 WU 原則登錄檔做什麼（純函式，方便測試）。

use std::collections::BTreeMap;

use chrono::NaiveDate;
use protocol::PatchItem;
use protocol::update::{ApplyState, PolicyData, UpdatePolicy, VALUE_NAMES};
use serde::{Deserialize, Serialize};

/// 目前套用的結果（存在 update_policy.json）
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Applied {
    pub policy_id: Option<i64>,
    pub revision: Option<i32>,
    /// 值名稱 → 自己寫入的內容：只刪這些值，而且只在沒被別人改過時刪
    pub written: BTreeMap<String, PolicyData>,
    /// None：從未處理
    pub state: Option<ApplyState>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// 不動登錄檔，狀態改成 (state, detail)
    Report { state: ApplyState, detail: String },
    /// 寫入 writes、刪除 deletes，完成後讀回確認
    Apply {
        writes: Vec<(String, PolicyData)>,
        deletes: Vec<String>,
    },
    /// 移出範圍：刪除 deletes，清空 written
    Release { deletes: Vec<String> },
}

/// 自己寫過、而且目前值仍等於寫入內容的值（沒被別人改過）
fn untouched<'a>(
    applied: &'a Applied,
    current: &'a dyn Fn(&str) -> Option<PolicyData>,
) -> impl Iterator<Item = &'a String> + 'a {
    applied
        .written
        .iter()
        .filter(move |(n, d)| current(n).as_ref() == Some(*d))
        .map(|(n, _)| n)
}

pub fn decide(
    desired: Option<&UpdatePolicy>,
    applied: &Applied,
    current: &dyn Fn(&str) -> Option<PolicyData>,
) -> Decision {
    let Some(p) = desired else {
        if applied.written.is_empty() {
            return Decision::Report {
                state: ApplyState::Unmanaged,
                detail: String::new(),
            };
        }
        return Decision::Release {
            deletes: untouched(applied, current).cloned().collect(),
        };
    };
    if let Some(bad) = p
        .values
        .iter()
        .find(|v| !VALUE_NAMES.contains(&v.name.as_str()) || v.data == PolicyData::Unknown)
    {
        return Decision::Report {
            state: ApplyState::Error,
            detail: format!("不支援的值：{}", bad.name),
        };
    }
    let same = applied.policy_id == Some(p.id) && applied.revision == Some(p.revision);
    let settled = matches!(
        applied.state,
        Some(ApplyState::Applied | ApplyState::Conflict)
    );
    if !same || !settled {
        let mut writes: Vec<(String, PolicyData)> = p
            .values
            .iter()
            .map(|v| (v.name.clone(), v.data.clone()))
            .collect();
        writes.sort_by(|a, b| a.0.cmp(&b.0));
        return Decision::Apply {
            deletes: untouched(applied, current)
                .filter(|n| !p.values.iter().any(|v| &v.name == *n))
                .cloned()
                .collect(),
            writes,
        };
    }
    // 同一版已處理過：只比對，被改過就是衝突（不覆寫，等原則改版）
    let changed: Vec<&str> = applied
        .written
        .iter()
        .filter(|(n, d)| current(n).as_ref() != Some(*d))
        .map(|(n, _)| n.as_str())
        .collect();
    if changed.is_empty() {
        Decision::Report {
            state: ApplyState::Applied,
            detail: String::new(),
        }
    } else {
        Decision::Report {
            state: ApplyState::Conflict,
            detail: changed.join(", "),
        }
    }
}

/// WMI `Win32_QuickFixEngineering.InstalledOn`：通常是 M/D/YYYY，少數是 16 位 hex FILETIME
fn parse_installed_on(s: &str) -> Option<NaiveDate> {
    let s = s.trim();
    if s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        let ticks = u64::from_str_radix(s, 16).ok()?;
        // FILETIME：1601-01-01 起的 100 奈秒數
        let secs = (ticks / 10_000_000) as i64 - 11_644_473_600;
        return chrono::DateTime::from_timestamp(secs, 0).map(|t| t.date_naive());
    }
    NaiveDate::parse_from_str(s, "%m/%d/%Y").ok()
}

pub fn last_patch_date(items: &[PatchItem]) -> Option<NaiveDate> {
    items
        .iter()
        .filter_map(|p| parse_installed_on(p.installed_on.as_deref()?))
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::PatchItem;
    use protocol::update::{PolicyValue, UpdatePolicy};

    fn dw(v: u32) -> PolicyData {
        PolicyData::Dword(v)
    }

    fn policy(revision: i32, values: &[(&str, PolicyData)]) -> UpdatePolicy {
        UpdatePolicy {
            id: 1,
            revision,
            values: values
                .iter()
                .map(|(n, d)| PolicyValue {
                    name: n.to_string(),
                    data: d.clone(),
                })
                .collect(),
        }
    }

    fn applied(revision: i32, written: &[(&str, PolicyData)], state: ApplyState) -> Applied {
        Applied {
            policy_id: Some(1),
            revision: Some(revision),
            written: written
                .iter()
                .map(|(n, d)| (n.to_string(), d.clone()))
                .collect(),
            state: Some(state),
            detail: String::new(),
        }
    }

    const A: &str = "DeferQualityUpdates";
    const B: &str = "DeferQualityUpdatesPeriodInDays";

    fn reg(values: &[(&str, PolicyData)]) -> impl Fn(&str) -> Option<PolicyData> {
        let m: BTreeMap<String, PolicyData> = values
            .iter()
            .map(|(n, d)| (n.to_string(), d.clone()))
            .collect();
        move |n| m.get(n).cloned()
    }

    #[test]
    fn first_apply_writes_everything() {
        let p = policy(1, &[(A, dw(1)), (B, dw(7))]);
        assert_eq!(
            decide(Some(&p), &Applied::default(), &reg(&[])),
            Decision::Apply {
                writes: vec![(A.into(), dw(1)), (B.into(), dw(7))],
                deletes: vec![],
            }
        );
    }

    #[test]
    fn new_revision_deletes_only_untouched_leftovers() {
        let p = policy(2, &[(A, dw(1))]);
        let old = applied(1, &[(A, dw(1)), (B, dw(7))], ApplyState::Applied);
        let d = decide(Some(&p), &old, &reg(&[(A, dw(1)), (B, dw(7))]));
        assert_eq!(
            d,
            Decision::Apply {
                writes: vec![(A.into(), dw(1))],
                deletes: vec![B.into()],
            }
        );
        let d = decide(Some(&p), &old, &reg(&[(A, dw(1)), (B, dw(30))]));
        assert_eq!(
            d,
            Decision::Apply {
                writes: vec![(A.into(), dw(1))],
                deletes: vec![],
            },
            "別人改過的值不刪"
        );
    }

    #[test]
    fn same_revision_checks_for_conflict() {
        let p = policy(1, &[(A, dw(1)), (B, dw(7))]);
        let st = applied(1, &[(A, dw(1)), (B, dw(7))], ApplyState::Applied);
        let ok = Decision::Report {
            state: ApplyState::Applied,
            detail: String::new(),
        };
        assert_eq!(decide(Some(&p), &st, &reg(&[(A, dw(1)), (B, dw(7))])), ok);
        let conflict = Decision::Report {
            state: ApplyState::Conflict,
            detail: format!("{A}, {B}"),
        };
        assert_eq!(decide(Some(&p), &st, &reg(&[(B, dw(30))])), conflict);
        // 衝突後不再寫入；值被改回就恢復
        let st = applied(1, &[(A, dw(1)), (B, dw(7))], ApplyState::Conflict);
        assert_eq!(decide(Some(&p), &st, &reg(&[(B, dw(30))])), conflict);
        assert_eq!(decide(Some(&p), &st, &reg(&[(A, dw(1)), (B, dw(7))])), ok);
    }

    #[test]
    fn error_is_retried() {
        let p = policy(1, &[(A, dw(1))]);
        let st = applied(1, &[], ApplyState::Error);
        assert!(matches!(
            decide(Some(&p), &st, &reg(&[])),
            Decision::Apply { .. }
        ));
    }

    #[test]
    fn unsupported_values_are_not_applied() {
        for p in [
            policy(1, &[(A, dw(1)), ("NoAutoUpdate", dw(1))]),
            policy(1, &[(A, PolicyData::Unknown)]),
        ] {
            match decide(Some(&p), &Applied::default(), &reg(&[])) {
                Decision::Report {
                    state: ApplyState::Error,
                    detail,
                } => assert!(detail.contains("不支援的值"), "{detail}"),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn released_deletes_only_untouched_values() {
        let st = applied(1, &[(A, dw(1)), (B, dw(7))], ApplyState::Applied);
        assert_eq!(
            decide(None, &st, &reg(&[(A, dw(1)), (B, dw(30))])),
            Decision::Release {
                deletes: vec![A.into()]
            }
        );
        assert_eq!(
            decide(None, &Applied::default(), &reg(&[])),
            Decision::Report {
                state: ApplyState::Unmanaged,
                detail: String::new()
            }
        );
    }

    fn patch(on: Option<&str>) -> PatchItem {
        PatchItem {
            kb: "KB1".into(),
            installed_on: on.map(str::to_string),
        }
    }

    #[test]
    fn last_patch_date_formats() {
        let d = |y, m, dd| chrono::NaiveDate::from_ymd_opt(y, m, dd);
        assert_eq!(
            last_patch_date(&[patch(Some("9/10/2026")), patch(Some("12/1/2025"))]),
            d(2026, 9, 10)
        );
        assert_eq!(
            last_patch_date(&[patch(Some("01d9e4c2a1b2c3d4"))]),
            d(2023, 9, 11),
            "WMI 的 16 位 hex FILETIME"
        );
        assert_eq!(last_patch_date(&[patch(None), patch(Some(""))]), None);
        assert_eq!(
            last_patch_date(&[
                patch(Some("garbage")),
                patch(Some("13/45/2020")),
                patch(Some("1/2/2020"))
            ]),
            d(2020, 1, 2)
        );
        assert_eq!(last_patch_date(&[]), None);
    }
}
