//! 更新原則的表單設定：驗證，以及轉成 Agent 要寫入的登錄檔值。

use anyhow::ensure;
use chrono::NaiveDate;
use protocol::update::{PolicyData, PolicyValue};
use serde::{Deserialize, Serialize};

/// Windows 在暫停開始日後自動恢復更新的天數
pub const PAUSE_DAYS: i64 = 35;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deadline {
    pub days: u32,
    pub grace: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveHours {
    pub start: u32,
    pub end: u32,
}

/// 存在 `update_policies.settings`（JSONB）。沒設定的項目不寫入。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicySettings {
    pub quality_defer_days: Option<u32>,
    pub feature_defer_days: Option<u32>,
    /// 暫停只由「暫停／恢復」按鈕設定，表單不含
    pub quality_pause_start: Option<NaiveDate>,
    pub feature_pause_start: Option<NaiveDate>,
    pub quality_deadline: Option<Deadline>,
    pub feature_deadline: Option<Deadline>,
    /// 寬限期結束前不自動重開機（套用到有設定的期限）
    pub no_auto_reboot: bool,
    pub active_hours: Option<ActiveHours>,
}

fn dword(name: &str, v: u32) -> PolicyValue {
    PolicyValue {
        name: name.into(),
        data: PolicyData::Dword(v),
    }
}

impl PolicySettings {
    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.quality_defer_days.is_none_or(|d| d <= 30),
            "品質更新延後必須是 0–30 天"
        );
        ensure!(
            self.feature_defer_days.is_none_or(|d| d <= 365),
            "功能更新延後必須是 0–365 天"
        );
        for (label, d) in [
            ("品質更新", self.quality_deadline),
            ("功能更新", self.feature_deadline),
        ] {
            if let Some(d) = d {
                ensure!(d.days <= 30, "{label}期限必須是 0–30 天");
                ensure!(d.grace <= 7, "{label}寬限期必須是 0–7 天");
            }
        }
        ensure!(
            !self.no_auto_reboot
                || self.quality_deadline.is_some()
                || self.feature_deadline.is_some(),
            "「期限前不自動重開機」需要設定期限"
        );
        if let Some(h) = self.active_hours {
            ensure!(h.start <= 23 && h.end <= 23, "使用中時段必須是 0–23 點");
            let span = (h.end + 24 - h.start) % 24;
            ensure!((1..=18).contains(&span), "使用中時段必須是 1–18 小時");
        }
        Ok(())
    }

    /// Agent 要寫入的值（依名稱排序）
    pub fn values(&self) -> Vec<PolicyValue> {
        let mut v = vec![];
        // ADMX 中暫停與延後是同一個原則：只設暫停時以延後 0 天一起寫入
        for (prefix, defer, pause) in [
            ("Quality", self.quality_defer_days, self.quality_pause_start),
            ("Feature", self.feature_defer_days, self.feature_pause_start),
        ] {
            if defer.is_some() || pause.is_some() {
                v.push(dword(&format!("Defer{prefix}Updates"), 1));
                v.push(dword(
                    &format!("Defer{prefix}UpdatesPeriodInDays"),
                    defer.unwrap_or(0),
                ));
            }
            if let Some(d) = pause {
                v.push(PolicyValue {
                    name: format!("Pause{prefix}UpdatesStartTime"),
                    data: PolicyData::String(d.format("%Y-%m-%d").to_string()),
                });
            }
        }
        // 24H2 以前的 Windows 用舊名稱（一個原則同時控制品質與功能更新期限）：新舊並存
        if self.quality_deadline.is_some() || self.feature_deadline.is_some() {
            v.push(dword("SetComplianceDeadline", 1));
            if self.no_auto_reboot {
                v.push(dword("ConfigureDeadlineNoAutoReboot", 1));
            }
        }
        if let Some(d) = self.quality_deadline {
            v.push(dword("SetComplianceDeadlineForQU", 1));
            v.push(dword("ConfigureDeadlineForQualityUpdates", d.days));
            v.push(dword("ConfigureDeadlineGracePeriod", d.grace));
            if self.no_auto_reboot {
                v.push(dword("ConfigureDeadlineNoAutoRebootForQualityUpdates", 1));
            }
        }
        if let Some(d) = self.feature_deadline {
            v.push(dword("SetComplianceDeadlineForFU", 1));
            v.push(dword("ConfigureDeadlineForFeatureUpdates", d.days));
            v.push(dword(
                "ConfigureDeadlineGracePeriodForFeatureUpdates",
                d.grace,
            ));
            if self.no_auto_reboot {
                v.push(dword("ConfigureDeadlineNoAutoRebootForFeatureUpdates", 1));
            }
        }
        if let Some(h) = self.active_hours {
            v.push(dword("SetActiveHours", 1));
            v.push(dword("ActiveHoursStart", h.start));
            v.push(dword("ActiveHoursEnd", h.end));
        }
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::update::{PolicyData, VALUE_NAMES};

    fn names(s: &PolicySettings) -> Vec<String> {
        s.values().into_iter().map(|v| v.name).collect()
    }

    fn get(s: &PolicySettings, name: &str) -> Option<PolicyData> {
        s.values()
            .into_iter()
            .find(|v| v.name == name)
            .map(|v| v.data)
    }

    fn date() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 9, 30).unwrap()
    }

    #[test]
    fn empty_settings_write_nothing() {
        assert!(PolicySettings::default().values().is_empty());
        assert!(PolicySettings::default().validate().is_ok());
    }

    #[test]
    fn pause_alone_brings_defer_zero() {
        let s = PolicySettings {
            quality_pause_start: Some(date()),
            ..Default::default()
        };
        assert_eq!(get(&s, "DeferQualityUpdates"), Some(PolicyData::Dword(1)));
        assert_eq!(
            get(&s, "DeferQualityUpdatesPeriodInDays"),
            Some(PolicyData::Dword(0))
        );
        assert_eq!(
            get(&s, "PauseQualityUpdatesStartTime"),
            Some(PolicyData::String("2026-09-30".into()))
        );
        assert!(get(&s, "DeferFeatureUpdates").is_none());
    }

    #[test]
    fn defer_and_pause_together() {
        let s = PolicySettings {
            feature_defer_days: Some(120),
            feature_pause_start: Some(date()),
            ..Default::default()
        };
        assert_eq!(
            names(&s),
            vec![
                "DeferFeatureUpdates",
                "DeferFeatureUpdatesPeriodInDays",
                "PauseFeatureUpdatesStartTime"
            ]
        );
        assert_eq!(
            get(&s, "DeferFeatureUpdatesPeriodInDays"),
            Some(PolicyData::Dword(120))
        );
    }

    #[test]
    fn deadlines_and_no_auto_reboot() {
        let s = PolicySettings {
            quality_deadline: Some(Deadline { days: 3, grace: 2 }),
            feature_deadline: Some(Deadline { days: 7, grace: 5 }),
            no_auto_reboot: true,
            ..Default::default()
        };
        assert!(s.validate().is_ok());
        for (n, v) in [
            ("SetComplianceDeadlineForQU", 1),
            ("ConfigureDeadlineForQualityUpdates", 3),
            ("ConfigureDeadlineGracePeriod", 2),
            ("SetComplianceDeadlineForFU", 1),
            ("ConfigureDeadlineForFeatureUpdates", 7),
            ("ConfigureDeadlineGracePeriodForFeatureUpdates", 5),
            ("ConfigureDeadlineNoAutoRebootForQualityUpdates", 1),
            ("ConfigureDeadlineNoAutoRebootForFeatureUpdates", 1),
            // 24H2 以前的 Windows 只認舊名稱：新舊並存
            ("SetComplianceDeadline", 1),
            ("ConfigureDeadlineNoAutoReboot", 1),
        ] {
            assert_eq!(get(&s, n), Some(PolicyData::Dword(v)), "{n}");
        }
        let q = PolicySettings {
            quality_deadline: Some(Deadline { days: 3, grace: 2 }),
            no_auto_reboot: true,
            ..Default::default()
        };
        assert!(get(&q, "ConfigureDeadlineNoAutoRebootForFeatureUpdates").is_none());
    }

    #[test]
    fn no_auto_reboot_requires_deadline() {
        let s = PolicySettings {
            no_auto_reboot: true,
            ..Default::default()
        };
        assert!(format!("{:#}", s.validate().unwrap_err()).contains("期限"));
    }

    #[test]
    fn active_hours() {
        let ok = |start, end| {
            PolicySettings {
                active_hours: Some(ActiveHours { start, end }),
                ..Default::default()
            }
            .validate()
            .is_ok()
        };
        assert!(ok(22, 6), "跨午夜 8 小時");
        assert!(ok(8, 17));
        assert!(ok(0, 18));
        assert!(!ok(0, 19), "19 小時");
        assert!(!ok(5, 5), "0 小時");
        assert!(!ok(24, 5));
        let s = PolicySettings {
            active_hours: Some(ActiveHours { start: 22, end: 6 }),
            ..Default::default()
        };
        assert_eq!(get(&s, "SetActiveHours"), Some(PolicyData::Dword(1)));
        assert_eq!(get(&s, "ActiveHoursStart"), Some(PolicyData::Dword(22)));
        assert_eq!(get(&s, "ActiveHoursEnd"), Some(PolicyData::Dword(6)));
    }

    #[test]
    fn ranges() {
        let v = |s: PolicySettings| s.validate().is_ok();
        assert!(v(PolicySettings {
            quality_defer_days: Some(30),
            ..Default::default()
        }));
        assert!(!v(PolicySettings {
            quality_defer_days: Some(31),
            ..Default::default()
        }));
        assert!(v(PolicySettings {
            feature_defer_days: Some(365),
            ..Default::default()
        }));
        assert!(!v(PolicySettings {
            feature_defer_days: Some(366),
            ..Default::default()
        }));
        assert!(!v(PolicySettings {
            quality_deadline: Some(Deadline { days: 31, grace: 0 }),
            ..Default::default()
        }));
        assert!(!v(PolicySettings {
            feature_deadline: Some(Deadline { days: 0, grace: 8 }),
            ..Default::default()
        }));
        assert!(v(PolicySettings {
            feature_deadline: Some(Deadline { days: 30, grace: 7 }),
            ..Default::default()
        }));
    }

    #[test]
    fn all_values_are_allowlisted_and_sorted() {
        let s = PolicySettings {
            quality_defer_days: Some(7),
            feature_defer_days: Some(30),
            quality_pause_start: Some(date()),
            feature_pause_start: Some(date()),
            quality_deadline: Some(Deadline { days: 3, grace: 2 }),
            feature_deadline: Some(Deadline { days: 7, grace: 5 }),
            no_auto_reboot: true,
            active_hours: Some(ActiveHours { start: 8, end: 20 }),
        };
        let n = names(&s);
        assert_eq!(n.len(), VALUE_NAMES.len(), "全部設定時用到每個值");
        assert!(n.iter().all(|x| VALUE_NAMES.contains(&x.as_str())));
        let mut sorted = n.clone();
        sorted.sort();
        assert_eq!(n, sorted);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<PolicySettings>(&json).unwrap(), s);
        assert_eq!(
            serde_json::from_str::<PolicySettings>("{}").unwrap(),
            PolicySettings::default()
        );
    }
}
