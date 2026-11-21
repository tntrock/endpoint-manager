//! 裝置頁的狀態卡與問題清單。

use time::{Date, OffsetDateTime};
use uuid::Uuid;

use crate::AppState;
use crate::compliance::rules::Severity;

/// 狀態卡
pub struct Card {
    pub label: &'static str,
    pub value: String,
    pub sub: String,
    /// ok／warn／bad／off；空字串為中性
    pub tone: &'static str,
    /// 點了開哪個分頁
    pub tab: Option<&'static str>,
}

pub struct Issue {
    /// high／medium／low
    pub severity: &'static str,
    pub title: String,
    pub detail: String,
    pub tab: Option<&'static str>,
}

/// 這台的基本狀態（由裝置頁查好後傳入）
pub struct Facts<'a> {
    pub id: Uuid,
    pub linux: bool,
    pub status: &'a str,
    pub last_seen: Option<OffsetDateTime>,
    pub online: bool,
    pub boot: String,
    pub agent: String,
    pub errors: &'a [(String, String)],
}

/// 相對時間：剛剛、N 分鐘前、N 小時前、N 天前
pub fn ago(now: OffsetDateTime, t: Option<OffsetDateTime>) -> String {
    let Some(t) = t else {
        return "從未回報".into();
    };
    let s = (now - t).whole_seconds().max(0);
    match s {
        0..60 => "剛剛".into(),
        60..3600 => format!("{} 分鐘前", s / 60),
        3600..86400 => format!("{} 小時前", s / 3600),
        _ => format!("{} 天前", s / 86400),
    }
}

fn rank(sev: &str) -> u8 {
    match sev {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

const WEEK: i64 = 7 * 86400;

type UpdateRow = (String, String, bool, Option<OffsetDateTime>, Option<Date>);

pub async fn build(st: &AppState, f: &Facts<'_>) -> Result<(Vec<Card>, Vec<Issue>), sqlx::Error> {
    let now = OffsetDateTime::now_utc();
    let mut cards = vec![];
    let mut issues = vec![];
    let stale = f.last_seen.is_none_or(|t| (now - t).whole_seconds() > WEEK);

    cards.push(Card {
        label: "連線",
        value: if f.online { "在線" } else { "離線" }.into(),
        sub: format!("最後回報 {}", ago(now, f.last_seen)),
        tone: if f.online {
            "ok"
        } else if stale {
            "bad"
        } else {
            "off"
        },
        tab: None,
    });
    if stale && matches!(f.status, "active" | "duplicate_suspect") {
        issues.push(Issue {
            severity: "high",
            title: "離線超過 7 天".into(),
            detail: format!(
                "最後回報 {}；確認是否已停用或需要除役",
                ago(now, f.last_seen)
            ),
            tab: None,
        });
    }
    match f.status {
        "duplicate_suspect" => issues.push(Issue {
            severity: "medium",
            title: "疑似重複".into(),
            detail: "硬體識別與另一台裝置相同".into(),
            tab: None,
        }),
        "pending_approval" => issues.push(Issue {
            severity: "medium",
            title: "待核准的重新註冊".into(),
            detail: "在總覽頁核准或拒絕".into(),
            tab: None,
        }),
        _ => {}
    }

    if f.linux {
        cards.push(Card {
            label: "開機時間",
            value: f.boot.clone(),
            sub: String::new(),
            tone: "",
            tab: None,
        });
        cards.push(Card {
            label: "Agent 版本",
            value: if f.agent.is_empty() {
                "—".into()
            } else {
                f.agent.clone()
            },
            sub: String::new(),
            tone: "",
            tab: None,
        });
    } else {
        windows(st, f, now, &mut cards, &mut issues).await?;
    }

    let failed: Vec<(String, Option<String>, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT r.action, s.name, t.finished_at FROM command_targets t \
         JOIN command_runs r ON r.id = t.run_id LEFT JOIN scripts s ON s.id = r.script_id \
         WHERE t.device_id = $1 AND t.status = 'failed' AND t.finished_at > now() - interval '7 days' \
         ORDER BY t.finished_at DESC LIMIT 5",
    )
    .bind(f.id)
    .fetch_all(&st.pool)
    .await?;
    for (action, script, at) in failed {
        issues.push(Issue {
            severity: "medium",
            title: format!(
                "遠端指令失敗：{}",
                script.unwrap_or_else(|| super::commands::action_label(&action).into())
            ),
            detail: ago(now, at),
            tab: Some("commands"),
        });
    }
    for (section, msg) in f.errors {
        issues.push(Issue {
            severity: "low",
            title: format!("收集錯誤：{section}"),
            detail: msg.clone(),
            tab: None,
        });
    }
    issues.sort_by_key(|i| rank(i.severity));
    Ok((cards, issues))
}

async fn windows(
    st: &AppState,
    f: &Facts<'_>,
    now: OffsetDateTime,
    cards: &mut Vec<Card>,
    issues: &mut Vec<Issue>,
) -> Result<(), sqlx::Error> {
    let rules: Vec<(String, String, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT r.name, r.severity, v.status, v.since FROM device_violations v \
         JOIN compliance_rules r ON r.id = v.rule_id \
         WHERE v.device_id = $1 AND v.status IN ('violating', 'unknown') AND r.enabled \
         ORDER BY v.since, r.name",
    )
    .bind(f.id)
    .fetch_all(&st.pool)
    .await?;
    let violating: Vec<_> = rules.iter().filter(|r| r.2 == "violating").collect();
    let high = violating.iter().filter(|r| r.1 == "high").count();
    cards.push(Card {
        label: "合規",
        value: if violating.is_empty() {
            "合規".into()
        } else {
            format!("違反 {} 條", violating.len())
        },
        sub: if high > 0 {
            format!("其中高風險 {high} 條")
        } else if violating.is_empty() {
            "沒有違反任何規則".into()
        } else {
            "沒有高風險".into()
        },
        tone: if high > 0 {
            "bad"
        } else if violating.is_empty() {
            "ok"
        } else {
            "warn"
        },
        tab: Some("compliance"),
    });
    for (name, severity, status, since) in &rules {
        let sev = Severity::parse(severity).unwrap_or(Severity::Medium);
        let unknown = status == "unknown";
        issues.push(Issue {
            severity: if unknown { "low" } else { sev.as_str() },
            title: if unknown {
                format!("無法判斷：{name}")
            } else {
                name.clone()
            },
            detail: format!(
                "{}規則・{}",
                sev.label(),
                if unknown {
                    format!("{}起資料不足", ago(now, Some(*since)))
                } else {
                    format!("{}開始違反", ago(now, Some(*since)))
                }
            ),
            tab: Some("compliance"),
        });
    }

    let update: Option<UpdateRow> = sqlx::query_as(
        "SELECT state, detail, reboot_pending, reboot_pending_since, last_patch_date \
         FROM update_policy_status WHERE device_id = $1",
    )
    .bind(f.id)
    .fetch_optional(&st.pool)
    .await?;
    let (value, sub, tone) = match &update {
        None => ("—".to_string(), "尚未回報更新狀態".to_string(), ""),
        Some((state, _, reboot, since, patched)) => {
            let value = patched
                .map(protocol::timefmt::format_date)
                .unwrap_or_else(|| "—".into());
            let late = since.is_some_and(|t| (now - t).whole_seconds() > WEEK);
            if *reboot {
                (
                    value,
                    format!("等待重新開機（{}）", ago(now, *since)),
                    if late { "bad" } else { "warn" },
                )
            } else {
                (
                    value,
                    format!("最後修補日期・原則{}", super::updates::state_label(state)),
                    if matches!(state.as_str(), "conflict" | "error") {
                        "warn"
                    } else {
                        "ok"
                    },
                )
            }
        }
    };
    cards.push(Card {
        label: "更新",
        value,
        sub,
        tone,
        tab: Some("updates"),
    });
    if let Some((state, detail, reboot, since, _)) = &update {
        if *reboot {
            let late = since.is_some_and(|t| (now - t).whole_seconds() > WEEK);
            issues.push(Issue {
                severity: if late { "high" } else { "medium" },
                title: "等待重新開機".into(),
                detail: format!("更新已安裝，{}開始等待重新開機", ago(now, *since)),
                tab: Some("updates"),
            });
        }
        if matches!(state.as_str(), "conflict" | "error") {
            issues.push(Issue {
                severity: "medium",
                title: format!("更新原則{}", super::updates::state_label(state)),
                detail: detail.clone(),
                tab: Some("updates"),
            });
        }
    }

    let deploys: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT dep.name, dep.stage, ds.status, ds.message FROM deployment_status ds \
         JOIN deployments dep ON dep.id = ds.deployment_id WHERE ds.device_id = $1 \
         ORDER BY ds.updated_at DESC",
    )
    .bind(f.id)
    .fetch_all(&st.pool)
    .await?;
    let failed = deploys.iter().filter(|d| d.2 == "failed").count();
    cards.push(Card {
        label: "派送",
        value: if deploys.is_empty() {
            "—".into()
        } else {
            format!("{} / {}", deploys.len() - failed, deploys.len())
        },
        sub: if deploys.is_empty() {
            "沒有派送".into()
        } else if failed > 0 {
            format!("失敗 {failed} 個")
        } else {
            "全部成功".into()
        },
        tone: if failed > 0 {
            "bad"
        } else if deploys.is_empty() {
            ""
        } else {
            "ok"
        },
        tab: Some("deployments"),
    });
    for (name, stage, status, message) in deploys {
        if status == "failed" && stage != "stopped" {
            issues.push(Issue {
                severity: "high",
                title: format!("派送失敗：{name}"),
                detail: message,
                tab: Some("deployments"),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    #[test]
    fn relative_time() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(ago(now, None), "從未回報");
        assert_eq!(ago(now, Some(now - Duration::seconds(5))), "剛剛");
        assert_eq!(ago(now, Some(now + Duration::seconds(30))), "剛剛");
        assert_eq!(ago(now, Some(now - Duration::minutes(5))), "5 分鐘前");
        assert_eq!(ago(now, Some(now - Duration::hours(3))), "3 小時前");
        assert_eq!(ago(now, Some(now - Duration::days(9))), "9 天前");
        assert_eq!(rank("high"), 0);
        assert_eq!(rank("low"), rank("other"));
    }
}
