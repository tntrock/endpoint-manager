//! 讀取裝置事實、套用評估結果、寫歷程。

use std::collections::HashMap;

use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::evaluate::{
    DeviceFacts, Outcome, ServiceFact, SoftwareFact, UpdateFact, evaluate, registry_key,
};
use super::rules::{Params, Rule, RuleSet, Severity};

type RuleRow = (i64, String, String, String, String, Vec<i64>, Vec<i64>);

/// 先讀 generation 再讀規則：若中間有人改規則，快取會帶著舊 generation，下次再重新載入。
pub async fn load_ruleset(conn: &mut PgConnection) -> Result<RuleSet, sqlx::Error> {
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&mut *conn)
        .await?;
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.severity, r.kind, r.params::text, \
                ARRAY(SELECT group_id FROM compliance_rule_groups g \
                      WHERE g.rule_id = r.id AND g.mode = 'include' ORDER BY group_id), \
                ARRAY(SELECT group_id FROM compliance_rule_groups g \
                      WHERE g.rule_id = r.id AND g.mode = 'exclude' ORDER BY group_id) \
         FROM compliance_rules r WHERE r.enabled ORDER BY r.id",
    )
    .fetch_all(&mut *conn)
    .await?;
    let rules = rows
        .into_iter()
        .map(|(id, name, severity, kind, params, include, exclude)| {
            let check = serde_json::from_str::<Value>(&params)
                .map_err(|e| e.to_string())
                .and_then(|v| Params::parse(&kind, &v))
                .map(|p| p.compile());
            if let Err(e) = &check {
                tracing::warn!(rule_id = id, error = %e, "compliance rule has invalid params");
            }
            Rule {
                id,
                name,
                severity: Severity::parse(&severity).unwrap_or(Severity::Medium),
                include,
                exclude,
                check,
            }
        })
        .collect();
    Ok(RuleSet::new(generation, rules))
}

type FactRow = (
    String,
    Option<i64>,
    Option<String>,
    Option<i32>,
    Option<String>,
);

/// security／registry／services 的事實（一次讀一批裝置）
#[derive(Default)]
struct ConfigFacts {
    security: HashMap<Uuid, protocol::SecurityInfo>,
    registry: HashMap<Uuid, HashMap<(String, String), protocol::RegistryValue>>,
    services: HashMap<Uuid, Vec<ServiceFact>>,
    updates: HashMap<Uuid, UpdateFact>,
}

type SecurityDbRow = (Uuid, String, String, String, String, String);
type RegistryDbRow = (Uuid, String, String, String, String, String);
type UpdateDbRow = (
    Uuid,
    String,
    String,
    bool,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::NaiveDate>,
);

async fn load_config(conn: &mut PgConnection, ids: &[Uuid]) -> Result<ConfigFacts, sqlx::Error> {
    let mut out = ConfigFacts::default();
    let rows: Vec<SecurityDbRow> = sqlx::query_as(
        "SELECT device_id, firewall::text, bitlocker::text, defender::text, password::text, \
                admins::text FROM device_security WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    for (id, a, b, c, d, e) in rows {
        out.security
            .insert(id, crate::inventory::security_from_row((a, b, c, d, e)));
    }
    let rows: Vec<RegistryDbRow> = sqlx::query_as(
        "SELECT device_id, path, name, state, kind, data FROM device_registry \
         WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    for (id, path, name, state, kind, data) in rows {
        let v = protocol::RegistryValue {
            state: crate::inventory::from_label(&state).unwrap_or(protocol::RegState::Absent),
            kind: crate::inventory::from_label(&kind).unwrap_or(protocol::RegKind::Other),
            data,
            path,
            name,
        };
        out.registry
            .entry(id)
            .or_default()
            .insert(registry_key(&v.path, &v.name), v);
    }
    let rows: Vec<(Uuid, String, String, String)> = sqlx::query_as(
        "SELECT device_id, name, start_mode, state FROM device_services WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    for (id, name, start_mode, state) in rows {
        out.services.entry(id).or_default().push(ServiceFact {
            name,
            start_mode,
            state,
        });
    }
    let rows: Vec<UpdateDbRow> = sqlx::query_as(
        "SELECT device_id, state, detail, reboot_pending, reboot_pending_since, last_patch_date \
         FROM update_policy_status WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    for (id, state, detail, reboot_pending, reboot_pending_since, last_patch_date) in rows {
        out.updates.insert(
            id,
            UpdateFact {
                state,
                detail,
                reboot_pending,
                reboot_pending_since,
                last_patch_date,
            },
        );
    }
    Ok(out)
}
type SoftwareRow = (String, Option<String>, Option<String>);

pub async fn load_facts(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<DeviceFacts>, sqlx::Error> {
    let row: Option<FactRow> = sqlx::query_as(
        "SELECT status, group_id, os_build, os_ubr, agent_version FROM devices WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((status, group_id, os_build, os_ubr, agent_version)) = row else {
        return Ok(None);
    };
    let sections: Vec<String> =
        sqlx::query_scalar("SELECT section FROM inventory_sections WHERE device_id = $1")
            .bind(id)
            .fetch_all(&mut *conn)
            .await?;
    let has = |s: &str| sections.iter().any(|x| x == s);
    let software = if has("software") {
        let rows: Vec<SoftwareRow> = sqlx::query_as(
            "SELECT name, version, publisher FROM device_software WHERE device_id = $1",
        )
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;
        Some(
            rows.into_iter()
                .map(|(name, version, publisher)| SoftwareFact {
                    name,
                    version,
                    publisher,
                })
                .collect(),
        )
    } else {
        None
    };
    let kbs = if has("patches") {
        Some(
            sqlx::query_scalar("SELECT kb FROM device_patches WHERE device_id = $1")
                .bind(id)
                .fetch_all(&mut *conn)
                .await?,
        )
    } else {
        None
    };
    let exempt: Vec<i64> = sqlx::query_scalar(
        "SELECT rule_id FROM compliance_exemptions WHERE device_id = $1 AND expires_at > now()",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await?;
    let mut cfg = load_config(conn, &[id]).await?;
    let now = chrono::Utc::now();
    Ok(Some(DeviceFacts {
        active: status == "active",
        group_id,
        os_build: has("basic").then(|| os_build.unwrap_or_default()),
        os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
        software,
        kbs,
        exempt,
        security: has("security").then(|| cfg.security.remove(&id)).flatten(),
        registry: has("registry").then(|| cfg.registry.remove(&id).unwrap_or_default()),
        services: has("services").then(|| cfg.services.remove(&id).unwrap_or_default()),
        agent_version,
        update_status: cfg.updates.remove(&id),
        now,
        today: super::today(now),
    }))
}

/// 一次寫入的歷程事件：(rule_id, rule_name, severity, from, to, detail)
type EventRow = (i64, String, String, String, String, String);

/// 只在「未知」與「無結果」之間變動的轉換不寫歷程：規則剛上線、資料還沒收集時，
/// 每台 × 每條規則都會是未知，逐筆記錄會讓歷程暴增（三萬台 × 千條規則＝三千萬筆）。
fn recorded(from: &str, to: &str) -> bool {
    let quiet = |s: &str| s == "none" || s == "unknown";
    !(quiet(from) && quiet(to))
}

async fn insert_events(
    conn: &mut PgConnection,
    device: Uuid,
    events: &[EventRow],
) -> Result<(), sqlx::Error> {
    if events.is_empty() {
        return Ok(());
    }
    let col = |f: fn(&EventRow) -> &str| events.iter().map(f).collect::<Vec<&str>>();
    let ids: Vec<i64> = events.iter().map(|e| e.0).collect();
    sqlx::query(
        "INSERT INTO violation_events \
         (device_id, rule_id, rule_name, severity, from_status, to_status, detail) \
         SELECT $1, r, n, s, f, t, d::jsonb \
         FROM UNNEST($2::bigint[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[]) \
              AS x(r, n, s, f, t, d)",
    )
    .bind(device)
    .bind(&ids)
    .bind(col(|e| &e.1))
    .bind(col(|e| &e.2))
    .bind(col(|e| &e.3))
    .bind(col(|e| &e.4))
    .bind(col(|e| &e.5))
    .execute(conn)
    .await?;
    Ok(())
}

type ExistingRow = (i64, String, String, String, String);

/// 與目前的違規比對差異：新增、狀態改變寫歷程；只有細節改變時只更新違規列。
/// 已停用規則的舊結果不在 outcomes 內，會被刪除並寫「→ none」事件。
/// 每種寫入各一個批次語句（重算時每台可能有數十筆結果）。
async fn apply(
    conn: &mut PgConnection,
    device: Uuid,
    rules: &RuleSet,
    outcomes: Vec<Outcome>,
) -> Result<(), sqlx::Error> {
    let existing: Vec<ExistingRow> = sqlx::query_as(
        "SELECT v.rule_id, v.status, v.detail::text, r.name, r.severity \
         FROM device_violations v JOIN compliance_rules r ON r.id = v.rule_id \
         WHERE v.device_id = $1",
    )
    .bind(device)
    .fetch_all(&mut *conn)
    .await?;
    let mut old: HashMap<i64, ExistingRow> = existing.into_iter().map(|r| (r.0, r)).collect();
    // (rule_id, status, detail)
    let mut inserts: Vec<(i64, &'static str, String)> = vec![];
    // (rule_id, status, detail, 狀態是否改變)
    let mut updates: Vec<(i64, &'static str, String, bool)> = vec![];
    let mut events: Vec<EventRow> = vec![];
    for o in outcomes {
        let rule = rules
            .rules
            .iter()
            .find(|r| r.id == o.rule_id)
            .expect("outcome from ruleset");
        let detail = o.detail.to_string();
        let status = o.status.as_str();
        let mut event = |from: &str| {
            events.push((
                rule.id,
                rule.name.clone(),
                rule.severity.as_str().into(),
                from.into(),
                status.into(),
                detail.clone(),
            ))
        };
        match old.remove(&o.rule_id) {
            None => {
                event("none");
                inserts.push((o.rule_id, status, detail));
            }
            Some((_, from, _, _, _)) if from != status => {
                event(&from);
                updates.push((o.rule_id, status, detail, true));
            }
            Some((_, _, old_detail, _, _)) => {
                if serde_json::from_str::<Value>(&old_detail).ok().as_ref() != Some(&o.detail) {
                    updates.push((o.rule_id, status, detail, false));
                }
            }
        }
    }
    let deletes: Vec<i64> = old.keys().copied().collect();
    for (rule_id, status, detail, name, severity) in old.into_values() {
        events.push((rule_id, name, severity, status, "none".into(), detail));
    }
    events.retain(|e| recorded(&e.3, &e.4));

    if !inserts.is_empty() {
        sqlx::query(
            "INSERT INTO device_violations (device_id, rule_id, status, detail) \
             SELECT $1, r, s, d::jsonb FROM UNNEST($2::bigint[], $3::text[], $4::text[]) \
                  AS x(r, s, d)",
        )
        .bind(device)
        .bind(inserts.iter().map(|i| i.0).collect::<Vec<i64>>())
        .bind(inserts.iter().map(|i| i.1).collect::<Vec<&str>>())
        .bind(inserts.iter().map(|i| i.2.as_str()).collect::<Vec<&str>>())
        .execute(&mut *conn)
        .await?;
    }
    if !updates.is_empty() {
        // 狀態改變時 since 重新起算；只有細節改變時保留原本的 since
        sqlx::query(
            "UPDATE device_violations v SET status = x.s, detail = x.d::jsonb, \
               since = CASE WHEN x.changed THEN now() ELSE v.since END, updated_at = now() \
             FROM UNNEST($2::bigint[], $3::text[], $4::text[], $5::bool[]) AS x(r, s, d, changed) \
             WHERE v.device_id = $1 AND v.rule_id = x.r",
        )
        .bind(device)
        .bind(updates.iter().map(|u| u.0).collect::<Vec<i64>>())
        .bind(updates.iter().map(|u| u.1).collect::<Vec<&str>>())
        .bind(updates.iter().map(|u| u.2.as_str()).collect::<Vec<&str>>())
        .bind(updates.iter().map(|u| u.3).collect::<Vec<bool>>())
        .execute(&mut *conn)
        .await?;
    }
    if !deletes.is_empty() {
        sqlx::query("DELETE FROM device_violations WHERE device_id = $1 AND rule_id = ANY($2)")
            .bind(device)
            .bind(&deletes)
            .execute(&mut *conn)
            .await?;
    }
    insert_events(conn, device, &events).await
}

/// 在呼叫端的交易內評估一台裝置。取裝置鎖後才讀事實，所以並行時以最新盤點為準。
/// 呼叫端可能已鎖住 devices 列（生命週期動作）；這裡只以一般 SELECT 讀 devices，
/// 上傳評估也只取這把 advisory lock，不會互相等待成環。
pub async fn refresh_device_in(
    conn: &mut PgConnection,
    rules: &RuleSet,
    id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('compliance:' || $1::text))")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    // 呼叫端的規則集可能在等鎖期間過期（例如背景重算已用新規則處理過這台）：
    // 取得鎖後再確認一次，過期就重新載入，避免把已停用規則的結果寫回去
    let current: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
        .fetch_one(&mut *conn)
        .await?;
    let fresh;
    let rules = if current == rules.generation {
        rules
    } else {
        fresh = load_ruleset(conn).await?;
        &fresh
    };
    let Some(facts) = load_facts(conn, id).await? else {
        return Ok(());
    };
    let outcomes = evaluate(&facts, rules);
    apply(conn, id, rules, outcomes).await
}

pub async fn refresh_device(pool: &PgPool, rules: &RuleSet, id: Uuid) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    refresh_device_in(&mut tx, rules, id).await?;
    tx.commit().await
}

/// 重新載入規則再評估（裝置生命週期與豁免變更用，頻率低，不走快取）。
pub async fn refresh_device_fresh(conn: &mut PgConnection, id: Uuid) -> Result<(), sqlx::Error> {
    // generation 不符會在 refresh_device_in 取鎖後載入最新規則
    refresh_device_in(conn, &RuleSet::empty(), id).await
}

type BulkDeviceRow = (
    Uuid,
    String,
    Option<i64>,
    Option<String>,
    Option<i32>,
    Option<String>,
);
type BulkSoftwareRow = (Uuid, String, Option<String>, Option<String>);

/// 一次讀一批裝置的事實（預覽用；不含豁免、不加鎖）。
pub async fn load_facts_bulk(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<(Uuid, DeviceFacts)>, sqlx::Error> {
    let devices: Vec<BulkDeviceRow> = sqlx::query_as(
        "SELECT id, status, group_id, os_build, os_ubr, agent_version FROM devices \
         WHERE id = ANY($1) ORDER BY id",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    let sections: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT device_id, section FROM inventory_sections WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    let software: Vec<BulkSoftwareRow> = sqlx::query_as(
        "SELECT device_id, name, version, publisher FROM device_software WHERE device_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&mut *conn)
    .await?;
    let patches: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT device_id, kb FROM device_patches WHERE device_id = ANY($1)")
            .bind(ids)
            .fetch_all(&mut *conn)
            .await?;
    let mut sw: HashMap<Uuid, Vec<SoftwareFact>> = HashMap::new();
    for (d, name, version, publisher) in software {
        sw.entry(d).or_default().push(SoftwareFact {
            name,
            version,
            publisher,
        });
    }
    let mut kbs: HashMap<Uuid, Vec<String>> = HashMap::new();
    for (d, kb) in patches {
        kbs.entry(d).or_default().push(kb);
    }
    let mut cfg = load_config(conn, ids).await?;
    let now = chrono::Utc::now();
    let mut has: std::collections::HashSet<(Uuid, String)> = std::collections::HashSet::new();
    has.extend(sections);
    let has = |d: Uuid, s: &str| has.contains(&(d, s.to_string()));
    Ok(devices
        .into_iter()
        .map(|(id, status, group_id, os_build, os_ubr, agent_version)| {
            let facts = DeviceFacts {
                active: status == "active",
                group_id,
                os_build: has(id, "basic").then(|| os_build.unwrap_or_default()),
                os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
                software: has(id, "software").then(|| sw.remove(&id).unwrap_or_default()),
                kbs: has(id, "patches").then(|| kbs.remove(&id).unwrap_or_default()),
                exempt: vec![],
                security: has(id, "security")
                    .then(|| cfg.security.remove(&id))
                    .flatten(),
                registry: has(id, "registry").then(|| cfg.registry.remove(&id).unwrap_or_default()),
                services: has(id, "services").then(|| cfg.services.remove(&id).unwrap_or_default()),
                agent_version,
                update_status: cfg.updates.remove(&id),
                now,
                today: super::today(now),
            };
            (id, facts)
        })
        .collect())
}
