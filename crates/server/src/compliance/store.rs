//! 讀取裝置事實、套用評估結果、寫歷程。

use std::collections::HashMap;

use serde_json::Value;
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use super::evaluate::{DeviceFacts, Outcome, SoftwareFact, evaluate};
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
    Ok(RuleSet { generation, rules })
}

type FactRow = (String, Option<i64>, Option<String>, Option<i32>);
type SoftwareRow = (String, Option<String>, Option<String>);

pub async fn load_facts(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<DeviceFacts>, sqlx::Error> {
    let row: Option<FactRow> =
        sqlx::query_as("SELECT status, group_id, os_build, os_ubr FROM devices WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((status, group_id, os_build, os_ubr)) = row else {
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
    Ok(Some(DeviceFacts {
        active: status == "active",
        group_id,
        os_build: has("basic").then(|| os_build.unwrap_or_default()),
        os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
        software,
        kbs,
        exempt,
    }))
}

async fn event(
    conn: &mut PgConnection,
    device: Uuid,
    rule: (i64, &str, &str),
    from: &str,
    to: &str,
    detail: &Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO violation_events \
         (device_id, rule_id, rule_name, severity, from_status, to_status, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)",
    )
    .bind(device)
    .bind(rule.0)
    .bind(rule.1)
    .bind(rule.2)
    .bind(from)
    .bind(to)
    .bind(detail.to_string())
    .execute(conn)
    .await?;
    Ok(())
}

type ExistingRow = (i64, String, String, String, String);

/// 與目前的違規比對差異：新增、狀態改變寫歷程；只有細節改變時只更新違規列。
/// 已停用規則的舊結果不在 outcomes 內，會被刪除並寫「→ none」事件。
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
    for o in outcomes {
        let rule = rules
            .rules
            .iter()
            .find(|r| r.id == o.rule_id)
            .expect("outcome from ruleset");
        let meta = (rule.id, rule.name.as_str(), rule.severity.as_str());
        let detail = o.detail.to_string();
        match old.remove(&o.rule_id) {
            None => {
                sqlx::query(
                    "INSERT INTO device_violations (device_id, rule_id, status, detail) \
                     VALUES ($1, $2, $3, $4::jsonb)",
                )
                .bind(device)
                .bind(o.rule_id)
                .bind(o.status.as_str())
                .bind(&detail)
                .execute(&mut *conn)
                .await?;
                event(conn, device, meta, "none", o.status.as_str(), &o.detail).await?;
            }
            Some((_, status, _, _, _)) if status != o.status.as_str() => {
                sqlx::query(
                    "UPDATE device_violations SET status = $3, detail = $4::jsonb, \
                     since = now(), updated_at = now() WHERE device_id = $1 AND rule_id = $2",
                )
                .bind(device)
                .bind(o.rule_id)
                .bind(o.status.as_str())
                .bind(&detail)
                .execute(&mut *conn)
                .await?;
                event(conn, device, meta, &status, o.status.as_str(), &o.detail).await?;
            }
            Some((_, _, old_detail, _, _)) => {
                if serde_json::from_str::<Value>(&old_detail).ok().as_ref() != Some(&o.detail) {
                    sqlx::query(
                        "UPDATE device_violations SET detail = $3::jsonb, updated_at = now() \
                         WHERE device_id = $1 AND rule_id = $2",
                    )
                    .bind(device)
                    .bind(o.rule_id)
                    .bind(&detail)
                    .execute(&mut *conn)
                    .await?;
                }
            }
        }
    }
    for (rule_id, status, detail, name, severity) in old.into_values() {
        sqlx::query("DELETE FROM device_violations WHERE device_id = $1 AND rule_id = $2")
            .bind(device)
            .bind(rule_id)
            .execute(&mut *conn)
            .await?;
        let detail: Value = serde_json::from_str(&detail).unwrap_or(Value::Null);
        event(
            conn,
            device,
            (rule_id, &name, &severity),
            &status,
            "none",
            &detail,
        )
        .await?;
    }
    Ok(())
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

type BulkDeviceRow = (Uuid, String, Option<i64>, Option<String>, Option<i32>);
type BulkSoftwareRow = (Uuid, String, Option<String>, Option<String>);

/// 一次讀一批裝置的事實（預覽用；不含豁免、不加鎖）。
pub async fn load_facts_bulk(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> Result<Vec<(Uuid, DeviceFacts)>, sqlx::Error> {
    let devices: Vec<BulkDeviceRow> = sqlx::query_as(
        "SELECT id, status, group_id, os_build, os_ubr FROM devices WHERE id = ANY($1) ORDER BY id",
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
    let mut has: std::collections::HashSet<(Uuid, String)> = std::collections::HashSet::new();
    has.extend(sections);
    let has = |d: Uuid, s: &str| has.contains(&(d, s.to_string()));
    Ok(devices
        .into_iter()
        .map(|(id, status, group_id, os_build, os_ubr)| {
            let facts = DeviceFacts {
                active: status == "active",
                group_id,
                os_build: has(id, "basic").then(|| os_build.unwrap_or_default()),
                os_ubr: os_ubr.and_then(|u| u32::try_from(u).ok()),
                software: has(id, "software").then(|| sw.remove(&id).unwrap_or_default()),
                kbs: has(id, "patches").then(|| kbs.remove(&id).unwrap_or_default()),
                exempt: vec![],
            };
            (id, facts)
        })
        .collect())
}
