//! 存下快取上傳的查詢結果。

use std::collections::HashSet;

use protocol::netdev::{MAX_INTERFACES, NetData, NetInterface, NetPollKind, NetSystem};
use sqlx::PgPool;

/// 存進資料庫的字串上限（設備回的描述可能很長）
const MAX_TEXT: usize = 1024;
const MAX_ERROR: usize = 500;

/// 去掉控制字元、截斷
pub fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect::<String>()
        .trim()
        .to_string()
}

fn opt(s: &str) -> Option<String> {
    let s = clean(s, MAX_TEXT);
    (!s.is_empty()).then_some(s)
}

/// 介面的自動角色：LLDP 鄰居是交換器、路由器，或是已登錄的網路設備，就是上行埠
pub fn auto_role(i: &NetInterface, known: &HashSet<String>) -> &'static str {
    let uplink = i.lldp.iter().any(|n| {
        n.is_switch_or_router
            || n.mgmt_address
                .as_deref()
                .is_some_and(|a| known.contains(&a.to_ascii_lowercase()))
    });
    if uplink { "auto_uplink" } else { "auto_edge" }
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    Stored,
    /// 第一期還不處理 MAC／ARP 表
    Ignored,
}

/// 呼叫前已確認設備屬於這台快取的據點
pub async fn store(pool: &PgPool, d: &NetData) -> Result<Outcome, sqlx::Error> {
    if d.kind == NetPollKind::Tables {
        return Ok(Outcome::Ignored);
    }
    let mut tx = pool.begin().await?;
    if let Some(err) = &d.error {
        sqlx::query(
            "UPDATE net_devices SET last_polled_at = now(), last_error = $2, \
             consecutive_failures = consecutive_failures + 1 WHERE id = $1",
        )
        .bind(d.device_id)
        .bind(clean(err, MAX_ERROR))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Outcome::Stored);
    }
    let sys = d.system.clone().unwrap_or_default();
    store_system(&mut tx, d.device_id, &sys).await?;
    store_interfaces(&mut tx, d.device_id, &d.interfaces).await?;
    tx.commit().await?;
    Ok(Outcome::Stored)
}

async fn store_system(
    tx: &mut sqlx::PgConnection,
    id: i64,
    s: &NetSystem,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE net_devices SET last_polled_at = now(), last_ok_at = now(), last_error = NULL, \
         consecutive_failures = 0, sys_name = $2, sys_descr = $3, sys_location = $4, \
         sys_contact = $5, sys_object_id = $6, uptime_secs = $7, model = $8, serial = $9, \
         firmware = $10 WHERE id = $1",
    )
    .bind(id)
    .bind(opt(&s.name))
    .bind(opt(&s.descr))
    .bind(opt(&s.location))
    .bind(opt(&s.contact))
    .bind(opt(&s.object_id))
    .bind(i64::try_from(s.uptime_secs).unwrap_or(i64::MAX))
    .bind(opt(&s.model))
    .bind(opt(&s.serial))
    .bind(opt(&s.firmware))
    .execute(&mut *tx)
    .await?;
    Ok(())
}

async fn store_interfaces(
    tx: &mut sqlx::PgConnection,
    id: i64,
    ifs: &[NetInterface],
) -> Result<(), sqlx::Error> {
    let known: Vec<String> =
        sqlx::query_scalar("SELECT lower(address) FROM net_devices WHERE id <> $1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    let known: HashSet<String> = known.into_iter().collect();
    // 同一個 ifIndex 出現兩次時取最後一筆
    let mut seen = HashSet::new();
    let ifs: Vec<&NetInterface> = ifs
        .iter()
        .take(MAX_INTERFACES)
        .rev()
        .filter(|i| seen.insert(i.index))
        .collect();
    let mut index = Vec::with_capacity(ifs.len());
    let mut name = Vec::with_capacity(ifs.len());
    let mut alias = Vec::with_capacity(ifs.len());
    let mut if_type = Vec::with_capacity(ifs.len());
    let mut admin = Vec::with_capacity(ifs.len());
    let mut oper = Vec::with_capacity(ifs.len());
    let mut speed: Vec<Option<i64>> = Vec::with_capacity(ifs.len());
    let mut mac: Vec<Option<String>> = Vec::with_capacity(ifs.len());
    let mut pvid: Vec<Option<i32>> = Vec::with_capacity(ifs.len());
    let mut ago: Vec<Option<i64>> = Vec::with_capacity(ifs.len());
    let mut role = Vec::with_capacity(ifs.len());
    let mut lldp = Vec::with_capacity(ifs.len());
    for i in ifs {
        index.push(i64::from(i.index));
        name.push(clean(&i.name, MAX_TEXT));
        alias.push(clean(&i.alias, MAX_TEXT));
        if_type.push(i32::try_from(i.if_type).unwrap_or(1));
        admin.push(i.admin_up);
        oper.push(i.oper_up);
        speed.push(i.speed_mbps.and_then(|s| i64::try_from(s).ok()));
        mac.push(i.mac.as_deref().map(|m| clean(m, 17).to_ascii_lowercase()));
        pvid.push(i.pvid.and_then(|v| i32::try_from(v).ok()));
        ago.push(
            i.last_change_secs_ago
                .and_then(|v| i64::try_from(v).ok())
                .filter(|v| *v < 100 * 365 * 86_400),
        );
        role.push(auto_role(i, &known));
        let neighbors: Vec<_> = i
            .lldp
            .iter()
            .take(16)
            .map(|n| {
                serde_json::json!({
                    "sys_name": clean(&n.sys_name, 255),
                    "port_id": clean(&n.port_id, 255),
                    "port_descr": clean(&n.port_descr, 255),
                    "chassis_id": clean(&n.chassis_id, 255),
                    "mgmt_address": n.mgmt_address.as_deref().map(|a| clean(a, 64)),
                    "is_switch_or_router": n.is_switch_or_router,
                })
            })
            .collect();
        lldp.push(serde_json::Value::Array(neighbors).to_string());
    }
    sqlx::query("DELETE FROM net_interfaces WHERE device_id = $1 AND if_index <> ALL($2)")
        .bind(id)
        .bind(&index)
        .execute(&mut *tx)
        .await?;
    // 管理員手動指定的角色（edge／uplink）保留，自動的重新判斷
    sqlx::query(
        "INSERT INTO net_interfaces (device_id, if_index, name, alias, if_type, admin_up, oper_up, \
                speed_mbps, mac, pvid, last_change_at, role, lldp) \
         SELECT $1, u.idx, u.name, u.alias, u.t, u.a, u.o, u.sp, u.mac, u.pvid, \
                now() - make_interval(secs => u.ago), u.role, u.lldp::jsonb \
         FROM UNNEST($2::bigint[], $3::text[], $4::text[], $5::int[], $6::bool[], $7::bool[], \
                     $8::bigint[], $9::text[], $10::int[], $11::bigint[], $12::text[], $13::text[]) \
              AS u(idx, name, alias, t, a, o, sp, mac, pvid, ago, role, lldp) \
         ON CONFLICT (device_id, if_index) DO UPDATE SET name = EXCLUDED.name, \
             alias = EXCLUDED.alias, if_type = EXCLUDED.if_type, admin_up = EXCLUDED.admin_up, \
             oper_up = EXCLUDED.oper_up, speed_mbps = EXCLUDED.speed_mbps, mac = EXCLUDED.mac, \
             pvid = EXCLUDED.pvid, last_change_at = EXCLUDED.last_change_at, \
             lldp = EXCLUDED.lldp, \
             role = CASE WHEN net_interfaces.role IN ('edge', 'uplink') THEN net_interfaces.role \
                         ELSE EXCLUDED.role END",
    )
    .bind(id)
    .bind(&index)
    .bind(&name)
    .bind(&alias)
    .bind(&if_type)
    .bind(&admin)
    .bind(&oper)
    .bind(&speed)
    .bind(&mac)
    .bind(&pvid)
    .bind(&ago)
    .bind(&role)
    .bind(&lldp)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::netdev::LldpNeighbor;

    fn iface(lldp: Vec<LldpNeighbor>) -> NetInterface {
        NetInterface {
            index: 1,
            name: "Gi1/0/1".into(),
            alias: String::new(),
            if_type: 6,
            admin_up: true,
            oper_up: true,
            speed_mbps: None,
            mac: None,
            pvid: None,
            last_change_secs_ago: None,
            lldp,
        }
    }

    fn neighbor(router: bool, mgmt: Option<&str>) -> LldpNeighbor {
        LldpNeighbor {
            sys_name: "n".into(),
            port_id: "p".into(),
            port_descr: String::new(),
            chassis_id: String::new(),
            mgmt_address: mgmt.map(String::from),
            is_switch_or_router: router,
        }
    }

    #[test]
    fn roles() {
        let known: HashSet<String> = ["10.0.0.2".to_string()].into();
        assert_eq!(auto_role(&iface(vec![]), &known), "auto_edge");
        // 電話、AP 之類的 LLDP 鄰居（不是交換器、也沒登錄）
        assert_eq!(
            auto_role(&iface(vec![neighbor(false, Some("10.0.0.9"))]), &known),
            "auto_edge"
        );
        assert_eq!(
            auto_role(&iface(vec![neighbor(true, None)]), &known),
            "auto_uplink"
        );
        assert_eq!(
            auto_role(&iface(vec![neighbor(false, Some("10.0.0.2"))]), &known),
            "auto_uplink"
        );
    }

    #[test]
    fn cleaning() {
        assert_eq!(clean(" a\u{0}b\nc ", 10), "abc");
        assert_eq!(clean("abcdef", 3), "abc");
        assert_eq!(opt("  "), None);
        assert_eq!(opt("x").as_deref(), Some("x"));
    }
}
