//! 第二期的查詢與動作：電腦的網路位置、未管理設備、已知標記、埠的角色。

use std::collections::HashMap;

use serde_json::json;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::ingest::normalize_mac;
use super::oui;
use crate::audit;
use crate::commands::CmdError;

/// 未管理設備：24 小時內看到過
pub const UNMANAGED_WINDOW_HOURS: i32 = 24;
/// 清單最多列幾台
pub const MAX_UNMANAGED: i64 = 5000;
const MAX_NOTE: usize = 200;

fn invalid(msg: impl Into<String>) -> anyhow::Error {
    CmdError::Invalid(msg.into()).into()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Location {
    pub net_device_id: Option<i64>,
    pub net_device: String,
    pub port: String,
    pub vlan: i32,
    pub mac: String,
    pub since: OffsetDateTime,
    pub until: Option<OffsetDateTime>,
    pub last_seen: Option<OffsetDateTime>,
}

#[derive(Debug, Default)]
pub struct EndpointLocation {
    /// 目前在端點埠上的位置（多張網卡可能有多個）
    pub current: Vec<Location>,
    /// 沒有端點埠的位置時：只在上行埠看到（下游有未登錄的交換器或 AP）
    pub via_uplink: Option<Location>,
    pub history: Vec<Location>,
}

type LocRow = (
    Option<i64>,
    String,
    String,
    i32,
    String,
    OffsetDateTime,
    Option<OffsetDateTime>,
    Option<OffsetDateTime>,
);

fn loc((net_device_id, net_device, port, vlan, mac, since, until, last_seen): LocRow) -> Location {
    Location {
        net_device_id,
        net_device,
        port,
        vlan,
        mac,
        since,
        until,
        last_seen,
    }
}

pub async fn endpoint_location(
    pool: &PgPool,
    device: Uuid,
) -> Result<EndpointLocation, sqlx::Error> {
    const LAST_SEEN: &str = "(SELECT max(s.last_seen) FROM net_mac_sightings s \
         WHERE s.mac = l.mac AND s.device_id = l.net_device_id AND s.if_index = l.if_index)";
    let current: Vec<LocRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT l.net_device_id, l.net_device_name, l.port_name, l.vlan, l.mac, l.started_at, \
                l.ended_at, {LAST_SEEN} \
         FROM endpoint_locations l WHERE l.device_id = $1 AND l.ended_at IS NULL \
         ORDER BY l.started_at DESC"
    )))
    .bind(device)
    .fetch_all(pool)
    .await?;
    let history: Vec<LocRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT l.net_device_id, l.net_device_name, l.port_name, l.vlan, l.mac, l.started_at, \
                l.ended_at, {LAST_SEEN} \
         FROM endpoint_locations l WHERE l.device_id = $1 \
         ORDER BY l.started_at DESC LIMIT 20"
    )))
    .bind(device)
    .fetch_all(pool)
    .await?;
    let via_uplink: Option<LocRow> = if current.is_empty() {
        sqlx::query_as(
            "SELECT nd.id, nd.name, i.name, s.vlan, s.mac, s.first_seen, NULL::timestamptz, \
                    s.last_seen \
             FROM net_mac_sightings s \
             JOIN device_macs m ON m.mac = s.mac AND m.device_id = $1 \
             JOIN net_interfaces i ON i.device_id = s.device_id AND i.if_index = s.if_index \
             JOIN net_devices nd ON nd.id = s.device_id \
             WHERE s.last_seen > now() - interval '1 day' \
             ORDER BY s.last_seen DESC, i.mac_count LIMIT 1",
        )
        .bind(device)
        .fetch_optional(pool)
        .await?
    } else {
        None
    };
    Ok(EndpointLocation {
        current: current.into_iter().map(loc).collect(),
        via_uplink: via_uplink.map(loc),
        history: history.into_iter().map(loc).collect(),
    })
}

/// 網路設備詳情：每個埠目前接著哪些電腦（if_index → (裝置 id, 主機名稱)）
pub async fn port_endpoints(
    pool: &PgPool,
    net_device: i64,
) -> Result<HashMap<i64, Vec<(Uuid, String)>>, sqlx::Error> {
    let rows: Vec<(i64, Uuid, String)> = sqlx::query_as(
        "SELECT DISTINCT l.if_index, d.id, d.hostname FROM endpoint_locations l \
         JOIN devices d ON d.id = l.device_id \
         WHERE l.net_device_id = $1 AND l.ended_at IS NULL ORDER BY d.hostname",
    )
    .bind(net_device)
    .fetch_all(pool)
    .await?;
    let mut m: HashMap<i64, Vec<(Uuid, String)>> = HashMap::new();
    for (i, id, host) in rows {
        m.entry(i).or_default().push((id, host));
    }
    Ok(m)
}

#[derive(Debug, Clone)]
pub struct Unmanaged {
    pub mac: String,
    pub ip: Option<String>,
    pub vendor: Option<&'static str>,
    pub random: bool,
    pub net_device_id: Option<i64>,
    pub net_device: Option<String>,
    pub site: String,
    pub port: Option<String>,
    pub if_index: Option<i64>,
    pub vlan: i32,
    pub first_seen: OffsetDateTime,
    pub last_seen: OffsetDateTime,
}

type UnmanagedRow = (
    String,
    Option<String>,
    Option<i64>,
    Option<String>,
    String,
    Option<String>,
    Option<i64>,
    i32,
    OffsetDateTime,
    OffsetDateTime,
);

/// 未管理設備：24 小時內出現在端點埠的 MAC 表，或據點網段內的 ARP 表；
/// 不是使用中電腦的網卡、不是網路設備的介面、也沒被標記為已知
pub async fn unmanaged(pool: &PgPool, site: Option<i64>) -> Result<Vec<Unmanaged>, sqlx::Error> {
    let rows: Vec<UnmanagedRow> = sqlx::query_as(
        "WITH edge AS ( \
           SELECT s.mac, s.device_id, s.if_index, s.vlan, s.first_seen, s.last_seen \
           FROM net_mac_sightings s \
           JOIN net_interfaces i ON i.device_id = s.device_id AND i.if_index = s.if_index \
           JOIN net_devices nd ON nd.id = s.device_id \
           WHERE s.last_seen > now() - make_interval(hours => $2) \
             AND NOT net_port_is_uplink(i.role, i.mac_count) \
             AND ($1::bigint IS NULL OR nd.site_id = $1)), \
         arp_only AS ( \
           SELECT a.mac, a.device_id, NULL::bigint AS if_index, 0 AS vlan, a.first_seen, \
                  a.last_seen \
           FROM net_arp a JOIN net_devices nd ON nd.id = a.device_id \
           JOIN sites st ON st.id = nd.site_id \
           WHERE a.last_seen > now() - make_interval(hours => $2) AND a.ip <<= ANY(st.cidrs) \
             AND ($1::bigint IS NULL OR nd.site_id = $1) \
             AND NOT EXISTS (SELECT 1 FROM edge e WHERE e.mac = a.mac)), \
         seen AS (SELECT * FROM edge UNION ALL SELECT * FROM arp_only) \
         SELECT DISTINCT ON (x.mac) x.mac, \
                (SELECT host(r.ip) FROM net_arp r WHERE r.mac = x.mac \
                 ORDER BY family(r.ip), r.last_seen DESC LIMIT 1), \
                x.device_id, nd.name, st.name, \
                CASE WHEN x.if_index IS NOT NULL THEN i.name END, x.if_index, x.vlan, \
                (SELECT min(y.first_seen) FROM seen y WHERE y.mac = x.mac), x.last_seen \
         FROM seen x \
         JOIN net_devices nd ON nd.id = x.device_id JOIN sites st ON st.id = nd.site_id \
         LEFT JOIN net_interfaces i ON i.device_id = x.device_id AND i.if_index = x.if_index \
         WHERE NOT EXISTS (SELECT 1 FROM device_macs m JOIN devices d ON d.id = m.device_id \
                           WHERE m.mac = x.mac AND d.status = 'active') \
           AND NOT EXISTS (SELECT 1 FROM net_interfaces n WHERE n.mac = x.mac) \
           AND NOT EXISTS (SELECT 1 FROM net_known_macs k WHERE \
                (k.match = 'mac' AND k.value = x.mac) \
             OR (k.match = 'oui' AND k.value = upper(replace(left(x.mac, 8), ':', ''))) \
             OR (k.match = 'port' AND x.if_index IS NOT NULL \
                 AND k.value = x.device_id || ':' || x.if_index)) \
         ORDER BY x.mac, x.if_index IS NULL, x.last_seen DESC \
         LIMIT $3",
    )
    .bind(site)
    .bind(UNMANAGED_WINDOW_HOURS)
    .bind(MAX_UNMANAGED)
    .fetch_all(pool)
    .await?;
    let mut out: Vec<Unmanaged> = rows
        .into_iter()
        .map(
            |(mac, ip, nd, nd_name, site, port, if_index, vlan, first, last)| Unmanaged {
                vendor: oui::vendor(&mac),
                random: oui::is_random(&mac),
                mac,
                ip,
                net_device_id: nd,
                net_device: nd_name,
                site,
                port,
                if_index,
                vlan,
                first_seen: first,
                last_seen: last,
            },
        )
        .collect();
    out.sort_by(|a, b| b.first_seen.cmp(&a.first_seen).then(a.mac.cmp(&b.mac)));
    Ok(out)
}

/// 24 小時內新出現的未管理設備台數（總覽）
pub async fn new_unmanaged(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let since = OffsetDateTime::now_utc() - time::Duration::hours(UNMANAGED_WINDOW_HOURS.into());
    Ok(unmanaged(pool, None)
        .await?
        .iter()
        .filter(|u| u.first_seen > since)
        .count() as i64)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownMatch {
    Mac,
    Oui,
    Port,
}

impl KnownMatch {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "mac" => Some(Self::Mac),
            "oui" => Some(Self::Oui),
            "port" => Some(Self::Port),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::Oui => "oui",
            Self::Port => "port",
        }
    }

    pub fn label(s: &str) -> &'static str {
        match s {
            "mac" => "這個 MAC",
            "oui" => "同廠牌（前綴）",
            "port" => "這個埠",
            _ => "未知",
        }
    }
}

/// 依未管理設備的一筆，算出要存的比對值
pub fn known_value(
    m: KnownMatch,
    mac: &str,
    net_device: Option<i64>,
    if_index: Option<i64>,
) -> anyhow::Result<String> {
    let mac = normalize_mac(mac).ok_or_else(|| invalid("MAC 位址格式不正確"))?;
    Ok(match m {
        KnownMatch::Mac => mac,
        KnownMatch::Oui => oui::prefix_hex(&mac).expect("normalized mac"),
        KnownMatch::Port => match (net_device, if_index) {
            (Some(d), Some(i)) => format!("{d}:{i}"),
            _ => return Err(invalid("這筆只在 ARP 表看到，沒有交換器的埠可以標記")),
        },
    })
}

pub async fn add_known(
    pool: &PgPool,
    m: KnownMatch,
    value: &str,
    note: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let note = note.trim();
    if note.is_empty() || note.chars().count() > MAX_NOTE {
        return Err(invalid(format!("請填寫說明（最多 {MAX_NOTE} 字）")));
    }
    if note.chars().any(char::is_control) {
        return Err(invalid("說明不能包含控制字元"));
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO net_known_macs (match, value, note, created_by) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (match, value) DO UPDATE SET note = EXCLUDED.note",
    )
    .bind(m.as_str())
    .bind(value)
    .bind(note)
    .bind(actor)
    .execute(&mut *tx)
    .await?;
    audit::record(
        &mut tx,
        actor,
        "netdevice_known_add",
        Some(value),
        json!({"match": m.as_str(), "note": note}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_known(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, String)> =
        sqlx::query_as("DELETE FROM net_known_macs WHERE id = $1 RETURNING match, value")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let (m, value) =
        row.ok_or_else(|| anyhow::Error::from(CmdError::NotFound("標記不存在".into())))?;
    audit::record(
        &mut tx,
        actor,
        "netdevice_known_delete",
        Some(&value),
        json!({"id": id, "match": m}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Known {
    pub id: i64,
    pub kind: String,
    pub value: String,
    pub note: String,
    pub created_by: String,
    pub created_at: OffsetDateTime,
}

pub async fn known(pool: &PgPool) -> Result<Vec<Known>, sqlx::Error> {
    let rows: Vec<(i64, String, String, String, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT id, match, value, note, created_by, created_at FROM net_known_macs \
         ORDER BY created_at DESC, id DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, kind, value, note, created_by, created_at)| Known {
            id,
            kind,
            value,
            note,
            created_by,
            created_at,
        })
        .collect())
}

/// 埠的角色：auto（依 LLDP 與 MAC 數自動判斷）、edge、uplink
pub async fn set_port_role(
    pool: &PgPool,
    net_device: i64,
    if_index: i64,
    role: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let role = match role {
        "auto" | "edge" | "uplink" => role,
        _ => return Err(invalid("角色要是自動、端點或上行")),
    };
    let mut tx = pool.begin().await?;
    // 改回自動時先當成端點埠，下一輪查詢會依 LLDP 重新判斷
    let n = sqlx::query(
        "UPDATE net_interfaces SET role = CASE $3 WHEN 'auto' THEN \
             CASE WHEN role = 'auto_uplink' THEN role ELSE 'auto_edge' END ELSE $3 END \
         WHERE device_id = $1 AND if_index = $2",
    )
    .bind(net_device)
    .bind(if_index)
    .bind(role)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(CmdError::NotFound("連接埠不存在".into()).into());
    }
    audit::record(
        &mut tx,
        actor,
        "netdevice_port_role",
        None,
        json!({"device_id": net_device, "if_index": if_index, "role": role}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert_eq!(
            known_value(KnownMatch::Mac, "00:1B:2C:00:00:01", None, None).unwrap(),
            "00:1b:2c:00:00:01"
        );
        assert_eq!(
            known_value(KnownMatch::Oui, "00:1b:2c:00:00:01", None, None).unwrap(),
            "001B2C"
        );
        assert_eq!(
            known_value(KnownMatch::Port, "00:1b:2c:00:00:01", Some(3), Some(48)).unwrap(),
            "3:48"
        );
        assert!(known_value(KnownMatch::Port, "00:1b:2c:00:00:01", Some(3), None).is_err());
        assert!(known_value(KnownMatch::Mac, "nope", None, None).is_err());
        for s in ["mac", "oui", "port"] {
            assert_eq!(KnownMatch::parse(s).unwrap().as_str(), s);
            assert_ne!(KnownMatch::label(s), "未知");
        }
        assert_eq!(KnownMatch::parse("x"), None);
        assert_eq!(KnownMatch::label("x"), "未知");
    }
}
