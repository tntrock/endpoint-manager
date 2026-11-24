//! 網路端交叉比對（竄改偵測規格 §5）：用交換器的 MAC 表、路由器的 ARP 表，
//! 找出 Agent 自己說不出來的事。
//!
//! 每台網路設備每次查詢完 MAC 表、ARP 表（同一個交易裡，這次的資料 `last_seen = now()`）就比對一次：
//! - `silent_on_network`：Agent 沒報到，端點埠上卻一直看得到這台的 MAC（連續 3 次）。
//! - `mac_duplicate`：這台的 MAC 同時出現在兩個端點埠（連續 2 次）。
//! - `ip_conflict`：這台回報的 IP，同據點的 ARP 表對到不是它的 MAC（連續 2 次）。
//!
//! 「連續幾次」記在 `net_crosscheck_streaks`：這次還成立的加一，不成立的刪除。
//! 成立次數夠了就開一筆持續中的發現；所有網路設備上都不再成立時結束。

use sqlx::PgConnection;
use uuid::Uuid;

use crate::findings::{close_network, insert_or_refresh_network};

pub const SILENT_ON_NETWORK: &str = "silent_on_network";
pub const MAC_DUPLICATE: &str = "mac_duplicate";
pub const IP_CONFLICT: &str = "ip_conflict";

/// 一種比對：連續幾次才標示、嚴重度、找出這次成立的 (裝置, 鍵, 細節) 的查詢
struct Check {
    kind: &'static str,
    streak: i32,
    severity: &'static str,
    /// `$1` 是網路設備 ID
    candidates: &'static str,
}

/// 只比對全球唯一的 MAC（隨機、虛擬網卡的位址可能重複），而且只屬於一台裝置的
const UNIQUE_MAC: &str = "substr(s.mac, 2, 1) NOT IN ('2', '3', '6', '7', 'a', 'b', 'e', 'f') \
     AND (SELECT count(*) FROM device_macs m2 WHERE m2.mac = s.mac) = 1";

const CHECKS: [Check; 3] = [
    Check {
        kind: SILENT_ON_NETWORK,
        streak: 3,
        severity: "high",
        // 超過「報到間隔 × 3，至少 5 分鐘」沒報到
        candidates: "SELECT DISTINCT ON (m.device_id, s.mac) m.device_id, s.mac, \
               jsonb_build_object('net_device', nd.name, 'net_device_id', nd.id, \
                                  'port', i.name, 'mac', s.mac, 'vlan', s.vlan) \
             FROM net_mac_sightings s \
             JOIN net_devices nd ON nd.id = s.device_id \
             JOIN net_interfaces i ON i.device_id = s.device_id AND i.if_index = s.if_index \
             JOIN device_macs m ON m.mac = s.mac \
             JOIN devices d ON d.id = m.device_id AND d.status = 'active' \
             WHERE s.device_id = $1 AND s.last_seen = now() \
               AND NOT net_port_is_uplink(i.role, i.mac_count) AND {UNIQUE_MAC} \
               AND d.last_seen_at < now() - make_interval(secs => greatest(300, 3 * coalesce( \
                   (SELECT (value #>> '{}')::int FROM settings WHERE key = 'checkin_interval_secs'), 60))) \
             ORDER BY m.device_id, s.mac, s.vlan DESC",
    },
    Check {
        kind: MAC_DUPLICATE,
        streak: 2,
        severity: "medium",
        candidates: "SELECT m.device_id, s.mac, \
               jsonb_build_object('net_device', nd.name, 'net_device_id', nd.id, 'mac', s.mac, \
                                  'ports', to_jsonb(array_agg(DISTINCT i.name ORDER BY i.name))) \
             FROM net_mac_sightings s \
             JOIN net_devices nd ON nd.id = s.device_id \
             JOIN net_interfaces i ON i.device_id = s.device_id AND i.if_index = s.if_index \
             JOIN device_macs m ON m.mac = s.mac \
             JOIN devices d ON d.id = m.device_id AND d.status = 'active' \
             WHERE s.device_id = $1 AND s.last_seen = now() \
               AND NOT net_port_is_uplink(i.role, i.mac_count) AND {UNIQUE_MAC} \
             GROUP BY m.device_id, s.mac, nd.name, nd.id \
             HAVING count(DISTINCT s.if_index) >= 2",
    },
    Check {
        kind: IP_CONFLICT,
        streak: 2,
        severity: "medium",
        // 只比對同據點網段內的位址（不同據點可能用同樣的私有網段）；
        // 裝置最近 10 分鐘有報到，而且回報過網卡（知道它有哪些 MAC）
        candidates: "SELECT DISTINCT ON (d.id, a.ip) d.id, host(a.ip), \
               jsonb_build_object('net_device', nd.name, 'net_device_id', nd.id, \
                                  'ip', host(a.ip), 'mac', a.mac) \
             FROM net_arp a \
             JOIN net_devices nd ON nd.id = a.device_id \
             JOIN sites st ON st.id = nd.site_id \
             JOIN devices d ON d.ips @> ARRAY[a.ip] AND d.status = 'active' \
             WHERE a.device_id = $1 AND a.last_seen = now() \
               AND a.ip <<= ANY(st.cidrs) \
               AND d.last_seen_at > now() - interval '10 minutes' \
               AND EXISTS (SELECT 1 FROM device_macs x WHERE x.device_id = d.id) \
               AND NOT EXISTS (SELECT 1 FROM device_macs x WHERE x.device_id = d.id AND x.mac = a.mac) \
             ORDER BY d.id, a.ip, a.mac",
    },
];

/// 這台網路設備查詢完 MAC 表、ARP 表後比對（呼叫端的交易裡）
pub async fn run(conn: &mut PgConnection, net_device_id: i64) -> Result<(), sqlx::Error> {
    for c in &CHECKS {
        let candidates = c.candidates.replace("{UNIQUE_MAC}", UNIQUE_MAC);
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO net_crosscheck_streaks (net_device_id, kind, device_id, key, detail) \
             SELECT $1, $2, c.* FROM ({candidates}) c \
             ON CONFLICT (net_device_id, kind, device_id, key) DO UPDATE \
             SET streak = net_crosscheck_streaks.streak + 1, last_at = now(), \
                 detail = EXCLUDED.detail"
        )))
        .bind(net_device_id)
        .bind(c.kind)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "DELETE FROM net_crosscheck_streaks \
             WHERE net_device_id = $1 AND kind = $2 AND last_at < now()",
        )
        .bind(net_device_id)
        .bind(c.kind)
        .execute(&mut *conn)
        .await?;
        insert_or_refresh_network(&mut *conn, net_device_id, c.kind, c.severity, c.streak).await?;
        close_network(&mut *conn, c.kind).await?;
    }
    Ok(())
}

/// Agent 報到了：「沒報到但在網路上」結束，連續次數歸零
pub async fn checked_in(conn: &mut PgConnection, devices: &[Uuid]) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM net_crosscheck_streaks WHERE kind = $1 AND device_id = ANY($2)")
        .bind(SILENT_ON_NETWORK)
        .bind(devices)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "UPDATE device_findings SET ended_at = now() \
         WHERE kind = $1 AND ended_at IS NULL AND device_id = ANY($2)",
    )
    .bind(SILENT_ON_NETWORK)
    .bind(devices)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
