//! MAC 位址表與 ARP 表的整理（純函式）。

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use async_snmp::{Value, VarBind};
use protocol::netdev::{ArpEntry, FdbEntry, format_mac};

use super::parse::{BASE_PORT_IFINDEX, bytes, dotted, num};

/// Q-BRIDGE-MIB dot1qTpFdbPort／Status（索引：fdbId.MAC）
pub const Q_FDB_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2];
pub const Q_FDB_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 3];
/// Q-BRIDGE-MIB dot1qVlanFdbId（索引：timeMark.VLAN → fdbId）
pub const Q_VLAN_FDB_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 3];
/// BRIDGE-MIB dot1dTpFdbPort／Status（索引：MAC；Cisco 每個 VLAN 一份）
pub const D_FDB_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2];
pub const D_FDB_STATUS: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3];
/// IP-MIB ipNetToPhysicalPhysAddress（索引：ifIndex.類型.長度.位址）
pub const IP_NET_TO_PHYS: &[u32] = &[1, 3, 6, 1, 2, 1, 4, 35, 1, 4];
/// RFC1213 ipNetToMediaPhysAddress（索引：ifIndex.a.b.c.d），舊設備用
pub const IP_NET_TO_MEDIA: &[u32] = &[1, 3, 6, 1, 2, 1, 4, 22, 1, 2];
/// CISCO-VTP-MIB vtpVlanState（索引：管理網域.VLAN；1 = 運作中）
pub const CISCO_VLAN_STATE: &[u32] = &[1, 3, 6, 1, 4, 1, 9, 9, 46, 1, 3, 1, 1, 2];
/// Cisco 的 sysObjectID 前綴
pub const CISCO_ENTERPRISE: &[u32] = &[1, 3, 6, 1, 4, 1, 9];

/// 單一欄（base 已含欄位號）：base.index… → (index, 值)
fn rows<'a>(
    vbs: &'a [VarBind],
    base: &'a [u32],
) -> impl Iterator<Item = (&'a [u32], &'a Value)> + 'a {
    vbs.iter().filter_map(move |vb| {
        let idx = vb.oid.arcs().strip_prefix(base)?;
        (!idx.is_empty()).then_some((idx, &vb.value))
    })
}

/// 單播位址才算；全 0、多播、廣播回 None
fn unicast(b: &[u8]) -> Option<String> {
    if b.len() != 6 || b.iter().all(|x| *x == 0) || b[0] & 1 == 1 {
        return None;
    }
    format_mac(b)
}

/// 索引裡的 6 個數字 → MAC
fn mac_of(arcs: &[u32]) -> Option<String> {
    if arcs.len() != 6 || arcs.iter().any(|b| *b > 255) {
        return None;
    }
    let b: Vec<u8> = arcs.iter().map(|x| *x as u8).collect();
    unicast(&b)
}

/// 橋接埠號 → ifIndex
pub fn base_ports(vbs: &[VarBind]) -> HashMap<u32, u32> {
    rows(vbs, BASE_PORT_IFINDEX)
        .filter_map(|(idx, v)| {
            let [port] = idx else { return None };
            Some((*port, u32::try_from(num(v)?).ok()?))
        })
        .collect()
}

/// 狀態欄：invalid(2)、self(4) 不算學到的位址；沒有狀態欄時都算
fn learned(status: &HashMap<Vec<u32>, u64>, idx: &[u32]) -> bool {
    !matches!(status.get(idx), Some(2 | 4))
}

fn status_map(vbs: &[VarBind], base: &[u32]) -> HashMap<Vec<u32>, u64> {
    rows(vbs, base)
        .filter_map(|(i, v)| Some((i.to_vec(), num(v)?)))
        .collect()
}

/// MAC 位址表的原始查詢結果
#[derive(Default)]
pub struct Fdb {
    pub base_ports: Vec<VarBind>,
    pub q_port: Vec<VarBind>,
    pub q_status: Vec<VarBind>,
    pub vlan_fdb_id: Vec<VarBind>,
    pub d_port: Vec<VarBind>,
    pub d_status: Vec<VarBind>,
}

/// 整理成 (MAC, ifIndex, VLAN)。有 Q-BRIDGE 就用它（含 VLAN），否則用 BRIDGE-MIB；
/// `vlan` 是 Cisco 逐 VLAN 查詢時這一份所屬的 VLAN
pub fn fdb(f: &Fdb, vlan: Option<u32>) -> Vec<FdbEntry> {
    let base = base_ports(&f.base_ports);
    // fdbId → VLAN：多個 VLAN 共用同一個 fdbId（共用學習）時無法判斷
    let mut fid_vlans: HashMap<u32, Vec<u32>> = HashMap::new();
    for (idx, v) in rows(&f.vlan_fdb_id, Q_VLAN_FDB_ID) {
        if let ([_, vl], Some(fid)) = (idx, num(v).and_then(|n| u32::try_from(n).ok())) {
            fid_vlans.entry(fid).or_default().push(*vl);
        }
    }
    let vlan_of = |fid: u32| match fid_vlans.get(&fid) {
        Some(v) if v.len() == 1 => Some(v[0]),
        Some(_) => None,
        // 沒有對應表時，多數設備的 fdbId 就是 VLAN
        None if fid_vlans.is_empty() => Some(fid),
        None => None,
    };
    let port_of = |v: &Value| {
        num(v)
            .and_then(|p| u32::try_from(p).ok())
            .and_then(|p| base.get(&p).copied())
    };
    let q_status = status_map(&f.q_status, Q_FDB_STATUS);
    let mut found: Vec<FdbEntry> = rows(&f.q_port, Q_FDB_PORT)
        .filter(|(idx, _)| learned(&q_status, idx))
        .filter_map(|(idx, v)| {
            let [fid, mac @ ..] = idx else { return None };
            Some(FdbEntry {
                mac: mac_of(mac)?,
                if_index: port_of(v)?,
                vlan: vlan_of(*fid),
            })
        })
        .collect();
    if found.is_empty() {
        let d_status = status_map(&f.d_status, D_FDB_STATUS);
        found = rows(&f.d_port, D_FDB_PORT)
            .filter(|(idx, _)| learned(&d_status, idx))
            .filter_map(|(idx, v)| {
                Some(FdbEntry {
                    mac: mac_of(idx)?,
                    if_index: port_of(v)?,
                    vlan,
                })
            })
            .collect();
    }
    let mut seen = HashSet::new();
    found.retain(|e| seen.insert((e.mac.clone(), e.if_index, e.vlan)));
    found
}

/// Cisco 運作中的 VLAN（不含 1002–1005 的保留 VLAN）
pub fn cisco_vlans(vbs: &[VarBind]) -> Vec<u32> {
    let mut v: Vec<u32> = rows(vbs, CISCO_VLAN_STATE)
        .filter_map(|(idx, val)| match idx {
            [_, vlan] if num(val) == Some(1) && !(1002..=1005).contains(vlan) => Some(*vlan),
            _ => None,
        })
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn is_cisco(object_id: &str) -> bool {
    let prefix = dotted(CISCO_ENTERPRISE);
    object_id == prefix || object_id.starts_with(&format!("{prefix}."))
}

/// ARP 表：先用 IP-MIB 新表（含 IPv6），沒有才用 RFC1213 舊表
pub fn arp(phys: &[VarBind], media: &[VarBind]) -> Vec<ArpEntry> {
    let mut out = Vec::new();
    for (idx, v) in rows(phys, IP_NET_TO_PHYS) {
        let [ifi, kind, len, addr @ ..] = idx else {
            continue;
        };
        if addr.len() != *len as usize || addr.iter().any(|b| *b > 255) {
            continue;
        }
        let b: Vec<u8> = addr.iter().map(|x| *x as u8).collect();
        let ip = match (
            kind,
            <[u8; 4]>::try_from(b.as_slice()),
            <[u8; 16]>::try_from(b.as_slice()),
        ) {
            (1, Ok(a), _) => Ipv4Addr::from(a).to_string(),
            (2, _, Ok(a)) => Ipv6Addr::from(a).to_string(),
            _ => continue,
        };
        if let Some(mac) = unicast(bytes(v)) {
            out.push(ArpEntry {
                ip,
                mac,
                if_index: Some(*ifi),
            });
        }
    }
    if !out.is_empty() {
        return out;
    }
    for (idx, v) in rows(media, IP_NET_TO_MEDIA) {
        let [ifi, a @ ..] = idx else { continue };
        let Ok(a) = <[u32; 4]>::try_from(a) else {
            continue;
        };
        let Ok(a) = a
            .map(u8::try_from)
            .into_iter()
            .collect::<Result<Vec<u8>, _>>()
        else {
            continue;
        };
        if let Some(mac) = unicast(bytes(v)) {
            out.push(ArpEntry {
                ip: Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string(),
                mac,
                if_index: Some(*ifi),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snmp::parse::tests::vb;
    use bytes::Bytes;

    fn raw(v: &[u8]) -> Value {
        Value::OctetString(Bytes::from(v.to_vec()))
    }

    fn mac_idx(prefix: &[u32], m: [u32; 6]) -> Vec<u32> {
        let mut v = prefix.to_vec();
        v.extend(m);
        v
    }

    #[test]
    fn fdb_q_bridge() {
        let mut f = Fdb::default();
        f.base_ports
            .push(vb(BASE_PORT_IFINDEX, &[1], Value::Integer(101)));
        f.base_ports
            .push(vb(BASE_PORT_IFINDEX, &[2], Value::Integer(102)));
        // fdbId 5 → VLAN 10；fdbId 9 被 VLAN 20、30 共用
        f.vlan_fdb_id
            .push(vb(Q_VLAN_FDB_ID, &[0, 10], Value::Gauge32(5)));
        f.vlan_fdb_id
            .push(vb(Q_VLAN_FDB_ID, &[0, 20], Value::Gauge32(9)));
        f.vlan_fdb_id
            .push(vb(Q_VLAN_FDB_ID, &[0, 30], Value::Gauge32(9)));
        let a = [0, 0x1b, 0x2c, 0, 0, 1];
        let b = [0, 0x1b, 0x2c, 0, 0, 2];
        let me = [0, 9, 9, 9, 9, 9];
        f.q_port
            .push(vb(Q_FDB_PORT, &mac_idx(&[5], a), Value::Integer(1)));
        f.q_port
            .push(vb(Q_FDB_PORT, &mac_idx(&[9], b), Value::Integer(2)));
        // 設備自己的位址（status 4）、多播、埠號 0、不認得的埠、重複
        f.q_port
            .push(vb(Q_FDB_PORT, &mac_idx(&[5], me), Value::Integer(1)));
        f.q_status
            .push(vb(Q_FDB_STATUS, &mac_idx(&[5], me), Value::Integer(4)));
        f.q_port.push(vb(
            Q_FDB_PORT,
            &mac_idx(&[5], [1, 0, 0x5e, 0, 0, 1]),
            Value::Integer(1),
        ));
        f.q_port.push(vb(
            Q_FDB_PORT,
            &mac_idx(&[5], [0, 7, 7, 7, 7, 7]),
            Value::Integer(0),
        ));
        f.q_port.push(vb(
            Q_FDB_PORT,
            &mac_idx(&[5], [0, 8, 8, 8, 8, 8]),
            Value::Integer(77),
        ));
        f.q_port
            .push(vb(Q_FDB_PORT, &mac_idx(&[5], a), Value::Integer(1)));
        let e = fdb(&f, None);
        assert_eq!(
            e,
            vec![
                FdbEntry {
                    mac: "00:1b:2c:00:00:01".into(),
                    if_index: 101,
                    vlan: Some(10)
                },
                FdbEntry {
                    mac: "00:1b:2c:00:00:02".into(),
                    if_index: 102,
                    vlan: None
                },
            ]
        );
        // 沒有 fdbId 對應表：fdbId 當 VLAN
        f.vlan_fdb_id.clear();
        assert_eq!(fdb(&f, None)[1].vlan, Some(9));
    }

    #[test]
    fn fdb_bridge_and_cisco() {
        let mut f = Fdb::default();
        f.base_ports
            .push(vb(BASE_PORT_IFINDEX, &[3], Value::Integer(10103)));
        f.d_port
            .push(vb(D_FDB_PORT, &[0, 0x50, 0x56, 1, 2, 3], Value::Integer(3)));
        f.d_port
            .push(vb(D_FDB_PORT, &[0, 0x50, 0x56, 1, 2, 4], Value::Integer(3)));
        f.d_status.push(vb(
            D_FDB_STATUS,
            &[0, 0x50, 0x56, 1, 2, 4],
            Value::Integer(2),
        ));
        let e = fdb(&f, Some(20));
        assert_eq!(e.len(), 1);
        assert_eq!(
            (e[0].mac.as_str(), e[0].if_index, e[0].vlan),
            ("00:50:56:01:02:03", 10103, Some(20))
        );
        let states = vec![
            vb(CISCO_VLAN_STATE, &[1, 1], Value::Integer(1)),
            vb(CISCO_VLAN_STATE, &[1, 20], Value::Integer(1)),
            vb(CISCO_VLAN_STATE, &[1, 30], Value::Integer(2)),
            vb(CISCO_VLAN_STATE, &[1, 1002], Value::Integer(1)),
        ];
        assert_eq!(cisco_vlans(&states), vec![1, 20]);
        assert!(is_cisco("1.3.6.1.4.1.9.1.1208"));
        assert!(is_cisco("1.3.6.1.4.1.9"));
        assert!(!is_cisco("1.3.6.1.4.1.99.1"));
        assert!(!is_cisco("1.3.6.1.4.1.47196.4"));
    }

    #[test]
    fn arp_tables() {
        let pc = [0, 0x1b, 0x2c, 0, 0, 1];
        let mut v6 = vec![5, 2, 16, 0xfe, 0x80];
        v6.extend([0; 13]);
        v6.push(1);
        let phys = vec![
            vb(IP_NET_TO_PHYS, &[5, 1, 4, 10, 0, 0, 5], raw(&pc)),
            vb(IP_NET_TO_PHYS, &v6, raw(&pc)),
            // 廣播、長度不符、未知類型
            vb(IP_NET_TO_PHYS, &[5, 1, 4, 10, 0, 0, 255], raw(&[0xff; 6])),
            vb(IP_NET_TO_PHYS, &[5, 1, 4, 10, 0, 0], raw(&pc)),
            vb(IP_NET_TO_PHYS, &[5, 9, 4, 10, 0, 0, 6], raw(&pc)),
        ];
        let a = arp(&phys, &[]);
        assert_eq!(a.len(), 2);
        assert_eq!(
            (a[0].ip.as_str(), a[0].mac.as_str(), a[0].if_index),
            ("10.0.0.5", "00:1b:2c:00:00:01", Some(5))
        );
        assert_eq!(a[1].ip, "fe80::1");
        let media = vec![
            vb(
                IP_NET_TO_MEDIA,
                &[7, 192, 168, 1, 20],
                raw(&[0, 1, 2, 3, 4, 5]),
            ),
            vb(IP_NET_TO_MEDIA, &[7, 1, 2], raw(&[0, 1, 2, 3, 4, 5])),
            vb(
                IP_NET_TO_MEDIA,
                &[7, 300, 1, 1, 1],
                raw(&[0, 1, 2, 3, 4, 5]),
            ),
        ];
        let a = arp(&[], &media);
        assert_eq!(a.len(), 1);
        assert_eq!((a[0].ip.as_str(), a[0].if_index), ("192.168.1.20", Some(7)));
    }
}
