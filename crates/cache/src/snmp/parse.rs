//! 把 SNMP 查詢結果（varbind）整理成 `NetSystem`、`NetInterface`。純函式，方便測試。

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

use async_snmp::{Value, VarBind};
use protocol::netdev::{LldpNeighbor, NetInterface, NetSystem, format_mac};

pub const SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
pub const SYS_OBJECT_ID: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 2, 0];
pub const SYS_UPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
pub const SYS_CONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
pub const SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
pub const SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];

/// ENTITY-MIB entPhysicalEntry
pub const ENT_PHYSICAL: &[u32] = &[1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1];
pub const ENT_COLUMNS: &[u32] = &[5, 9, 10, 11, 13];
/// IF-MIB ifEntry
pub const IF_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1];
pub const IF_COLUMNS: &[u32] = &[2, 3, 5, 6, 7, 8, 9];
/// IF-MIB ifXEntry
pub const IFX_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1];
pub const IFX_COLUMNS: &[u32] = &[1, 15, 18];
/// BRIDGE-MIB dot1dBasePortIfIndex（橋接埠號 → ifIndex）
pub const BASE_PORT_IFINDEX: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
/// Q-BRIDGE-MIB dot1qPvid（橋接埠號 → 預設 VLAN）
pub const Q_PVID: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 5, 1, 1];
/// LLDP-MIB lldpLocPortEntry
pub const LLDP_LOC_PORT: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 7, 1];
pub const LLDP_LOC_COLUMNS: &[u32] = &[3, 4];
/// LLDP-MIB lldpRemEntry
pub const LLDP_REM: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
pub const LLDP_REM_COLUMNS: &[u32] = &[4, 5, 6, 7, 8, 9, 12];
/// LLDP-MIB lldpRemManAddrIfSubtype（位址在索引裡）
pub const LLDP_REM_MAN_ADDR: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 4, 2, 1, 3];

/// 欄位：base.col.index… → (index, 值)
pub fn column<'a>(
    vbs: &'a [VarBind],
    base: &'a [u32],
    col: u32,
) -> impl Iterator<Item = (&'a [u32], &'a Value)> + 'a {
    vbs.iter().filter_map(move |vb| {
        let arcs = vb.oid.arcs();
        (arcs.len() > base.len() + 1 && arcs.starts_with(base) && arcs[base.len()] == col)
            .then(|| (&arcs[base.len() + 1..], &vb.value))
    })
}

/// 單一整數索引的欄位
fn column_by_index(vbs: &[VarBind], base: &[u32], col: u32) -> BTreeMap<u32, Value> {
    column(vbs, base, col)
        .filter(|(idx, _)| idx.len() == 1)
        .map(|(idx, v)| (idx[0], v.clone()))
        .collect()
}

pub fn text(v: &Value) -> String {
    match v {
        Value::OctetString(b) => String::from_utf8_lossy(b)
            .trim_end_matches('\0')
            .trim()
            .to_string(),
        Value::ObjectIdentifier(o) => dotted(o.arcs()),
        _ => v.as_u64().map(|n| n.to_string()).unwrap_or_default(),
    }
}

pub(crate) fn dotted(arcs: &[u32]) -> String {
    arcs.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

pub(crate) fn bytes(v: &Value) -> &[u8] {
    match v {
        Value::OctetString(b) => b,
        _ => &[],
    }
}

/// 整數類的值（INTEGER、Gauge、Counter、TimeTicks）
pub(crate) fn num(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => v.as_u64(),
    }
}

/// sysUpTime（百分之一秒）
pub fn uptime_ticks(scalars: &[VarBind]) -> Option<u64> {
    scalars
        .iter()
        .find(|vb| vb.oid.arcs() == SYS_UPTIME)
        .and_then(|vb| num(&vb.value))
}

pub fn system(scalars: &[VarBind], entities: &[VarBind]) -> NetSystem {
    let get = |oid: &[u32]| {
        scalars
            .iter()
            .find(|vb| vb.oid.arcs() == oid)
            .map(|vb| text(&vb.value))
            .unwrap_or_default()
    };
    let (model, serial, firmware) = entity(entities);
    NetSystem {
        name: get(SYS_NAME),
        descr: get(SYS_DESCR),
        location: get(SYS_LOCATION),
        contact: get(SYS_CONTACT),
        object_id: get(SYS_OBJECT_ID),
        uptime_secs: uptime_ticks(scalars).unwrap_or(0) / 100,
        model,
        serial,
        firmware,
    }
}

/// ENTITY-MIB：機箱（class 3）優先，其次第一個有型號的實體。(型號, 序號, 韌體)
pub fn entity(vbs: &[VarBind]) -> (String, String, String) {
    let class = column_by_index(vbs, ENT_PHYSICAL, 5);
    let firmware = column_by_index(vbs, ENT_PHYSICAL, 9);
    let software = column_by_index(vbs, ENT_PHYSICAL, 10);
    let serial = column_by_index(vbs, ENT_PHYSICAL, 11);
    let model = column_by_index(vbs, ENT_PHYSICAL, 13);
    let t = |m: &BTreeMap<u32, Value>, i: u32| m.get(&i).map(text).unwrap_or_default();
    let has_id = |i: u32| !t(&model, i).is_empty() || !t(&serial, i).is_empty();
    let pick = class
        .iter()
        .find(|(i, c)| num(c) == Some(3) && has_id(**i))
        .map(|(i, _)| *i)
        .or_else(|| model.keys().copied().find(|i| !t(&model, *i).is_empty()));
    let Some(i) = pick else {
        return Default::default();
    };
    // 軟體版本（IOS、韌體映像）比較有意義；沒有才用韌體版本
    let fw = Some(t(&software, i))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| t(&firmware, i));
    (t(&model, i), t(&serial, i), fw)
}

/// lldpRemSysCapEnabled（BITS）：bridge 或 router，但不是電話（IP 電話內建小交換器，也會宣告 bridge）
pub fn is_switch_or_router(caps: &[u8]) -> bool {
    let b = caps.first().copied().unwrap_or(0);
    let bridge = b & 0x20 != 0;
    let router = b & 0x08 != 0;
    let telephone = b & 0x04 != 0;
    (bridge || router) && !telephone
}

/// LLDP 的 ID：子類型是 MAC 時轉成 aa:bb:…，可列印的文字照原樣，其他用十六進位
fn lldp_id(subtype: Option<u64>, mac_subtype: u64, v: &Value) -> String {
    let b = bytes(v);
    if subtype == Some(mac_subtype)
        && let Some(m) = format_mac(b)
    {
        return m;
    }
    match std::str::from_utf8(b) {
        Ok(s) if s.chars().all(|c| !c.is_control()) => s.trim().to_string(),
        _ => b
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    }
}

/// 管理位址的索引：…subtype.len.bytes
fn man_addr(idx: &[u32]) -> Option<(u32, u32, u32, String)> {
    let [tm, lp, ri, subtype, len, rest @ ..] = idx else {
        return None;
    };
    if rest.len() != *len as usize || rest.iter().any(|b| *b > 255) {
        return None;
    }
    let b: Vec<u8> = rest.iter().map(|x| *x as u8).collect();
    let addr = match (subtype, b.len()) {
        (1, 4) => Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string(),
        (2, 16) => Ipv6Addr::from(<[u8; 16]>::try_from(b.as_slice()).ok()?).to_string(),
        _ => return None,
    };
    Some((*tm, *lp, *ri, addr))
}

/// LLDP 鄰居，依本機的 LLDP 埠號分組
pub fn lldp_neighbors(rem: &[VarBind], man: &[VarBind]) -> BTreeMap<u32, Vec<LldpNeighbor>> {
    // (timeMark, localPort, remIndex) → 欄位
    let mut rows: BTreeMap<(u32, u32, u32), HashMap<u32, Value>> = BTreeMap::new();
    for col in LLDP_REM_COLUMNS {
        for (idx, v) in column(rem, LLDP_REM, *col) {
            if let [tm, lp, ri] = idx {
                rows.entry((*tm, *lp, *ri))
                    .or_default()
                    .insert(*col, v.clone());
            }
        }
    }
    let mut addrs: HashMap<(u32, u32, u32), String> = HashMap::new();
    for vb in man {
        let arcs = vb.oid.arcs();
        if arcs.starts_with(LLDP_REM_MAN_ADDR)
            && let Some((tm, lp, ri, a)) = man_addr(&arcs[LLDP_REM_MAN_ADDR.len()..])
        {
            // IPv4 優先（先出現的 IPv4 不被 IPv6 蓋掉）
            let e = addrs.entry((tm, lp, ri)).or_insert_with(|| a.clone());
            if e.contains(':') && !a.contains(':') {
                *e = a;
            }
        }
    }
    let mut out: BTreeMap<u32, Vec<LldpNeighbor>> = BTreeMap::new();
    for (key, cols) in rows {
        let get = |c: u32| cols.get(&c);
        let empty = Value::OctetString(Default::default());
        out.entry(key.1).or_default().push(LldpNeighbor {
            sys_name: get(9).map(text).unwrap_or_default(),
            // 子類型 4：chassis 是 MAC；3：埠號是 MAC
            chassis_id: lldp_id(get(4).and_then(num), 4, get(5).unwrap_or(&empty)),
            port_id: lldp_id(get(6).and_then(num), 3, get(7).unwrap_or(&empty)),
            port_descr: get(8).map(text).unwrap_or_default(),
            mgmt_address: addrs.get(&key).cloned(),
            is_switch_or_router: is_switch_or_router(get(12).map(bytes).unwrap_or(&[])),
        });
    }
    out
}

/// 所有表格的原始查詢結果
#[derive(Default)]
pub struct Tables {
    pub if_table: Vec<VarBind>,
    pub ifx_table: Vec<VarBind>,
    pub base_ports: Vec<VarBind>,
    pub pvid: Vec<VarBind>,
    pub lldp_loc: Vec<VarBind>,
    pub lldp_rem: Vec<VarBind>,
    pub lldp_man: Vec<VarBind>,
}

pub fn interfaces(t: &Tables, uptime: Option<u64>) -> Vec<NetInterface> {
    let descr = column_by_index(&t.if_table, IF_ENTRY, 2);
    let if_type = column_by_index(&t.if_table, IF_ENTRY, 3);
    let speed = column_by_index(&t.if_table, IF_ENTRY, 5);
    let phys = column_by_index(&t.if_table, IF_ENTRY, 6);
    let admin = column_by_index(&t.if_table, IF_ENTRY, 7);
    let oper = column_by_index(&t.if_table, IF_ENTRY, 8);
    let last_change = column_by_index(&t.if_table, IF_ENTRY, 9);
    let name = column_by_index(&t.ifx_table, IFX_ENTRY, 1);
    let high_speed = column_by_index(&t.ifx_table, IFX_ENTRY, 15);
    let alias = column_by_index(&t.ifx_table, IFX_ENTRY, 18);

    // 橋接埠號 → ifIndex，再對到 PVID
    let base: HashMap<u32, u32> = t
        .base_ports
        .iter()
        .filter_map(|vb| {
            let [port] = vb.oid.arcs().strip_prefix(BASE_PORT_IFINDEX)? else {
                return None;
            };
            Some((*port, u32::try_from(num(&vb.value)?).ok()?))
        })
        .collect();
    let mut pvid: HashMap<u32, u32> = HashMap::new();
    for vb in &t.pvid {
        let arcs = vb.oid.arcs();
        if let Some([port]) = arcs.strip_prefix(Q_PVID)
            && let Some(ifi) = base.get(port)
            && let Some(v) = num(&vb.value).and_then(|v| u32::try_from(v).ok())
        {
            pvid.insert(*ifi, v);
        }
    }

    let indices: Vec<u32> = descr
        .keys()
        .chain(name.keys())
        .copied()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut out: Vec<NetInterface> = indices
        .iter()
        .map(|i| {
            let t = |m: &BTreeMap<u32, Value>| m.get(i).map(text).unwrap_or_default();
            let n = |m: &BTreeMap<u32, Value>| m.get(i).and_then(num);
            let nm = Some(t(&name))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| t(&descr));
            let speed_mbps = match n(&high_speed) {
                Some(h) if h > 0 => Some(h),
                _ => n(&speed).filter(|s| *s > 0).map(|s| s / 1_000_000),
            };
            let last_change_secs_ago = match (uptime, n(&last_change)) {
                (Some(up), Some(lc)) if lc > 0 && lc <= up => Some((up - lc) / 100),
                _ => None,
            };
            NetInterface {
                index: *i,
                name: nm,
                alias: t(&alias),
                if_type: n(&if_type).and_then(|v| u32::try_from(v).ok()).unwrap_or(1),
                admin_up: n(&admin) == Some(1),
                oper_up: n(&oper) == Some(1),
                speed_mbps,
                mac: phys.get(i).and_then(|v| format_mac(bytes(v))),
                pvid: pvid.get(i).copied(),
                last_change_secs_ago,
                lldp: vec![],
            }
        })
        .collect();

    // LLDP 本機埠號 → ifIndex：先用名稱比對（埠號不一定等於 ifIndex），對不到再假設相等
    let loc_id = column_by_index(&t.lldp_loc, LLDP_LOC_PORT, 3);
    let loc_desc = column_by_index(&t.lldp_loc, LLDP_LOC_PORT, 4);
    let by_name: HashMap<String, u32> = out
        .iter()
        .flat_map(|i| {
            let d = descr.get(&i.index).map(text).unwrap_or_default();
            [i.name.to_ascii_lowercase(), d.to_ascii_lowercase()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .map(move |s| (s, i.index))
        })
        .collect();
    let known: std::collections::HashSet<u32> = out.iter().map(|i| i.index).collect();
    let neighbors = lldp_neighbors(&t.lldp_rem, &t.lldp_man);
    for (lp, ns) in neighbors {
        let names = [loc_desc.get(&lp), loc_id.get(&lp)];
        let ifi = names
            .into_iter()
            .flatten()
            .map(|v| text(v).to_ascii_lowercase())
            .find_map(|s| by_name.get(&s).copied())
            .or_else(|| known.contains(&lp).then_some(lp));
        if let Some(ifi) = ifi
            && let Some(i) = out.iter_mut().find(|i| i.index == ifi)
        {
            i.lldp.extend(ns);
        }
    }
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use async_snmp::Oid;
    use bytes::Bytes;

    pub fn vb(base: &[u32], tail: &[u32], value: Value) -> VarBind {
        let mut arcs = base.to_vec();
        arcs.extend_from_slice(tail);
        VarBind {
            oid: Oid::from_slice(&arcs),
            value,
        }
    }

    pub fn s(v: &str) -> Value {
        Value::OctetString(Bytes::from(v.as_bytes().to_vec()))
    }

    fn raw(v: &[u8]) -> Value {
        Value::OctetString(Bytes::from(v.to_vec()))
    }

    #[test]
    fn system_and_entity() {
        let scalars = vec![
            vb(SYS_DESCR, &[], s("Cisco IOS Software, C2960X\0")),
            vb(
                SYS_OBJECT_ID,
                &[],
                Value::ObjectIdentifier(Oid::from_slice(&[1, 3, 6, 1, 4, 1, 9, 1, 1208])),
            ),
            vb(SYS_UPTIME, &[], Value::TimeTicks(123_456)),
            vb(SYS_NAME, &[], s("sw-tp-01")),
            vb(SYS_LOCATION, &[], s("3F 機房")),
        ];
        let ent = vec![
            // 1：電源（class 6）有型號但不是機箱；2：機箱
            vb(ENT_PHYSICAL, &[5, 1], Value::Integer(6)),
            vb(ENT_PHYSICAL, &[13, 1], s("PWR-C1")),
            vb(ENT_PHYSICAL, &[5, 2], Value::Integer(3)),
            vb(ENT_PHYSICAL, &[9, 2], s("")),
            vb(ENT_PHYSICAL, &[10, 2], s("15.2(7)E8")),
            vb(ENT_PHYSICAL, &[11, 2], s("FOC1234X0AB")),
            vb(ENT_PHYSICAL, &[13, 2], s("WS-C2960X-48FPD-L")),
        ];
        let sys = system(&scalars, &ent);
        assert_eq!(sys.name, "sw-tp-01");
        assert_eq!(sys.descr, "Cisco IOS Software, C2960X");
        assert_eq!(sys.location, "3F 機房");
        assert_eq!(sys.contact, "");
        assert_eq!(sys.object_id, "1.3.6.1.4.1.9.1.1208");
        assert_eq!(sys.uptime_secs, 1234);
        assert_eq!(sys.model, "WS-C2960X-48FPD-L");
        assert_eq!(sys.serial, "FOC1234X0AB");
        assert_eq!(sys.firmware, "15.2(7)E8");

        // 沒有機箱：用第一個有型號的；沒有軟體版本就用韌體版本
        let ent = vec![
            vb(ENT_PHYSICAL, &[13, 7], s("")),
            vb(ENT_PHYSICAL, &[13, 9], s("AP-505")),
            vb(ENT_PHYSICAL, &[9, 9], s("8.10.0.2")),
        ];
        assert_eq!(
            entity(&ent),
            ("AP-505".into(), String::new(), "8.10.0.2".into())
        );
        assert_eq!(entity(&[]), Default::default());
    }

    #[test]
    fn capabilities() {
        assert!(is_switch_or_router(&[0x20, 0]));
        assert!(is_switch_or_router(&[0x08]));
        // 電話（bridge + telephone）
        assert!(!is_switch_or_router(&[0x24]));
        // 只有 AP
        assert!(!is_switch_or_router(&[0x10]));
        assert!(!is_switch_or_router(&[]));
    }

    fn tables() -> Tables {
        let mut t = Tables::default();
        for (i, d, ty, admin, oper, mac) in [
            (
                1u32,
                "GigabitEthernet1/0/1",
                6,
                1,
                1,
                Some([0, 0x1b, 0x2c, 0x3d, 0x4e, 0x01]),
            ),
            (2, "GigabitEthernet1/0/2", 6, 1, 2, None),
            (3, "GigabitEthernet1/0/48", 6, 2, 2, None),
            (10, "Vlan10", 53, 1, 1, None),
        ] {
            t.if_table.push(vb(IF_ENTRY, &[2, i], s(d)));
            t.if_table.push(vb(IF_ENTRY, &[3, i], Value::Integer(ty)));
            t.if_table
                .push(vb(IF_ENTRY, &[5, i], Value::Gauge32(1_000_000_000)));
            t.if_table.push(vb(
                IF_ENTRY,
                &[6, i],
                raw(&mac.map(|m| m.to_vec()).unwrap_or_default()),
            ));
            t.if_table
                .push(vb(IF_ENTRY, &[7, i], Value::Integer(admin)));
            t.if_table.push(vb(IF_ENTRY, &[8, i], Value::Integer(oper)));
        }
        t.if_table
            .push(vb(IF_ENTRY, &[9, 1], Value::TimeTicks(100_000)));
        t.if_table.push(vb(IF_ENTRY, &[9, 2], Value::TimeTicks(0)));
        t.ifx_table.push(vb(IFX_ENTRY, &[1, 1], s("Gi1/0/1")));
        t.ifx_table.push(vb(IFX_ENTRY, &[1, 48], s("Gi1/0/48")));
        t.ifx_table
            .push(vb(IFX_ENTRY, &[15, 1], Value::Gauge32(1000)));
        t.ifx_table
            .push(vb(IFX_ENTRY, &[15, 3], Value::Gauge32(10_000)));
        t.ifx_table.push(vb(IFX_ENTRY, &[18, 1], s("會議室 A")));
        // 橋接埠 1 → ifIndex 1、埠 2 → ifIndex 2；PVID
        t.base_ports
            .push(vb(BASE_PORT_IFINDEX, &[1], Value::Integer(1)));
        t.base_ports
            .push(vb(BASE_PORT_IFINDEX, &[2], Value::Integer(2)));
        t.pvid.push(vb(Q_PVID, &[1], Value::Gauge32(10)));
        t.pvid.push(vb(Q_PVID, &[2], Value::Gauge32(20)));
        // 沒有對應 ifIndex 的橋接埠
        t.pvid.push(vb(Q_PVID, &[99], Value::Gauge32(30)));
        // LLDP：本機埠號 48 的描述是 GigabitEthernet1/0/48（ifIndex 3）
        t.lldp_loc.push(vb(LLDP_LOC_PORT, &[3, 48], s("Gi1/0/48")));
        t.lldp_loc
            .push(vb(LLDP_LOC_PORT, &[4, 48], s("GigabitEthernet1/0/48")));
        let rem = |col: u32, v: Value| vb(LLDP_REM, &[col, 0, 48, 1], v);
        t.lldp_rem.push(rem(4, Value::Integer(4)));
        t.lldp_rem.push(rem(5, raw(&[0xaa, 0xbb, 0xcc, 0, 0, 1])));
        t.lldp_rem.push(rem(6, Value::Integer(5)));
        t.lldp_rem.push(rem(7, s("Te1/1/1")));
        t.lldp_rem.push(rem(8, s("uplink")));
        t.lldp_rem.push(rem(9, s("core-sw")));
        t.lldp_rem.push(rem(12, raw(&[0x28, 0])));
        // 本機埠號 1 = ifIndex 1（沒有 lldpLocPort 資料，靠埠號相等）：電話
        let rem1 = |col: u32, v: Value| vb(LLDP_REM, &[col, 0, 1, 2], v);
        t.lldp_rem.push(rem1(9, s("SEP001122334455")));
        t.lldp_rem.push(rem1(12, raw(&[0x24])));
        // 管理位址：IPv6 先出現，IPv4 優先
        let mut v6 = vec![0, 48, 1, 2, 16];
        v6.extend([0xfdu32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        t.lldp_man
            .push(vb(LLDP_REM_MAN_ADDR, &v6, Value::Integer(2)));
        t.lldp_man.push(vb(
            LLDP_REM_MAN_ADDR,
            &[0, 48, 1, 1, 4, 10, 0, 0, 1],
            Value::Integer(2),
        ));
        // 長度不符的索引略過
        t.lldp_man.push(vb(
            LLDP_REM_MAN_ADDR,
            &[0, 1, 2, 1, 4, 10, 0],
            Value::Integer(2),
        ));
        t
    }

    #[test]
    fn interface_table() {
        let ifs = interfaces(&tables(), Some(200_000));
        assert_eq!(
            ifs.len(),
            5,
            "ifIndex 1、2、3、10，加上只出現在 ifXTable 的 48"
        );
        let g1 = &ifs[0];
        assert_eq!(g1.index, 1);
        assert_eq!(g1.name, "Gi1/0/1");
        assert_eq!(g1.alias, "會議室 A");
        assert!(g1.admin_up && g1.oper_up);
        assert_eq!(g1.speed_mbps, Some(1000));
        assert_eq!(g1.mac.as_deref(), Some("00:1b:2c:3d:4e:01"));
        assert_eq!(g1.pvid, Some(10));
        assert_eq!(g1.last_change_secs_ago, Some(1000));
        assert_eq!(g1.lldp.len(), 1);
        assert_eq!(g1.lldp[0].sys_name, "SEP001122334455");
        assert!(!g1.lldp[0].is_switch_or_router);
        assert_eq!(g1.lldp[0].mgmt_address, None);

        let g2 = &ifs[1];
        assert_eq!(g2.name, "GigabitEthernet1/0/2", "沒有 ifName 用 ifDescr");
        assert!(g2.admin_up && !g2.oper_up);
        assert_eq!(g2.speed_mbps, Some(1000), "沒有 ifHighSpeed 用 ifSpeed");
        assert_eq!(g2.pvid, Some(20));
        assert_eq!(g2.last_change_secs_ago, None, "0 表示開機後沒變過");
        assert_eq!(g2.mac, None);

        let g48 = ifs.iter().find(|i| i.index == 3).unwrap();
        assert!(!g48.admin_up);
        assert_eq!(g48.speed_mbps, Some(10_000));
        assert_eq!(g48.lldp.len(), 1);
        let n = &g48.lldp[0];
        assert_eq!(n.sys_name, "core-sw");
        assert_eq!(n.chassis_id, "aa:bb:cc:00:00:01");
        assert_eq!(n.port_id, "Te1/1/1");
        assert_eq!(n.port_descr, "uplink");
        assert_eq!(n.mgmt_address.as_deref(), Some("10.0.0.1"));
        assert!(n.is_switch_or_router);

        let vlan = ifs.iter().find(|i| i.index == 10).unwrap();
        assert_eq!(vlan.if_type, 53);
        assert_eq!(vlan.pvid, None);
        let only_x = ifs.iter().find(|i| i.index == 48).unwrap();
        assert_eq!(only_x.name, "Gi1/0/48");
        assert!(only_x.lldp.is_empty(), "LLDP 依名稱對到 ifIndex 3，不是 48");
    }

    #[test]
    fn ids_and_text() {
        assert_eq!(
            lldp_id(Some(4), 4, &raw(&[1, 2, 3, 4, 5, 6])),
            "01:02:03:04:05:06"
        );
        assert_eq!(lldp_id(Some(7), 4, &s("sw1")), "sw1");
        assert_eq!(lldp_id(None, 4, &raw(&[0, 0xff])), "00:ff");
        assert_eq!(text(&Value::Integer(5)), "5");
        assert_eq!(text(&Value::Null), "");
        assert_eq!(
            man_addr(&[0, 1, 1, 9, 4, 1, 2, 3, 4]),
            None,
            "未知的位址類型"
        );
        assert_eq!(man_addr(&[0, 1, 1, 1, 4, 1, 2, 3, 300]), None);
        assert_eq!(man_addr(&[0, 1]), None);
    }
}
