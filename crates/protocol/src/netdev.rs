//! 網路設備（SNMP）：中央在快取報到回應裡下發查詢工作，快取查詢後上傳結果。
//!
//! 只做唯讀查詢；帳密只在中央加密保存，經 mTLS 下發給該據點的快取，快取只放記憶體。

use serde::{Deserialize, Serialize};

/// 單台設備一次上傳最多幾個介面（超過的部分捨棄）
pub const MAX_INTERFACES: usize = 10_000;
/// 單台設備一次上傳最多幾筆 MAC 位址表或 ARP 表（超過的部分捨棄）
pub const MAX_TABLE_ENTRIES: usize = 200_000;
/// 一份工作最多幾台設備
pub const MAX_TARGETS: usize = 5_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnmpAuthProtocol {
    Sha1,
    Sha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SnmpPrivProtocol {
    Aes128,
    /// AES-256（Blumenthal 金鑰延伸，net-snmp 等多數廠牌）
    Aes256,
    /// AES-256（Reeder 金鑰延伸，Cisco 的 aes 256）
    #[serde(rename = "aes256c")]
    Aes256Cisco,
}

/// SNMP 帳密。Debug 不印出機密。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "version", rename_all = "lowercase")]
pub enum SnmpCredential {
    V2c {
        community: String,
    },
    /// 只支援 authPriv
    V3 {
        user: String,
        auth: SnmpAuthProtocol,
        auth_pass: String,
        privacy: SnmpPrivProtocol,
        priv_pass: String,
    },
}

impl std::fmt::Debug for SnmpCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnmpCredential::V2c { .. } => f.write_str("V2c { community: *** }"),
            SnmpCredential::V3 {
                user,
                auth,
                privacy,
                ..
            } => f
                .debug_struct("V3")
                .field("user", user)
                .field("auth", auth)
                .field("privacy", privacy)
                .finish_non_exhaustive(),
        }
    }
}

impl SnmpCredential {
    pub fn version_label(&self) -> &'static str {
        match self {
            SnmpCredential::V2c { .. } => "v2c",
            SnmpCredential::V3 { .. } => "v3",
        }
    }
}

/// Cisco 的 MAC 位址表要逐個 VLAN 查詢（v2c 用 community@vlan，v3 用 context vlan-N）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CiscoVlanMode {
    /// 依 sysObjectID 判斷
    #[default]
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpTarget {
    pub id: i64,
    /// IP 位址或主機名稱
    pub address: String,
    pub port: u16,
    pub credential: SnmpCredential,
    #[serde(default)]
    pub cisco_vlan: CiscoVlanMode,
    /// 管理員剛新增或修改：不等排程，立即查詢一次
    #[serde(default)]
    pub poll_now: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnmpJob {
    pub targets: Vec<SnmpTarget>,
    /// 系統資訊、實體、介面、LLDP
    pub system_interval_secs: u32,
    /// MAC 位址表、ARP 表
    pub table_interval_secs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetPollKind {
    System,
    Tables,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetSystem {
    pub name: String,
    pub descr: String,
    pub location: String,
    pub contact: String,
    /// sysObjectID，點分十進位
    pub object_id: String,
    pub uptime_secs: u64,
    /// ENTITY-MIB 的機箱（或第一個有型號的實體）
    pub model: String,
    pub serial: String,
    pub firmware: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpNeighbor {
    pub sys_name: String,
    pub port_id: String,
    pub port_descr: String,
    pub chassis_id: String,
    pub mgmt_address: Option<String>,
    /// lldpRemSysCapEnabled 有 bridge 或 router
    pub is_switch_or_router: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetInterface {
    pub index: u32,
    /// ifName（沒有時用 ifDescr）
    pub name: String,
    /// ifAlias：管理員設定的說明
    pub alias: String,
    /// IANAifType
    pub if_type: u32,
    pub admin_up: bool,
    pub oper_up: bool,
    pub speed_mbps: Option<u64>,
    /// aa:bb:cc:dd:ee:ff
    pub mac: Option<String>,
    /// 埠的預設 VLAN（Q-BRIDGE dot1qPvid）
    pub pvid: Option<u32>,
    /// ifLastChange 距今幾秒（設備開機後才變動過才有）
    pub last_change_secs_ago: Option<u64>,
    #[serde(default)]
    pub lldp: Vec<LldpNeighbor>,
}

/// MAC 位址表的一筆：這個 MAC 從哪個埠學到
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FdbEntry {
    pub mac: String,
    pub if_index: u32,
    pub vlan: Option<u32>,
}

/// ARP（或 IPv6 鄰居）表的一筆
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub if_index: Option<u32>,
}

/// 快取上傳一台設備一輪的查詢結果（`POST /v1/cache/netdata`）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetData {
    pub device_id: i64,
    pub kind: NetPollKind,
    /// 查詢失敗的原因；有值時其他欄位忽略
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub system: Option<NetSystem>,
    #[serde(default)]
    pub interfaces: Vec<NetInterface>,
    /// MAC 位址表（`tables` 輪）
    #[serde(default)]
    pub fdb: Vec<FdbEntry>,
    /// ARP 表（`tables` 輪）
    #[serde(default)]
    pub arp: Vec<ArpEntry>,
}

/// MAC 位址的標準寫法：小寫、冒號分隔；長度不是 6 位元組時回 None
pub fn format_mac(bytes: &[u8]) -> Option<String> {
    (bytes.len() == 6).then(|| {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_debug_hides_secrets() {
        let c = SnmpCredential::V2c {
            community: "s3cret".into(),
        };
        assert!(!format!("{c:?}").contains("s3cret"));
        let c = SnmpCredential::V3 {
            user: "monitor".into(),
            auth: SnmpAuthProtocol::Sha256,
            auth_pass: "authpass1".into(),
            privacy: SnmpPrivProtocol::Aes128,
            priv_pass: "privpass1".into(),
        };
        let d = format!("{c:?}");
        assert!(d.contains("monitor") && !d.contains("authpass1") && !d.contains("privpass1"));
        assert_eq!(c.version_label(), "v3");
    }

    #[test]
    fn credential_json_is_tagged() {
        let c: SnmpCredential =
            serde_json::from_str(r#"{"version":"v2c","community":"public"}"#).unwrap();
        assert_eq!(
            c,
            SnmpCredential::V2c {
                community: "public".into()
            }
        );
        let j = serde_json::to_value(SnmpCredential::V3 {
            user: "u".into(),
            auth: SnmpAuthProtocol::Sha1,
            auth_pass: "a".into(),
            privacy: SnmpPrivProtocol::Aes256,
            priv_pass: "p".into(),
        })
        .unwrap();
        assert_eq!(j["version"], "v3");
        assert_eq!(j["auth"], "sha1");
        assert_eq!(j["privacy"], "aes256");
    }

    #[test]
    fn target_defaults() {
        let t: SnmpTarget = serde_json::from_str(
            r#"{"id":1,"address":"10.0.0.1","port":161,
                "credential":{"version":"v2c","community":"c"}}"#,
        )
        .unwrap();
        assert_eq!(t.cisco_vlan, CiscoVlanMode::Auto);
        assert!(!t.poll_now);
    }

    #[test]
    fn netdata_roundtrip_and_defaults() {
        let d: NetData = serde_json::from_str(r#"{"device_id":3,"kind":"system"}"#).unwrap();
        assert_eq!(d.error, None);
        assert!(d.system.is_none() && d.interfaces.is_empty());
        assert!(d.fdb.is_empty() && d.arp.is_empty());
        let d = NetData {
            device_id: 3,
            kind: NetPollKind::System,
            error: None,
            system: Some(NetSystem {
                name: "sw1".into(),
                uptime_secs: 10,
                ..Default::default()
            }),
            interfaces: vec![NetInterface {
                index: 1,
                name: "Gi1/0/1".into(),
                alias: String::new(),
                if_type: 6,
                admin_up: true,
                oper_up: false,
                speed_mbps: Some(1000),
                mac: format_mac(&[0, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f]),
                pvid: Some(10),
                last_change_secs_ago: None,
                lldp: vec![],
            }],
            fdb: vec![FdbEntry {
                mac: "00:1b:2c:3d:4e:5f".into(),
                if_index: 1,
                vlan: Some(10),
            }],
            arp: vec![ArpEntry {
                ip: "10.0.0.5".into(),
                mac: "00:1b:2c:3d:4e:5f".into(),
                if_index: None,
            }],
        };
        let back: NetData = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back, d);
        assert_eq!(back.interfaces[0].mac.as_deref(), Some("00:1b:2c:3d:4e:5f"));
    }

    #[test]
    fn mac_format() {
        assert_eq!(format_mac(&[1, 2, 3]), None);
        assert_eq!(
            format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
    }
}
