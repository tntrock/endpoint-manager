//! 實際的 SNMP 查詢：一台設備一輪。只用 GET 與 GETBULK（唯讀）。

use std::time::Duration;

use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::{Auth, Client, ErrorKind, Oid, Retry, UdpHandle, UsmConfig, VarBind};
use protocol::netdev::{
    CiscoVlanMode, MAX_TABLE_ENTRIES, NetData, NetPollKind, SnmpAuthProtocol, SnmpCredential,
    SnmpPrivProtocol, SnmpTarget,
};

use super::parse::{self, Tables};
use super::tables::{self, Fdb};

/// 查詢限制（規格 §4）
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub request_timeout: Duration,
    pub retries: u32,
    pub max_repetitions: u32,
    /// 單台設備一輪的上限
    pub deadline: Duration,
    /// 單一子樹最多讀幾筆（避免設備回應異常時無限讀下去）
    pub max_varbinds: usize,
    /// Cisco 逐 VLAN 查詢時最多查幾個 VLAN
    pub max_vlans: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            request_timeout: Duration::from_secs(2),
            retries: 2,
            max_repetitions: 25,
            deadline: Duration::from_secs(120),
            max_varbinds: 100_000,
            max_vlans: 256,
        }
    }
}

/// 帳密；`vlan` 有值時是 Cisco 的逐 VLAN 查詢（v2c：community@vlan，v3：context vlan-N）
fn auth_of(c: &SnmpCredential, vlan: Option<u32>) -> anyhow::Result<Auth> {
    Ok(match c {
        SnmpCredential::V2c { community } => {
            let c = match vlan {
                Some(v) => format!("{community}@{v}"),
                None => community.clone(),
            };
            Auth::v2c(c.into_bytes())
        }
        SnmpCredential::V3 {
            user,
            auth,
            auth_pass,
            privacy,
            priv_pass,
        } => {
            let a = match auth {
                SnmpAuthProtocol::Sha1 => AuthProtocol::Sha1,
                SnmpAuthProtocol::Sha256 => AuthProtocol::Sha256,
            };
            let p = match privacy {
                SnmpPrivProtocol::Aes128 => PrivProtocol::Aes128,
                SnmpPrivProtocol::Aes256 => PrivProtocol::Aes256Blumenthal,
                SnmpPrivProtocol::Aes256Cisco => PrivProtocol::Aes256Reeder,
            };
            let mut cfg = UsmConfig::new(user.as_bytes().to_vec())
                .auth_priv(a, auth_pass, p, priv_pass)
                .map_err(|e| anyhow::anyhow!("SNMPv3 設定錯誤：{e}"))?;
            if let Some(v) = vlan {
                cfg = cfg.context_name(format!("vlan-{v}"));
            }
            cfg.into()
        }
    })
}

/// 給管理員看的錯誤說明
pub fn describe(e: &async_snmp::Error, t: &SnmpTarget) -> String {
    match e.kind() {
        ErrorKind::Timeout => format!(
            "逾時：快取主機沒有收到 {}:{} 的回應。請確認網路與防火牆允許 UDP {}；\
             v2c 的 community 錯誤時設備也不會回應",
            t.address, t.port, t.port
        ),
        ErrorKind::Auth | ErrorKind::Report => {
            format!("驗證失敗：請確認 SNMPv3 使用者名稱、密碼與演算法（{e}）")
        }
        ErrorKind::Network => format!("網路錯誤：{e}"),
        _ => format!("查詢失敗：{e}"),
    }
}

type Snmp = Client<UdpHandle>;

async fn connect(t: &SnmpTarget, l: &Limits, vlan: Option<u32>) -> anyhow::Result<Snmp> {
    let auth = auth_of(&t.credential, vlan)?;
    let retry = Retry::fixed(l.retries, Duration::ZERO)
        .map_err(|e| anyhow::anyhow!("查詢設定錯誤：{e}"))?;
    Client::builder((t.address.as_str(), t.port), auth)
        .request_timeout(l.request_timeout)
        .retry(retry)
        .connect()
        .await
        .map_err(|e| anyhow::Error::new(e).context("connect"))
}

async fn walk(client: &Snmp, base: &[u32], l: &Limits) -> async_snmp::Result<Vec<VarBind>> {
    let mut out = Vec::new();
    let mut w = client.bulk_walk(Oid::from_slice(base), l.max_repetitions)?;
    while let Some(vb) = w.next().await {
        out.push(vb?);
        if out.len() >= l.max_varbinds {
            tracing::warn!(oid = ?base, "walk truncated");
            break;
        }
    }
    Ok(out)
}

async fn optional(client: &Snmp, base: &[u32], l: &Limits) -> Vec<VarBind> {
    walk(client, base, l).await.unwrap_or_else(|e| {
        tracing::debug!(oid = ?base, error = %e, "optional walk failed");
        vec![]
    })
}

/// 每個欄位分別走訪；某個欄位失敗（設備不支援這個 MIB）時略過
async fn walk_columns(client: &Snmp, entry: &[u32], cols: &[u32], l: &Limits) -> Vec<VarBind> {
    let mut out = Vec::new();
    for c in cols {
        let mut base = entry.to_vec();
        base.push(*c);
        out.extend(optional(client, &base, l).await);
    }
    out
}

async fn system_round(client: &Snmp, l: &Limits) -> async_snmp::Result<NetData> {
    // 系統資訊一定要有：失敗就是這一輪失敗
    let scalars = client
        .get_many(&[
            Oid::from_slice(parse::SYS_DESCR),
            Oid::from_slice(parse::SYS_OBJECT_ID),
            Oid::from_slice(parse::SYS_UPTIME),
            Oid::from_slice(parse::SYS_CONTACT),
            Oid::from_slice(parse::SYS_NAME),
            Oid::from_slice(parse::SYS_LOCATION),
        ])
        .await?
        .varbinds;
    let if_table = walk_columns(client, parse::IF_ENTRY, parse::IF_COLUMNS, l).await;
    let tables = Tables {
        if_table,
        ifx_table: walk_columns(client, parse::IFX_ENTRY, parse::IFX_COLUMNS, l).await,
        base_ports: optional(client, parse::BASE_PORT_IFINDEX, l).await,
        pvid: optional(client, parse::Q_PVID, l).await,
        lldp_loc: walk_columns(client, parse::LLDP_LOC_PORT, parse::LLDP_LOC_COLUMNS, l).await,
        lldp_rem: walk_columns(client, parse::LLDP_REM, parse::LLDP_REM_COLUMNS, l).await,
        lldp_man: optional(client, parse::LLDP_REM_MAN_ADDR, l).await,
    };
    let entities = walk_columns(client, parse::ENT_PHYSICAL, parse::ENT_COLUMNS, l).await;
    let uptime = parse::uptime_ticks(&scalars);
    Ok(NetData {
        system: Some(parse::system(&scalars, &entities)),
        interfaces: parse::interfaces(&tables, uptime),
        ..empty(0, NetPollKind::System)
    })
}

fn empty(id: i64, kind: NetPollKind) -> NetData {
    NetData {
        device_id: id,
        kind,
        error: None,
        system: None,
        interfaces: vec![],
        fdb: vec![],
        arp: vec![],
    }
}

/// 一般的 MAC 位址表（Q-BRIDGE，沒有才用 BRIDGE-MIB）
async fn plain_fdb(
    client: &Snmp,
    l: &Limits,
    vlan: Option<u32>,
) -> Vec<protocol::netdev::FdbEntry> {
    let mut f = Fdb {
        base_ports: optional(client, parse::BASE_PORT_IFINDEX, l).await,
        q_port: optional(client, tables::Q_FDB_PORT, l).await,
        ..Default::default()
    };
    if f.q_port.is_empty() {
        f.d_port = optional(client, tables::D_FDB_PORT, l).await;
        f.d_status = optional(client, tables::D_FDB_STATUS, l).await;
    } else {
        f.q_status = optional(client, tables::Q_FDB_STATUS, l).await;
        f.vlan_fdb_id = optional(client, tables::Q_VLAN_FDB_ID, l).await;
    }
    tables::fdb(&f, vlan)
}

async fn tables_round(t: &SnmpTarget, client: &Snmp, l: &Limits) -> anyhow::Result<NetData> {
    // sysObjectID：判斷是不是 Cisco，也順便確認設備連得到、帳密正確
    let oid = client
        .get(&Oid::from_slice(parse::SYS_OBJECT_ID))
        .await?
        .varbinds;
    let object_id = oid
        .first()
        .map(|v| parse::text(&v.value))
        .unwrap_or_default();
    let per_vlan = match t.cisco_vlan {
        CiscoVlanMode::On => true,
        CiscoVlanMode::Off => false,
        CiscoVlanMode::Auto => tables::is_cisco(&object_id),
    };
    let mut fdb = Vec::new();
    if per_vlan {
        let vlans = tables::cisco_vlans(&optional(client, tables::CISCO_VLAN_STATE, l).await);
        for v in vlans.into_iter().take(l.max_vlans) {
            match connect(t, l, Some(v)).await {
                Ok(c) => fdb.extend(plain_fdb(&c, l, Some(v)).await),
                Err(e) => tracing::debug!(vlan = v, error = %e, "per-VLAN connect failed"),
            }
            if fdb.len() >= MAX_TABLE_ENTRIES {
                break;
            }
        }
    }
    if fdb.is_empty() {
        fdb = plain_fdb(client, l, None).await;
    }
    fdb.truncate(MAX_TABLE_ENTRIES);
    let mut arp = tables::arp(&optional(client, tables::IP_NET_TO_PHYS, l).await, &[]);
    if arp.is_empty() {
        arp = tables::arp(&[], &optional(client, tables::IP_NET_TO_MEDIA, l).await);
    }
    arp.truncate(MAX_TABLE_ENTRIES);
    Ok(NetData {
        fdb,
        arp,
        ..empty(t.id, NetPollKind::Tables)
    })
}

fn explain(e: &anyhow::Error, t: &SnmpTarget) -> String {
    // async_snmp 的錯誤是 Box<Error>
    let found = e.chain().find_map(|c| {
        c.downcast_ref::<async_snmp::Error>()
            .or_else(|| c.downcast_ref::<Box<async_snmp::Error>>().map(|b| &**b))
    });
    match found {
        Some(s) => describe(s, t),
        None => format!("{e:#}"),
    }
}

/// 查詢一台設備一輪；失敗時 `error` 有值
pub async fn poll(t: &SnmpTarget, kind: NetPollKind, l: &Limits) -> NetData {
    let run = async {
        let client = connect(t, l, None).await?;
        match kind {
            NetPollKind::System => Ok(system_round(&client, l).await?),
            NetPollKind::Tables => tables_round(t, &client, l).await,
        }
    };
    let mut d = match tokio::time::timeout(l.deadline, run).await {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => NetData {
            error: Some(explain(&e, t)),
            ..empty(t.id, kind)
        },
        Err(_) => NetData {
            error: Some(format!(
                "查詢超過 {} 秒仍未完成，已中止",
                l.deadline.as_secs()
            )),
            ..empty(t.id, kind)
        },
    };
    d.device_id = t.id;
    d.kind = kind;
    d
}

/// 系統資訊、實體、介面與 LLDP
pub async fn poll_system(t: &SnmpTarget, l: &Limits) -> NetData {
    poll(t, NetPollKind::System, l).await
}
