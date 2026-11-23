//! 實際的 SNMP 查詢：一台設備一輪。只用 GET 與 GETBULK（唯讀）。

use std::time::Duration;

use async_snmp::v3::{AuthProtocol, PrivProtocol};
use async_snmp::{Auth, Client, ErrorKind, Oid, Retry, UsmConfig, VarBind};
use protocol::netdev::{
    NetData, NetPollKind, SnmpAuthProtocol, SnmpCredential, SnmpPrivProtocol, SnmpTarget,
};

use super::parse::{self, Tables};

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
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            request_timeout: Duration::from_secs(2),
            retries: 2,
            max_repetitions: 25,
            deadline: Duration::from_secs(120),
            max_varbinds: 100_000,
        }
    }
}

fn auth_of(c: &SnmpCredential) -> anyhow::Result<Auth> {
    Ok(match c {
        SnmpCredential::V2c { community } => Auth::v2c(community.as_bytes().to_vec()),
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
            UsmConfig::new(user.as_bytes().to_vec())
                .auth_priv(a, auth_pass, p, priv_pass)
                .map_err(|e| anyhow::anyhow!("SNMPv3 設定錯誤：{e}"))?
                .into()
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

async fn walk<T>(client: &Client<T>, base: &[u32], l: &Limits) -> async_snmp::Result<Vec<VarBind>>
where
    T: async_snmp::Transport + Clone + 'static,
{
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

/// 每個欄位分別走訪；某個欄位失敗（設備不支援這個 MIB）時略過
async fn walk_columns<T>(
    client: &Client<T>,
    entry: &[u32],
    cols: &[u32],
    l: &Limits,
) -> Vec<VarBind>
where
    T: async_snmp::Transport + Clone + 'static,
{
    let mut out = Vec::new();
    for c in cols {
        let mut base = entry.to_vec();
        base.push(*c);
        match walk(client, &base, l).await {
            Ok(v) => out.extend(v),
            Err(e) => tracing::debug!(oid = ?base, error = %e, "optional walk failed"),
        }
    }
    out
}

async fn optional<T>(client: &Client<T>, base: &[u32], l: &Limits) -> Vec<VarBind>
where
    T: async_snmp::Transport + Clone + 'static,
{
    walk(client, base, l).await.unwrap_or_else(|e| {
        tracing::debug!(oid = ?base, error = %e, "optional walk failed");
        vec![]
    })
}

async fn system_round<T>(client: &Client<T>, l: &Limits) -> async_snmp::Result<NetData>
where
    T: async_snmp::Transport + Clone + 'static,
{
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
        device_id: 0,
        kind: NetPollKind::System,
        error: None,
        system: Some(parse::system(&scalars, &entities)),
        interfaces: parse::interfaces(&tables, uptime),
    })
}

/// 查詢一台設備的系統資訊、實體、介面與 LLDP；失敗時 `error` 有值
pub async fn poll_system(t: &SnmpTarget, l: &Limits) -> NetData {
    let failed = |msg: String| NetData {
        device_id: t.id,
        kind: NetPollKind::System,
        error: Some(msg),
        system: None,
        interfaces: vec![],
    };
    let auth = match auth_of(&t.credential) {
        Ok(a) => a,
        Err(e) => return failed(format!("{e:#}")),
    };
    let retry = match Retry::fixed(l.retries, Duration::ZERO) {
        Ok(r) => r,
        Err(e) => return failed(format!("查詢設定錯誤：{e}")),
    };
    let client = Client::builder((t.address.as_str(), t.port), auth)
        .request_timeout(l.request_timeout)
        .retry(retry)
        .connect();
    let run = async {
        let client = client.await?;
        system_round(&client, l).await
    };
    match tokio::time::timeout(l.deadline, run).await {
        Ok(Ok(mut d)) => {
            d.device_id = t.id;
            d
        }
        Ok(Err(e)) => failed(describe(&e, t)),
        Err(_) => failed(format!(
            "查詢超過 {} 秒仍未完成，已中止",
            l.deadline.as_secs()
        )),
    }
}
