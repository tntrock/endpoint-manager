//! network 區段的 Windows 讀取：WMI `ROOT\StandardCimv2`（與 Get-NetAdapter 相同的資料來源）。

use std::collections::HashMap;

use anyhow::Context;
use protocol::{NetInterface, NetworkInfo};
use serde::Deserialize;

use crate::network as parse;
use crate::serde_util::u64_any;

#[derive(Deserialize)]
#[serde(rename = "MSFT_NetAdapter", rename_all = "PascalCase")]
struct Adapter {
    name: Option<String>,
    interface_description: Option<String>,
    #[serde(default, deserialize_with = "u64_any")]
    interface_index: Option<u64>,
    #[serde(default, deserialize_with = "u64_any")]
    interface_type: Option<u64>,
    #[serde(default, deserialize_with = "u64_any")]
    ndis_physical_medium: Option<u64>,
    /// 1 = 已連線
    #[serde(default, deserialize_with = "u64_any")]
    media_connect_state: Option<u64>,
    /// 不分隔的 12 碼 hex（Get-NetAdapter 的 MacAddress 是 PowerShell 算出來的，WMI 查不到）
    permanent_address: Option<String>,
    #[serde(rename = "Virtual")]
    is_virtual: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename = "MSFT_NetIPAddress", rename_all = "PascalCase")]
struct Address {
    #[serde(default, deserialize_with = "u64_any")]
    interface_index: Option<u64>,
    #[serde(rename = "IPAddress")]
    ip_address: Option<String>,
    #[serde(default, deserialize_with = "u64_any")]
    prefix_length: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Route {
    #[serde(default, deserialize_with = "u64_any")]
    interface_index: Option<u64>,
    next_hop: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename = "MSFT_DNSClientServerAddress", rename_all = "PascalCase")]
struct Dns {
    #[serde(default, deserialize_with = "u64_any")]
    interface_index: Option<u64>,
    server_addresses: Option<Vec<String>>,
}

const ROUTES: &str = "SELECT InterfaceIndex, NextHop FROM MSFT_NetRoute \
                      WHERE DestinationPrefix = '0.0.0.0/0' OR DestinationPrefix = '::/0'";

/// `netsh wlan` 讀 SSID；沒有無線網路服務或沒有權限（Windows 11 要開定位）時就是空的
fn ssids() -> HashMap<String, String> {
    let out = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output();
    match out {
        Ok(o) if o.status.success() => parse::netsh_ssids(&String::from_utf8_lossy(&o.stdout)),
        _ => HashMap::new(),
    }
}

pub fn collect() -> anyhow::Result<NetworkInfo> {
    let con = wmi::WMIConnection::with_namespace_path(r"ROOT\StandardCimv2")
        .context(r"connecting to ROOT\StandardCimv2")?;
    let adapters: Vec<Adapter> = con.query().context("MSFT_NetAdapter")?;
    let addresses: Vec<Address> = con.query().unwrap_or_default();
    let routes: Vec<Route> = con.raw_query(ROUTES).unwrap_or_default();
    let dns: Vec<Dns> = con.query().unwrap_or_default();

    let mut addr_by: HashMap<u64, Vec<String>> = HashMap::new();
    for a in addresses {
        let (Some(i), Some(ip)) = (a.interface_index, a.ip_address) else {
            continue;
        };
        let cidr = match a.prefix_length {
            Some(p) => format!("{ip}/{p}"),
            None => ip,
        };
        if parse::reportable(&cidr) {
            addr_by.entry(i).or_default().push(cidr);
        }
    }
    let mut gw_by: HashMap<u64, Vec<String>> = HashMap::new();
    for r in routes {
        if let (Some(i), Some(h)) = (r.interface_index, r.next_hop) {
            gw_by.entry(i).or_default().push(h);
        }
    }
    // IPv4 與 IPv6 各一筆，合併
    let mut dns_by: HashMap<u64, Vec<String>> = HashMap::new();
    for d in dns {
        if let Some(i) = d.interface_index {
            dns_by.entry(i).or_default().extend(
                d.server_addresses
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| parse::real_dns(s)),
            );
        }
    }
    let mut ssid_by = ssids();

    let mut out = Vec::new();
    for a in adapters {
        let idx = a.interface_index.unwrap_or(u64::MAX);
        let desc = a.interface_description.unwrap_or_default();
        let kind = parse::windows_kind(
            a.interface_type.unwrap_or(0) as u32,
            a.ndis_physical_medium.unwrap_or(0) as u32,
            &desc,
            a.is_virtual.unwrap_or(false),
        );
        let name = a.name.unwrap_or_default();
        out.push(NetInterface {
            description: Some(desc).filter(|d| !d.is_empty()),
            kind: kind.to_string(),
            up: a.media_connect_state == Some(1),
            mac: a.permanent_address.as_deref().and_then(parse::mac_from_hex),

            addresses: addr_by.remove(&idx).unwrap_or_default(),
            gateways: gw_by.remove(&idx).unwrap_or_default(),
            dns: dns_by.remove(&idx).unwrap_or_default(),
            ssid: ssid_by.remove(&name),
            name,
        });
    }
    Ok(parse::finish(out))
}
