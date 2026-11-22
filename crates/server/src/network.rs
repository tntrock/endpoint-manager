//! 多重連線（dual-homed）判斷（網路規格 §5.1）。

use std::net::IpAddr;

use protocol::NetInterface;

use crate::branch::sites::{cidr_contains, parse_cidr};

/// 據點與它的網段
#[derive(Debug, Clone)]
pub struct SiteNets {
    pub name: String,
    pub cidrs: Vec<(IpAddr, u8)>,
}

/// 讀取所有據點的網段
pub async fn load_sites(pool: &sqlx::PgPool) -> Result<Vec<SiteNets>, sqlx::Error> {
    let rows: Vec<(String, Vec<String>)> =
        sqlx::query_as("SELECT name, cidrs::text[] FROM sites ORDER BY id")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(name, cidrs)| SiteNets {
            name,
            cidrs: cidrs.iter().filter_map(|c| parse_cidr(c).ok()).collect(),
        })
        .collect())
}

fn ip_of(cidr: &str) -> Option<IpAddr> {
    cidr.split('/').next()?.parse().ok()
}

/// 位址所在的據點（第一個符合的）
pub fn site_of<'a>(sites: &'a [SiteNets], addr: &str) -> Option<&'a str> {
    let ip = ip_of(addr)?;
    sites
        .iter()
        .find(|s| s.cidrs.iter().any(|c| cidr_contains(c, &ip)))
        .map(|s| s.name.as_str())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DualHomed {
    /// 條件 1：兩張以上有預設閘道的實體網卡
    TwoUplinks(Vec<String>),
    /// 條件 2：一張在據點網段內，另一張的預設閘道通往據點以外
    CrossesSite { inside: String, outside: String },
}

impl DualHomed {
    pub fn describe(&self) -> String {
        match self {
            DualHomed::TwoUplinks(names) => {
                format!("{} 都有預設閘道（兩條對外路徑）", names.join("、"))
            }
            DualHomed::CrossesSite { inside, outside } => {
                format!("{inside} 在公司據點網段內，同時 {outside} 經由據點以外的閘道連線")
            }
        }
    }

    pub fn interfaces(&self) -> Vec<&str> {
        match self {
            DualHomed::TwoUplinks(n) => n.iter().map(String::as_str).collect(),
            DualHomed::CrossesSite { inside, outside } => vec![inside, outside],
        }
    }
}

/// 條件 2 只看實體網卡：VPN 連回公司（位址在據點網段內）是正常用法
fn physical(i: &NetInterface) -> bool {
    i.up && !matches!(
        i.kind.as_str(),
        NetInterface::VIRTUAL | NetInterface::LOOPBACK | NetInterface::VPN
    )
}

/// 依目前的網卡狀態判斷。沒有設定據點時只用條件 1
pub fn dual_homed(nics: &[NetInterface], sites: &[SiteNets]) -> Option<DualHomed> {
    let uplinks: Vec<String> = nics
        .iter()
        .filter(|i| i.is_uplink())
        .map(|i| i.name.clone())
        .collect();
    if uplinks.len() >= 2 {
        return Some(DualHomed::TwoUplinks(uplinks));
    }
    if sites.is_empty() {
        return None;
    }
    let in_site = |i: &NetInterface| i.addresses.iter().any(|a| site_of(sites, a).is_some());
    let inside = nics.iter().find(|i| physical(i) && in_site(i))?;
    let outside = nics.iter().find(|i| {
        physical(i) && !i.gateways.is_empty() && !i.addresses.is_empty() && !in_site(i)
    })?;
    Some(DualHomed::CrossesSite {
        inside: inside.name.clone(),
        outside: outside.name.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(name: &str, kind: &str, addr: &str, gw: bool) -> NetInterface {
        NetInterface {
            name: name.into(),
            description: None,
            kind: kind.into(),
            up: true,
            mac: None,
            addresses: if addr.is_empty() {
                vec![]
            } else {
                vec![addr.into()]
            },
            gateways: if gw { vec!["x".into()] } else { vec![] },
            dns: vec![],
            ssid: None,
        }
    }

    fn hq() -> Vec<SiteNets> {
        vec![SiteNets {
            name: "總部".into(),
            cidrs: vec![parse_cidr("10.1.0.0/16").unwrap()],
        }]
    }

    #[test]
    fn two_uplinks() {
        let eth = nic("eth", "ethernet", "10.1.2.3/24", true);
        let lte = nic("lte", "cellular", "100.64.1.2/10", true);
        assert_eq!(
            dual_homed(&[eth.clone(), lte.clone()], &[]),
            Some(DualHomed::TwoUplinks(vec!["eth".into(), "lte".into()]))
        );
        // VPN、虛擬網卡不算對外路徑
        let vpn = nic("wg", "vpn", "10.9.0.2/24", true);
        let vm = nic("vEthernet", "virtual", "172.20.0.1/20", true);
        assert_eq!(dual_homed(&[eth.clone(), vpn, vm], &[]), None);
        // 停用的不算
        let mut off = lte.clone();
        off.up = false;
        assert_eq!(dual_homed(&[eth.clone(), off], &[]), None);
        // 只有一條
        assert_eq!(dual_homed(&[eth], &[]), None);
        let d = dual_homed(&[nic("a", "wifi", "", true), lte], &[]).unwrap();
        assert!(d.describe().contains("a、lte"));
        assert_eq!(d.interfaces(), ["a", "lte"]);
    }

    #[test]
    fn crosses_site() {
        // 公司網路沒有閘道（靜態路由進內網），Wi-Fi 熱點有閘道
        let eth = nic("eth", "ethernet", "10.1.2.3/24", false);
        let hotspot = nic("wifi", "wifi", "192.168.43.5/24", true);
        let d = dual_homed(&[eth.clone(), hotspot.clone()], &hq()).unwrap();
        assert_eq!(
            d,
            DualHomed::CrossesSite {
                inside: "eth".into(),
                outside: "wifi".into()
            }
        );
        assert!(d.describe().contains("據點以外"));
        assert_eq!(d.interfaces(), ["eth", "wifi"]);
        // 沒設定據點時不用條件 2
        assert_eq!(dual_homed(&[eth.clone(), hotspot.clone()], &[]), None);
        // 在家連 VPN 回公司：VPN 的位址在據點網段內，但 VPN 不算
        let vpn = nic("vpn", "vpn", "10.1.200.9/24", false);
        assert_eq!(dual_homed(&[vpn, hotspot.clone()], &hq()), None);
        // 兩張都在據點內
        let eth2 = nic("eth2", "ethernet", "10.1.9.9/24", true);
        assert_eq!(dual_homed(&[eth.clone(), eth2], &hq()), None);
        // 虛擬網卡在外面不算
        let vm = nic("docker0", "virtual", "172.17.0.1/16", true);
        assert_eq!(dual_homed(&[eth, vm], &hq()), None);
    }

    #[test]
    fn site_lookup() {
        assert_eq!(site_of(&hq(), "10.1.0.5/24"), Some("總部"));
        assert_eq!(site_of(&hq(), "10.2.0.5"), None);
        assert_eq!(site_of(&hq(), "bogus"), None);
    }
}
