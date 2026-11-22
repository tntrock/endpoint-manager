//! network 區段的 Linux 讀取：/sys/class/net、`ip` 指令、DNS 設定。

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context;
use protocol::{NetInterface, NetworkInfo};

use super::exec::{CMD_TIMEOUT, run_capture};
use crate::network::{self as parse, LinkFacts};

fn read_trim(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
}

fn facts(dir: &Path, name: &str) -> LinkFacts {
    let devtype = read_trim(&dir.join("uevent")).and_then(|u| {
        u.lines()
            .find_map(|l| l.strip_prefix("DEVTYPE="))
            .map(str::to_string)
    });
    LinkFacts {
        name: name.to_string(),
        is_virtual: std::fs::canonicalize(dir)
            .map(|p| p.starts_with("/sys/devices/virtual"))
            .unwrap_or(false),
        wireless: dir.join("wireless").exists() || dir.join("phy80211").exists(),
        devtype,
        driver: std::fs::read_link(dir.join("device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|f| f.to_string_lossy().into_owned())),
        arp_type: read_trim(&dir.join("type"))
            .and_then(|t| t.parse().ok())
            .unwrap_or(0),
    }
}

/// operstate 是 up；tun／wireguard 常回報 unknown，這時看 carrier
fn is_up(dir: &Path) -> bool {
    match read_trim(&dir.join("operstate")).as_deref() {
        Some("up") => true,
        Some("unknown") => read_trim(&dir.join("carrier")).as_deref() == Some("1"),
        _ => false,
    }
}

fn mac(dir: &Path) -> Option<String> {
    read_trim(&dir.join("address"))
        .map(|m| m.to_uppercase())
        .filter(|m| !m.is_empty() && m.chars().any(|c| c != '0' && c != ':'))
}

fn default_routes() -> HashMap<String, Vec<String>> {
    let mut m: HashMap<String, Vec<String>> = HashMap::new();
    for (args, v6) in [
        (&["-o", "route", "show", "default"][..], false),
        (&["-o", "-6", "route", "show", "default"][..], true),
    ] {
        let Ok(out) = run_capture("ip", args, CMD_TIMEOUT) else {
            continue;
        };
        for (dev, gw) in parse::linux_default_routes(&out, v6) {
            m.entry(dev).or_default().push(gw);
        }
    }
    m
}

/// systemd-resolved 有每張網卡的 DNS；沒有時用 resolv.conf，掛在有預設閘道的網卡上
fn dns() -> (HashMap<String, Vec<String>>, Vec<String>) {
    let per_link = run_capture("resolvectl", &["dns"], CMD_TIMEOUT)
        .map(|o| parse::resolvectl_dns(&o))
        .unwrap_or_default();
    let global = std::fs::read_to_string("/etc/resolv.conf")
        .map(|s| parse::resolv_conf(&s))
        .unwrap_or_default();
    (per_link, global)
}

pub fn collect() -> anyhow::Result<NetworkInfo> {
    let addr_out = run_capture("ip", &["-o", "addr", "show"], CMD_TIMEOUT)
        .context("無法執行 ip 指令（需要 iproute2）")?;
    let mut addrs = parse::linux_addresses(&addr_out);
    let mut routes = default_routes();
    let (mut per_link, global) = dns();
    let root = Path::new("/sys/class/net");
    let mut out = Vec::new();
    for e in std::fs::read_dir(root)
        .context("讀取 /sys/class/net 失敗")?
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        let dir = root.join(&name);
        let f = facts(&dir, &name);
        let kind = parse::linux_kind(&f);
        let gateways = routes.remove(&name).unwrap_or_default();
        let dns = per_link.remove(&name).unwrap_or_else(|| {
            if gateways.is_empty() {
                vec![]
            } else {
                global.clone()
            }
        });
        let ssid = if kind == NetInterface::WIFI {
            run_capture("iw", &["dev", &name, "link"], CMD_TIMEOUT)
                .ok()
                .and_then(|o| parse::iw_ssid(&o))
        } else {
            None
        };
        out.push(NetInterface {
            description: f.driver.clone(),
            kind: kind.to_string(),
            up: is_up(&dir),
            mac: mac(&dir),
            addresses: addrs.remove(&name).unwrap_or_default(),
            gateways,
            dns,
            ssid,
            name,
        });
    }
    Ok(parse::finish(out))
}

/// 心跳用：IP 清單，有預設閘道的網卡排前面
pub fn heartbeat_ips() -> Vec<String> {
    let Ok(addr_out) = run_capture("ip", &["-o", "addr", "show"], CMD_TIMEOUT) else {
        return vec![];
    };
    let gw: Vec<String> = run_capture("ip", &["-o", "route", "show", "default"], CMD_TIMEOUT)
        .map(|o| {
            parse::linux_default_routes(&o, false)
                .into_iter()
                .map(|(d, _)| d)
                .collect()
        })
        .unwrap_or_default();
    let mut by_if: Vec<(String, Vec<String>)> =
        parse::linux_addresses(&addr_out).into_iter().collect();
    // HashMap 沒有順序：先依名稱排，結果才穩定
    by_if.sort();
    parse::primary_first(
        by_if
            .into_iter()
            .map(|(name, a)| {
                let has_gw = gw.contains(&name);
                let ips = a
                    .into_iter()
                    .map(|c| c.split('/').next().unwrap_or("").to_string())
                    .collect();
                (has_gw, ips)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CI 的 Linux 主機一定有網卡：至少要讀得到一張有位址的
    #[test]
    fn collects_real_interfaces() {
        let n = collect().unwrap();
        assert!(
            n.interfaces.iter().any(|i| !i.addresses.is_empty()),
            "{n:?}"
        );
        assert!(
            n.interfaces
                .iter()
                .all(|i| i.kind != NetInterface::LOOPBACK)
        );
        let ips = heartbeat_ips();
        assert!(!ips.is_empty());
        assert!(ips.iter().all(|i| !i.contains('/')));
    }
}
