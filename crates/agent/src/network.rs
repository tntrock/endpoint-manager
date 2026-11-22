//! network 區段：網卡種類判斷與指令輸出解析。純函式，各平台都能編譯與測試。

use std::collections::HashMap;
use std::net::IpAddr;

use protocol::{NetInterface as N, NetworkInfo};

/// 描述含這些字的網卡是 VPN（小寫比對）
const VPN_WORDS: [&str; 13] = [
    "wireguard",
    "openvpn",
    "anyconnect",
    "forticlient",
    "fortinet",
    "globalprotect",
    "pangp",
    "tap-windows",
    "wintun",
    "tailscale",
    "zerotier",
    "nordlynx",
    "vpn",
];

/// 描述含這些字的網卡是虛擬網卡
const VIRTUAL_WORDS: [&str; 12] = [
    "hyper-v",
    "vethernet",
    "wsl",
    "docker",
    "virtualbox",
    "vmware",
    "wi-fi direct",
    "npcap",
    "loopback",
    "kernel debug",
    "teredo",
    "isatap",
];

/// 描述含這些字的網卡是行動網路（含手機 USB 分享）
const CELLULAR_WORDS: [&str; 5] = [
    "mobile broadband",
    "wwan",
    "remote ndis",
    "rndis",
    "apple mobile device",
];

/// Linux 上 USB 網卡與手機分享的驅動
const CELLULAR_DRIVERS: [&str; 4] = ["cdc_mbim", "qmi_wwan", "cdc_ether", "rndis_host"];

/// Linux 上以名稱判斷的 VPN 網卡
const VPN_PREFIXES: [&str; 6] = ["tun", "wg", "tailscale", "zt", "ppp", "nordlynx"];

fn has_word(desc: &str, words: &[&str]) -> bool {
    let d = desc.to_lowercase();
    words.iter().any(|w| d.contains(w))
}

/// Windows：`MSFT_NetAdapter` 的 InterfaceType（IANA ifType）、NdisPhysicalMedium、描述與 Virtual 屬性
pub fn windows_kind(
    if_type: u32,
    physical_medium: u32,
    description: &str,
    is_virtual: bool,
) -> &'static str {
    if if_type == 24 {
        return N::LOOPBACK;
    }
    // PPP、通道，或常見 VPN 用戶端的網卡
    if matches!(if_type, 23 | 131) || has_word(description, &VPN_WORDS) {
        return N::VPN;
    }
    if has_word(description, &VIRTUAL_WORDS) {
        return N::VIRTUAL;
    }
    // 71 = IEEE 802.11；NdisPhysicalMedium 9 = Native802_11
    if if_type == 71 || physical_medium == 9 {
        return N::WIFI;
    }
    // 243/244 = WWAN；NdisPhysicalMedium 8 = WirelessWan
    if matches!(if_type, 243 | 244)
        || physical_medium == 8
        || has_word(description, &CELLULAR_WORDS)
    {
        return N::CELLULAR;
    }
    if is_virtual {
        return N::VIRTUAL;
    }
    if if_type == 6 {
        return N::ETHERNET;
    }
    N::OTHER
}

/// Linux：從 /sys/class/net/<名稱> 讀到的事實
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LinkFacts {
    pub name: String,
    /// 在 /sys/devices/virtual/net 底下
    pub is_virtual: bool,
    /// 有 wireless 或 phy80211
    pub wireless: bool,
    /// uevent 的 DEVTYPE（wlan、wwan、bridge…）
    pub devtype: Option<String>,
    /// device/driver 連結的名稱
    pub driver: Option<String>,
    /// /sys/class/net/<名稱>/type（ARPHRD_*）
    pub arp_type: u32,
}

pub fn linux_kind(f: &LinkFacts) -> &'static str {
    // 772 = ARPHRD_LOOPBACK
    if f.arp_type == 772 {
        return N::LOOPBACK;
    }
    // 65534 = ARPHRD_NONE（tun、wireguard）；512 = ARPHRD_PPP
    if matches!(f.arp_type, 65534 | 512) || VPN_PREFIXES.iter().any(|p| f.name.starts_with(p)) {
        return N::VPN;
    }
    if f.wireless || f.devtype.as_deref() == Some("wlan") {
        return N::WIFI;
    }
    if f.devtype.as_deref() == Some("wwan")
        || f.driver
            .as_deref()
            .is_some_and(|d| CELLULAR_DRIVERS.contains(&d))
    {
        return N::CELLULAR;
    }
    if f.is_virtual {
        return N::VIRTUAL;
    }
    // 1 = ARPHRD_ETHER
    if f.arp_type == 1 {
        return N::ETHERNET;
    }
    N::OTHER
}

/// 位址是否值得回報：IPv6 link-local（fe80::/10）每張網卡都有，只是雜訊
pub fn reportable(addr: &str) -> bool {
    let ip = addr.split('/').next().unwrap_or("");
    let ip = ip.split('%').next().unwrap_or("");
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => !v.is_loopback(),
        Ok(IpAddr::V6(v)) => !v.is_loopback() && (v.segments()[0] & 0xffc0) != 0xfe80,
        Err(_) => false,
    }
}

/// `ip -o addr show`：網卡名稱 → CIDR 位址（略過 link-local 與 loopback）
pub fn linux_addresses(ip_o_addr: &str) -> HashMap<String, Vec<String>> {
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for line in ip_o_addr.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || !matches!(f[2], "inet" | "inet6") || !reportable(f[3]) {
            continue;
        }
        let name = f[1].trim_end_matches(':');
        let name = name.split('@').next().unwrap_or(name);
        out.entry(name.to_string())
            .or_default()
            .push(f[3].to_string());
    }
    out
}

/// `ip -o route show default`（IPv4 或 IPv6）：(網卡, 閘道)。沒有 via 的預設路由（直接連線）
/// 以 0.0.0.0／:: 表示，跟 Windows 的 NextHop 一致
pub fn linux_default_routes(out: &str, v6: bool) -> Vec<(String, String)> {
    let on_link = if v6 { "::" } else { "0.0.0.0" };
    let mut routes = Vec::new();
    for line in out.lines() {
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.first() != Some(&"default") {
            continue;
        }
        // 多路徑路由會有好幾組 nexthop via X dev Y
        let mut via: Option<&str> = None;
        let mut i = 1;
        while i + 1 < t.len() {
            match t[i] {
                "via" => {
                    via = Some(t[i + 1]);
                    i += 2;
                }
                "dev" => {
                    routes.push((
                        t[i + 1].to_string(),
                        via.take().unwrap_or(on_link).to_string(),
                    ));
                    i += 2;
                }
                _ => i += 1,
            }
        }
    }
    routes
}

/// `resolvectl dns`：`Link 2 (eth0): 192.168.1.1 fe80::1%2` → eth0 → [192.168.1.1, fe80::1]
pub fn resolvectl_dns(out: &str) -> HashMap<String, Vec<String>> {
    let mut m = HashMap::new();
    for line in out.lines() {
        let Some(rest) = line.trim().strip_prefix("Link ") else {
            continue;
        };
        let (Some(open), Some(close)) = (rest.find('('), rest.find("):")) else {
            continue;
        };
        if close < open {
            continue;
        }
        let name = &rest[open + 1..close];
        let servers: Vec<String> = rest[close + 2..]
            .split_whitespace()
            .map(|s| s.split('%').next().unwrap_or(s))
            .map(|s| s.split('#').next().unwrap_or(s).to_string())
            .collect();
        if !servers.is_empty() {
            m.insert(name.to_string(), servers);
        }
    }
    m
}

/// /etc/resolv.conf 的 nameserver（略過 127.0.0.53 這類本機轉送）
pub fn resolv_conf(s: &str) -> Vec<String> {
    s.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|v| v.trim().to_string())
        .filter(|v| v.parse::<IpAddr>().is_ok_and(|ip| !ip.is_loopback()))
        .collect()
}

/// `iw dev <名稱> link` 的 SSID
pub fn iw_ssid(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("SSID:"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// `netsh wlan show interfaces`：網卡名稱 → SSID。欄位名稱會翻譯（「名稱」），
/// 所以每個區塊的第一個「欄位 : 值」當名稱，SSID 與 BSSID 不會翻譯
pub fn netsh_ssids(out: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for block in out.split("\n\n").flat_map(|b| b.split("\r\n\r\n")) {
        let mut name = None;
        let mut ssid = None;
        for line in block.lines() {
            let Some((k, v)) = line.split_once(" : ").or_else(|| line.split_once(": ")) else {
                continue;
            };
            let (k, v) = (k.trim(), v.trim());
            if name.is_none() {
                name = Some(v.to_string());
            }
            if k == "SSID" && !v.is_empty() {
                ssid = Some(v.to_string());
            }
        }
        if let (Some(n), Some(s)) = (name, ssid) {
            m.insert(n, s);
        }
    }
    m
}

/// `107C61BB6563` → `10:7C:61:BB:65:63`；長度不對或全為 0 時 None
pub fn mac_from_hex(s: &str) -> Option<String> {
    let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if s.len() != 12 || s.chars().all(|c| c == '0') {
        return None;
    }
    let pairs: Vec<&str> = (0..6).map(|i| &s[i * 2..i * 2 + 2]).collect();
    Some(pairs.join(":").to_uppercase())
}

/// Windows 沒有 IPv6 DNS 時會列出 fec0:0:0:ffff::1～3（已廢除的預設值），不是真的設定
pub fn real_dns(s: &str) -> bool {
    !s.to_lowercase().starts_with("fec0:0:0:ffff::")
}

/// 去掉沒有位址的虛擬網卡（Docker 每個容器一張 veth，會讓區段一直變動），
/// 也去掉 loopback
pub fn finish(mut interfaces: Vec<N>) -> NetworkInfo {
    interfaces
        .retain(|i| i.kind != N::LOOPBACK && !(i.kind == N::VIRTUAL && i.addresses.is_empty()));
    NetworkInfo { interfaces }
}

/// 心跳的 IP 清單：有預設閘道的網卡排前面，同一組裡 IPv4 在前。
/// 伺服器把第一個當「主要位址」（規格 §6.1）
pub fn primary_first(nics: Vec<(bool, Vec<String>)>) -> Vec<String> {
    let mut all: Vec<(bool, bool, String)> = nics
        .into_iter()
        .flat_map(|(gw, addrs)| {
            addrs.into_iter().map(move |a| {
                let v6 = a.contains(':');
                (!gw, v6, a)
            })
        })
        .collect();
    all.sort_by_key(|(no_gw, v6, _)| (*no_gw, *v6));
    all.into_iter().map(|(_, _, a)| a).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_kinds() {
        let cases: [(u32, u32, &str, bool, &str); 14] = [
            (
                6,
                14,
                "Intel(R) Ethernet Connection I219-LM",
                false,
                N::ETHERNET,
            ),
            (71, 9, "Intel(R) Wi-Fi 6 AX201 160MHz", false, N::WIFI),
            (6, 9, "Realtek USB Wireless", false, N::WIFI),
            (
                243,
                8,
                "Generic Mobile Broadband Adapter",
                false,
                N::CELLULAR,
            ),
            (
                6,
                14,
                "Remote NDIS based Internet Sharing Device",
                false,
                N::CELLULAR,
            ),
            (6, 0, "Apple Mobile Device Ethernet", false, N::CELLULAR),
            (53, 0, "WireGuard Tunnel", true, N::VPN),
            (6, 0, "TAP-Windows Adapter V9", true, N::VPN),
            (23, 0, "WAN Miniport (PPPOE)", true, N::VPN),
            (6, 0, "Hyper-V Virtual Ethernet Adapter", true, N::VIRTUAL),
            (
                71,
                9,
                "Microsoft Wi-Fi Direct Virtual Adapter",
                true,
                N::VIRTUAL,
            ),
            (6, 0, "Some Unknown Virtual NIC", true, N::VIRTUAL),
            (24, 0, "Software Loopback Interface 1", true, N::LOOPBACK),
            (1, 0, "Weird", false, N::OTHER),
        ];
        for (t, m, d, v, want) in cases {
            assert_eq!(windows_kind(t, m, d, v), want, "{d}");
        }
    }

    #[test]
    fn linux_kinds() {
        let f = |name: &str, arp: u32| LinkFacts {
            name: name.into(),
            arp_type: arp,
            ..Default::default()
        };
        let cases = [
            (f("lo", 772), N::LOOPBACK),
            (f("eth0", 1), N::ETHERNET),
            (f("wg0", 65534), N::VPN),
            (f("tun0", 65534), N::VPN),
            (f("ppp0", 512), N::VPN),
            (
                LinkFacts {
                    is_virtual: true,
                    ..f("tailscale0", 65534)
                },
                N::VPN,
            ),
            (
                LinkFacts {
                    wireless: true,
                    ..f("wlp2s0", 1)
                },
                N::WIFI,
            ),
            (
                LinkFacts {
                    devtype: Some("wlan".into()),
                    ..f("wlan0", 1)
                },
                N::WIFI,
            ),
            (
                LinkFacts {
                    devtype: Some("wwan".into()),
                    ..f("wwan0", 1)
                },
                N::CELLULAR,
            ),
            (
                LinkFacts {
                    driver: Some("rndis_host".into()),
                    ..f("usb0", 1)
                },
                N::CELLULAR,
            ),
            (
                LinkFacts {
                    is_virtual: true,
                    devtype: Some("bridge".into()),
                    ..f("docker0", 1)
                },
                N::VIRTUAL,
            ),
            (f("ib0", 32), N::OTHER),
        ];
        for (facts, want) in cases {
            assert_eq!(linux_kind(&facts), want, "{}", facts.name);
        }
    }

    #[test]
    fn parses_ip_addr_and_routes() {
        let addr = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                    2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\\ x\n\
                    2: eth0    inet6 fe80::1/64 scope link \\ x\n\
                    2: eth0    inet6 2001:db8::5/64 scope global \\ x\n\
                    5: eth0@if6    inet 172.17.0.2/16 scope global eth0\n\
                    garbage\n";
        let m = linux_addresses(addr);
        assert_eq!(
            m["eth0"],
            ["10.0.0.5/24", "2001:db8::5/64", "172.17.0.2/16"]
        );
        assert!(!m.contains_key("lo"));

        let r = "default via 10.0.0.1 dev eth0 proto dhcp metric 100\n\
                 default via 192.168.8.1 dev usb0 metric 700\n\
                 default dev wg0 scope link\n\
                 default proto static metric 50 nexthop via 10.1.0.1 dev eth1 weight 1 nexthop via 10.2.0.1 dev eth2 weight 1\n\
                 10.0.0.0/24 dev eth0 scope link\n";
        assert_eq!(
            linux_default_routes(r, false),
            [
                ("eth0".to_string(), "10.0.0.1".to_string()),
                ("usb0".into(), "192.168.8.1".into()),
                ("wg0".into(), "0.0.0.0".into()),
                ("eth1".into(), "10.1.0.1".into()),
                ("eth2".into(), "10.2.0.1".into()),
            ]
        );
        assert_eq!(
            linux_default_routes("default dev ppp0 metric 1", true),
            [("ppp0".to_string(), "::".to_string())]
        );
    }

    #[test]
    fn parses_dns_and_ssid() {
        let r = "Global: 9.9.9.9\nLink 2 (eth0): 192.168.1.1 fe80::1%2\nLink 3 (wlan0):\nLink 4 (wg0): 10.9.0.1#dns.example\n";
        let m = resolvectl_dns(r);
        assert_eq!(m["eth0"], ["192.168.1.1", "fe80::1"]);
        assert_eq!(m["wg0"], ["10.9.0.1"]);
        assert!(!m.contains_key("wlan0"));
        assert!(resolvectl_dns("Link x) (y: z").is_empty());

        let rc = "# comment\nnameserver 127.0.0.53\nnameserver 1.1.1.1\nnameserver bogus\noptions edns0\n";
        assert_eq!(resolv_conf(rc), ["1.1.1.1"]);

        assert_eq!(
            iw_ssid("Connected to aa:bb (on wlan0)\n\tSSID: Office-5G\n\tfreq: 5180\n"),
            Some("Office-5G".into())
        );
        assert_eq!(iw_ssid("Not connected.\n"), None);

        let netsh = "\r\n系統上有 2 個介面: \r\n\r\n    名稱                   : Wi-Fi\r\n    描述                   : Intel\r\n    SSID                   : Office\r\n    BSSID                  : aa:bb\r\n\r\n    名稱                   : Wi-Fi 2\r\n    狀態                   : 已中斷連線\r\n";
        let m = netsh_ssids(netsh);
        assert_eq!(m.len(), 1);
        assert_eq!(m["Wi-Fi"], "Office");
    }

    fn nic(name: &str, kind: &str, addrs: &[&str]) -> N {
        N {
            name: name.into(),
            description: None,
            kind: kind.into(),
            up: true,
            mac: None,
            addresses: addrs.iter().map(|s| s.to_string()).collect(),
            gateways: vec![],
            dns: vec![],
            ssid: None,
        }
    }

    #[test]
    fn finish_drops_noise() {
        let n = finish(vec![
            nic("lo", N::LOOPBACK, &["127.0.0.1/8"]),
            nic("veth1", N::VIRTUAL, &[]),
            nic("docker0", N::VIRTUAL, &["172.17.0.1/16"]),
            nic("eth0", N::ETHERNET, &[]),
        ]);
        let names: Vec<&str> = n.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["docker0", "eth0"]);
        assert!(reportable("10.0.0.1/24") && !reportable("fe80::1%3/64"));
        assert!(!reportable("::1") && !reportable("nope"));
    }

    #[test]
    fn windows_mac_and_dns() {
        assert_eq!(
            mac_from_hex("107C61BB6563").as_deref(),
            Some("10:7C:61:BB:65:63")
        );
        assert_eq!(
            mac_from_hex("00-15-5d-43-67-bc").as_deref(),
            Some("00:15:5D:43:67:BC")
        );
        assert_eq!(mac_from_hex(""), None);
        assert_eq!(mac_from_hex("000000000000"), None);
        assert!(real_dns("140.124.1.1") && real_dns("2001:4860::8888"));
        assert!(!real_dns("fec0:0:0:ffff::1") && !real_dns("FEC0:0:0:FFFF::3"));
    }

    #[test]
    fn primary_address_comes_first() {
        let ips = primary_first(vec![
            (false, vec!["172.17.0.1".into()]),
            (true, vec!["2001:db8::5".into(), "10.0.0.5".into()]),
            (false, vec!["fd00::1".into()]),
        ]);
        assert_eq!(ips, ["10.0.0.5", "2001:db8::5", "172.17.0.1", "fd00::1"]);
    }
}
