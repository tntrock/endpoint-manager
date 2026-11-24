//! 對外開放的服務與遠端登入（錯誤設定規格 §5.1）。只有純函式，各平台都能測試；
//! 實際讀取在 `windows::exposure` 與 `linux::exposure`。

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use protocol::{ListenItem, SshdInfo};

/// 只監聽本機（127.0.0.0/8、::1、對應到 IPv4 的 127.x）
pub fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

/// 去掉重複（同一個程式在多個執行緒開同一個埠）、只監聽本機的，最多 `max` 筆
pub fn finish(items: Vec<(IpAddr, ListenItem)>, max: usize) -> (Vec<ListenItem>, bool) {
    let set: BTreeSet<ListenItem> = items
        .into_iter()
        .filter(|(ip, _)| !is_loopback(*ip))
        .map(|(_, i)| i)
        .collect();
    let truncated = set.len() > max;
    (set.into_iter().take(max).collect(), truncated)
}

// ---------------------------------------------------------------------------
// Linux：/proc/net/tcp、tcp6、udp、udp6
// ---------------------------------------------------------------------------

/// `/proc/net/tcp` 的位址：每 4 個位元組以本機位元組順序印成十六進位
fn proc_addr(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let v = u32::from_str_radix(hex, 16).ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(v.to_le_bytes())))
        }
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let v = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
            }
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// 監聽中的 socket：(位址, 項目（還沒有程式名稱）, inode)。
/// TCP 只取 LISTEN（0A）；UDP 取沒有連線對象的（07，遠端連接埠 0）
pub fn parse_proc_net(text: &str, proto: &str) -> Vec<(IpAddr, ListenItem, u64)> {
    let listen_state = if proto == "tcp" { "0A" } else { "07" };
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 10 || f[3] != listen_state {
                return None;
            }
            let (addr, port) = f[1].split_once(':')?;
            if proto == "udp" && !f[2].ends_with(":0000") {
                return None;
            }
            let ip = proc_addr(addr)?;
            let port = u16::from_str_radix(port, 16).ok()?;
            let inode: u64 = f[9].parse().ok()?;
            Some((
                ip,
                ListenItem {
                    proto: proto.into(),
                    addr: ip.to_string(),
                    port,
                    process: None,
                },
                inode,
            ))
        })
        .collect()
}

/// `/proc/<pid>/fd/*` 的連結內容 `socket:[12345]` 取出 inode
pub fn socket_inode(link: &str) -> Option<u64> {
    link.strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

// ---------------------------------------------------------------------------
// Linux：sshd -T
// ---------------------------------------------------------------------------

/// `sshd -T` 的輸出：每行「小寫鍵 值」
pub fn parse_sshd_t(out: &str) -> Option<SshdInfo> {
    let mut info = SshdInfo {
        permit_root_login: String::new(),
        password_authentication: false,
        permit_empty_passwords: false,
        ports: vec![],
    };
    let mut seen = false;
    for line in out.lines() {
        let Some((k, v)) = line.trim().split_once(' ') else {
            continue;
        };
        let v = v.trim();
        match k {
            "permitrootlogin" => {
                info.permit_root_login = v.to_string();
                seen = true;
            }
            "passwordauthentication" => info.password_authentication = v == "yes",
            "permitemptypasswords" => info.permit_empty_passwords = v == "yes",
            "port" => {
                if let Ok(p) = v.parse() {
                    info.ports.push(p);
                }
            }
            _ => {}
        }
    }
    seen.then_some(info)
}

// ---------------------------------------------------------------------------
// Windows：防火牆規則（登錄檔字串）
// ---------------------------------------------------------------------------

/// 防火牆規則字串 `v2.33|Action=Allow|Active=TRUE|Dir=In|…|Name=…|`：
/// 允許、啟用、輸入，而且沒有限定遠端位址、本機連接埠、程式或服務時回傳規則名稱。
/// ICMP 規則沒有連接埠的概念，不算
pub fn allow_all_rule(value: &str, fallback_name: &str) -> Option<String> {
    let mut kv: Vec<(&str, &str)> = vec![];
    for part in value.split('|').skip(1) {
        if let Some((k, v)) = part.split_once('=') {
            kv.push((k, v));
        }
    }
    let get = |k: &str| {
        kv.iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(k))
            .map(|(_, v)| *v)
    };
    let is = |k: &str, v: &str| get(k).is_some_and(|x| x.eq_ignore_ascii_case(v));
    if !is("Action", "Allow") || !is("Active", "TRUE") || !is("Dir", "In") {
        return None;
    }
    if matches!(get("Protocol"), Some("1" | "58")) {
        return None;
    }
    const LIMITS: [&str; 12] = [
        "LPort",
        "LPort2_10",
        "LPort2_20",
        "RA4",
        "RA6",
        "RA42",
        "RA62",
        "App",
        "Svc",
        "PFN",
        "AppPkgId",
        "LUAuth",
    ];
    if LIMITS
        .iter()
        .any(|k| get(k).is_some_and(|v| !v.is_empty() && v != "*"))
    {
        return None;
    }
    let name = get("Name")
        .filter(|n| !n.is_empty())
        .unwrap_or(fallback_name);
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1 0000000000000000 100 0 0 10 0
   2: 0500000A:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3333 1 0000000000000000 100 0 0 10 0
   3: 0500000A:0050 0600000A:C350 01 00000000:00000000 00:00000000 00000000     0        0 4444 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn proc_net_tcp() {
        let v = parse_proc_net(TCP, "tcp");
        assert_eq!(v.len(), 3, "只取 LISTEN");
        assert_eq!(
            (v[0].1.addr.as_str(), v[0].1.port, v[0].2),
            ("0.0.0.0", 22, 1111)
        );
        assert!(is_loopback(v[1].0));
        assert_eq!((v[2].1.addr.as_str(), v[2].1.port), ("10.0.0.5", 80));
        let (items, truncated) = finish(v.into_iter().map(|(ip, i, _)| (ip, i)).collect(), 10);
        assert_eq!(items.len(), 2, "本機的不算");
        assert!(!truncated);
    }

    #[test]
    fn proc_net_tcp6_and_udp() {
        let tcp6 = "  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 5555 1
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6666 1
   2: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7777 1
";
        let v = parse_proc_net(tcp6, "tcp");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].1.addr, "::");
        assert!(is_loopback(v[1].0), "::1");
        assert!(is_loopback(v[2].0), "::ffff:127.0.0.1");
        let udp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  10: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 8888 2 0000000000000000 0
  11: 0500000A:A1B2 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 9999 2 0000000000000000 0
  12: 0500000A:A1B3 08080808:0035 07 00000000:00000000 00:00000000 00000000     0        0 9998 2 0000000000000000 0
";
        let v = parse_proc_net(udp, "udp");
        assert_eq!(v.len(), 1, "有連線對象的 UDP 不算：{v:?}");
        assert_eq!((v[0].1.proto.as_str(), v[0].1.port), ("udp", 68));
        assert!(parse_proc_net("header\n 0: zz:zz 0:0 0A a b c d e f\n", "tcp").is_empty());
        assert_eq!(proc_addr("123"), None);
    }

    #[test]
    fn finish_dedups_and_truncates() {
        let item = |port| ListenItem {
            proto: "tcp".into(),
            addr: "0.0.0.0".into(),
            port,
            process: None,
        };
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let (v, t) = finish(vec![(any, item(1)), (any, item(1)), (any, item(2))], 5);
        assert_eq!((v.len(), t), (2, false));
        let (v, t) = finish((0..5).map(|p| (any, item(p))).collect(), 3);
        assert_eq!((v.len(), t), (3, true));
    }

    #[test]
    fn socket_inodes() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("pipe:[1]"), None);
        assert_eq!(socket_inode("/dev/null"), None);
    }

    #[test]
    fn sshd_config() {
        let out = "port 22\nport 2222\npermitrootlogin prohibit-password\npasswordauthentication yes\npermitemptypasswords no\nx\n";
        let s = parse_sshd_t(out).unwrap();
        assert_eq!(s.permit_root_login, "prohibit-password");
        assert!(s.password_authentication && !s.permit_empty_passwords);
        assert_eq!(s.ports, [22, 2222]);
        let s = parse_sshd_t("permitrootlogin yes\npermitemptypasswords yes\nport x\n").unwrap();
        assert!(s.permit_empty_passwords && !s.password_authentication);
        assert!(s.ports.is_empty());
        assert_eq!(parse_sshd_t("garbage"), None);
    }

    #[test]
    fn firewall_rules() {
        let all = "v2.33|Action=Allow|Active=TRUE|Dir=In|Name=Open everything|";
        assert_eq!(
            allow_all_rule(all, "{id}").as_deref(),
            Some("Open everything")
        );
        let tcp_any = "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|Profile=Public|";
        assert_eq!(
            allow_all_rule(tcp_any, "{id}").as_deref(),
            Some("{id}"),
            "沒有名稱用值的名稱"
        );
        for limited in [
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|Name=RDP|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|RA4=LocalSubnet|Name=x|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\\x.exe|Name=x|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Svc=Dnscache|Name=x|",
            "v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=1|Name=ping|",
            "v2.33|Action=Allow|Active=FALSE|Dir=In|Name=off|",
            "v2.33|Action=Block|Active=TRUE|Dir=In|Name=block|",
            "v2.33|Action=Allow|Active=TRUE|Dir=Out|Name=out|",
        ] {
            assert_eq!(allow_all_rule(limited, "x"), None, "{limited}");
        }
        assert_eq!(
            allow_all_rule(
                "v2.33|Action=Allow|Active=TRUE|Dir=In|RA4=*|Name=star|",
                "x"
            )
            .as_deref(),
            Some("star")
        );
    }
}
