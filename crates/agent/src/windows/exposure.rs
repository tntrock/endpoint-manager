//! Windows 對外開放的服務與遠端登入（錯誤設定規格 §5.1）：
//! 監聽中的連接埠（`GetExtendedTcpTable`／`GetExtendedUdpTable`）、防火牆全開規則（登錄檔）、
//! 遠端桌面是否開啟與 Remote Desktop Users 群組成員。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use protocol::{ExposureInfo, ListenItem, RdpInfo};
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use winreg::RegKey;
use winreg::enums::HKEY_LOCAL_MACHINE;

use crate::exposure::{allow_all_rule, finish};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// 依呼叫取得需要的大小、配置後再讀一次（表格在兩次呼叫之間可能變大，最多重試幾次）。
/// 緩衝區以 u32 配置，對齊表格裡的 DWORD
fn table(read: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> std::io::Result<Vec<u32>> {
    let mut size = 0u32;
    for _ in 0..5 {
        let mut buf = vec![0u32; (size as usize).div_ceil(4).max(1)];
        let mut len = (buf.len() * 4) as u32;
        let rc = read(buf.as_mut_ptr().cast(), &mut len);
        if rc == 0 {
            return Ok(buf);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        size = len;
    }
    Err(std::io::Error::other("table keeps growing"))
}

/// 表格的列：開頭是 `dwNumEntries`，之後是 `T` 的陣列
fn rows<T: Copy>(buf: &[u32]) -> Vec<T> {
    let n = buf.first().copied().unwrap_or(0) as usize;
    let start = std::mem::size_of::<u32>();
    // 列的對齊可能大於 4（不會發生在這幾種結構，以防萬一照 T 的對齊算）
    let start = start.next_multiple_of(std::mem::align_of::<T>());
    let bytes = buf.len() * 4;
    let max = bytes.saturating_sub(start) / std::mem::size_of::<T>();
    let base = buf.as_ptr().cast::<u8>();
    (0..n.min(max))
        .map(|i| {
            // SAFETY: 範圍在緩衝區內（上面以位元組數限制），T 是單純的 C 結構
            unsafe {
                std::ptr::read_unaligned(base.add(start + i * std::mem::size_of::<T>()).cast())
            }
        })
        .collect()
}

/// `dwLocalPort` 的低 16 位元是網路位元組順序
fn port(p: u32) -> u16 {
    u16::from_be(p as u16)
}

/// 程式名稱（只有檔名）；pid 4 是 System
fn process_name(pid: u32, cache: &mut HashMap<u32, Option<String>>) -> Option<String> {
    cache
        .entry(pid)
        .or_insert_with(|| {
            if pid == 0 {
                return None;
            }
            if pid == 4 {
                return Some("System".into());
            }
            // SAFETY: 只查詢；handle 在下面關閉
            let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if h.is_null() {
                return None;
            }
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            // SAFETY: 緩衝區大小已傳給 API
            let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
            unsafe { CloseHandle(h) };
            if ok == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..len as usize]);
            path.rsplit('\\').next().map(str::to_string)
        })
        .clone()
}

fn listening(errors: &mut Vec<String>) -> Vec<(IpAddr, ListenItem)> {
    let mut cache = HashMap::new();
    let mut out = vec![];
    let mut push = |ip: IpAddr, proto: &str, p: u32, pid: u32, out: &mut Vec<_>| {
        out.push((
            ip,
            ListenItem {
                proto: proto.into(),
                addr: ip.to_string(),
                port: port(p),
                process: process_name(pid, &mut cache),
            },
        ));
    };
    // SAFETY（四個表格）：緩衝區與大小由 table() 管理，表格類別對應下面讀取的列結構
    match table(|b, l| unsafe {
        GetExtendedTcpTable(b, l, 0, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)
    }) {
        Ok(buf) => {
            for r in rows::<MIB_TCPROW_OWNER_PID>(&buf) {
                let ip = IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes()));
                push(ip, "tcp", r.dwLocalPort, r.dwOwningPid, &mut out);
            }
        }
        Err(e) => errors.push(format!("無法讀取 TCP 連接埠：{e}")),
    }
    match table(|b, l| unsafe {
        GetExtendedTcpTable(b, l, 0, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0)
    }) {
        Ok(buf) => {
            for r in rows::<MIB_TCP6ROW_OWNER_PID>(&buf) {
                let ip = IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr));
                push(ip, "tcp", r.dwLocalPort, r.dwOwningPid, &mut out);
            }
        }
        Err(e) => errors.push(format!("無法讀取 TCP（IPv6）連接埠：{e}")),
    }
    match table(|b, l| unsafe { GetExtendedUdpTable(b, l, 0, AF_INET, UDP_TABLE_OWNER_PID, 0) }) {
        Ok(buf) => {
            for r in rows::<MIB_UDPROW_OWNER_PID>(&buf) {
                let ip = IpAddr::V4(Ipv4Addr::from(r.dwLocalAddr.to_le_bytes()));
                push(ip, "udp", r.dwLocalPort, r.dwOwningPid, &mut out);
            }
        }
        Err(e) => errors.push(format!("無法讀取 UDP 連接埠：{e}")),
    }
    match table(|b, l| unsafe { GetExtendedUdpTable(b, l, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0) }) {
        Ok(buf) => {
            for r in rows::<MIB_UDP6ROW_OWNER_PID>(&buf) {
                let ip = IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr));
                push(ip, "udp", r.dwLocalPort, r.dwOwningPid, &mut out);
            }
        }
        Err(e) => errors.push(format!("無法讀取 UDP（IPv6）連接埠：{e}")),
    }
    out
}

/// 本機與群組原則的防火牆規則裡，全開的規則名稱
fn firewall_allow_all() -> std::io::Result<Vec<String>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut out = vec![];
    for path in [
        r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
        r"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
    ] {
        let key = match hklm.open_subkey(path) {
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for (name, _) in key.enum_values().flatten() {
            if let Ok(v) = key.get_value::<String, _>(&name)
                && let Some(rule) = allow_all_rule(&v, &name)
            {
                out.push(rule);
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn rdp() -> anyhow::Result<RdpInfo> {
    let deny: u32 = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Control\Terminal Server")
        .and_then(|k| k.get_value("fDenyTSConnections"))
        .unwrap_or(1);
    Ok(RdpInfo {
        enabled: deny == 0,
        users: super::security::remote_desktop_users()?,
    })
}

pub fn collect() -> ExposureInfo {
    let mut info = ExposureInfo::default();
    let raw = listening(&mut info.errors);
    (info.listening, info.truncated) = finish(raw, protocol::MAX_LISTENING);
    match firewall_allow_all() {
        Ok(v) => info.firewall_allow_all = Some(v),
        Err(e) => info.errors.push(format!("無法讀取防火牆規則：{e}")),
    }
    match rdp() {
        Ok(r) => info.rdp = Some(r),
        Err(e) => info.errors.push(format!("無法讀取遠端桌面設定：{e:#}")),
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_byte_order() {
        assert_eq!(port(0x5000), 80);
        assert_eq!(port(0xBD01), 445);
    }

    /// 自己開一個監聽，確認讀得到，而且程式名稱是測試程式
    #[test]
    fn sees_own_listener() {
        let l = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let p = l.local_addr().unwrap().port();
        let mut errors = vec![];
        let items = listening(&mut errors);
        assert!(errors.is_empty(), "{errors:?}");
        let mine = items
            .iter()
            .find(|(_, i)| i.proto == "tcp" && i.port == p)
            .unwrap_or_else(|| panic!("找不到 {p}"));
        assert_eq!(mine.1.addr, "0.0.0.0");
        let exe = std::env::current_exe().unwrap();
        let name = exe.file_name().unwrap().to_str().unwrap();
        assert_eq!(mine.1.process.as_deref(), Some(name));
        let info = collect();
        assert!(info.listening.iter().any(|i| i.port == p));
        assert!(info.firewall_allow_all.is_some(), "{:?}", info.errors);
        assert!(info.rdp.is_some(), "{:?}", info.errors);
        let mut cache = HashMap::new();
        assert_eq!(process_name(4, &mut cache).as_deref(), Some("System"));
        assert_eq!(process_name(0, &mut cache), None);
    }
}
