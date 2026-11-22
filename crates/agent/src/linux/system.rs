//! 識別、心跳、basic、hardware 的 Linux 讀取。

use super::exec::{CMD_TIMEOUT, is_not_found, run_capture};
use crate::collector::{Heartbeat, Identity};
use crate::linux_parse::system as parse;
use anyhow::Context;
use protocol::{BasicInfo, Disk, HardwareInfo, RunsIn};
use std::ffi::CString;

fn read(path: &str) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("讀取 {path} 失敗"))
}

/// DMI 欄位：讀不到（沒權限、虛擬環境沒有）或空白就是 None
fn dmi(name: &str) -> Option<String> {
    let v = std::fs::read_to_string(format!("/sys/class/dmi/id/{name}")).ok()?;
    let v = v.trim();
    (!v.is_empty()).then(|| v.to_string())
}

fn hostname() -> anyhow::Result<String> {
    Ok(read("/proc/sys/kernel/hostname")?.trim().to_string())
}

fn mac_addresses() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for e in rd.flatten() {
        if e.file_name() == "lo" {
            continue;
        }
        let Ok(mac) = std::fs::read_to_string(e.path().join("address")) else {
            continue;
        };
        let mac = mac.trim().to_uppercase();
        if !mac.is_empty() && mac.chars().any(|c| c != '0' && c != ':') {
            out.push(mac);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// `systemd-detect-virt <旗標>`：沒有這個指令回 None；沒偵測到時它以結束碼 1 輸出 none
fn detect_virt(flag: &str) -> Option<String> {
    match run_capture("systemd-detect-virt", &[flag], CMD_TIMEOUT) {
        Ok(out) => Some(out.trim().to_string()),
        Err(e) if is_not_found(&e) => None,
        Err(_) => Some("none".into()),
    }
}

pub fn runs_in() -> RunsIn {
    parse::runs_in(std::path::Path::new("/"), &detect_virt)
}

pub fn identity() -> anyhow::Result<Identity> {
    // 容器與 WSL 讀到的 DMI 是所在主機的：拿去比對會被當成主機重新註冊或疑似重複
    let guest = runs_in().is_guest();
    Ok(Identity {
        hostname: hostname()?,
        smbios_uuid: dmi("product_uuid").filter(|_| !guest),
        bios_serial: dmi("product_serial").filter(|_| !guest),
        mac_addresses: mac_addresses(),
    })
}

pub fn heartbeat() -> anyhow::Result<Heartbeat> {
    let boot_time = parse::boot_time(&read("/proc/stat")?).context("/proc/stat 沒有 btime")?;
    // ip、who 不存在或失敗不影響心跳
    let ip_addresses = super::network::heartbeat_ips();
    let logged_on_user = run_capture("who", &[], CMD_TIMEOUT)
        .ok()
        .and_then(|o| parse::first_user(&o));
    Ok(Heartbeat {
        boot_time,
        logged_on_user,
        ip_addresses,
    })
}

pub fn basic() -> BasicInfo {
    BasicInfo {
        hostname: hostname().unwrap_or_default(),
        domain: None,
        is_domain_joined: false,
        os_caption: read("/etc/os-release")
            .ok()
            .and_then(|s| parse::os_caption(&s))
            .unwrap_or_else(|| "Linux".into()),
        os_build: read("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default(),
        os_ubr: None,
        runs_in: Some(runs_in()),
    }
}

fn disk(mount: &str) -> Option<Disk> {
    let c = CString::new(mount).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c 是有效的 C 字串，st 是可寫入的 statvfs 結構。
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let frsize = st.f_frsize as u64;
    let size_bytes = st.f_blocks as u64 * frsize;
    (size_bytes > 0).then(|| Disk {
        name: mount.to_string(),
        size_bytes,
        free_bytes: st.f_bavail as u64 * frsize,
    })
}

pub fn hardware() -> anyhow::Result<HardwareInfo> {
    let ram_mb =
        parse::mem_total_mb(&read("/proc/meminfo")?).context("/proc/meminfo 沒有 MemTotal")?;
    let disks = read("/proc/mounts")
        .map(|m| parse::real_mounts(&m))
        .unwrap_or_default()
        .iter()
        .filter_map(|m| disk(m))
        .collect();
    Ok(HardwareInfo {
        manufacturer: dmi("sys_vendor"),
        model: dmi("product_name"),
        cpu: read("/proc/cpuinfo")
            .ok()
            .and_then(|s| parse::cpu_model(&s)),
        ram_mb,
        disks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_machine() {
        assert!(!identity().unwrap().hostname.is_empty());
        assert!(!basic().os_caption.is_empty());
        assert!(hardware().unwrap().ram_mb > 0);
    }
}
