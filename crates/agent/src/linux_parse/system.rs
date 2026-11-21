//! `/etc/os-release`、`/proc/*`、`ip`、`who` 輸出的解析。

use protocol::RunsIn;
use std::net::IpAddr;
use std::path::Path;

/// 去掉成對的 `"` 或 `'`
fn unquote(v: &str) -> &str {
    let v = v.trim();
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    v
}

fn os_release_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
        .map(|v| unquote(v).to_string())
        .filter(|v| !v.is_empty())
}

/// `PRETTY_NAME`；沒有就 `NAME` + 空白 + `VERSION`。
pub fn os_caption(os_release: &str) -> Option<String> {
    if let Some(p) = os_release_value(os_release, "PRETTY_NAME") {
        return Some(p);
    }
    let name = os_release_value(os_release, "NAME")?;
    Some(match os_release_value(os_release, "VERSION") {
        Some(v) => format!("{name} {v}"),
        None => name,
    })
}

/// `/proc/stat` 的 `btime`（開機時間，Unix 秒）
pub fn boot_time(proc_stat: &str) -> Option<time::OffsetDateTime> {
    let secs: i64 = proc_stat
        .lines()
        .find_map(|l| l.strip_prefix("btime"))?
        .trim()
        .parse()
        .ok()?;
    time::OffsetDateTime::from_unix_timestamp(secs).ok()
}

/// `MemTotal` kB 轉 MB（整數除法）
pub fn mem_total_mb(meminfo: &str) -> Option<u64> {
    let kb: u64 = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .ok()?;
    Some(kb / 1024)
}

/// 第一個 `model name`
pub fn cpu_model(cpuinfo: &str) -> Option<String> {
    cpuinfo
        .lines()
        .filter(|l| l.starts_with("model name"))
        .find_map(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

const VIRTUAL_FS: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "overlay",
    "squashfs",
    "devpts",
    "mqueue",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "autofs",
    "hugetlbfs",
    "fusectl",
    "configfs",
    "binfmt_misc",
    "efivarfs",
    "ramfs",
    "nsfs",
    "rpc_pipefs",
    // 網路檔案系統：掛載失聯時 statvfs 會卡住
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "9p",
    "fuse.sshfs",
    "ceph",
    "glusterfs",
];

/// 還原 `/proc/mounts` 的八進位跳脫（例如 `\040` 是空白）
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == 0x5c
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = (b[i + 1] - b'0') as u32 * 64
                + (b[i + 2] - b'0') as u32 * 8
                + (b[i + 3] - b'0') as u32;
            out.push(v as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 實體檔案系統的掛載點（排除虛擬檔案系統與 snap，同一掛載點只留一次）
pub fn real_mounts(proc_mounts: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in proc_mounts.lines() {
        let mut f = line.split_whitespace();
        let (Some(_), Some(mp), Some(fs)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if VIRTUAL_FS.contains(&fs) {
            continue;
        }
        let mp = unescape_mount(mp);
        if mp.starts_with("/snap/") || out.contains(&mp) {
            continue;
        }
        out.push(mp);
    }
    out
}

/// 解析 `ip -o addr show`，回傳非 loopback、非 link-local 的位址
pub fn ip_addresses(ip_o_addr: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in ip_o_addr.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // 格式：<索引>: <介面> inet|inet6 <位址/前綴> ...
        if f.len() < 4 || f[1].trim_end_matches(':') == "lo" || !matches!(f[2], "inet" | "inet6") {
            continue;
        }
        let addr = f[3].split('/').next().unwrap_or("");
        let Ok(ip) = addr.parse::<IpAddr>() else {
            continue;
        };
        let skip = match ip {
            IpAddr::V4(v) => v.is_loopback(),
            IpAddr::V6(v) => v.is_loopback() || (v.segments()[0] & 0xffc0) == 0xfe80,
        };
        if !skip {
            out.push(addr.to_string());
        }
    }
    out
}

/// `who` 輸出第一個不是 root 的使用者
pub fn first_user(who: &str) -> Option<String> {
    who.lines()
        .filter_map(|l| l.split_whitespace().next())
        .find(|u| *u != "root")
        .map(str::to_string)
}

/// WSL 的核心版本字串：WSL 2 是 `…-microsoft-standard-WSL2`，WSL 1 是 `…-Microsoft`
fn wsl_version(osrelease: &str) -> Option<&'static str> {
    let l = osrelease.to_ascii_lowercase();
    if l.contains("wsl2") || l.contains("microsoft-standard") {
        Some("2")
    } else if l.contains("microsoft") || l.contains("wsl") {
        Some("1")
    } else {
        None
    }
}

/// 不靠 systemd 判斷容器：`/.dockerenv`、`/run/.containerenv`、PID 1 的 `container=`
fn container_by_files(root: &Path) -> Option<String> {
    if root.join(".dockerenv").exists() {
        return Some("docker".into());
    }
    if root.join("run/.containerenv").exists() {
        return Some("podman".into());
    }
    let env = std::fs::read(root.join("proc/1/environ")).ok()?;
    env.split(|b| *b == 0).find_map(|kv| {
        let v = std::str::from_utf8(kv).ok()?.strip_prefix("container=")?;
        (!v.is_empty()).then(|| v.to_string())
    })
}

/// Agent 的執行環境。`root` 是根目錄（測試時換成暫存目錄）；`detect_virt(旗標)` 執行
/// `systemd-detect-virt <旗標>`：沒有這個指令回 None，否則回輸出（沒偵測到是 `none`）。
pub fn runs_in(root: &Path, detect_virt: &dyn Fn(&str) -> Option<String>) -> RunsIn {
    let read = |p: &str| std::fs::read_to_string(root.join(p)).ok();
    if let Some(v) = read("proc/sys/kernel/osrelease")
        .as_deref()
        .and_then(wsl_version)
    {
        return RunsIn::new(RunsIn::WSL, Some(v));
    }
    let container = detect_virt("--container")
        .filter(|v| v != "none" && !v.is_empty())
        .or_else(|| container_by_files(root));
    if let Some(c) = container {
        return RunsIn::new(RunsIn::CONTAINER, Some(&c));
    }
    let vm = detect_virt("--vm").filter(|v| !v.is_empty()).or_else(|| {
        let vendor = read("sys/class/dmi/id/sys_vendor");
        let model = read("sys/class/dmi/id/product_name");
        (vendor.is_some() || model.is_some()).then(|| {
            protocol::vm_from_vendor(
                vendor.as_deref().unwrap_or("").trim(),
                model.as_deref().unwrap_or("").trim(),
            )
            .to_string()
        })
    });
    RunsIn::new(RunsIn::HOST, vm.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_caption_prefers_pretty_name() {
        assert_eq!(
            os_caption("NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n").as_deref(),
            Some("Ubuntu 24.04.1 LTS")
        );
        assert_eq!(
            os_caption("NAME=\"Rocky Linux\"\nVERSION='9.4 (Blue Onyx)'\n").as_deref(),
            Some("Rocky Linux 9.4 (Blue Onyx)")
        );
        assert_eq!(os_caption("ID=foo\n"), None);
    }

    #[test]
    fn boot_time_reads_btime() {
        let t = boot_time("cpu  1 2 3\nbtime 1729700000\nprocesses 5\n").unwrap();
        assert_eq!(t.unix_timestamp(), 1729700000);
        assert_eq!(boot_time("cpu 1\n"), None);
    }

    #[test]
    fn meminfo_and_cpu() {
        assert_eq!(
            mem_total_mb("MemTotal:       16318412 kB\nMemFree: 1 kB\n"),
            Some(15935)
        );
        let cpu = "processor\t: 0\nmodel name\t: Intel A\nprocessor\t: 1\nmodel name\t: Intel B\n";
        assert_eq!(cpu_model(cpu).as_deref(), Some("Intel A"));
    }
    #[test]
    fn real_mounts_filters_virtual() {
        let m = r"/dev/sda1 / ext4 rw 0 0
/dev/sda2 /boot/efi vfat rw 0 0
proc /proc proc rw 0 0
tmpfs /run tmpfs rw 0 0
/dev/loop0 /snap/core/1 squashfs ro 0 0
/dev/sdb1 /mnt/my\040disk ext4 rw 0 0
/dev/sda1 / ext4 rw 0 0
";
        assert_eq!(real_mounts(m), ["/", "/boot/efi", "/mnt/my disk"]);
        // 網路檔案系統掛載失聯會讓 statvfs 卡住
        let n = "srv:/x /mnt/nfs nfs4 rw 0 0\n//h/s /mnt/c cifs rw 0 0\n/dev/sdb1 /d ext4 rw 0 0\n";
        assert_eq!(real_mounts(n), ["/d"]);
    }

    #[test]
    fn ip_addresses_skip_loopback_and_link_local() {
        let ip = r"1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever
1: lo    inet6 ::1/128 scope host \       valid_lft forever
2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\       valid_lft forever
2: eth0    inet6 fe80::1/64 scope link \       valid_lft forever
2: eth0    inet6 2001:db8::5/64 scope global \       valid_lft forever
";
        assert_eq!(ip_addresses(ip), ["10.0.0.5", "2001:db8::5"]);
    }
    #[test]
    fn first_user_skips_root() {
        let who = "root     pts/0        2024-10-23 10:00 (1.2.3.4)\nalice    tty2         2024-10-23 10:01\n";
        assert_eq!(first_user(who).as_deref(), Some("alice"));
        assert_eq!(first_user(""), None);
    }

    fn root_with(files: &[(&str, &[u8])]) -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (p, body) in files {
            let path = d.path().join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
        d
    }

    fn kind(r: &RunsIn) -> (&str, Option<&str>) {
        (r.kind.as_str(), r.detail.as_deref())
    }

    #[test]
    fn runs_in_detects_wsl_container_and_vm() {
        let none = |_: &str| None;
        // WSL 優先於其他判斷
        let d = root_with(&[(
            "proc/sys/kernel/osrelease",
            b"5.15.153.1-microsoft-standard-WSL2\n",
        )]);
        assert_eq!(kind(&runs_in(d.path(), &none)), ("wsl", Some("2")));
        let d = root_with(&[("proc/sys/kernel/osrelease", b"4.4.0-19041-Microsoft\n")]);
        assert_eq!(kind(&runs_in(d.path(), &none)), ("wsl", Some("1")));

        // 容器：systemd-detect-virt 優先，沒有時看檔案
        let d = root_with(&[("proc/sys/kernel/osrelease", b"6.8.0-45-generic\n")]);
        let virt = |f: &str| Some(if f == "--container" { "lxc" } else { "none" }.to_string());
        assert_eq!(kind(&runs_in(d.path(), &virt)), ("container", Some("lxc")));
        let d = root_with(&[(".dockerenv", b"")]);
        assert_eq!(
            kind(&runs_in(d.path(), &none)),
            ("container", Some("docker"))
        );
        let d = root_with(&[("run/.containerenv", b"")]);
        assert_eq!(
            kind(&runs_in(d.path(), &none)),
            ("container", Some("podman"))
        );
        let d = root_with(&[("proc/1/environ", b"PATH=/bin\0container=oci\0HOME=/")]);
        assert_eq!(kind(&runs_in(d.path(), &none)), ("container", Some("oci")));
        // systemd 說 none，但檔案顯示是 docker
        let d = root_with(&[(".dockerenv", b"")]);
        let no_virt = |_: &str| Some("none".to_string());
        assert_eq!(
            kind(&runs_in(d.path(), &no_virt)),
            ("container", Some("docker"))
        );

        // 主機：systemd-detect-virt --vm，沒有時用 DMI
        let d = root_with(&[]);
        let kvm = |f: &str| Some(if f == "--vm" { "kvm" } else { "none" }.to_string());
        assert_eq!(kind(&runs_in(d.path(), &kvm)), ("host", Some("kvm")));
        assert_eq!(kind(&runs_in(d.path(), &no_virt)), ("host", Some("none")));
        let d = root_with(&[
            ("sys/class/dmi/id/sys_vendor", b"VMware, Inc.\n"),
            ("sys/class/dmi/id/product_name", b"VMware7,1\n"),
        ]);
        assert_eq!(kind(&runs_in(d.path(), &none)), ("host", Some("vmware")));
        let d = root_with(&[("sys/class/dmi/id/sys_vendor", b"Dell Inc.\n")]);
        assert_eq!(kind(&runs_in(d.path(), &none)), ("host", Some("none")));
        // 什麼都讀不到
        let d = root_with(&[("proc/1/environ", b"PATH=/bin\0container=\0")]);
        assert_eq!(kind(&runs_in(d.path(), &none)), ("host", None));
    }
}
