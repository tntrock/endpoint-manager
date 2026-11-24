//! Linux 對外開放的服務（錯誤設定規格 §5.1）：`/proc/net` 的監聽 socket 對到程式，
//! 加上 `sshd -T` 的實際設定。解析在 [`crate::exposure`]。

use std::collections::HashMap;
use std::path::Path;

use protocol::ExposureInfo;

use super::exec::{Run, is_not_found, real_run};
use crate::exposure::{finish, parse_proc_net, parse_sshd_t, socket_inode};

/// 錯誤訊息最長幾個字
const MAX_ERROR_CHARS: usize = 500;

pub fn collect() -> ExposureInfo {
    collect_with(&real_run, Path::new("/proc"))
}

/// socket inode → 程式名稱（`/proc/<pid>/comm`）。讀不到的程序略過
fn inode_owners(proc_dir: &Path) -> HashMap<u64, String> {
    let mut out = HashMap::new();
    let Ok(dir) = std::fs::read_dir(proc_dir) else {
        return out;
    };
    for entry in dir.flatten() {
        let pid = entry.path();
        if !entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(pid.join("fd")) else {
            continue;
        };
        let comm = std::fs::read_to_string(pid.join("comm"))
            .map(|c| c.trim().to_string())
            .unwrap_or_default();
        for fd in fds.flatten() {
            if let Some(inode) = std::fs::read_link(fd.path())
                .ok()
                .and_then(|l| socket_inode(&l.to_string_lossy()))
            {
                out.entry(inode).or_insert_with(|| comm.clone());
            }
        }
    }
    out
}

/// `proc_dir` 是 /proc（測試換成暫存目錄）
pub fn collect_with(run: Run, proc_dir: &Path) -> ExposureInfo {
    let mut info = ExposureInfo::default();
    let mut raw = vec![];
    for (file, proto) in [
        ("tcp", "tcp"),
        ("tcp6", "tcp"),
        ("udp", "udp"),
        ("udp6", "udp"),
    ] {
        match std::fs::read_to_string(proc_dir.join("net").join(file)) {
            Ok(text) => raw.extend(parse_proc_net(&text, proto)),
            // 關掉 IPv6 的機器沒有 tcp6、udp6
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => info.errors.push(format!("無法讀取 /proc/net/{file}：{e}")),
        }
    }
    let owners = if raw.is_empty() {
        HashMap::new()
    } else {
        inode_owners(proc_dir)
    };
    let items = raw
        .into_iter()
        .map(|(ip, mut item, inode)| {
            item.process = owners.get(&inode).filter(|c| !c.is_empty()).cloned();
            (ip, item)
        })
        .collect();
    (info.listening, info.truncated) = finish(items, protocol::MAX_LISTENING);
    match run("sshd", &["-T"]) {
        Ok(out) => info.sshd = parse_sshd_t(&out),
        Err(e) if is_not_found(&e) => {}
        Err(e) => info.errors.push(format!(
            "無法讀取 sshd 設定：{}",
            e.to_string()
                .chars()
                .take(MAX_ERROR_CHARS)
                .collect::<String>()
        )),
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::exec::not_found;

    #[test]
    fn listening_sockets_with_owners() {
        let proc_dir = tempfile::tempdir().unwrap();
        let net = proc_dir.path().join("net");
        std::fs::create_dir(&net).unwrap();
        std::fs::write(
            net.join("tcp"),
            "header\n   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1\n   1: 0100007F:0019 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4343 1\n",
        )
        .unwrap();
        // 假的程序：pid 77 的 fd 3 指向 socket 4242
        let pid = proc_dir.path().join("77");
        std::fs::create_dir_all(pid.join("fd")).unwrap();
        std::fs::write(pid.join("comm"), "sshd\n").unwrap();
        std::os::unix::fs::symlink("socket:[4242]", pid.join("fd/3")).unwrap();
        std::os::unix::fs::symlink("/dev/null", pid.join("fd/4")).unwrap();
        std::fs::create_dir(proc_dir.path().join("self")).unwrap();
        let run = |p: &str, a: &[&str]| {
            assert_eq!((p, a), ("sshd", &["-T"][..]));
            Ok("permitrootlogin no\npasswordauthentication no\nport 22\n".to_string())
        };
        let info = collect_with(&run, proc_dir.path());
        assert_eq!(info.listening.len(), 1, "{:?}", info.listening);
        assert_eq!(info.listening[0].process.as_deref(), Some("sshd"));
        assert_eq!(info.listening[0].port, 22);
        assert_eq!(info.sshd.unwrap().permit_root_login, "no");
        assert!(info.errors.is_empty());
        assert!(info.firewall_allow_all.is_none() && info.rdp.is_none());
    }

    #[test]
    fn missing_sshd_and_errors() {
        let proc_dir = tempfile::tempdir().unwrap();
        let missing = |p: &str, _: &[&str]| Err(not_found(p));
        let info = collect_with(&missing, proc_dir.path());
        assert!(info.listening.is_empty() && info.sshd.is_none() && info.errors.is_empty());
        let broken = |_: &str, _: &[&str]| Err(anyhow::anyhow!("no hostkeys available"));
        let info = collect_with(&broken, proc_dir.path());
        assert_eq!(info.errors.len(), 1);
        assert!(info.errors[0].contains("no hostkeys"));
    }

    #[test]
    fn collect_runs_on_this_machine() {
        let info = collect();
        assert!(
            info.listening
                .iter()
                .all(|l| l.proto == "tcp" || l.proto == "udp")
        );
    }
}
