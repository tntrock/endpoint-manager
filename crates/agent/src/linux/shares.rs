//! Linux 共用（錯誤設定規格 §4.1）：Samba（`testparm -s` 的實際設定）與 NFS（`/etc/exports`）。
//! 解析在 [`crate::shares`]。

use std::path::Path;

use protocol::SharesInfo;

use super::exec::{Run, is_not_found, real_run};
use crate::shares::{parse_exports, parse_testparm};

/// 錯誤訊息最長幾個字
const MAX_ERROR_CHARS: usize = 500;

pub fn collect() -> SharesInfo {
    collect_with(&real_run, Path::new("/etc"))
}

/// `etc` 是 exports 檔所在的目錄（測試換成暫存目錄）
pub fn collect_with(run: Run, etc: &Path) -> SharesInfo {
    let mut info = SharesInfo::default();
    // 沒有安裝 Samba 時沒有 testparm：不回報
    match run("testparm", &["-s"]) {
        Ok(out) => info.shares.extend(parse_testparm(&out)),
        Err(e) if is_not_found(&e) => {}
        Err(e) => info.errors.push(format!(
            "無法讀取 Samba 設定：{}",
            e.to_string()
                .chars()
                .take(MAX_ERROR_CHARS)
                .collect::<String>()
        )),
    }
    let mut files = vec![etc.join("exports")];
    if let Ok(dir) = std::fs::read_dir(etc.join("exports.d")) {
        let mut extra: Vec<_> = dir
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "exports"))
            .collect();
        extra.sort();
        files.extend(extra);
    }
    for f in files {
        match std::fs::read_to_string(&f) {
            Ok(text) => info.shares.extend(parse_exports(&text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => info.errors.push(format!("無法讀取 {}：{e}", f.display())),
        }
    }
    info.shares.truncate(protocol::MAX_SHARES);
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::exec::not_found;
    use protocol::ShareAccess;

    #[test]
    fn samba_and_nfs_together() {
        let etc = tempfile::tempdir().unwrap();
        std::fs::write(etc.path().join("exports"), "/srv/a *(rw)\n").unwrap();
        std::fs::create_dir(etc.path().join("exports.d")).unwrap();
        std::fs::write(
            etc.path().join("exports.d/b.exports"),
            "/srv/b 10.0.0.0/8\n",
        )
        .unwrap();
        std::fs::write(etc.path().join("exports.d/ignored.txt"), "/srv/c *\n").unwrap();
        let run = |p: &str, a: &[&str]| {
            assert_eq!((p, a), ("testparm", &["-s"][..]));
            Ok("[pub]\n\tpath = /srv/pub\n\tguest ok = yes\n".to_string())
        };
        let info = collect_with(&run, etc.path());
        let names: Vec<&str> = info.shares.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["pub", "/srv/a", "/srv/b"]);
        assert!(info.errors.is_empty());
        assert_eq!(info.shares[1].anonymous, ShareAccess::Write);
    }

    #[test]
    fn missing_samba_and_errors() {
        let etc = tempfile::tempdir().unwrap();
        let missing = |p: &str, _: &[&str]| Err(not_found(p));
        let info = collect_with(&missing, etc.path());
        assert!(info.shares.is_empty() && info.errors.is_empty(), "都沒有");
        let broken = |_: &str, _: &[&str]| Err(anyhow::anyhow!("Load smb config files failed"));
        // exports 是目錄：讀取失敗
        std::fs::create_dir(etc.path().join("exports")).unwrap();
        let info = collect_with(&broken, etc.path());
        assert_eq!(info.errors.len(), 2, "{:?}", info.errors);
        assert!(info.errors[0].starts_with("無法讀取 Samba 設定"));
    }

    #[test]
    fn collect_runs_on_this_machine() {
        let info = collect();
        assert!(
            info.shares
                .iter()
                .all(|s| s.kind == "samba" || s.kind == "nfs")
        );
    }
}
