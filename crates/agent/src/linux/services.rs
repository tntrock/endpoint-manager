//! systemd 服務。

use super::exec::{CMD_TIMEOUT, is_not_found, run_capture};
use crate::linux_parse::services as parse;
use protocol::ServiceItem;
use std::path::Path;

const NO_SYSTEMD: &str = "沒有 systemd，不收集服務";

/// sd_booted 的標準判斷：systemd 是 PID 1 時才有此目錄（容器、無 systemd 的 WSL 沒有）
fn booted_with_systemd(dir: &Path) -> bool {
    dir.is_dir()
}

/// 沒有 systemctl → 空清單 + 說明；其他錯誤 → Err。
pub fn collect() -> anyhow::Result<(Vec<ServiceItem>, Option<String>)> {
    if !booted_with_systemd(Path::new("/run/systemd/system")) {
        return Ok((Vec::new(), Some(NO_SYSTEMD.to_string())));
    }
    let units = [
        "list-units",
        "--type=service",
        "--all",
        "--no-legend",
        "--plain",
        "--no-pager",
    ];
    let files = [
        "list-unit-files",
        "--type=service",
        "--no-legend",
        "--no-pager",
    ];
    let units = match run_capture("systemctl", &units, CMD_TIMEOUT) {
        Ok(o) => o,
        Err(e) if is_not_found(&e) => {
            return Ok((Vec::new(), Some(NO_SYSTEMD.to_string())));
        }
        Err(e) => return Err(e),
    };
    let files = run_capture("systemctl", &files, CMD_TIMEOUT)?;
    Ok((parse::parse(&units, &files), None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booted_check_follows_directory() {
        let d = std::env::temp_dir().join(format!("em-sd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        assert!(!booted_with_systemd(&d));
        std::fs::create_dir_all(&d).unwrap();
        assert!(booted_with_systemd(&d));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
