//! 已安裝套件（dpkg 優先，其次 rpm）。

use super::exec::{CMD_TIMEOUT, is_not_found, run_capture};
use crate::linux_parse::packages as parse;
use protocol::SoftwareItem;

/// 回清單與 section 說明；指令存在但失敗 → Err，由收集器記成 section 錯誤。
pub fn collect() -> anyhow::Result<(Vec<SoftwareItem>, Option<String>)> {
    let dpkg = [
        "-W",
        "-f",
        "${Status}\t${Package}\t${Version}\t${Maintainer}\t${Architecture}\n",
    ];
    match run_capture("dpkg-query", &dpkg, CMD_TIMEOUT) {
        Ok(out) => return Ok((parse::parse_dpkg(&out), None)),
        Err(e) if !is_not_found(&e) => return Err(e),
        Err(_) => {}
    }
    let rpm = [
        "-qa",
        "--qf",
        "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\t%{ARCH}\n",
    ];
    match run_capture("rpm", &rpm, CMD_TIMEOUT) {
        Ok(out) => Ok((parse::parse_rpm(&out), None)),
        Err(e) if is_not_found(&e) => {
            Ok((Vec::new(), Some("此發行版的套件系統不支援".to_string())))
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_this_machine_packages() {
        let (items, note) = super::collect().unwrap();
        assert!(!items.is_empty());
        assert!(note.is_none());
    }
}
