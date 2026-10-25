//! systemd 服務。

use super::exec::{CMD_TIMEOUT, is_not_found, run_capture};
use crate::linux_parse::services as parse;
use protocol::ServiceItem;

/// 沒有 systemctl → 空清單 + 說明；其他錯誤 → Err。
pub fn collect() -> anyhow::Result<(Vec<ServiceItem>, Option<String>)> {
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
            return Ok((Vec::new(), Some("沒有 systemd，不收集服務".to_string())));
        }
        Err(e) => return Err(e),
    };
    let files = run_capture("systemctl", &files, CMD_TIMEOUT)?;
    Ok((parse::parse(&units, &files), None))
}
