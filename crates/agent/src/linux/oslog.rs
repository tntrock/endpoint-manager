//! Linux：Agent 服務的啟動類型、系統是否正在關機、journald 裡 Agent 服務被停止的紀錄
//! （竄改偵測規格 §4.1、§4.3）。解析在 [`crate::oslog`]。

use std::sync::Mutex;

use protocol::AgentEvent;
use time::OffsetDateTime;

use super::exec::{CMD_TIMEOUT, run_capture};
use crate::journal::Journal;
use crate::oslog::{parse_journal, start_type_from_unit_file_state, unit_from_cgroup};

/// Agent 所在的 systemd 服務；不是由 systemd 啟動時為 None
pub fn own_unit() -> Option<String> {
    unit_from_cgroup(&std::fs::read_to_string("/proc/self/cgroup").ok()?)
}

/// Agent 服務的啟動類型
pub fn start_type() -> Option<&'static str> {
    let unit = own_unit()?;
    let out = run_capture(
        "systemctl",
        &["show", "-p", "UnitFileState", "--value", &unit],
        CMD_TIMEOUT,
    )
    .ok()?;
    start_type_from_unit_file_state(&out)
}

/// 系統正在關機或重新開機
pub fn system_stopping() -> bool {
    run_capture(
        "systemctl",
        &["show", "-p", "SystemState", "--value"],
        std::time::Duration::from_secs(2),
    )
    .is_ok_and(|s| s.trim() == "stopping")
}

/// 讀 `since` 之後 systemd 對 Agent 服務的停止紀錄，記進日誌
pub fn record_since(journal: &Mutex<Journal>, since: OffsetDateTime) {
    let Some(unit) = own_unit() else {
        return;
    };
    let since = format!("@{}", since.unix_timestamp());
    let out = match run_capture(
        "journalctl",
        &["-u", &unit, "--since", &since, "-o", "json", "--no-pager"],
        CMD_TIMEOUT,
    ) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot read journald");
            return;
        }
    };
    let mut j = journal.lock().unwrap_or_else(|p| p.into_inner());
    for s in parse_journal(&out) {
        let data = serde_json::to_value(s).expect("serializes");
        if let Err(e) = j.append(
            AgentEvent::OS_SERVICE_STOPPED,
            data,
            OffsetDateTime::now_utc(),
        ) {
            tracing::warn!(error = %e, "cannot record service stop");
            return;
        }
    }
}
