//! Linux：Agent 服務的啟動類型、系統是否正在關機、journald 裡 Agent 服務被停止的紀錄
//! （竄改偵測規格 §4.1、§4.3）。解析在 [`crate::oslog`]。

use std::sync::Mutex;

use protocol::AgentEvent;
use time::OffsetDateTime;

use super::exec::{Run, real_run};
use crate::journal::Journal;
use crate::oslog::{parse_journal, start_type_from_unit_file_state, unit_from_cgroup};

/// Agent 所在的 systemd 服務；不是由 systemd 啟動時為 None
pub fn own_unit() -> Option<String> {
    unit_from_cgroup(&std::fs::read_to_string("/proc/self/cgroup").ok()?)
}

/// Agent 服務的啟動類型
pub fn start_type() -> Option<&'static str> {
    start_type_with(&real_run, own_unit())
}

pub fn start_type_with(run: Run, unit: Option<String>) -> Option<&'static str> {
    let unit = unit?;
    let out = run(
        "systemctl",
        &["show", "-p", "UnitFileState", "--value", &unit],
    )
    .ok()?;
    start_type_from_unit_file_state(&out)
}

/// 系統正在關機或重新開機
pub fn system_stopping() -> bool {
    system_stopping_with(&real_run)
}

pub fn system_stopping_with(run: Run) -> bool {
    run("systemctl", &["show", "-p", "SystemState", "--value"])
        .is_ok_and(|s| s.trim() == "stopping")
}

/// 讀 `since` 之後 systemd 對 Agent 服務的停止紀錄，記進日誌
pub fn record_since(journal: &Mutex<Journal>, since: OffsetDateTime) {
    record_since_with(&real_run, own_unit(), journal, since);
}

/// 回傳記下幾筆
pub fn record_since_with(
    run: Run,
    unit: Option<String>,
    journal: &Mutex<Journal>,
    since: OffsetDateTime,
) -> usize {
    let Some(unit) = unit else {
        return 0;
    };
    let since = format!("@{}", since.unix_timestamp());
    let out = match run(
        "journalctl",
        &["-u", &unit, "--since", &since, "-o", "json", "--no-pager"],
    ) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "cannot read journald");
            return 0;
        }
    };
    let mut j = journal.lock().unwrap_or_else(|p| p.into_inner());
    let mut n = 0;
    for s in parse_journal(&out) {
        let data = serde_json::to_value(s).expect("serializes");
        if let Err(e) = j.append(
            AgentEvent::OS_SERVICE_STOPPED,
            data,
            OffsetDateTime::now_utc(),
        ) {
            tracing::warn!(error = %e, "cannot record service stop");
            break;
        }
        n += 1;
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_type_from_systemctl() {
        let run = |p: &str, a: &[&str]| {
            assert_eq!(p, "systemctl");
            assert_eq!(a.last(), Some(&"em.service"));
            Ok("disabled\n".to_string())
        };
        assert_eq!(
            start_type_with(&run, Some("em.service".into())),
            Some("disabled")
        );
        // 不是由 systemd 啟動、指令失敗
        assert_eq!(start_type_with(&run, None), None);
        let fail = |_: &str, _: &[&str]| Err(anyhow::anyhow!("x"));
        assert_eq!(start_type_with(&fail, Some("em.service".into())), None);
    }

    #[test]
    fn stopping_state() {
        let stopping = |_: &str, _: &[&str]| Ok("stopping\n".to_string());
        let running = |_: &str, _: &[&str]| Ok("running\n".to_string());
        let fail = |_: &str, _: &[&str]| Err(anyhow::anyhow!("x"));
        assert!(system_stopping_with(&stopping));
        assert!(!system_stopping_with(&running));
        assert!(!system_stopping_with(&fail));
    }

    #[test]
    fn journal_records_are_appended() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Mutex::new(Journal::open(dir.path()));
        let since = OffsetDateTime::from_unix_timestamp(1_764_000_000).unwrap();
        let run = |p: &str, a: &[&str]| {
            assert_eq!(p, "journalctl");
            assert!(a.contains(&"@1764000000"));
            assert!(a.contains(&"em.service"));
            Ok(concat!(
                r#"{"MESSAGE":"em.service: Main process exited, code=killed, status=9/KILL","__REALTIME_TIMESTAMP":"1764000100000000","_PID":"1"}"#,
                "\n",
                r#"{"MESSAGE":"Started em.service","__REALTIME_TIMESTAMP":"1764000110000000","_PID":"1"}"#,
            )
            .to_string())
        };
        assert_eq!(
            record_since_with(&run, Some("em.service".into()), &journal, since),
            1
        );
        let ev = journal.lock().unwrap().pending(10);
        assert_eq!(ev[0].kind, AgentEvent::OS_SERVICE_STOPPED);
        assert_eq!(ev[0].data["killed"], true);
        assert_eq!(record_since_with(&run, None, &journal, since), 0);
        let fail = |_: &str, _: &[&str]| Err(anyhow::anyhow!("x"));
        assert_eq!(
            record_since_with(&fail, Some("em.service".into()), &journal, since),
            0
        );
        assert_eq!(journal.lock().unwrap().len(), 1);
    }
}
