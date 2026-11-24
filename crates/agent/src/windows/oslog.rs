//! 讀 Windows 系統紀錄與安全性紀錄裡和竄改有關的事件（竄改偵測規格 §4.2）。
//!
//! 每分鐘查一次上次讀到之後的事件（`EvtQuery`），讀到哪裡存在狀態目錄的 `oslog.json`；
//! Agent 停止期間發生的事件，啟動後的第一次查詢就會補上。解析與判斷在 [`crate::oslog`]。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::AgentEvent;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::watch;
use windows_service::service::{ServiceAccess, ServiceStartType};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_ITEMS, GetLastError,
};
use windows_sys::Win32::System::EventLog::{
    EVT_HANDLE, EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection,
    EvtRender, EvtRenderEventXml,
};
use windows_sys::Win32::System::Threading::OpenMutexW;

use super::service::{DISPLAY_NAME, SERVICE_NAME};
use crate::journal::Journal;
use crate::oslog::{Cursor, OsEvent, SECURITY_IDS, SYSTEM_IDS, classify, parse_event_xml, xpath};

pub const STATE_FILE: &str = "oslog.json";
/// 多久查一次
pub const POLL_EVERY: Duration = Duration::from_secs(60);
/// 一次最多讀幾筆（避免紀錄很多時卡太久，下次再接著讀）
const MAX_PER_POLL: usize = 500;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

struct Handle(EVT_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { EvtClose(self.0) };
        }
    }
}

fn render(ev: EVT_HANDLE) -> std::io::Result<String> {
    let mut buf: Vec<u16> = vec![0; 4096];
    loop {
        let mut used = 0u32;
        let mut props = 0u32;
        let ok = unsafe {
            EvtRender(
                0,
                ev,
                EvtRenderEventXml,
                (buf.len() * 2) as u32,
                buf.as_mut_ptr().cast(),
                &mut used,
                &mut props,
            )
        };
        if ok != 0 {
            let n = (used as usize / 2).min(buf.len());
            let end = buf[..n].iter().position(|&c| c == 0).unwrap_or(n);
            return Ok(String::from_utf16_lossy(&buf[..end]));
        }
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || used as usize <= buf.len() * 2
        {
            return Err(std::io::Error::last_os_error());
        }
        buf.resize(used as usize / 2 + 1, 0);
    }
}

/// 查詢一個紀錄，回傳每筆事件的 XML（最舊的在前）
pub fn query(channel: &str, query: &str, max: usize) -> std::io::Result<Vec<String>> {
    let (c, q) = (wide(channel), wide(query));
    let h = Handle(unsafe {
        EvtQuery(
            0,
            c.as_ptr(),
            q.as_ptr(),
            EvtQueryChannelPath | EvtQueryForwardDirection,
        )
    });
    if h.0 == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    while out.len() < max {
        let mut batch: [EVT_HANDLE; 16] = [0; 16];
        let mut n = 0u32;
        let ok = unsafe { EvtNext(h.0, batch.len() as u32, batch.as_mut_ptr(), 1000, 0, &mut n) };
        if ok == 0 {
            if unsafe { GetLastError() } == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(std::io::Error::last_os_error());
        }
        // 每個 handle 都要關，先全部包起來
        let events: Vec<Handle> = batch[..n as usize].iter().map(|&e| Handle(e)).collect();
        for e in &events {
            out.push(render(e.0)?);
        }
    }
    Ok(out)
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    system: Option<Cursor>,
    security: Option<Cursor>,
}

fn load(dir: &Path) -> State {
    std::fs::read(dir.join(STATE_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save(dir: &Path, s: &State) -> std::io::Result<()> {
    std::fs::write(dir.join(STATE_FILE), serde_json::to_vec(s)?)
}

/// Agent 服務的啟動類型（沒有安裝成服務時為 None）
pub fn start_type() -> Option<&'static str> {
    use protocol::start_type::*;
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let svc = mgr
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)
        .ok()?;
    Some(match svc.query_config().ok()?.start_type {
        ServiceStartType::AutoStart
        | ServiceStartType::SystemStart
        | ServiceStartType::BootStart => AUTO,
        ServiceStartType::OnDemand => MANUAL,
        ServiceStartType::Disabled => DISABLED,
    })
}

/// Windows Installer 正在安裝（升級、修復、移除）：這時收到的停止要求來自安裝程式
pub fn installer_running() -> bool {
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let name = wide("Global\\_MSIExecute");
    let h = unsafe { OpenMutexW(SYNCHRONIZE, 0, name.as_ptr()) };
    if h.is_null() {
        return false;
    }
    unsafe { CloseHandle(h) };
    true
}

fn lock(j: &Mutex<Journal>) -> std::sync::MutexGuard<'_, Journal> {
    j.lock().unwrap_or_else(|p| p.into_inner())
}

/// 讀一個紀錄上次之後的事件，記進日誌；回傳是否看到啟動類型被改變
fn poll_channel(
    channel: &str,
    ids: &[u32],
    cursor: &mut Cursor,
    journal: &Mutex<Journal>,
) -> std::io::Result<bool> {
    let mut start_type_changed = false;
    for xml in query(channel, &xpath(ids, cursor.time), MAX_PER_POLL)? {
        let Some(ev) = parse_event_xml(&xml) else {
            continue;
        };
        if cursor.seen(&ev) {
            continue;
        }
        cursor.advance(&ev);
        let (kind, data) = match classify(&ev, SERVICE_NAME, DISPLAY_NAME) {
            Some(OsEvent::ServiceStopped(s)) => {
                (AgentEvent::OS_SERVICE_STOPPED, serde_json::to_value(s)?)
            }
            Some(OsEvent::LogCleared(c)) => (AgentEvent::OS_LOG_CLEARED, serde_json::to_value(c)?),
            Some(OsEvent::StartTypeChanged) => {
                start_type_changed = true;
                continue;
            }
            None => continue,
        };
        lock(journal).append(kind, data, OffsetDateTime::now_utc())?;
    }
    Ok(start_type_changed)
}

fn poll(dir: &Path, journal: &Mutex<Journal>) -> std::io::Result<()> {
    let mut state = load(dir);
    let now = OffsetDateTime::now_utc();
    // 第一次執行：從現在開始，不回頭讀舊紀錄
    let mut sys = state.system.unwrap_or(Cursor {
        time: now,
        record: 0,
    });
    let mut sec = state.security.unwrap_or(Cursor {
        time: now,
        record: 0,
    });
    let changed = poll_channel("System", &SYSTEM_IDS, &mut sys, journal);
    let sec_result = poll_channel("Security", &SECURITY_IDS, &mut sec, journal);
    state.system = Some(sys);
    state.security = Some(sec);
    save(dir, &state)?;
    if changed? && let Some(t) = start_type() {
        crate::lifecycle::check_start_type(dir, journal, t, OffsetDateTime::now_utc())?;
    }
    sec_result.map(|_| ())
}

/// 啟動時查一次，之後每分鐘查一次，直到收到停止訊號
pub async fn run(dir: PathBuf, journal: Arc<Mutex<Journal>>, mut shutdown: watch::Receiver<bool>) {
    let mut last_error: Option<String> = None;
    loop {
        let (d, j) = (dir.clone(), journal.clone());
        let r = tokio::task::spawn_blocking(move || poll(&d, &j)).await;
        let err = match r {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(e) => Some(e.to_string()),
        };
        if let Some(msg) = &err
            && crate::agent::error_changed(last_error.as_ref(), msg)
        {
            tracing::warn!(error = %msg, "cannot read Windows event logs");
        }
        last_error = err;
        tokio::select! {
            _ = tokio::time::sleep(POLL_EVERY) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::eventlog::{EventLog, SOURCE};
    use windows_sys::Win32::System::EventLog::EVENTLOG_INFORMATION_TYPE;

    /// 實際查詢：寫一筆事件到應用程式紀錄，再用同樣的方式查出來
    #[test]
    fn query_reads_events_written_to_the_log() {
        let marker = format!("oslog-test-{}", uuid::Uuid::new_v4());
        let since = OffsetDateTime::now_utc() - time::Duration::MINUTE;
        EventLog::open()
            .unwrap()
            .report(EVENTLOG_INFORMATION_TYPE, &marker);
        let t = protocol::timefmt::format_rfc3339(since).unwrap();
        let q =
            format!("*[System[Provider[@Name='{SOURCE}'] and TimeCreated[@SystemTime>='{t}']]]");
        let mut found = None;
        for _ in 0..20 {
            let xmls = query("Application", &q, 1000).unwrap();
            found = xmls.into_iter().find(|x| x.contains(&marker));
            if found.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let ev = parse_event_xml(&found.expect("event not found")).unwrap();
        assert_eq!(ev.provider, SOURCE);
        assert_eq!(ev.channel, "Application");
        assert!(ev.time >= since);
        // 不存在的紀錄
        assert!(query("No-Such-Log-For-Test", "*", 10).is_err());
    }

    #[test]
    fn installer_is_not_running_during_tests() {
        assert!(!installer_running());
    }

    #[test]
    fn poll_starts_from_now_and_saves_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Mutex::new(Journal::open(dir.path()));
        // 一般使用者讀不到安全性紀錄時會失敗，但系統紀錄的位置仍要存下來
        let _ = poll(dir.path(), &journal);
        let s = load(dir.path());
        assert!(s.system.is_some());
        assert!(s.security.is_some());
    }
}
