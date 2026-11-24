//! Agent 的啟動與停止紀錄（竄改偵測規格 §4.1）。
//!
//! - **正常結束標記**：狀態目錄的 `alive` 每 30 秒寫入現在時間；正常停止時另外寫 `clean`。
//!   下次啟動沒看到 `clean` 就是非正常結束（被強制結束、當機、斷電），`alive` 的時間就是
//!   最後活著的時間。是否其實是斷電或重新開機，由伺服器比對開機時間判斷。
//! - **啟動、停止事件**：`agent.started`、`agent.stopping` 寫進事件日誌，停止時盡量在幾秒內送出。
//! - **啟動類型**：每次報到檢查 Agent 服務的啟動類型，改變時記 `agent.service_config`。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::{AgentEvent, AgentStarted, AgentStopping, ServiceConfigChange, timefmt};
use time::OffsetDateTime;
use tokio::sync::watch;

use crate::eventpush::{self, SharedTarget, Target};
use crate::journal::Journal;

pub const ALIVE_FILE: &str = "alive";
pub const CLEAN_FILE: &str = "clean";
/// 計畫中的停止：安裝或設定工具在重新啟動服務前寫入原因（`upgrade`、`reconfigure`）
pub const PLANNED_STOP_FILE: &str = "planned_stop";
/// 上一次看到的服務啟動類型
pub const START_TYPE_FILE: &str = "service_start_type";
/// 多久更新一次 `alive`
pub const ALIVE_EVERY: Duration = Duration::from_secs(30);
/// 停止時最多等多久把事件送出（Windows 服務停止有時間限制）
pub const STOP_FLUSH: Duration = Duration::from_secs(3);
/// 計畫中的停止標記多久內有效：太舊的不採信
pub const PLANNED_STOP_MAX_AGE: Duration = Duration::from_secs(600);

fn lock(j: &Mutex<Journal>) -> std::sync::MutexGuard<'_, Journal> {
    j.lock().unwrap_or_else(|p| p.into_inner())
}

fn read_time(path: &Path) -> Option<OffsetDateTime> {
    let s = std::fs::read_to_string(path).ok()?;
    timefmt::parse_rfc3339(s.trim()).ok()
}

fn write_time(path: &Path, t: OffsetDateTime) -> std::io::Result<()> {
    let s = timefmt::format_rfc3339(t).map_err(std::io::Error::other)?;
    std::fs::write(path, s)
}

/// 讀上一次的結束狀態，記一筆 `agent.started`，並開始這一次的標記
pub fn started(
    dir: &Path,
    journal: &Mutex<Journal>,
    version: &str,
    boot_time: Option<OffsetDateTime>,
    now: OffsetDateTime,
) -> std::io::Result<AgentStarted> {
    let alive = dir.join(ALIVE_FILE);
    let clean = dir.join(CLEAN_FILE);
    let last_alive = read_time(&alive);
    // 兩個檔案都沒有：第一次啟動（或從沒有這個功能的版本升級）
    let first = !alive.exists() && !clean.exists();
    let info = AgentStarted {
        version: version.to_string(),
        clean: first || clean.exists(),
        last_alive,
        boot_time,
    };
    lock(journal).append(
        AgentEvent::AGENT_STARTED,
        serde_json::to_value(&info).expect("serializes"),
        now,
    )?;
    match std::fs::remove_file(&clean) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    // 上次留下、沒用到的計畫停止標記不能沿用到這一次
    let _ = std::fs::remove_file(dir.join(PLANNED_STOP_FILE));
    write_time(&alive, now)?;
    Ok(info)
}

/// 每 30 秒更新 `alive`，直到收到停止訊號
pub async fn keep_alive(dir: PathBuf, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(ALIVE_EVERY) => {}
            _ = shutdown.changed() => return,
        }
        if let Err(e) = write_time(&dir.join(ALIVE_FILE), OffsetDateTime::now_utc()) {
            tracing::warn!(error = %e, "cannot update alive marker");
        }
    }
}

/// 安裝或設定工具重新啟動服務前呼叫：這次停止不是有人停掉 Agent
pub fn plan_stop(dir: &Path, reason: &str) -> std::io::Result<()> {
    std::fs::write(dir.join(PLANNED_STOP_FILE), reason)
}

/// 讀取並刪除計畫中的停止標記（太舊的不算）
pub fn take_planned_stop(dir: &Path, now: std::time::SystemTime) -> Option<String> {
    let path = dir.join(PLANNED_STOP_FILE);
    let modified = std::fs::metadata(&path).and_then(|m| m.modified()).ok()?;
    let reason = std::fs::read_to_string(&path).ok();
    let _ = std::fs::remove_file(&path);
    let fresh = now
        .duration_since(modified)
        .is_ok_and(|age| age <= PLANNED_STOP_MAX_AGE);
    reason
        .map(|r| r.trim().to_string())
        .filter(|r| fresh && !r.is_empty() && r.len() <= 32)
}

/// 停止原因：由平台的停止處理（服務控制、SIGTERM）在送出停止訊號前設定
static STOP_REASON: Mutex<Option<String>> = Mutex::new(None);

pub fn set_stop_reason(reason: &str) {
    *STOP_REASON.lock().unwrap_or_else(|p| p.into_inner()) = Some(reason.to_string());
}

/// 取出停止原因（沒設定過時為 `service_stop`）
pub fn stop_reason() -> String {
    STOP_REASON
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
        .unwrap_or_else(|| protocol::stop_reason::SERVICE_STOP.to_string())
}

/// 記一筆 `agent.stopping`，盡量在 `STOP_FLUSH` 內送出，最後寫入正常結束標記。
/// 送不出去的事件留在日誌，下次啟動後補送。
pub async fn stopping(
    dir: &Path,
    journal: &Arc<Mutex<Journal>>,
    target: &SharedTarget,
    reason: &str,
) {
    let now = OffsetDateTime::now_utc();
    let data = serde_json::to_value(AgentStopping {
        reason: reason.to_string(),
    })
    .expect("serializes");
    if let Err(e) = lock(journal).append(AgentEvent::AGENT_STOPPING, data, now) {
        tracing::warn!(error = %e, "cannot record agent stop");
    }
    let t = target.lock().unwrap_or_else(|p| p.into_inner()).clone();
    if let Some(t) = t {
        let _ = tokio::time::timeout(STOP_FLUSH, flush(journal, t)).await;
    }
    if let Err(e) = mark_clean(dir, OffsetDateTime::now_utc()) {
        tracing::warn!(error = %e, "cannot write clean-shutdown marker");
    }
}

async fn flush(journal: &Mutex<Journal>, t: Target) {
    let send = move |up| {
        let t = t.clone();
        async move {
            let client =
                crate::client::ServerClient::new(&t.url, &t.root_pem, t.identity_pem).ok()?;
            Some(client.push_events(&up).await)
        }
    };
    while eventpush::send_once(journal, &send).await == eventpush::Sent::More {}
}

/// 平台啟動時呼叫：讀開機時間、記 `agent.started`、開始定期更新 `alive`
pub async fn begin<C: crate::collector::Collector>(
    dir: &Path,
    agent: &crate::agent::Agent<C>,
    shutdown: watch::Receiver<bool>,
) -> Option<AgentStarted> {
    let collector = agent.collector();
    let boot = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || collector.heartbeat()),
    )
    .await
    .ok()
    .and_then(|r| r.ok())
    .and_then(|r| r.ok())
    .map(|h| h.boot_time);
    let info = match started(
        dir,
        &agent.journal(),
        crate::agent::AGENT_VERSION,
        boot,
        OffsetDateTime::now_utc(),
    ) {
        Ok(i) => Some(i),
        Err(e) => {
            tracing::warn!(error = %e, "cannot record agent start");
            None
        }
    };
    tokio::spawn(keep_alive(dir.to_path_buf(), shutdown));
    info
}

/// 平台結束時呼叫。`signalled` 為 false 表示不是收到停止要求，而是 Agent 自己停止（憑證被拒）
pub async fn end(
    dir: &Path,
    journal: &Arc<Mutex<Journal>>,
    target: &SharedTarget,
    signalled: bool,
) {
    let reason = if signalled {
        take_planned_stop(dir, std::time::SystemTime::now()).unwrap_or_else(stop_reason)
    } else {
        protocol::stop_reason::CERTIFICATE.to_string()
    };
    stopping(dir, journal, target, &reason).await;
}

/// 正常結束：更新最後活著的時間並寫 `clean`
pub fn mark_clean(dir: &Path, now: OffsetDateTime) -> std::io::Result<()> {
    write_time(&dir.join(ALIVE_FILE), now)?;
    std::fs::write(dir.join(CLEAN_FILE), "")
}

/// 比對上一次記下的啟動類型；改變（或第一次就不是自動）時記 `agent.service_config`
pub fn check_start_type(
    dir: &Path,
    journal: &Mutex<Journal>,
    current: &str,
    now: OffsetDateTime,
) -> std::io::Result<Option<ServiceConfigChange>> {
    let path = dir.join(START_TYPE_FILE);
    let prev = std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if prev.as_deref() == Some(current) {
        return Ok(None);
    }
    let change = ServiceConfigChange {
        from: prev.clone(),
        to: current.to_string(),
    };
    // 第一次檢查而且是自動：正常狀態，只記下來
    let record = prev.is_some() || current != protocol::start_type::AUTO;
    if record {
        lock(journal).append(
            AgentEvent::AGENT_SERVICE_CONFIG,
            serde_json::to_value(&change).expect("serializes"),
            now,
        )?;
    }
    std::fs::write(&path, current)?;
    Ok(record.then_some(change))
}

#[cfg(test)]
mod tests {
    use super::*;
    use protocol::stop_reason;
    use time::macros::datetime;

    fn setup() -> (tempfile::TempDir, Arc<Mutex<Journal>>) {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::open(dir.path());
        (dir, Arc::new(Mutex::new(j)))
    }

    fn started_data(j: &Mutex<Journal>) -> AgentStarted {
        let ev = lock(j).pending(100);
        let e = ev
            .iter()
            .rev()
            .find(|e| e.kind == AgentEvent::AGENT_STARTED)
            .unwrap();
        serde_json::from_value(e.data.clone()).unwrap()
    }

    #[test]
    fn first_start_is_clean_and_unclean_stop_is_noticed() {
        let (d, j) = setup();
        let t1 = datetime!(2026-11-24 01:00 UTC);
        let s = started(d.path(), &j, "1.0", None, t1).unwrap();
        assert!(s.clean);
        assert_eq!(s.last_alive, None);
        assert_eq!(started_data(&j), s);

        // 被強制結束：沒有 clean，last_alive 是最後一次更新的時間
        let t2 = datetime!(2026-11-24 02:00 UTC);
        let s = started(d.path(), &j, "1.0", Some(t1), t2).unwrap();
        assert!(!s.clean);
        assert_eq!(s.last_alive, Some(t1));
        assert_eq!(s.boot_time, Some(t1));

        // 正常結束後再啟動
        let t3 = datetime!(2026-11-24 03:00 UTC);
        mark_clean(d.path(), t3).unwrap();
        let s = started(d.path(), &j, "1.0", None, datetime!(2026-11-24 04:00 UTC)).unwrap();
        assert!(s.clean);
        assert_eq!(s.last_alive, Some(t3));
        assert!(!d.path().join(CLEAN_FILE).exists());
    }

    #[test]
    fn planned_stop_is_used_once_and_expires() {
        let d = tempfile::tempdir().unwrap();
        let now = std::time::SystemTime::now();
        assert_eq!(take_planned_stop(d.path(), now), None);
        plan_stop(d.path(), stop_reason::UPGRADE).unwrap();
        assert_eq!(
            take_planned_stop(d.path(), now + Duration::from_secs(5)).as_deref(),
            Some(stop_reason::UPGRADE)
        );
        assert_eq!(take_planned_stop(d.path(), now), None);
        plan_stop(d.path(), stop_reason::UPGRADE).unwrap();
        assert_eq!(
            take_planned_stop(d.path(), now + PLANNED_STOP_MAX_AGE * 2),
            None
        );
        assert!(!d.path().join(PLANNED_STOP_FILE).exists());
    }

    #[test]
    fn stop_reason_defaults_to_service_stop() {
        assert_eq!(stop_reason(), stop_reason::SERVICE_STOP);
        set_stop_reason(stop_reason::SHUTDOWN);
        assert_eq!(stop_reason(), stop_reason::SHUTDOWN);
        assert_eq!(stop_reason(), stop_reason::SERVICE_STOP);
    }

    #[tokio::test]
    async fn stopping_without_server_keeps_event_and_marks_clean() {
        let (d, j) = setup();
        let target: SharedTarget = Default::default();
        stopping(d.path(), &j, &target, stop_reason::SERVICE_STOP).await;
        let ev = lock(&j).pending(10);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, AgentEvent::AGENT_STOPPING);
        assert_eq!(ev[0].data["reason"], "service_stop");
        assert!(d.path().join(CLEAN_FILE).exists());
        let s = started(d.path(), &j, "1.0", None, OffsetDateTime::now_utc()).unwrap();
        assert!(s.clean);
    }

    #[test]
    fn start_type_changes_are_recorded() {
        let (d, j) = setup();
        let now = datetime!(2026-11-24 01:00 UTC);
        // 第一次是自動：不記事件
        assert_eq!(check_start_type(d.path(), &j, "auto", now).unwrap(), None);
        assert!(lock(&j).is_empty());
        assert_eq!(check_start_type(d.path(), &j, "auto", now).unwrap(), None);
        let c = check_start_type(d.path(), &j, "disabled", now)
            .unwrap()
            .unwrap();
        assert_eq!(c.from.as_deref(), Some("auto"));
        assert_eq!(c.to, "disabled");
        assert_eq!(lock(&j).len(), 1);
        // 第一次就不是自動（裝好之前就被改掉）也要記
        let (d, j) = setup();
        let c = check_start_type(d.path(), &j, "manual", now)
            .unwrap()
            .unwrap();
        assert_eq!(c.from, None);
        assert_eq!(lock(&j).len(), 1);
    }
}
