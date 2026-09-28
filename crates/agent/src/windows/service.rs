//! 由服務控制管理員（SCM）啟動：`endpoint-agent.exe service`。

use std::ffi::OsString;
use std::time::Duration;

use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use super::eventlog::EventLog;

pub const SERVICE_NAME: &str = "EndpointManagerAgent";

define_windows_service!(ffi_service_main, service_main);

pub fn run() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run_service() {
        tracing::error!(error = %format!("{e:#}"), "service failed");
    }
}

fn status(state: ServiceState, exit_code: ServiceExitCode) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

const OK: ServiceExitCode = ServiceExitCode::Win32(0);
/// 服務專用結束代碼：1 = 執行中發生錯誤；2 = 資料目錄不可信（需重新安裝）
const UNTRUSTED_DATA_DIR: u32 = 2;

fn run_service() -> anyhow::Result<()> {
    if let Ok(log) = EventLog::open() {
        tracing_subscriber::fmt()
            .with_writer(log)
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    let (tx, rx) = watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    // 資料目錄不可信（權限被改、被換成 junction）時不回報「執行中」，直接以結束代碼 2 停止
    let dir = super::agent_dir();
    if let Err(e) = super::secdir::verify_data_dir(&dir) {
        tracing::error!(error = %format!("{e:#}"), "untrusted data directory; agent will not start");
        handle.set_service_status(status(
            ServiceState::Stopped,
            ServiceExitCode::ServiceSpecific(UNTRUSTED_DATA_DIR),
        ))?;
        return Err(e);
    }
    handle.set_service_status(status(ServiceState::Running, OK))?;

    let result = tokio::runtime::Runtime::new()
        .map_err(anyhow::Error::from)
        .and_then(|rt| {
            let r = rt.block_on(super::run(&dir, rx));
            let _ = handle.set_service_status(status(ServiceState::StopPending, OK));
            // 卡住的 WMI 執行緒無法取消，不等它們結束
            rt.shutdown_timeout(Duration::from_secs(5));
            r
        });
    // 失敗時回報非 0 結束代碼，讓 SCM 的失敗復原動作重新啟動服務；
    // 伺服器拒絕憑證（401）屬正常停止，回報 0，避免無限重啟。
    let exit = match &result {
        Ok(()) => OK,
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "agent stopped with error");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    handle.set_service_status(status(ServiceState::Stopped, exit))?;
    result
}
