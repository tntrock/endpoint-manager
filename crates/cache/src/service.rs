//! Windows 服務：`endpoint-cache.exe service [--data-dir D]`，由 SCM 啟動。
//! 註冊服務：`sc.exe create EndpointManagerCache binPath= "<路徑>\endpoint-cache.exe service" start= auto`

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use tokio::sync::watch;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "EndpointManagerCache";

static DATA_DIR: OnceLock<PathBuf> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

pub fn run(dir: PathBuf) -> anyhow::Result<()> {
    let _ = DATA_DIR.set(dir);
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
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

fn service_main(_args: Vec<OsString>) {
    let dir = DATA_DIR
        .get()
        .cloned()
        .unwrap_or_else(crate::config::default_data_dir);
    if let Ok(f) = crate::logfile::open(&dir) {
        tracing_subscriber::fmt()
            .with_writer(std::sync::Mutex::new(f))
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .init();
    }
    if let Err(e) = run_service(dir) {
        tracing::error!(error = %format!("{e:#}"), "service failed");
    }
}

fn run_service(dir: PathBuf) -> anyhow::Result<()> {
    let (tx, rx) = watch::channel(false);
    let handle = service_control_handler::register(SERVICE_NAME, move |ev| match ev {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    handle.set_service_status(status(ServiceState::Running, ServiceExitCode::Win32(0)))?;
    let result = tokio::runtime::Runtime::new()
        .map_err(anyhow::Error::from)
        .and_then(|rt| rt.block_on(crate::run::run(&dir, rx)));
    // 失敗時回報非 0，讓 SCM 的復原動作重新啟動服務
    let exit = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "cache stopped with error");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    handle.set_service_status(status(ServiceState::Stopped, exit))?;
    result
}
