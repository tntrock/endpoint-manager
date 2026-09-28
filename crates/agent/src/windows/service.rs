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

fn status(state: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(70),
        process_id: None,
    }
}

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
    handle.set_service_status(status(ServiceState::Running))?;

    let dir = super::agent_dir();
    let result = crate::state::secure_dir(&dir)
        .and_then(|()| tokio::runtime::Runtime::new()?.block_on(super::run(&dir, rx)));
    if let Err(e) = &result {
        tracing::error!(error = %format!("{e:#}"), "agent stopped with error");
    }
    handle.set_service_status(status(ServiceState::Stopped))?;
    result
}
