#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    match std::env::args().nth(1).as_deref() {
        Some("service") => endpoint_agent::windows::service::run(),
        Some("run") => endpoint_agent::windows::run_console(),
        Some("configure") => {
            use endpoint_agent::windows::{agent_dir, eventlog, install};
            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
            let result = install::configure(
                &agent_dir(),
                install::flag(&args, "--server-url").as_deref(),
                install::flag(&args, "--token").as_deref(),
                install::flag(&args, "--root-ca").as_deref(),
            )
            .and_then(|()| install::set_recovery());
            // MSI 只會顯示 1603；把原因寫進事件檢視器，IT 才查得到（例如資料目錄被占用）
            if let Err(e) = &result
                && let Ok(log) = eventlog::EventLog::open()
            {
                log.report(
                    windows_sys::Win32::System::EventLog::EVENTLOG_ERROR_TYPE,
                    &format!("Endpoint Manager Agent 安裝設定失敗：{e:#}"),
                );
            }
            result
        }
        Some("unconfigure") => {
            endpoint_agent::windows::install::unconfigure(&endpoint_agent::windows::agent_dir())
        }
        _ => anyhow::bail!(
            "usage: endpoint-agent run | service | configure [--server-url URL] [--token TOKEN] [--root-ca BASE64] | unconfigure"
        ),
    }
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use endpoint_agent::config::flag;
    use endpoint_agent::linux::{agent_dir, install, run_foreground};
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
    match std::env::args().nth(1).as_deref() {
        Some("run") => run_foreground(),
        Some("configure") => install::configure(
            &agent_dir(),
            flag(&args, "--server-url").as_deref(),
            flag(&args, "--token").as_deref(),
            flag(&args, "--root-ca").as_deref(),
        ),
        Some("unconfigure") => install::unconfigure(&agent_dir()),
        _ => anyhow::bail!(
            "usage: endpoint-agent run | configure [--server-url URL] [--token TOKEN] [--root-ca BASE64] | unconfigure"
        ),
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn main() {
    eprintln!("endpoint-agent only runs on Windows and Linux");
    std::process::exit(1);
}
