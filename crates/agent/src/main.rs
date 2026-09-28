#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    match std::env::args().nth(1).as_deref() {
        Some("service") => endpoint_agent::windows::service::run(),
        Some("run") => endpoint_agent::windows::run_console(),
        Some("configure") => {
            use endpoint_agent::windows::{agent_dir, install};
            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(2).collect();
            install::configure(
                &agent_dir(),
                install::flag(&args, "--server-url").as_deref(),
                install::flag(&args, "--token").as_deref(),
                install::flag(&args, "--root-ca").as_deref(),
            )?;
            install::set_recovery()
        }
        Some("unconfigure") => {
            endpoint_agent::windows::install::unconfigure(&endpoint_agent::windows::agent_dir())
        }
        _ => anyhow::bail!(
            "usage: endpoint-agent run | service | configure [--server-url URL] [--token TOKEN] [--root-ca BASE64] | unconfigure"
        ),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("endpoint-agent only runs on Windows");
    std::process::exit(1);
}
