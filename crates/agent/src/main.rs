#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    match std::env::args().nth(1).as_deref() {
        Some("service") => endpoint_agent::windows::service::run(),
        Some("run") => endpoint_agent::windows::run_console(),
        _ => anyhow::bail!("usage: endpoint-agent run | service"),
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("endpoint-agent only runs on Windows");
    std::process::exit(1);
}
