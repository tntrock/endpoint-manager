use std::path::PathBuf;
use std::process::ExitCode;

use endpoint_cache::{config, run};

const USAGE: &str = "usage:
  endpoint-cache enroll --server URL --root ROOT.PEM --token TOKEN --name NAME --url https://HOST[:PORT] --dns NAME[,NAME...] [--data-dir DIR]
  endpoint-cache run [--data-dir DIR]
  endpoint-cache service [--data-dir DIR]   (Windows service entry point)";

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == name).map(|w| w[1].clone())
}

fn required(args: &[String], name: &str) -> anyhow::Result<String> {
    flag(args, name).ok_or_else(|| anyhow::anyhow!("missing {name}\n{USAGE}"))
}

fn main() -> ExitCode {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    let dir = flag(&args, "--data-dir")
        .map(PathBuf::from)
        .unwrap_or_else(config::default_data_dir);
    let result = match args.get(1).map(String::as_str) {
        Some("enroll") => enroll(&args, &dir),
        Some("run") => run_console(&dir),
        #[cfg(windows)]
        Some("service") => endpoint_cache::service::run(dir),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn enroll(args: &[String], dir: &std::path::Path) -> anyhow::Result<()> {
    let a = run::EnrollArgs {
        server: required(args, "--server")?,
        root_pem_path: required(args, "--root")?.into(),
        token: required(args, "--token")?,
        name: required(args, "--name")?,
        url: required(args, "--url")?,
        dns: required(args, "--dns")?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
    };
    config::secure_data_dir(dir)?;
    let id = tokio::runtime::Runtime::new()?.block_on(run::enroll(dir, &a))?;
    println!(
        "已送出註冊（快取 id {id}）。請平台管理員在管理網頁核准並指定據點，之後執行 `endpoint-cache run` 或啟動服務。"
    );
    Ok(())
}

fn run_console(dir: &std::path::Path) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = tx.send(true);
        });
        run::run(dir, rx).await
    })
}
