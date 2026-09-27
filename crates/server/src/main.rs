use std::path::Path;

use anyhow::{Context, bail};
use endpoint_server::{config::Config, tokens};

const USAGE: &str = "usage:
  endpoint-server serve
  endpoint-server ca-init <dir> <server-dns-name>...
  endpoint-server token-create <name> <max_uses> [group_label] [valid_days]";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => endpoint_server::serve(Config::from_env()?).await,
        Some("ca-init") if args.len() >= 3 => {
            endpoint_server::ca::init_ca(Path::new(&args[1]), args[2..].to_vec())?;
            println!(
                "CA 已建立於 {}。請將 root.key 移到離線儲存媒體後從伺服器刪除。",
                args[1]
            );
            Ok(())
        }
        Some("token-create") if args.len() >= 3 => {
            let cfg = Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            endpoint_server::db::migrate(&pool).await?;
            let max_uses: i32 = args[2].parse().context("max_uses")?;
            let days: Option<i64> = args
                .get(4)
                .map(|d| d.parse())
                .transpose()
                .context("valid_days")?;
            let (id, token) = tokens::create_token(
                &pool,
                &tokens::NewToken {
                    name: args[1].clone(),
                    group_label: args.get(3).cloned(),
                    expires_at: days.map(|d| chrono::Utc::now() + chrono::Duration::days(d)),
                    max_uses,
                    created_by: "cli".into(),
                },
            )
            .await?;
            println!("token id {id}：{token}\n（明碼只顯示這一次）");
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}
