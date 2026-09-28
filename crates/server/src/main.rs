use std::path::Path;

use anyhow::{Context, bail};
use endpoint_server::{config::Config, tokens};

const USAGE: &str = "usage:
  endpoint-server serve
  endpoint-server ca-init <dir> <server-dns-name>...
  endpoint-server token-create <name> <max_uses> [group_name] [valid_days]
  endpoint-server admin-create <username>   (password from stdin)";

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
        Some("admin-create") if args.len() >= 2 => {
            let cfg = Config::from_env()?;
            let pool = sqlx::PgPool::connect(&cfg.database_url).await?;
            endpoint_server::db::migrate(&pool).await?;
            eprintln!(
                "輸入密碼（至少 {} 字元）：",
                endpoint_server::web::auth::MIN_PASSWORD_LEN
            );
            let mut pw = String::new();
            std::io::stdin().read_line(&mut pw)?;
            let id = endpoint_server::accounts::create(
                &pool,
                &endpoint_server::accounts::NewAdmin {
                    username: args[1].clone(),
                    password: pw.trim_end_matches(['\r', '\n']).to_string(),
                    role: endpoint_server::web::auth::Role::Platform,
                    groups: vec![],
                },
                "cli",
            )
            .await?;
            println!("platform admin id {id} created");
            Ok(())
        }
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
            let group_id = match args.get(3) {
                Some(name) => {
                    let mut c = pool.acquire().await?;
                    Some(endpoint_server::groups::find_or_create(&mut c, name).await?)
                }
                None => None,
            };
            let (id, token) = tokens::create_token(
                &pool,
                &tokens::NewToken {
                    name: args[1].clone(),
                    group_id,
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
