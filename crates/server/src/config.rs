//! 由環境變數讀取設定。

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub database_url: String,
    pub ca_dir: PathBuf,
    pub agent_listen: SocketAddr,
    pub web_listen: SocketAddr,
    /// 管理網頁顯示時間的時區（UTC 偏移小時）
    pub display_utc_offset: i32,
    /// 註冊端點每個 IP 每分鐘上限（負載測試時調高）
    pub enroll_per_ip_per_minute: u32,
    /// 通用範本 MSI 的路徑；未設定時網頁不提供「下載安裝檔」
    pub agent_msi: Option<PathBuf>,
    /// 下載安裝檔時預設的伺服器網址（例：https://em.example.com:8443）
    pub agent_public_url: String,
    /// 合規通知的 Webhook 簽章密鑰（只從環境變數讀）
    pub webhook_secret: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
        Ok(Config {
            database_url: get("DATABASE_URL").context("DATABASE_URL is required")?,
            ca_dir: get("EM_CA_DIR").unwrap_or_else(|| "./pki".into()).into(),
            agent_listen: get("EM_AGENT_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:8443".into())
                .parse()
                .context("EM_AGENT_LISTEN")?,
            web_listen: get("EM_WEB_LISTEN")
                .unwrap_or_else(|| "0.0.0.0:443".into())
                .parse()
                .context("EM_WEB_LISTEN")?,
            display_utc_offset: {
                let h: i32 = get("EM_DISPLAY_UTC_OFFSET")
                    .unwrap_or_else(|| "8".into())
                    .parse()
                    .context("EM_DISPLAY_UTC_OFFSET")?;
                anyhow::ensure!(
                    (-12..=14).contains(&h),
                    "EM_DISPLAY_UTC_OFFSET out of range"
                );
                h
            },
            enroll_per_ip_per_minute: {
                let n: u32 = match get("EM_ENROLL_PER_IP_PER_MINUTE") {
                    Some(v) => v.parse().context("EM_ENROLL_PER_IP_PER_MINUTE")?,
                    None => crate::ENROLL_PER_IP_PER_MINUTE,
                };
                anyhow::ensure!(n >= 1, "EM_ENROLL_PER_IP_PER_MINUTE must be >= 1");
                n
            },
            agent_msi: get("EM_AGENT_MSI")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            agent_public_url: get("EM_AGENT_PUBLIC_URL").unwrap_or_default(),
            webhook_secret: get("EM_WEBHOOK_SECRET").filter(|s| !s.is_empty()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_required() {
        let c =
            Config::from_lookup(|k| (k == "DATABASE_URL").then(|| "postgres://x".into())).unwrap();
        assert_eq!(c.agent_listen.port(), 8443);
        assert_eq!(c.ca_dir, PathBuf::from("./pki"));
        assert!(Config::from_lookup(|_| None).is_err());
    }

    #[test]
    fn web_defaults_and_offset() {
        let c =
            Config::from_lookup(|k| (k == "DATABASE_URL").then(|| "postgres://x".into())).unwrap();
        assert_eq!(c.web_listen.port(), 443);
        assert_eq!(c.display_utc_offset, 8);
        let bad = Config::from_lookup(|k| match k {
            "DATABASE_URL" => Some("postgres://x".into()),
            "EM_DISPLAY_UTC_OFFSET" => Some("99".into()),
            _ => None,
        });
        assert!(bad.is_err());
    }

    #[test]
    fn notify_secrets_env() {
        let c = Config::from_lookup(|k| match k {
            "DATABASE_URL" => Some("postgres://x".into()),
            "EM_WEBHOOK_SECRET" => Some("".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.webhook_secret, None, "空字串視為未設定");
    }

    #[test]
    fn enroll_limit_env() {
        let base = |v: Option<&str>| {
            let v = v.map(String::from);
            Config::from_lookup(move |k| match k {
                "DATABASE_URL" => Some("postgres://x".into()),
                "EM_ENROLL_PER_IP_PER_MINUTE" => v.clone(),
                _ => None,
            })
        };
        assert_eq!(base(None).unwrap().enroll_per_ip_per_minute, 60);
        assert_eq!(
            base(Some("100000")).unwrap().enroll_per_ip_per_minute,
            100_000
        );
        assert!(base(Some("0")).is_err());
        assert!(base(Some("abc")).is_err());
    }
}
