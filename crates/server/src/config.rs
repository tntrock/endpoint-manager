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
    /// Linux agent 的 deb／rpm 安裝包；未設定時網頁不提供對應的下載
    pub agent_deb: Option<PathBuf>,
    pub agent_rpm: Option<PathBuf>,
    /// 下載安裝檔時預設的伺服器網址（例：https://em.example.com:8443）
    pub agent_public_url: String,
    /// 合規通知的 Webhook 簽章密鑰（只從環境變數讀）
    pub webhook_secret: Option<String>,
    /// 派送套件檔案目錄（`EM_PACKAGE_DIR`，預設 `packages`）
    pub package_dir: PathBuf,
    /// 同時下載套件的上限（`EM_DOWNLOAD_CONCURRENCY`，預設 50）
    pub download_concurrency: usize,
    /// `/metrics` 的 Bearer 權杖（`EM_METRICS_TOKEN`）；None 表示關閉
    pub metrics_token: Option<String>,
    /// 管理網頁單一登入（`EM_OIDC_*`）；None 表示關閉
    pub oidc: Option<crate::oidc::OidcConfig>,
    /// 資料庫裡機密（SNMP 帳密）的加密金鑰檔（`EM_SECRET_KEY_FILE`）；None 表示不能保存帳密
    pub secret_key_file: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Config> {
        let oidc = crate::oidc::OidcConfig::from_lookup(&get)?;
        Ok(Config {
            oidc,
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
            agent_deb: get("EM_AGENT_DEB")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            agent_rpm: get("EM_AGENT_RPM")
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            agent_public_url: get("EM_AGENT_PUBLIC_URL").unwrap_or_default(),
            webhook_secret: get("EM_WEBHOOK_SECRET").filter(|s| !s.is_empty()),
            secret_key_file: get("EM_SECRET_KEY_FILE")
                .filter(|s| !s.trim().is_empty())
                .map(PathBuf::from),
            package_dir: get("EM_PACKAGE_DIR")
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "packages".into())
                .into(),
            download_concurrency: {
                let n: usize = match get("EM_DOWNLOAD_CONCURRENCY") {
                    Some(v) => v.parse().context("EM_DOWNLOAD_CONCURRENCY")?,
                    None => crate::DOWNLOAD_CONCURRENCY,
                };
                anyhow::ensure!(n >= 1, "EM_DOWNLOAD_CONCURRENCY must be >= 1");
                n
            },
            metrics_token: match get("EM_METRICS_TOKEN").map(|t| t.trim().to_string()) {
                Some(t) if t.is_empty() => None,
                Some(t) => {
                    anyhow::ensure!(
                        t.chars().count() >= crate::metrics::MIN_TOKEN_LEN,
                        "EM_METRICS_TOKEN must be at least {} characters",
                        crate::metrics::MIN_TOKEN_LEN
                    );
                    Some(t)
                }
                None => None,
            },
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
    fn secret_key_file_env() {
        let with = |v: &str| {
            let v = v.to_string();
            Config::from_lookup(move |k| match k {
                "DATABASE_URL" => Some("postgres://x".into()),
                "EM_SECRET_KEY_FILE" => Some(v.clone()),
                _ => None,
            })
            .unwrap()
            .secret_key_file
        };
        assert_eq!(with(" "), None, "空白視為未設定");
        assert_eq!(
            with("/run/secrets/em.key"),
            Some(PathBuf::from("/run/secrets/em.key"))
        );
    }

    #[test]
    fn linux_packages_env() {
        let c = Config::from_lookup(|k| match k {
            "DATABASE_URL" => Some("postgres://x".into()),
            "EM_AGENT_DEB" => Some("/agent/endpoint-agent.deb".into()),
            "EM_AGENT_RPM" => Some("".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            c.agent_deb,
            Some(PathBuf::from("/agent/endpoint-agent.deb"))
        );
        assert_eq!(c.agent_rpm, None, "空字串視為未設定");
    }

    #[test]
    fn metrics_token_env() {
        let with = |v: &str| {
            let v = v.to_string();
            Config::from_lookup(move |k| match k {
                "DATABASE_URL" => Some("postgres://x".into()),
                "EM_METRICS_TOKEN" => Some(v.clone()),
                _ => None,
            })
        };
        let none = Config::from_lookup(|k| (k == "DATABASE_URL").then(|| "postgres://x".into()));
        assert_eq!(none.unwrap().metrics_token, None);
        assert_eq!(with("").unwrap().metrics_token, None, "空字串視為未設定");
        assert!(with("too-short").is_err());
        let t = "0123456789abcdef0123456789abcdef";
        assert_eq!(with(t).unwrap().metrics_token.as_deref(), Some(t));
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
