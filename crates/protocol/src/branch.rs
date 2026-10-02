//! 第七期：分點快取（據點的快取主機就近提供派送套件）。

use serde::{Deserialize, Serialize};

/// 快取回報已存套件的上限
pub const MAX_STORED: usize = 10_000;
const MAX_CSR: usize = 8192;

/// 報到時告訴 Agent：這台的套件向哪台快取下載
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageSource {
    pub cache_id: i64,
    /// `https://<主機>:<埠>`，下載路徑與中央相同（`/v1/packages/{id}/content`）
    pub url: String,
    /// 快取無法使用時，是否改向中央下載
    pub fallback_to_central: bool,
}

/// 派送結果：套件是從哪裡下載的
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadSource {
    Cache,
    Central,
    #[serde(other)]
    Unknown,
}

impl DownloadSource {
    pub fn as_str(self) -> Option<&'static str> {
        match self {
            DownloadSource::Cache => Some("cache"),
            DownloadSource::Central => Some("central"),
            DownloadSource::Unknown => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEnrollRequest {
    pub token: String,
    pub name: String,
    pub url: String,
    /// 快取對外的主機名稱與 IP（寫進憑證的 SAN）
    pub dns_names: Vec<String>,
    pub csr_pem: String,
}

impl CacheEnrollRequest {
    pub fn validate(&self) -> Result<(), &'static str> {
        let n = self.name.trim().chars().count();
        if n == 0 || n > 100 || self.name.chars().any(char::is_control) {
            return Err("name must be 1-100 chars without control characters");
        }
        if !self.url.starts_with("https://") || self.url.len() > 300 {
            return Err("url must start with https:// (max 300 chars)");
        }
        if self.dns_names.is_empty() || self.dns_names.len() > 10 {
            return Err("dns_names must have 1-10 entries");
        }
        let ok = |d: &str| {
            !d.is_empty()
                && d.len() <= 253
                && d.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        };
        if !self.dns_names.iter().all(|d| ok(d)) {
            return Err("dns_names must be host names or IP addresses");
        }
        // 端點用 url 連線並以憑證 SAN 驗證主機：主機必須在 dns_names 裡
        let host = url_host(&self.url).ok_or("url must be https://<host>[:<port>]")?;
        if !self.dns_names.iter().any(|d| same_host(d, host)) {
            return Err("url host must be one of dns_names");
        }
        if self.csr_pem.len() > MAX_CSR || self.token.len() > 200 {
            return Err("request too large");
        }
        Ok(())
    }
}

/// `https://<主機>[:<埠>]` 的主機（IPv6 去掉方括號）；有路徑、查詢、帳號或格式不對時回 None
fn url_host(url: &str) -> Option<&str> {
    let auth = url.strip_prefix("https://")?;
    if auth.is_empty() || auth.contains(['/', '?', '#', '@']) || auth.contains(char::is_whitespace)
    {
        return None;
    }
    let (host, port) = match auth.strip_prefix('[') {
        Some(rest) => {
            let (h, after) = rest.split_once(']')?;
            (
                h,
                after.strip_prefix(':').or(after.is_empty().then_some(""))?,
            )
        }
        None => auth.split_once(':').unwrap_or((auth, "")),
    };
    let port_ok = port.is_empty() || port.parse::<u16>().is_ok_and(|p| p > 0);
    (!host.is_empty() && port_ok).then_some(host)
}

/// 主機名稱不分大小寫；IP 依位址比較（`fd00::1` 與 `fd00:0::1` 相同）
pub fn same_host(a: &str, b: &str) -> bool {
    match (a.parse::<std::net::IpAddr>(), b.parse::<std::net::IpAddr>()) {
        (Ok(x), Ok(y)) => x == y,
        _ => a.eq_ignore_ascii_case(b),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEnrollResponse {
    pub cache_id: i64,
    /// 輪詢核准結果用（核准前快取還沒有憑證）
    pub poll_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEnrollPoll {
    pub cache_id: i64,
    pub poll_secret: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheEnrollState {
    Pending,
    Approved,
    Rejected,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEnrollPollResponse {
    pub state: CacheEnrollState,
    #[serde(default)]
    pub certificate_chain_pem: Option<String>,
    #[serde(default)]
    pub root_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPackage {
    pub package_id: i64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheCheckin {
    pub version: String,
    pub disk_used_bytes: u64,
    #[serde(default)]
    pub stored: Vec<StoredPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePackage {
    pub id: i64,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheCheckinResponse {
    /// 應預先下載的套件（所有未停止派送用到的）
    pub packages: Vec<CachePackage>,
    #[serde(default)]
    pub bandwidth_limit_mbps: Option<u32>,
    pub disk_limit_gb: u32,
    #[serde(default)]
    pub renew_certificate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheAuthorize {
    /// 端點用戶端憑證的指紋（SHA-256 hex）
    pub device_cert_fingerprint: String,
    pub package_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheAuthorizeResponse {
    pub allowed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::{DeployResult, DeployStatus};

    fn enroll() -> CacheEnrollRequest {
        CacheEnrollRequest {
            token: "t".into(),
            name: "台北快取".into(),
            url: "https://cache-tp.corp:8443".into(),
            dns_names: vec!["cache-tp.corp".into(), "10.1.2.3".into()],
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----".into(),
        }
    }

    #[test]
    fn old_checkin_response_has_no_source() {
        let r: crate::CheckinResponse = serde_json::from_str(
            r#"{"next_checkin_seconds":60,"request_sections":[],
                "collection_intervals":{"hardware_secs":1,"software_secs":1,"patches_secs":1,
                "services_secs":1},"renew_certificate":false}"#,
        )
        .unwrap();
        assert!(r.package_source.is_none());
    }

    #[test]
    fn deploy_result_source() {
        let r: DeployResult = serde_json::from_str(
            r#"{"revision":1,"status":"succeeded","exit_code":0,"message":"","attempts":1}"#,
        )
        .unwrap();
        assert_eq!(r.source, None);
        let r = DeployResult {
            source: Some(DownloadSource::Cache),
            ..r
        };
        let back: DeployResult = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back.source, Some(DownloadSource::Cache));
        assert_eq!(back.status, DeployStatus::Succeeded);
        let s: DownloadSource = serde_json::from_str(r#""peer""#).unwrap();
        assert_eq!(s, DownloadSource::Unknown);
    }

    #[test]
    fn enroll_url_must_match_dns_names() {
        for ok in [
            "https://cache-tp.corp:8443",
            "https://CACHE-TP.corp",
            "https://10.1.2.3:8443",
        ] {
            let r = CacheEnrollRequest {
                url: ok.into(),
                ..enroll()
            };
            assert!(r.validate().is_ok(), "{ok}");
        }
        let v6 = CacheEnrollRequest {
            url: "https://[fd00::1]:8443".into(),
            dns_names: vec!["fd00::1".into()],
            ..enroll()
        };
        assert!(v6.validate().is_ok());
        for bad in [
            "https://other.corp:8443",
            "https://cache-tp.corp:8443/x",
            "https://cache-tp.corp?a=1",
            "https://user@cache-tp.corp",
            "https://cache-tp.corp:84 43",
            "https://cache-tp.corp:x",
            "https://",
        ] {
            let r = CacheEnrollRequest {
                url: bad.into(),
                ..enroll()
            };
            assert!(r.validate().is_err(), "{bad}");
        }
    }

    #[test]
    fn enroll_validation() {
        assert!(enroll().validate().is_ok());
        for bad in [
            CacheEnrollRequest {
                url: "http://cache-tp.corp".into(),
                ..enroll()
            },
            CacheEnrollRequest {
                dns_names: vec!["cache tp".into()],
                ..enroll()
            },
            CacheEnrollRequest {
                dns_names: (0..11).map(|i| format!("h{i}.corp")).collect(),
                ..enroll()
            },
            CacheEnrollRequest {
                dns_names: vec![],
                ..enroll()
            },
            CacheEnrollRequest {
                name: "a\tb".into(),
                ..enroll()
            },
            CacheEnrollRequest {
                csr_pem: "x".repeat(8193),
                ..enroll()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }
}
