//! 與伺服器通訊：只信任 root.pem、HTTP/1.1、上傳一律 gzip。

use std::io::Write;
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use protocol::{
    CheckinRequest, CheckinResponse, EnrollRequest, EnrollResponse, InventoryUpload, RenewRequest,
    RenewResponse,
};
use reqwest::{StatusCode, header};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// 伺服器給的 Retry-After 夾在這個範圍：0 會讓 Agent 空轉，極大值會讓它失聯。
pub const RETRY_AFTER_MIN: Duration = Duration::from_secs(10);
pub const RETRY_AFTER_MAX: Duration = Duration::from_secs(30 * 60);

pub fn retry_after(secs: u64) -> Duration {
    Duration::from_secs(secs).clamp(RETRY_AFTER_MIN, RETRY_AFTER_MAX)
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("server busy or unreachable")]
    Retry(Option<Duration>),
    #[error("unauthorized")]
    Unauthorized,
    #[error("rejected by server ({0}): {1}")]
    Rejected(u16, String),
}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        // 保留完整原因（TLS 驗證失敗、連線被拒…），服務模式只記錄 INFO 以上
        tracing::warn!(error = ?e, "request failed");
        ClientError::Retry(None)
    }
}

pub struct ServerClient {
    http: reqwest::Client,
    base: String,
}

impl ServerClient {
    pub fn new(base: &str, root_pem: &str, identity_pem: Option<String>) -> anyhow::Result<Self> {
        let mut b = reqwest::Client::builder()
            .tls_certs_only([reqwest::Certificate::from_pem(root_pem.as_bytes())?])
            .http1_only()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("endpoint-agent/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = identity_pem {
            b = b.identity(reqwest::Identity::from_pem(pem.as_bytes())?);
        }
        Ok(Self {
            http: b.build()?,
            base: base.trim_end_matches('/').to_string(),
        })
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response, ClientError> {
        let resp = rb.send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let retry_after = resp
            .headers()
            .get(header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(retry_after);
        Err(match status {
            StatusCode::UNAUTHORIZED => ClientError::Unauthorized,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                ClientError::Retry(retry_after)
            }
            s if s.is_client_error() => {
                ClientError::Rejected(s.as_u16(), resp.text().await.unwrap_or_default())
            }
            _ => ClientError::Retry(retry_after),
        })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub async fn enroll(&self, req: &EnrollRequest) -> Result<EnrollResponse, ClientError> {
        Ok(self
            .send(self.http.post(self.url("/v1/enroll")).json(req))
            .await?
            .json()
            .await?)
    }

    pub async fn checkin(&self, req: &CheckinRequest) -> Result<CheckinResponse, ClientError> {
        Ok(self
            .send(self.http.post(self.url("/v1/checkin")).json(req))
            .await?
            .json()
            .await?)
    }

    pub async fn renew(&self, req: &RenewRequest) -> Result<RenewResponse, ClientError> {
        Ok(self
            .send(self.http.post(self.url("/v1/renew")).json(req))
            .await?
            .json()
            .await?)
    }

    pub async fn upload(&self, up: &InventoryUpload) -> Result<(), ClientError> {
        let json = serde_json::to_vec(up).expect("upload serializes");
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(&json).expect("write to Vec");
        let body = gz.finish().expect("gzip to Vec");
        let url = self.url(&format!("/v1/inventory/{}", up.payload.section().as_str()));
        self.send(
            self.http
                .put(url)
                .header(header::CONTENT_ENCODING, "gzip")
                .header(header::CONTENT_TYPE, "application/json")
                .body(body),
        )
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_clamped() {
        assert_eq!(retry_after(0), RETRY_AFTER_MIN);
        assert_eq!(retry_after(120), Duration::from_secs(120));
        assert_eq!(retry_after(u64::MAX), RETRY_AFTER_MAX);
    }
}
