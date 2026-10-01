//! 與伺服器通訊：只信任 root.pem、HTTP/1.1、上傳一律 gzip。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use protocol::deploy::{DeployResult, PackageSpec};
use protocol::{
    CheckinRequest, CheckinResponse, EnrollRequest, EnrollResponse, InventoryUpload, RenewRequest,
    RenewResponse,
};
use reqwest::{StatusCode, header};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// 下載套件時兩次收到資料之間最長可以閒置多久（大檔案在慢速線路上總時間可以很長）
pub const DOWNLOAD_IDLE: Duration = Duration::from_secs(2 * 60);
/// 下載的總時間上限（只為了不讓連線永遠掛著）
pub const DOWNLOAD_MAX: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("server busy or unreachable")]
    Retry(Option<Duration>),
    #[error("unauthorized")]
    Unauthorized,
    #[error("伺服器上找不到套件檔案（或這台已不在派送範圍內）")]
    NotFound,
    #[error("下載的檔案大小或 SHA-256 與伺服器提供的不符")]
    Mismatch,
    #[error("寫入套件檔案失敗：{0}")]
    Io(#[from] std::io::Error),
}

/// 下載中的暫存檔：中途失敗或不符時刪除
struct Partial {
    path: PathBuf,
    keep: bool,
}

impl Drop for Partial {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn retry_after_of(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .map(retry_after)
}

/// 伺服器給的 Retry-After 夾在這個範圍：0 會讓 Agent 空轉，極大值會讓它失聯。
pub const RETRY_AFTER_MIN: Duration = Duration::from_secs(10);
pub const RETRY_AFTER_MAX: Duration = Duration::from_secs(30 * 60);

/// 伺服器拒絕的是這份內容本身（格式、大小、驗證）：同一份內容不再重送。
/// 其他錯誤碼都當成暫時問題，之後再試。
pub fn is_payload_rejection(code: u16) -> bool {
    matches!(code, 400 | 413 | 415 | 422)
}

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
        let retry_after = retry_after_of(&resp);
        Err(match status {
            StatusCode::UNAUTHORIZED => ClientError::Unauthorized,
            StatusCode::TOO_MANY_REQUESTS | StatusCode::SERVICE_UNAVAILABLE => {
                ClientError::Retry(retry_after)
            }
            s if is_payload_rejection(s.as_u16()) => {
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

    /// 下載套件到 dest：邊寫邊算雜湊，大小或 SHA-256 不符時刪檔並回 Mismatch。
    pub async fn download(&self, pkg: &PackageSpec, dest: &Path) -> Result<(), DownloadError> {
        let part = Partial {
            path: dest.with_extension("part"),
            keep: false,
        };
        let mut f = tokio::fs::File::create(&part.path).await?;
        self.fetch(pkg, Some(&mut f)).await?;
        f.flush().await?;
        drop(f);
        tokio::fs::rename(&part.path, dest).await?;
        Ok(())
    }

    /// 只下載並驗證大小與 SHA-256，不寫檔（負載測試用）
    pub async fn verify_package(&self, pkg: &PackageSpec) -> Result<(), DownloadError> {
        self.fetch(pkg, None).await
    }

    /// 串流下載並驗證；有 sink 時同時寫入
    async fn fetch(
        &self,
        pkg: &PackageSpec,
        mut sink: Option<&mut tokio::fs::File>,
    ) -> Result<(), DownloadError> {
        let url = self.url(&format!("/v1/packages/{}/content", pkg.id));
        let send = self.http.get(url).timeout(DOWNLOAD_MAX).send();
        let mut resp = match tokio::time::timeout(DOWNLOAD_IDLE, send).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(error = ?e, "package download failed");
                return Err(DownloadError::Retry(None));
            }
            Err(_) => {
                tracing::warn!("package download: no response");
                return Err(DownloadError::Retry(None));
            }
        };
        match resp.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(DownloadError::NotFound),
            StatusCode::UNAUTHORIZED => return Err(DownloadError::Unauthorized),
            _ => return Err(DownloadError::Retry(retry_after_of(&resp))),
        }
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        loop {
            let chunk = match tokio::time::timeout(DOWNLOAD_IDLE, resp.chunk()).await {
                Ok(Ok(Some(c))) => c,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    tracing::warn!(error = ?e, "package download interrupted");
                    return Err(DownloadError::Retry(None));
                }
                Err(_) => {
                    tracing::warn!("package download stalled");
                    return Err(DownloadError::Retry(None));
                }
            };
            size += chunk.len() as u64;
            if size > pkg.size {
                return Err(DownloadError::Mismatch);
            }
            hasher.update(&chunk);
            if let Some(f) = sink.as_deref_mut() {
                f.write_all(&chunk).await?;
            }
        }
        if size != pkg.size || !hex::encode(hasher.finalize()).eq_ignore_ascii_case(&pkg.sha256) {
            return Err(DownloadError::Mismatch);
        }
        Ok(())
    }

    pub async fn report(&self, deployment_id: i64, r: &DeployResult) -> Result<(), ClientError> {
        let url = self.url(&format!("/v1/deployments/{deployment_id}/result"));
        self.send(self.http.post(url).json(r)).await?;
        Ok(())
    }

    pub async fn update_status(
        &self,
        s: &protocol::update::UpdateStatus,
    ) -> Result<(), ClientError> {
        self.send(self.http.put(self.url("/v1/update-status")).json(s))
            .await?;
        Ok(())
    }

    /// 回報指令結果；404（伺服器已沒有這筆）也算完成
    pub async fn command_result(
        &self,
        id: i64,
        r: &protocol::command::CommandResult,
    ) -> Result<(), ClientError> {
        let resp = self
            .http
            .post(self.url(&format!("/v1/commands/{id}/result")))
            .json(r)
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(match status {
            StatusCode::UNAUTHORIZED => ClientError::Unauthorized,
            s if is_payload_rejection(s.as_u16()) => {
                ClientError::Rejected(s.as_u16(), resp.text().await.unwrap_or_default())
            }
            _ => ClientError::Retry(retry_after_of(&resp)),
        })
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

    /// 只有「內容本身有問題」的 4xx 才記為被拒（同一份內容不再重送）；
    /// 其他 4xx（404、409、403…）多半是伺服器暫時狀態或版本差異，之後再試。
    #[test]
    fn only_payload_errors_are_permanent_rejections() {
        for code in [400, 413, 415, 422] {
            assert!(is_payload_rejection(code), "{code}");
        }
        for code in [403, 404, 405, 408, 409, 410] {
            assert!(!is_payload_rejection(code), "{code}");
        }
    }

    #[test]
    fn retry_after_is_clamped() {
        assert_eq!(retry_after(0), RETRY_AFTER_MIN);
        assert_eq!(retry_after(120), Duration::from_secs(120));
        assert_eq!(retry_after(u64::MAX), RETRY_AFTER_MAX);
    }
}
