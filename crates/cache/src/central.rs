//! 與中央通訊：只信任 root.pem、HTTP/1.1；用快取憑證做 mTLS（註冊與輪詢時還沒有）。

use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use protocol::branch::{
    CacheAuthorize, CacheAuthorizeResponse, CacheCheckin, CacheCheckinResponse, CacheEnrollPoll,
    CacheEnrollPollResponse, CacheEnrollRequest, CacheEnrollResponse, CachePackage,
};
use protocol::{RenewRequest, RenewResponse};
use reqwest::{StatusCode, header};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::identity::Identity;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// 下載時兩次收到資料之間最長可以閒置多久
pub const DOWNLOAD_IDLE: Duration = Duration::from_secs(2 * 60);
/// 下載的總時間上限（只為了不讓連線永遠掛著）
pub const DOWNLOAD_MAX: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
pub enum CentralError {
    #[error("central unreachable or busy")]
    Unavailable(Option<Duration>),
    #[error("unauthorized")]
    Unauthorized,
    #[error("not found")]
    NotFound,
    #[error("rejected ({0}): {1}")]
    Rejected(u16, String),
    #[error("downloaded file does not match sha256/size")]
    Mismatch,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<reqwest::Error> for CentralError {
    fn from(e: reqwest::Error) -> Self {
        tracing::warn!(error = ?e, "request to central failed");
        CentralError::Unavailable(None)
    }
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
        .map(Duration::from_secs)
}

/// 限速：已傳 bytes、經過 elapsed，以 limit_mbps 計算還要等多久
pub fn pace(bytes: u64, elapsed: Duration, limit_mbps: u32) -> Duration {
    let bits_per_sec = u64::from(limit_mbps.max(1)) * 1_000_000;
    let expected = Duration::from_secs_f64(bytes as f64 * 8.0 / bits_per_sec as f64);
    expected.saturating_sub(elapsed)
}

pub struct Central {
    base: String,
    root_pem: String,
    http: RwLock<reqwest::Client>,
    downloads: AtomicU64,
}

fn build_client(root_pem: &str, identity: Option<&Identity>) -> anyhow::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(root_pem.as_bytes())?])
        .http1_only()
        .user_agent(concat!("endpoint-cache/", env!("CARGO_PKG_VERSION")));
    if let Some(id) = identity {
        let pem = format!("{}{}", id.chain_pem, id.key_pem);
        b = b.identity(reqwest::Identity::from_pem(pem.as_bytes())?);
    }
    Ok(b.build()?)
}

impl Central {
    pub fn new(base: &str, root_pem: &str, identity: Option<&Identity>) -> anyhow::Result<Central> {
        Ok(Central {
            base: base.trim_end_matches('/').to_string(),
            root_pem: root_pem.to_string(),
            http: RwLock::new(build_client(root_pem, identity)?),
            downloads: AtomicU64::new(0),
        })
    }

    /// 換發或重新啟用後換上新的用戶端憑證
    pub fn set_identity(&self, id: &Identity) -> anyhow::Result<()> {
        let c = build_client(&self.root_pem, Some(id))?;
        *self.http.write().expect("client lock") = c;
        Ok(())
    }

    fn http(&self) -> reqwest::Client {
        self.http.read().expect("client lock").clone()
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<reqwest::Response, CentralError> {
        let resp = rb.timeout(REQUEST_TIMEOUT).send().await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        Err(match status {
            StatusCode::UNAUTHORIZED => CentralError::Unauthorized,
            StatusCode::NOT_FOUND => CentralError::NotFound,
            s if matches!(s.as_u16(), 400 | 409 | 413 | 422) => {
                CentralError::Rejected(s.as_u16(), resp.text().await.unwrap_or_default())
            }
            _ => CentralError::Unavailable(retry_after_of(&resp)),
        })
    }

    async fn post<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, CentralError> {
        Ok(self
            .send(self.http().post(self.url(path)).json(body))
            .await?
            .json()
            .await?)
    }

    pub async fn enroll(
        &self,
        r: &CacheEnrollRequest,
    ) -> Result<CacheEnrollResponse, CentralError> {
        self.post("/v1/cache/enroll", r).await
    }

    pub async fn poll(&self, r: &CacheEnrollPoll) -> Result<CacheEnrollPollResponse, CentralError> {
        self.post("/v1/cache/enroll/poll", r).await
    }

    pub async fn checkin(&self, r: &CacheCheckin) -> Result<CacheCheckinResponse, CentralError> {
        self.post("/v1/cache/checkin", r).await
    }

    pub async fn renew(&self, csr_pem: &str) -> Result<String, CentralError> {
        let r: RenewResponse = self
            .post(
                "/v1/cache/renew",
                &RenewRequest {
                    csr_pem: csr_pem.to_string(),
                },
            )
            .await?;
        Ok(r.certificate_chain_pem)
    }

    pub async fn authorize(&self, r: &CacheAuthorize) -> Result<bool, CentralError> {
        let a: CacheAuthorizeResponse = self.post("/v1/cache/authorize", r).await?;
        Ok(a.allowed)
    }

    /// 實際開始的下載次數（測試與記錄用）
    pub fn downloads_started(&self) -> u64 {
        self.downloads.load(Ordering::Relaxed)
    }

    /// 下載到 dest：先寫 `<dest>.part`，大小與 SHA-256 都符合才改名
    pub async fn download(
        &self,
        p: &CachePackage,
        dest: &Path,
        limit_mbps: Option<u32>,
    ) -> Result<(), CentralError> {
        let mut part_path = dest.as_os_str().to_owned();
        part_path.push(".part");
        let mut part = Partial {
            path: PathBuf::from(part_path),
            keep: false,
        };
        self.downloads.fetch_add(1, Ordering::Relaxed);
        let url = self.url(&format!("/v1/cache/packages/{}/content", p.id));
        let send = self.http().get(url).timeout(DOWNLOAD_MAX).send();
        let resp = match tokio::time::timeout(DOWNLOAD_IDLE, send).await {
            Ok(r) => r?,
            Err(_) => return Err(CentralError::Unavailable(None)),
        };
        let mut resp = match resp.status() {
            StatusCode::OK => resp,
            StatusCode::UNAUTHORIZED => return Err(CentralError::Unauthorized),
            StatusCode::NOT_FOUND => return Err(CentralError::NotFound),
            _ => return Err(CentralError::Unavailable(retry_after_of(&resp))),
        };
        let mut f = tokio::fs::File::create(&part.path).await?;
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        let started = Instant::now();
        loop {
            let chunk = match tokio::time::timeout(DOWNLOAD_IDLE, resp.chunk()).await {
                Ok(Ok(Some(c))) => c,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    tracing::warn!(error = ?e, package_id = p.id, "download interrupted");
                    return Err(CentralError::Unavailable(None));
                }
                Err(_) => {
                    tracing::warn!(package_id = p.id, "download stalled");
                    return Err(CentralError::Unavailable(None));
                }
            };
            size += chunk.len() as u64;
            if size > p.size {
                return Err(CentralError::Mismatch);
            }
            hasher.update(&chunk);
            f.write_all(&chunk).await?;
            if let Some(limit) = limit_mbps {
                tokio::time::sleep(pace(size, started.elapsed(), limit)).await;
            }
        }
        f.flush().await?;
        f.sync_all().await?;
        drop(f);
        if size != p.size || !hex::encode(hasher.finalize()).eq_ignore_ascii_case(&p.sha256) {
            tracing::error!(
                package_id = p.id,
                "package from central does not match its sha256/size"
            );
            return Err(CentralError::Mismatch);
        }
        tokio::fs::rename(&part.path, dest).await?;
        part.keep = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacing() {
        // 10 Mbps = 1.25 MB/s
        assert_eq!(pace(1_250_000, Duration::ZERO, 10), Duration::from_secs(1));
        assert_eq!(pace(1_250_000, Duration::from_secs(2), 10), Duration::ZERO);
        assert_eq!(pace(0, Duration::ZERO, 1), Duration::ZERO);
        assert_eq!(
            pace(1_250_000, Duration::from_millis(400), 10),
            Duration::from_millis(600)
        );
    }
}
