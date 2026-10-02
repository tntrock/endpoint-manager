//! 對端點的 mTLS 伺服器：`GET /v1/packages/{id}/content`（路徑與中央相同，Agent 只換網址）。

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use protocol::branch::CacheAuthorize;
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::auth::AuthCache;
use crate::central::Central;
use crate::fetch::{Catalog, FetchError, Fetcher};
use crate::identity::Identity;
use crate::store::Store;

const CHUNK: usize = 64 * 1024;
const HANDSHAKE: Duration = Duration::from_secs(10);
const HEADER_READ: Duration = Duration::from_secs(10);
/// 按需下載時，端點請求最多等多久（低於 Agent 的 DOWNLOAD_IDLE 2 分鐘）
const ENSURE_WAIT: Duration = Duration::from_secs(90);
/// 單一連線最長存活時間：大檔案在慢速線路上要夠長
const MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

/// 清單過時時立即報到一次；回傳清單是否為最新（報到成功）
pub type Refresh = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;

#[derive(Clone)]
pub struct CacheState {
    pub central: Arc<Central>,
    pub fetcher: Arc<Fetcher>,
    pub store: Arc<Store>,
    pub catalog: Arc<Catalog>,
    pub auth: Arc<AuthCache>,
    /// 同時下載上限
    pub downloads: Arc<Semaphore>,
    pub refresh: Refresh,
}

/// 端點用戶端憑證（第一張）的 SHA-256 指紋，與中央 device_certs 相同
#[derive(Clone, Debug)]
pub struct PeerCert {
    pub fingerprint: String,
}

/// 可熱更新的伺服器憑證：換發後呼叫 set，新連線就用新憑證
#[derive(Debug)]
pub struct CertSlot {
    current: RwLock<Arc<CertifiedKey>>,
}

fn certified_key(id: &Identity) -> anyhow::Result<Arc<CertifiedKey>> {
    let certs =
        CertificateDer::pem_slice_iter(id.chain_pem.as_bytes()).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(!certs.is_empty(), "empty certificate chain");
    let key = PrivateKeyDer::from_pem_slice(id.key_pem.as_bytes())?;
    let signer = rustls::crypto::ring::sign::any_supported_type(&key)?;
    Ok(Arc::new(CertifiedKey::new(certs, signer)))
}

impl CertSlot {
    pub fn new(id: &Identity) -> anyhow::Result<Arc<CertSlot>> {
        Ok(Arc::new(CertSlot {
            current: RwLock::new(certified_key(id)?),
        }))
    }

    pub fn set(&self, id: &Identity) -> anyhow::Result<()> {
        let k = certified_key(id)?;
        *self.current.write().expect("cert lock") = k;
        Ok(())
    }
}

impl ResolvesServerCert for CertSlot {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current.read().expect("cert lock").clone())
    }
}

/// 一定要帶用戶端憑證，信任錨是中央的 root.pem
pub fn tls_config(root_pem: &str, slot: Arc<CertSlot>) -> anyhow::Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
        roots.add(c?)?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(slot);
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub fn router(st: CacheState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/packages/{id}/content", get(content))
        .with_state(st)
}

fn busy() -> Response {
    let mut r = StatusCode::SERVICE_UNAVAILABLE.into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

async fn content(
    State(st): State<CacheState>,
    peer: Option<axum::Extension<PeerCert>>,
    Path(id): Path<i64>,
) -> Response {
    let Some(axum::Extension(peer)) = peer else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // 清單可能比中央舊（剛派送、快取還沒報到）：找不到時先刷新一次
    let pkg = match st.catalog.get(id) {
        Some(p) => p,
        None => {
            // 刷新失敗（中央連不上）時不能回 404：Agent 會當成不再指派
            if !(st.refresh)().await {
                return busy();
            }
            match st.catalog.get(id) {
                Some(p) => p,
                None => return StatusCode::NOT_FOUND.into_response(),
            }
        }
    };
    let allowed = match st.auth.get(&peer.fingerprint, id) {
        Some(a) => a,
        None => match st
            .central
            .authorize(&CacheAuthorize {
                device_cert_fingerprint: peer.fingerprint.clone(),
                package_id: id,
            })
            .await
        {
            Ok(a) => {
                st.auth.put(&peer.fingerprint, id, a);
                a
            }
            Err(e) => {
                tracing::warn!(error = %e, "authorize failed");
                return busy();
            }
        },
    };
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    // 先標記使用中再確保檔案在本機：清除工作不會在兩者之間把檔案刪掉
    let in_use = st.store.use_file(&pkg.sha256);
    // 等待上限低於 Agent 的閒置逾時（2 分鐘）：還沒下載完就回 503，Agent 稍後重試快取
    let path = match st.fetcher.ensure(&pkg, None, Some(ENSURE_WAIT)).await {
        Ok(p) => p,
        Err(FetchError::Mismatch) => return StatusCode::BAD_GATEWAY.into_response(),
        Err(FetchError::NotListed) => return StatusCode::NOT_FOUND.into_response(),
        Err(FetchError::Unavailable | FetchError::Disk) => return busy(),
    };
    // 檔案備妥才佔用下載數：等待中央的請求不會擋住本機已有的檔案。許可跟著串流歸還
    let Ok(permit) = st.downloads.clone().try_acquire_owned() else {
        return busy();
    };
    st.store.touch(&pkg.sha256);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "opening package failed");
            return busy();
        }
    };
    let stream = futures_util::stream::unfold(Some((file, permit, in_use)), |state| async move {
        let (mut file, permit, in_use) = state?;
        let mut buf = vec![0u8; CHUNK];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((
                    Ok::<_, std::io::Error>(Bytes::from(buf)),
                    Some((file, permit, in_use)),
                ))
            }
            Err(e) => Some((Err(e), None)),
        }
    });
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, pkg.size.to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response()
}

/// accept 迴圈（比照中央 tls::serve_mtls）：握手與標頭逾時、單連線存活上限、同時連線上限
pub async fn serve(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    max_conns: usize,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let slots = Arc::new(Semaphore::new(max_conns));
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (tcp, _remote): (_, SocketAddr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(HANDSHAKE, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| PeerCert {
                    fingerprint: hex::encode(Sha256::digest(c)),
                });
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                if let Some(p) = &peer {
                    req.extensions_mut().insert(p.clone());
                }
                app.clone().oneshot(req)
            });
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ)
                .serve_connection(TokioIo::new(tls), svc);
            let _ = tokio::time::timeout(MAX_LIFETIME, conn).await;
        });
    }
}
