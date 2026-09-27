//! 自行 accept TLS，把用戶端憑證指紋放進 request extension 後交給 axum。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// 連線層的防護：未帶憑證的連線也能進來（/v1/enroll），所以必須限制資源。
#[derive(Clone, Copy, Debug)]
pub struct ConnLimits {
    /// TLS 握手的最長時間
    pub handshake: Duration,
    /// 等待 HTTP 標頭的最長時間（防 slowloris）
    pub header_read: Duration,
    /// 單一連線的最長存活時間，Agent 到期後重新連線即可
    pub max_lifetime: Duration,
    /// 同時連線數上限；滿了就暫停 accept（背壓）
    pub max_conns: usize,
}

impl Default for ConnLimits {
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(10),
            max_lifetime: Duration::from_secs(120),
            max_conns: 10_000,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerCert {
    pub fingerprint: String,
}

/// 用戶端憑證「可選」：/v1/enroll 不需要憑證，其他端點由 AuthedDevice 強制要求。
pub fn server_config(ca_dir: &Path) -> anyhow::Result<Arc<ServerConfig>> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from_pem_file(ca_dir.join("root.pem"))?)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()?;
    let certs =
        CertificateDer::pem_file_iter(ca_dir.join("server.pem"))?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(ca_dir.join("server.key"))?;
    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub async fn serve_mtls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
    limits: ConnLimits,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let slots = Arc::new(Semaphore::new(limits.max_conns));
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (tcp, remote): (_, SocketAddr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                // EMFILE、ECONNABORTED 等暫時性錯誤不應讓整個服務結束
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(limits.handshake, acceptor.accept(tcp)).await {
                Ok(Ok(s)) => s,
                _ => return,
            };
            let peer = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| PeerCert {
                    fingerprint: crate::ca::fingerprint(c),
                });
            let svc = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
                req.extensions_mut().insert(ConnectInfo(remote));
                if let Some(p) = &peer {
                    req.extensions_mut().insert(p.clone());
                }
                app.clone().oneshot(req)
            });
            // 只用 HTTP/1.1：Agent 請求量小，且 auto 版本偵測會無限期等待第一個位元組
            let conn = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(limits.header_read)
                .serve_connection(TokioIo::new(tls), svc);
            let _ = tokio::time::timeout(limits.max_lifetime, conn).await;
        });
    }
}
