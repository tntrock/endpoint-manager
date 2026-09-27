//! 自行 accept TLS，把用戶端憑證指紋放進 request extension 後交給 axum。

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::RootCertStore;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

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
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub async fn serve_mtls(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    app: Router,
) -> anyhow::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    loop {
        let (tcp, remote): (_, SocketAddr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let tls =
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
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
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(tls), svc)
                .await;
        });
    }
}
