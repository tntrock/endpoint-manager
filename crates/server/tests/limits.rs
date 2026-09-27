mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestServer;
use endpoint_server::tls::ConnLimits;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use sqlx::PgPool;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// 完成 TLS 握手後什麼都不送（slowloris），伺服器必須主動斷線。
#[sqlx::test(migrations = false)]
async fn idle_unauthenticated_connection_is_closed(pool: PgPool) {
    let limits = ConnLimits {
        header_read: Duration::from_secs(1),
        ..ConnLimits::default()
    };
    let s = TestServer::start_with(pool, limits).await;

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(s.root_pem.as_bytes()).unwrap())
        .unwrap();
    let cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(s.addr).await.unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();

    let mut buf = [0u8; 64];
    let r = tokio::time::timeout(Duration::from_secs(5), tls.read(&mut buf)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "server should close the idle connection, got {r:?}"
    );
}
