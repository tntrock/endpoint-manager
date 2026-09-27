mod common;

use common::TestServer;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn healthz_ok_without_client_cert(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let r = s.client(None).get(s.url("/healthz")).send().await.unwrap();
    assert_eq!(r.status(), 200);
}
