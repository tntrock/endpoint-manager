//! Endpoint Manager 伺服器。

pub mod ca;
pub mod db;
pub mod error;
pub mod heartbeat;
pub mod identity;
pub mod partitions;
pub mod ratelimit;
pub mod tls;
pub mod tokens;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::get;
use sqlx::PgPool;

pub const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;
pub const ENROLL_PER_IP_PER_MINUTE: u32 = 60;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub ca: Arc<ca::Ca>,
    pub heartbeat: Arc<heartbeat::HeartbeatBuffer>,
    pub enroll_limiter: Arc<ratelimit::RateLimiter>,
}

impl AppState {
    pub fn new(pool: PgPool, ca: ca::Ca) -> Self {
        Self {
            pool,
            ca: Arc::new(ca),
            heartbeat: Arc::new(heartbeat::HeartbeatBuffer::new()),
            enroll_limiter: Arc::new(ratelimit::RateLimiter::new(
                ENROLL_PER_IP_PER_MINUTE,
                Duration::from_secs(60),
            )),
        }
    }
}

async fn healthz(State(st): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&st.pool).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

pub fn agent_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}
