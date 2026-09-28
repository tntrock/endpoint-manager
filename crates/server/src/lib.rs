//! Endpoint Manager 伺服器。

pub mod accounts;
pub mod audit;
pub mod ca;
pub mod checkin;
pub mod config;
pub mod db;
pub mod devices;
pub mod diff;
pub mod enroll;
pub mod error;
pub mod groups;
pub mod heartbeat;
pub mod identity;
pub mod inventory;
pub mod partitions;
pub mod ratelimit;
pub mod renew;
pub mod tls;
pub mod tokens;
pub mod web;

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
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
        .route("/v1/enroll", post(enroll::enroll))
        .route("/v1/checkin", post(checkin::checkin))
        .route("/v1/inventory/{section}", put(inventory::upload))
        .route("/v1/renew", post(renew::renew))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

pub async fn serve(cfg: config::Config) -> anyhow::Result<()> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(32)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await?;
    db::migrate(&pool).await?;
    partitions::maintain_partitions(&pool, chrono::Utc::now()).await?;

    let state = AppState::new(pool.clone(), ca::Ca::load(&cfg.ca_dir)?);
    let tls_cfg = tls::server_config(&cfg.ca_dir)?;

    let hb = state.heartbeat.clone();
    let hb_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(heartbeat::FLUSH_INTERVAL_SECS));
        loop {
            tick.tick().await;
            if let Err(e) = hb.flush(&hb_pool).await {
                tracing::error!(error = %e, "heartbeat flush failed");
            }
        }
    });
    let part_pool = pool.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(24 * 3600));
        loop {
            tick.tick().await;
            if let Err(e) = partitions::maintain_partitions(&part_pool, chrono::Utc::now()).await {
                tracing::error!(error = %e, "partition maintenance failed");
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(cfg.agent_listen).await?;
    tracing::info!(addr = %cfg.agent_listen, "agent API listening");
    tokio::select! {
        r = tls::serve_mtls(listener, tls_cfg, agent_router(state.clone()), tls::ConnLimits::default()) => r?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutting down"),
    }
    state.heartbeat.flush(&pool).await?;
    Ok(())
}
