//! Endpoint Manager 伺服器。

pub mod accounts;
pub mod audit;
pub mod ca;
pub mod checkin;
pub mod compliance;
pub mod config;
pub mod db;
pub mod devices;
pub mod diff;
pub mod enroll;
pub mod error;
pub mod groups;
pub mod heartbeat;
pub mod identity;
pub mod installer;
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
/// 管理網頁登入：每個 IP 每分鐘最多嘗試次數
pub const LOGIN_PER_IP_PER_MINUTE: u32 = 30;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub ca: Arc<ca::Ca>,
    pub heartbeat: Arc<heartbeat::HeartbeatBuffer>,
    pub enroll_limiter: Arc<ratelimit::RateLimiter>,
    pub login_limiter: Arc<ratelimit::RateLimiter>,
    /// 管理網頁顯示時間用的時區
    pub display_offset: chrono::FixedOffset,
    /// 通用範本 MSI；None 表示不提供下載安裝檔
    pub agent_msi: Option<std::path::PathBuf>,
    pub agent_public_url: String,
    /// 伺服器憑證的名稱（下載安裝檔時檢查網址）
    pub server_names: Arc<Vec<String>>,
    /// 合規規則快取
    pub rules: Arc<compliance::RuleCache>,
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
            login_limiter: Arc::new(ratelimit::RateLimiter::new(
                LOGIN_PER_IP_PER_MINUTE,
                Duration::from_secs(60),
            )),
            display_offset: chrono::FixedOffset::east_opt(8 * 3600).expect("valid offset"),
            agent_msi: None,
            agent_public_url: String::new(),
            server_names: Arc::new(vec![]),
            rules: Arc::new(compliance::RuleCache::new()),
        }
    }

    pub fn with_installer(
        mut self,
        msi: Option<std::path::PathBuf>,
        public_url: String,
        server_names: Vec<String>,
    ) -> Self {
        self.agent_msi = msi;
        self.agent_public_url = public_url;
        self.server_names = Arc::new(server_names);
        self
    }

    pub fn with_enroll_limit(mut self, per_minute: u32) -> Self {
        self.enroll_limiter = Arc::new(ratelimit::RateLimiter::new(
            per_minute,
            Duration::from_secs(60),
        ));
        self
    }

    pub fn with_display_offset(mut self, hours: i32) -> Self {
        if let Some(o) = chrono::FixedOffset::east_opt(hours * 3600) {
            self.display_offset = o;
        }
        self
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

    let server_names = ca::server_names(&cfg.ca_dir)?;
    let public_url = if cfg.agent_public_url.is_empty() {
        installer::default_public_url(&server_names, cfg.agent_listen.port())
    } else {
        cfg.agent_public_url.clone()
    };
    let state = AppState::new(pool.clone(), ca::Ca::load(&cfg.ca_dir)?)
        .with_display_offset(cfg.display_utc_offset)
        .with_enroll_limit(cfg.enroll_per_ip_per_minute)
        .with_installer(cfg.agent_msi.clone(), public_url, server_names);
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
    let web_listener = tokio::net::TcpListener::bind(cfg.web_listen).await?;
    tracing::info!(addr = %cfg.web_listen, "admin web listening");
    let web_tls = tls::web_server_config(&cfg.ca_dir)?;
    tokio::select! {
        r = tls::serve_mtls(listener, tls_cfg, agent_router(state.clone()), tls::ConnLimits::default()) => r?,
        r = tls::serve_mtls(web_listener, web_tls, web::web_router(state.clone()), tls::ConnLimits::default()) => r?,
        _ = shutdown_signal() => tracing::info!("shutting down"),
    }
    // compose 的 stop_grace_period 為 30 秒，保留餘裕
    state
        .heartbeat
        .flush_before_exit(&pool, Duration::from_secs(20))
        .await;
    Ok(())
}

/// Ctrl+C 或（Unix）SIGTERM：docker stop 送的是 SIGTERM。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::error!(error = %e, "cannot install SIGTERM handler"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
