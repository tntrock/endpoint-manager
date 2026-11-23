//! Endpoint Manager 伺服器。

pub mod accounts;
pub mod audit;
pub mod branch;
pub mod ca;
pub mod checkin;
pub mod commands;
pub mod compliance;
pub mod config;
pub mod db;
pub mod deploy;
pub mod devices;
pub mod diff;
pub mod enroll;
pub mod error;
pub mod events;
pub mod gencache;
pub mod groups;
pub mod heartbeat;
pub mod identity;
pub mod installer;
pub mod inventory;
pub mod metrics;
pub mod mfa;
pub mod netdev;
pub mod network;
pub mod notify;
pub mod oidc;
pub mod partitions;
pub mod ratelimit;
pub mod renew;
pub mod retention;
pub mod secret;
pub mod signing;
pub mod stats;
pub mod tls;
pub mod tokens;
pub mod totp;
pub mod updates;
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
/// 同時下載套件的預設上限（`EM_DOWNLOAD_CONCURRENCY`）
pub const DOWNLOAD_CONCURRENCY: usize = 50;
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
    pub display_offset: time::UtcOffset,
    /// 通用範本 MSI；None 表示不提供下載安裝檔
    pub agent_msi: Option<std::path::PathBuf>,
    /// Linux agent 安裝包（原樣提供下載）；None 表示不提供
    pub agent_deb: Option<std::path::PathBuf>,
    pub agent_rpm: Option<std::path::PathBuf>,
    pub agent_public_url: String,
    /// 伺服器憑證的名稱（下載安裝檔時檢查網址）
    pub server_names: Arc<Vec<String>>,
    /// 合規規則快取
    pub rules: Arc<compliance::RuleCache>,
    /// 通知用的機密與網址
    pub notify: Arc<notify::NotifySecrets>,
    /// 派送指派快取
    pub deploy: Arc<deploy::assign::DeployCache>,
    /// 套件檔案目錄
    pub package_dir: std::path::PathBuf,
    /// 同時下載套件的上限
    pub downloads: Arc<tokio::sync::Semaphore>,
    /// 更新原則快取
    pub updates: Arc<updates::assign::UpdatePolicyCache>,
    /// 據點與快取（報到時下發 package_source）
    pub branch: Arc<branch::assign::BranchCache>,
    /// 監控指標（`/metrics`）
    pub metrics: Arc<metrics::Metrics>,
    /// 管理網頁單一登入；None 表示關閉
    pub oidc: Option<Arc<oidc::Provider>>,
    /// 資料庫機密的加密金鑰；None 表示沒設定 `EM_SECRET_KEY_FILE`
    pub secrets: Option<Arc<secret::SecretBox>>,
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
            display_offset: time::UtcOffset::from_whole_seconds(8 * 3600).expect("valid offset"),
            agent_msi: None,
            agent_deb: None,
            agent_rpm: None,
            agent_public_url: String::new(),
            server_names: Arc::new(vec![]),
            rules: Arc::new(compliance::RuleCache::default()),
            notify: Arc::new(notify::NotifySecrets::default()),
            deploy: Arc::new(deploy::assign::DeployCache::default()),
            package_dir: "packages".into(),
            downloads: Arc::new(tokio::sync::Semaphore::new(DOWNLOAD_CONCURRENCY)),
            updates: Arc::new(updates::assign::UpdatePolicyCache::default()),
            branch: Arc::new(branch::assign::BranchCache::default()),
            metrics: Arc::new(metrics::Metrics::default()),
            oidc: None,
            secrets: None,
        }
    }

    pub fn with_secrets(mut self, secrets: Option<secret::SecretBox>) -> Self {
        self.secrets = secrets.map(Arc::new);
        self
    }

    pub fn with_packages(mut self, dir: std::path::PathBuf, concurrency: usize) -> Self {
        self.package_dir = dir;
        self.downloads = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
        self
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

    pub fn with_linux_packages(
        mut self,
        deb: Option<std::path::PathBuf>,
        rpm: Option<std::path::PathBuf>,
    ) -> Self {
        self.agent_deb = deb;
        self.agent_rpm = rpm;
        self
    }

    pub fn with_oidc(mut self, provider: Option<oidc::Provider>) -> Self {
        self.oidc = provider.map(Arc::new);
        self
    }

    pub fn with_metrics_token(mut self, token: Option<&str>) -> Self {
        self.metrics = Arc::new(metrics::Metrics::new(token));
        self
    }

    pub fn with_notify(mut self, secrets: notify::NotifySecrets) -> Self {
        self.notify = Arc::new(secrets);
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
        if let Ok(o) = time::UtcOffset::from_whole_seconds(hours * 3600) {
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
        .route("/v1/cache/enroll", post(branch::api::enroll))
        .route("/v1/cache/enroll/poll", post(branch::api::poll))
        .route("/v1/cache/renew", post(branch::api::renew))
        .route("/v1/cache/checkin", post(branch::api::checkin))
        .route(
            "/v1/cache/packages/{id}/content",
            get(branch::api::package_content),
        )
        .route("/v1/cache/authorize", post(branch::api::authorize))
        .route("/v1/cache/netdata", post(netdev::api::netdata))
        .route("/v1/packages/{id}/content", get(deploy::api::download))
        .route("/v1/deployments/{id}/result", post(deploy::api::result))
        .route("/v1/update-status", put(updates::api::status))
        .route("/v1/commands/{id}/result", post(commands::api::result))
        .route_layer(axum::middleware::from_fn_with_state(
            (state.metrics.clone(), "agent"),
            metrics::track,
        ))
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
    partitions::maintain_partitions(&pool, time::OffsetDateTime::now_utc()).await?;
    deploy::store::cleanup_temp(&cfg.package_dir).await;

    let server_names = ca::server_names(&cfg.ca_dir)?;
    let public_url = if cfg.agent_public_url.is_empty() {
        installer::default_public_url(&server_names, cfg.agent_listen.port())
    } else {
        cfg.agent_public_url.clone()
    };
    let state = AppState::new(pool.clone(), ca::Ca::load(&cfg.ca_dir)?)
        .with_display_offset(cfg.display_utc_offset)
        .with_enroll_limit(cfg.enroll_per_ip_per_minute)
        .with_installer(cfg.agent_msi.clone(), public_url, server_names)
        .with_linux_packages(cfg.agent_deb.clone(), cfg.agent_rpm.clone())
        .with_notify(notify::NotifySecrets {
            webhook_secret: cfg.webhook_secret.clone(),
        })
        .with_metrics_token(cfg.metrics_token.as_deref())
        .with_oidc(cfg.oidc.clone().map(oidc::Provider::new).transpose()?)
        .with_secrets(
            cfg.secret_key_file
                .as_deref()
                .map(secret::SecretBox::load)
                .transpose()?,
        )
        .with_packages(cfg.package_dir.clone(), cfg.download_concurrency);
    // 安裝檔可以晚點才放上去（網頁每次顯示時會再檢查），這裡只先提醒
    for (var, path) in [
        ("EM_AGENT_MSI", &cfg.agent_msi),
        ("EM_AGENT_DEB", &cfg.agent_deb),
        ("EM_AGENT_RPM", &cfg.agent_rpm),
    ] {
        if let Some(p) = path
            && !std::fs::metadata(p).is_ok_and(|m| m.is_file())
        {
            tracing::warn!(var, path = %p.display(), "agent installer file not found");
        }
    }
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
            if let Err(e) =
                partitions::maintain_partitions(&part_pool, time::OffsetDateTime::now_utc()).await
            {
                tracing::error!(error = %e, "partition maintenance failed");
            }
        }
    });
    compliance::set_display_offset(state.display_offset);
    compliance::worker::spawn(pool.clone());
    commands::worker::spawn(pool.clone());
    notify::worker::spawn(pool.clone(), state.notify.clone());
    retention::spawn(pool.clone(), state.metrics.clone());

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
