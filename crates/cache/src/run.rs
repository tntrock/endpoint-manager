//! 背景工作：等待核准、報到、預先下載、清除、換發憑證、被停用時改為輪詢。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use protocol::branch::{
    CacheCheckin, CacheEnrollPoll, CacheEnrollRequest, CacheEnrollState, StoredPackage,
};
use tokio::sync::{Mutex, watch};

use crate::auth::{AUTH_TTL, AuthCache};
use crate::central::{Central, CentralError};
use crate::config::Config;
use crate::fetch::{Catalog, Fetcher};
use crate::identity::{self, Enrollment, Identity};
use crate::server::{self, CacheState, CertSlot, Refresh};
use crate::store::{self, Store};

pub const CHECKIN_EVERY: Duration = Duration::from_secs(60);
pub const POLL_EVERY: Duration = Duration::from_secs(30);
/// 清單過時時的立即報到，最多這麼久一次（避免被不存在的套件 id 觸發大量報到）
const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(10);
/// 同時連線上限（下載數另有 max_downloads）
const MAX_CONNS: usize = 10_000;

pub struct EnrollArgs {
    pub server: String,
    pub root_pem_path: PathBuf,
    pub token: String,
    pub name: String,
    pub url: String,
    pub dns: Vec<String>,
}

/// 寫好 config.json、root.pem、pending.key、enroll.json 並送出註冊，回傳快取 id。
/// 呼叫前請先 `config::secure_data_dir`。
pub async fn enroll(dir: &Path, a: &EnrollArgs) -> anyhow::Result<i64> {
    if identity::load_enrollment(dir)?.is_some() {
        bail!(
            "already enrolled ({}); remove the data directory to enroll again",
            dir.display()
        );
    }
    let root_pem = std::fs::read_to_string(&a.root_pem_path)
        .with_context(|| format!("reading {}", a.root_pem_path.display()))?;
    let central = Central::new(&a.server, &root_pem, None)?;
    let (key_pem, csr_pem) = identity::new_key_and_csr()?;
    let r = central
        .enroll(&CacheEnrollRequest {
            token: a.token.clone(),
            name: a.name.clone(),
            url: a.url.clone(),
            dns_names: a.dns.clone(),
            csr_pem,
        })
        .await
        .map_err(|e| anyhow::anyhow!("enroll failed: {e}"))?;
    std::fs::write(dir.join("root.pem"), &root_pem)?;
    identity::save_pending_key(dir, &key_pem)?;
    identity::save_enrollment(
        dir,
        &Enrollment {
            cache_id: r.cache_id,
            poll_secret: r.poll_secret,
        },
    )?;
    if !dir.join(crate::config::CONFIG_FILE).exists() {
        Config {
            server_url: a.server.clone(),
            listen: "0.0.0.0:8443".into(),
            storage_dir: None,
            max_downloads: 200,
        }
        .save(dir)?;
    }
    Ok(r.cache_id)
}

pub struct Cache {
    dir: PathBuf,
    config: Config,
    enrollment: Enrollment,
    pub state: CacheState,
    slot: Arc<CertSlot>,
    root_pem: String,
}

/// 等待核准：輪詢到取得憑證為止（stop 時回 None）
async fn wait_for_approval(
    dir: &Path,
    central: &Central,
    e: &Enrollment,
    mut stop: watch::Receiver<bool>,
    every: Duration,
) -> anyhow::Result<Option<Identity>> {
    let key_pem =
        identity::load_pending_key(dir)?.context("pending.key is missing; enroll again")?;
    loop {
        if *stop.borrow() {
            return Ok(None);
        }
        match central
            .poll(&CacheEnrollPoll {
                cache_id: e.cache_id,
                poll_secret: e.poll_secret.clone(),
            })
            .await
        {
            Ok(p) if p.state == CacheEnrollState::Approved => {
                if let Some(chain_pem) = p.certificate_chain_pem {
                    let id = Identity { key_pem, chain_pem };
                    identity::save_identity(dir, &id)?;
                    identity::remove_pending_key(dir)?;
                    tracing::info!(cache_id = e.cache_id, "cache approved");
                    return Ok(Some(id));
                }
            }
            Ok(p) if p.state == CacheEnrollState::Rejected => {
                bail!("enrollment was rejected by an administrator")
            }
            Ok(_) => tracing::info!(cache_id = e.cache_id, "waiting for approval"),
            Err(err) => tracing::warn!(error = %err, "polling enrollment failed"),
        }
        tokio::select! {
            _ = tokio::time::sleep(every) => {}
            _ = stop.changed() => {}
        }
    }
}

fn stored(catalog: &Catalog, store: &Store) -> Vec<StoredPackage> {
    catalog
        .all()
        .into_iter()
        .filter(|p| store.has(&p.sha256, p.size))
        .map(|p| StoredPackage {
            package_id: p.id,
            size: p.size,
        })
        .collect()
}

fn checkin_request(catalog: &Catalog, store: &Store) -> CacheCheckin {
    CacheCheckin {
        version: env!("CARGO_PKG_VERSION").into(),
        disk_used_bytes: store.used_bytes(),
        stored: stored(catalog, store),
    }
}

impl Cache {
    pub async fn start(dir: &Path, stop: watch::Receiver<bool>) -> anyhow::Result<Option<Cache>> {
        Self::start_with(dir, stop, POLL_EVERY).await
    }

    /// 載入身分；尚未核准時每 poll_every 輪詢一次
    pub async fn start_with(
        dir: &Path,
        stop: watch::Receiver<bool>,
        poll_every: Duration,
    ) -> anyhow::Result<Option<Cache>> {
        let config = Config::load(dir)?;
        let root_pem = identity::load_root(dir)?;
        let enrollment = identity::load_enrollment(dir)?
            .context("not enrolled; run `endpoint-cache enroll` first")?;
        let id = match identity::load_identity(dir)? {
            Some(id) => id,
            None => {
                let anon = Central::new(&config.server_url, &root_pem, None)?;
                match wait_for_approval(dir, &anon, &enrollment, stop, poll_every).await? {
                    Some(id) => id,
                    None => return Ok(None),
                }
            }
        };
        let central = Arc::new(Central::new(&config.server_url, &root_pem, Some(&id))?);
        let store = Arc::new(Store::open(&config.storage(dir), dir)?);
        let catalog = Arc::new(Catalog::default());
        // 上次刷新完成的時間與結果
        let last_refresh: Arc<Mutex<Option<(Instant, bool)>>> = Arc::default();
        let refresh: Refresh = {
            let (central, catalog, store) = (central.clone(), catalog.clone(), store.clone());
            Arc::new(move || {
                let (central, catalog, store, last) = (
                    central.clone(),
                    catalog.clone(),
                    store.clone(),
                    last_refresh.clone(),
                );
                Box::pin(async move {
                    // 同時多個請求只報到一次；完成後 10 秒內直接沿用結果（成功或失敗），
                    // 中央卡住時等鎖的請求不會一個接一個再等一次逾時
                    let mut last = last.lock().await;
                    if let Some((t, ok)) = *last
                        && t.elapsed() < REFRESH_MIN_INTERVAL
                    {
                        return ok;
                    }
                    let ok = match central.checkin(&checkin_request(&catalog, &store)).await {
                        Ok(r) => {
                            catalog.replace(&r);
                            true
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "refreshing package list failed");
                            false
                        }
                    };
                    *last = Some((Instant::now(), ok));
                    ok
                })
            })
        };
        let state = CacheState {
            fetcher: Arc::new(Fetcher::new(central.clone(), store.clone())),
            central,
            store,
            catalog,
            auth: Arc::new(AuthCache::new(AUTH_TTL)),
            downloads: Arc::new(tokio::sync::Semaphore::new(config.max_downloads)),
            refresh,
        };
        Ok(Some(Cache {
            dir: dir.to_path_buf(),
            slot: CertSlot::new(&id)?,
            config,
            enrollment,
            state,
            root_pem,
        }))
    }

    pub fn router(&self) -> axum::Router {
        server::router(self.state.clone())
    }

    pub fn tls(&self) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        server::tls_config(&self.root_pem, self.slot.clone())
    }

    fn install(&self, id: &Identity) -> anyhow::Result<()> {
        identity::save_identity(&self.dir, id)?;
        self.state.central.set_identity(id)?;
        self.slot.set(id)?;
        Ok(())
    }

    /// 一次報到：回報已存套件 → 更新清單與上限 → 需要時換發 → 清除 → 存存取時間
    pub async fn checkin_once(&self) -> anyhow::Result<()> {
        let st = &self.state;
        let req = checkin_request(&st.catalog, &st.store);
        let resp = match st.central.checkin(&req).await {
            Ok(r) => r,
            Err(CentralError::Unauthorized) => {
                if self.recover().await? {
                    st.central.checkin(&req).await?
                } else {
                    bail!(
                        "cache is disabled or its certificate was revoked; waiting to be re-enabled"
                    )
                }
            }
            Err(e) => return Err(e.into()),
        };
        st.catalog.replace(&resp);
        // 中央已恢復：不再因先前的授權失敗回 503
        st.auth.clear_failure();
        if resp.renew_certificate
            && let Err(e) = self.renew().await
        {
            tracing::warn!(error = %format!("{e:#}"), "certificate renewal failed");
        }
        let (_, disk_limit) = st.catalog.limits();
        st.store
            .evict(&st.catalog.listed_shas(), disk_limit, store::now_secs())?;
        st.store.save_access()?;
        Ok(())
    }

    async fn renew(&self) -> anyhow::Result<()> {
        // 送出前先存（或沿用上次沒完成的）：回應遺失時中央已記下這把金鑰的 CSR
        let (key_pem, csr_pem) = identity::renew_key_and_csr(&self.dir)?;
        let chain_pem = self.state.central.renew(&csr_pem).await?;
        self.install(&Identity { key_pem, chain_pem })?;
        identity::remove_renew_key(&self.dir)?;
        tracing::info!("certificate renewed");
        Ok(())
    }

    /// 報到被拒（停用或憑證被撤銷）時：輪詢中央，重新啟用後拿到新憑證就換上
    pub async fn recover(&self) -> anyhow::Result<bool> {
        let p = self
            .state
            .central
            .poll(&CacheEnrollPoll {
                cache_id: self.enrollment.cache_id,
                poll_secret: self.enrollment.poll_secret.clone(),
            })
            .await?;
        let current = identity::load_identity(&self.dir)?.context("identity is missing")?;
        match p.certificate_chain_pem {
            Some(chain_pem)
                if p.state == CacheEnrollState::Approved && chain_pem != current.chain_pem =>
            {
                // 重新啟用時中央用最新的 CSR 簽發：通常是目前的金鑰；
                // 換發回應遺失時則是換發前存下的那把
                let key_pem = [Some(current.key_pem), identity::load_renew_key(&self.dir)?]
                    .into_iter()
                    .flatten()
                    .find(|k| identity::key_matches(k, &chain_pem))
                    .context("no local key matches the re-issued certificate")?;
                self.install(&Identity { key_pem, chain_pem })?;
                identity::remove_renew_key(&self.dir)?;
                tracing::info!("cache re-enabled; new certificate installed");
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// 依清單逐一預先下載缺少的套件（有頻寬上限時限速），回傳這次下載了幾個
    pub async fn prefetch(&self) -> usize {
        let st = &self.state;
        let (limit, _) = st.catalog.limits();
        let mut n = 0;
        for p in st.catalog.all() {
            if st.store.has(&p.sha256, p.size) {
                continue;
            }
            match st.fetcher.ensure(&p, limit, None).await {
                Ok(_) => n += 1,
                Err(e) => tracing::warn!(package_id = p.id, error = ?e, "prefetch failed"),
            }
        }
        n
    }
}

/// run 子命令與 Windows 服務共用
pub async fn run(dir: &Path, mut stop: watch::Receiver<bool>) -> anyhow::Result<()> {
    let Some(cache) = Cache::start(dir, stop.clone()).await? else {
        return Ok(());
    };
    let cache = Arc::new(cache);
    let listener = tokio::net::TcpListener::bind(&cache.config.listen)
        .await
        .with_context(|| format!("listening on {}", cache.config.listen))?;
    tracing::info!(listen = %cache.config.listen, "cache serving");
    let server = tokio::spawn(server::serve(
        listener,
        cache.tls()?,
        cache.router(),
        MAX_CONNS,
    ));
    // 授權快取每分鐘清一次，與報到成敗無關
    let prune = tokio::spawn(crate::auth::prune_loop(
        cache.state.auth.clone(),
        Duration::from_secs(60),
    ));
    // 預先下載在自己的 task：限速下載可能很久，報到、換發、清除照常進行，停止時立即中斷
    let wake = Arc::new(tokio::sync::Notify::new());
    let prefetch = {
        let (cache, wake) = (cache.clone(), wake.clone());
        tokio::spawn(async move {
            loop {
                wake.notified().await;
                cache.prefetch().await;
            }
        })
    };
    loop {
        match cache.checkin_once().await {
            Ok(()) => wake.notify_one(),
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "checkin failed"),
        }
        tokio::select! {
            _ = tokio::time::sleep(CHECKIN_EVERY) => {}
            _ = stop.changed() => {}
        }
        if *stop.borrow() {
            break;
        }
    }
    prefetch.abort();
    prune.abort();
    server.abort();
    tracing::info!("cache stopped");
    Ok(())
}
