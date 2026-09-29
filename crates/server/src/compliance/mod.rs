//! 軟體與修補合規：規則、評估、違規與歷程。

pub mod admin;
pub mod evaluate;
pub mod matcher;
pub mod preview;
pub mod rules;
pub mod store;
pub mod worker;

use std::sync::Arc;

use protocol::Section;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::AppState;
use rules::RuleSet;

/// 啟用中規則的快取；以 compliance_state.generation 判斷是否過期。
pub struct RuleCache {
    current: RwLock<Arc<RuleSet>>,
    /// 上次確認 generation 的時間：報到路徑最多每 CHECK_EVERY 查一次資料庫
    checked: std::sync::Mutex<Option<std::time::Instant>>,
}

pub const CHECK_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

impl Default for RuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleCache {
    pub fn new() -> RuleCache {
        RuleCache {
            current: RwLock::new(Arc::new(RuleSet::empty())),
            checked: std::sync::Mutex::new(None),
        }
    }

    pub async fn get(&self, pool: &PgPool) -> Result<Arc<RuleSet>, sqlx::Error> {
        let generation: i64 = sqlx::query_scalar("SELECT generation FROM compliance_state")
            .fetch_one(pool)
            .await?;
        {
            let cur = self.current.read().await;
            if cur.generation == generation {
                return Ok(cur.clone());
            }
        }
        let mut conn = pool.acquire().await?;
        let fresh = Arc::new(store::load_ruleset(&mut conn).await?);
        *self.current.write().await = fresh.clone();
        Ok(fresh)
    }

    /// 報到用：距離上次確認不到 CHECK_EVERY 就直接用快取（規則變更最多晚幾秒下發）。
    pub async fn get_throttled(&self, pool: &PgPool) -> Result<Arc<RuleSet>, sqlx::Error> {
        let fresh_enough = self
            .checked
            .lock()
            .expect("cache lock")
            .is_some_and(|t| t.elapsed() < CHECK_EVERY);
        if fresh_enough {
            return Ok(self.current.read().await.clone());
        }
        let r = self.get(pool).await?;
        *self.checked.lock().expect("cache lock") = Some(std::time::Instant::now());
        Ok(r)
    }
}

/// 會影響合規結果的區段
pub fn affects_compliance(section: Section) -> bool {
    matches!(
        section,
        Section::Basic
            | Section::Software
            | Section::Patches
            | Section::Services
            | Section::Security
            | Section::Registry
    )
}

pub async fn refresh_after_upload(st: &AppState, device_id: Uuid) -> Result<(), sqlx::Error> {
    let start = std::time::Instant::now();
    let rules = st.rules.get(&st.pool).await?;
    store::refresh_device(&st.pool, &rules, device_id).await?;
    // 負載測試以 RUST_LOG=endpoint_server::compliance=debug 統計評估耗時
    tracing::debug!(
        elapsed_us = start.elapsed().as_micros() as u64,
        "compliance refresh"
    );
    Ok(())
}
