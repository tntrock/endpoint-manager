//! 軟體與修補合規：規則、評估、違規與歷程。

pub mod admin;
pub mod evaluate;
pub mod matcher;
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
}

impl Default for RuleCache {
    fn default() -> Self {
        Self::new()
    }
}

impl RuleCache {
    pub fn new() -> RuleCache {
        RuleCache {
            current: RwLock::new(Arc::new(RuleSet::empty())),
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
}

/// 會影響合規結果的區段
pub fn affects_compliance(section: Section) -> bool {
    matches!(
        section,
        Section::Basic | Section::Software | Section::Patches
    )
}

pub async fn refresh_after_upload(st: &AppState, device_id: Uuid) -> Result<(), sqlx::Error> {
    let rules = st.rules.get(&st.pool).await?;
    store::refresh_device(&st.pool, &rules, device_id).await
}
