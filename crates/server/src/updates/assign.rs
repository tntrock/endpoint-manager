//! 報到時的更新原則：「群組 → 原則」快取在記憶體（依 update_state.generation 判斷過期），
//! 每次報到只用裝置的群組查表，不額外查資料庫。

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use protocol::update::UpdatePolicy;
use sqlx::PgPool;

use super::policy::PolicySettings;
use crate::gencache::{GenerationCache, Snapshot};

#[derive(Debug, Default)]
pub struct PolicySet {
    pub generation: i64,
    pub by_group: HashMap<i64, Arc<UpdatePolicy>>,
}

impl PolicySet {
    pub fn policy_for(&self, group: Option<i64>) -> Option<UpdatePolicy> {
        group
            .and_then(|g| self.by_group.get(&g))
            .map(|p| UpdatePolicy::clone(p))
    }
}

pub async fn load(pool: &PgPool) -> Result<PolicySet, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM update_state")
        .fetch_one(&mut *tx)
        .await?;
    let rows: Vec<(i64, i32, String)> =
        sqlx::query_as("SELECT id, revision, settings::text FROM update_policies")
            .fetch_all(&mut *tx)
            .await?;
    let groups: Vec<(i64, i64)> =
        sqlx::query_as("SELECT group_id, policy_id FROM update_policy_groups")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    let mut policies = HashMap::new();
    for (id, revision, settings) in rows {
        // 設定被手動改壞時跳過這個原則，不讓報到失敗
        match serde_json::from_str::<PolicySettings>(&settings) {
            Ok(s) => {
                policies.insert(
                    id,
                    Arc::new(UpdatePolicy {
                        id,
                        revision,
                        values: s.values(),
                    }),
                );
            }
            Err(e) => tracing::error!(policy_id = id, error = %e, "更新原則設定無法解析"),
        }
    }
    let by_group = groups
        .into_iter()
        .filter_map(|(g, p)| Some((g, policies.get(&p)?.clone())))
        .collect();
    Ok(PolicySet {
        generation,
        by_group,
    })
}

pub type UpdatePolicyCache = GenerationCache<PolicySet>;

impl Snapshot for PolicySet {
    const GENERATION_SQL: &'static str = "SELECT generation FROM update_state";
    fn generation(&self) -> i64 {
        self.generation
    }
    fn empty() -> Self {
        PolicySet {
            generation: -1,
            by_group: HashMap::new(),
        }
    }
    fn load(pool: &PgPool) -> impl Future<Output = Result<Self, sqlx::Error>> + Send {
        load(pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_group_no_policy() {
        let p = Arc::new(UpdatePolicy {
            id: 1,
            revision: 1,
            values: vec![],
        });
        let set = PolicySet {
            generation: 0,
            by_group: HashMap::from([(5, p)]),
        };
        assert!(set.policy_for(None).is_none());
        assert!(set.policy_for(Some(6)).is_none());
        assert_eq!(set.policy_for(Some(5)).unwrap().id, 1);
    }
}
