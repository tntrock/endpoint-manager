//! 報到時的派送指派：未停止的派送快取在記憶體（依 deploy_state.generation 判斷過期），
//! 每次報到只依裝置群組篩選，不額外查資料庫。

use std::sync::Arc;

use protocol::deploy::{Assignment, DeployAction, Detect, PackageKind, PackageSpec};
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::compliance::CHECK_EVERY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Pilot,
    All,
}

#[derive(Debug, Clone)]
pub struct Active {
    pub id: i64,
    pub revision: i32,
    pub action: DeployAction,
    /// 暫停中的派送以暫停前的階段判斷範圍（回報仍接受），但不下發
    pub stage: Stage,
    pub paused: bool,
    pub pilot_group: Option<i64>,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
    pub package: PackageSpec,
}

impl Active {
    /// 裝置是否在這個派送的範圍內（不看是否暫停）：試點階段只含試點群組；排除優先
    pub fn targets(&self, group: Option<i64>) -> bool {
        if group.is_some_and(|g| self.exclude.contains(&g)) {
            return false;
        }
        match self.stage {
            Stage::Pilot => group.is_some() && group == self.pilot_group,
            Stage::All => {
                self.include.is_empty() || group.is_some_and(|g| self.include.contains(&g))
            }
        }
    }

    fn assignment(&self) -> Assignment {
        Assignment {
            deployment_id: self.id,
            revision: self.revision,
            action: self.action,
            package: self.package.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub struct DeploySet {
    pub generation: i64,
    pub deployments: Vec<Active>,
}

impl DeploySet {
    /// 報到回應的指派：範圍內、未暫停
    pub fn assignments_for(&self, group: Option<i64>) -> Vec<Assignment> {
        self.deployments
            .iter()
            .filter(|d| !d.paused && d.targets(group))
            .map(Active::assignment)
            .collect()
    }

    pub fn find(&self, id: i64) -> Option<&Active> {
        self.deployments.iter().find(|d| d.id == id)
    }
}

#[derive(sqlx::FromRow)]
struct DeployRow {
    id: i64,
    revision: i32,
    action: String,
    stage: String,
    paused_from: Option<String>,
    pilot_group_id: Option<i64>,
    package_id: i64,
    kind: String,
    sha256: String,
    size: i64,
    file_name: String,
    install_args: String,
    uninstall_args: String,
    msi_product_code: Option<String>,
    success_codes: Vec<i32>,
    detect_name: String,
    detect_publisher: Option<String>,
    detect_min_version: Option<String>,
}

pub async fn load(pool: &PgPool) -> Result<DeploySet, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM deploy_state")
        .fetch_one(&mut *tx)
        .await?;
    let rows: Vec<DeployRow> = sqlx::query_as(
        "SELECT d.id, d.revision, d.action, d.stage, d.paused_from, d.pilot_group_id, \
                p.id AS package_id, p.kind, p.sha256, p.size, p.file_name, p.install_args, p.uninstall_args, \
                p.msi_product_code, p.success_codes, p.detect_name, p.detect_publisher, \
                p.detect_min_version \
         FROM deployments d JOIN packages p ON p.id = d.package_id \
         WHERE d.stage <> 'stopped' ORDER BY d.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let groups: Vec<(i64, i64, String)> =
        sqlx::query_as("SELECT deployment_id, group_id, mode FROM deployment_groups")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    let deployments = rows
        .into_iter()
        .map(|r| {
            let (id, revision, action, stage, paused_from, pilot_group) = (
                r.id,
                r.revision,
                r.action,
                r.stage,
                r.paused_from,
                r.pilot_group_id,
            );
            let effective = if stage == "paused" {
                paused_from.unwrap_or_default()
            } else {
                stage.clone()
            };
            let of = |mode: &str| {
                groups
                    .iter()
                    .filter(|g| g.0 == id && g.2 == mode)
                    .map(|g| g.1)
                    .collect::<Vec<i64>>()
            };
            Active {
                id,
                revision,
                action: if action == "uninstall" {
                    DeployAction::Uninstall
                } else {
                    DeployAction::Install
                },
                stage: if effective == "pilot" {
                    Stage::Pilot
                } else {
                    Stage::All
                },
                paused: stage == "paused",
                pilot_group,
                include: of("include"),
                exclude: of("exclude"),
                package: PackageSpec {
                    id: r.package_id,
                    kind: if r.kind == "msi" {
                        PackageKind::Msi
                    } else {
                        PackageKind::Exe
                    },
                    sha256: r.sha256,
                    size: r.size.max(0) as u64,
                    file_name: r.file_name,
                    install_args: r.install_args,
                    uninstall_args: r.uninstall_args,
                    msi_product_code: r.msi_product_code,
                    success_codes: r.success_codes,
                    detect: Detect {
                        name: r.detect_name,
                        publisher: r.detect_publisher,
                        min_version: r.detect_min_version,
                    },
                },
            }
        })
        .collect();
    Ok(DeploySet {
        generation,
        deployments,
    })
}

/// 同 `compliance::RuleCache`：報到路徑最多每 CHECK_EVERY 確認一次 generation。
pub struct DeployCache {
    current: RwLock<Arc<DeploySet>>,
    checked: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Default for DeployCache {
    fn default() -> Self {
        DeployCache {
            current: RwLock::new(Arc::new(DeploySet {
                generation: -1,
                deployments: vec![],
            })),
            checked: std::sync::Mutex::new(None),
        }
    }
}

impl DeployCache {
    pub async fn get(&self, pool: &PgPool) -> Result<Arc<DeploySet>, sqlx::Error> {
        let generation: i64 = sqlx::query_scalar("SELECT generation FROM deploy_state")
            .fetch_one(pool)
            .await?;
        {
            let cur = self.current.read().await;
            if cur.generation == generation {
                return Ok(cur.clone());
            }
        }
        let fresh = Arc::new(load(pool).await?);
        *self.current.write().await = fresh.clone();
        Ok(fresh)
    }

    pub async fn get_throttled(&self, pool: &PgPool) -> Result<Arc<DeploySet>, sqlx::Error> {
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

    /// 下次報到時重新確認 generation（測試與管理動作後使用）
    pub fn invalidate(&self) {
        *self.checked.lock().expect("cache lock") = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active(stage: Stage, include: Vec<i64>, exclude: Vec<i64>) -> Active {
        Active {
            id: 1,
            revision: 1,
            action: DeployAction::Install,
            stage,
            paused: false,
            pilot_group: Some(9),
            include,
            exclude,
            package: PackageSpec {
                id: 1,
                kind: PackageKind::Exe,
                sha256: String::new(),
                size: 0,
                file_name: "a.exe".into(),
                install_args: String::new(),
                uninstall_args: String::new(),
                msi_product_code: None,
                success_codes: vec![],
                detect: Detect {
                    name: "A".into(),
                    publisher: None,
                    min_version: None,
                },
            },
        }
    }

    #[test]
    fn scope_rules() {
        let all = active(Stage::All, vec![], vec![3]);
        assert!(all.targets(None) && all.targets(Some(1)));
        assert!(!all.targets(Some(3)), "排除優先");
        let only = active(Stage::All, vec![1], vec![]);
        assert!(only.targets(Some(1)) && !only.targets(Some(2)) && !only.targets(None));
        let pilot = active(Stage::Pilot, vec![], vec![9]);
        assert!(!pilot.targets(Some(9)), "試點群組被排除時也不派送");
        let pilot = active(Stage::Pilot, vec![], vec![]);
        assert!(pilot.targets(Some(9)) && !pilot.targets(Some(1)) && !pilot.targets(None));
    }
}
