//! 報到時的據點對應：據點與使用中的快取載入記憶體（依 branch_state.generation 判斷過期），
//! 每次報到只用 Agent 回報的 IP 比對，不額外查資料庫。

use std::net::IpAddr;
use std::sync::Arc;

use protocol::branch::PackageSource;
use sqlx::PgPool;
use tokio::sync::RwLock;

use super::sites::{cidr_contains, parse_cidr};
use crate::compliance::CHECK_EVERY;

#[derive(Debug, Clone)]
pub struct SiteEntry {
    pub site_id: i64,
    pub cidrs: Vec<(IpAddr, u8)>,
    /// 據點有使用中的快取時才有值
    pub source: Option<PackageSource>,
}

#[derive(Debug, Clone)]
pub struct BranchSet {
    pub generation: i64,
    pub sites: Vec<SiteEntry>,
}

impl BranchSet {
    /// 回報的 IP 中，被前綴最長的網段包含的據點；前綴長度相同時 site_id 小的優先
    pub fn site_for(&self, ips: &[IpAddr]) -> Option<&SiteEntry> {
        self.sites
            .iter()
            .filter_map(|s| {
                s.cidrs
                    .iter()
                    .filter(|c| ips.iter().any(|ip| cidr_contains(c, ip)))
                    .map(|c| c.1)
                    .max()
                    .map(|len| (len, s))
            })
            .max_by(|(la, a), (lb, b)| la.cmp(lb).then(b.site_id.cmp(&a.site_id)))
            .map(|(_, s)| s)
    }

    /// 解析失敗的 IP 略過
    pub fn source_for(&self, ips: &[String]) -> Option<PackageSource> {
        let ips: Vec<IpAddr> = ips.iter().filter_map(|s| s.trim().parse().ok()).collect();
        self.site_for(&ips)?.source.clone()
    }
}

async fn load(pool: &PgPool) -> Result<BranchSet, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // 和資料一起讀 generation：讀到一半有人改也不會把舊資料記成新 generation
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;
    let generation: i64 = sqlx::query_scalar("SELECT generation FROM branch_state")
        .fetch_one(&mut *tx)
        .await?;
    let rows: Vec<(i64, Vec<String>, bool, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT s.id, s.cidrs::text[], s.fallback_to_central, c.id, c.url FROM sites s \
         LEFT JOIN caches c ON c.site_id = s.id AND c.status = 'active' ORDER BY s.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let sites = rows
        .into_iter()
        .map(|(site_id, cidrs, fallback, cache_id, url)| SiteEntry {
            site_id,
            // 資料庫的 cidr 一定合法；萬一解析失敗就略過那個網段
            cidrs: cidrs.iter().filter_map(|c| parse_cidr(c).ok()).collect(),
            source: cache_id.zip(url).map(|(cache_id, url)| PackageSource {
                cache_id,
                url,
                fallback_to_central: fallback,
            }),
        })
        .collect();
    Ok(BranchSet { generation, sites })
}

/// 比照 DeployCache：依 branch_state.generation 判斷是否重新載入
pub struct BranchCache {
    current: RwLock<Arc<BranchSet>>,
    checked: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Default for BranchCache {
    fn default() -> Self {
        BranchCache {
            current: RwLock::new(Arc::new(BranchSet {
                generation: -1,
                sites: vec![],
            })),
            checked: std::sync::Mutex::new(None),
        }
    }
}

impl BranchCache {
    pub async fn get(&self, pool: &PgPool) -> Result<Arc<BranchSet>, sqlx::Error> {
        let generation: i64 = sqlx::query_scalar("SELECT generation FROM branch_state")
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

    pub async fn get_throttled(&self, pool: &PgPool) -> Result<Arc<BranchSet>, sqlx::Error> {
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

    fn site(id: i64, cidrs: &[&str], cache: bool) -> SiteEntry {
        SiteEntry {
            site_id: id,
            cidrs: cidrs
                .iter()
                .map(|c| super::super::sites::parse_cidr(c).unwrap())
                .collect(),
            source: cache.then(|| PackageSource {
                cache_id: id * 10,
                url: format!("https://cache{id}:8443"),
                fallback_to_central: true,
            }),
        }
    }

    fn set(sites: Vec<SiteEntry>) -> BranchSet {
        BranchSet {
            generation: 0,
            sites,
        }
    }

    fn ips(v: &[&str]) -> Vec<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn longest_prefix_wins() {
        let b = set(vec![
            site(1, &["10.1.0.0/16"], true),
            site(2, &["10.1.2.0/24"], true),
            site(3, &["fd00::/8"], true),
        ]);
        assert_eq!(b.site_for(&ips(&["10.1.2.5"])).unwrap().site_id, 2);
        assert_eq!(b.site_for(&ips(&["10.1.9.9"])).unwrap().site_id, 1);
        assert_eq!(b.site_for(&ips(&["fd12::1"])).unwrap().site_id, 3);
        assert_eq!(
            b.site_for(&ips(&["192.168.1.1", "10.1.9.9"]))
                .unwrap()
                .site_id,
            1,
            "第二個 IP 符合也算"
        );
        assert!(b.site_for(&ips(&["172.16.0.1"])).is_none());
    }

    #[test]
    fn equal_prefix_prefers_smaller_site_id() {
        let b = set(vec![
            site(5, &["10.2.0.0/16"], true),
            site(4, &["10.1.0.0/16"], true),
        ]);
        // 兩個 IP 分屬兩個 /16：前綴一樣長，site_id 小的優先
        assert_eq!(
            b.site_for(&ips(&["10.2.0.1", "10.1.0.1"])).unwrap().site_id,
            4
        );
    }

    #[test]
    fn source_needs_active_cache_and_parsable_ip() {
        let b = set(vec![
            site(1, &["10.1.0.0/16"], false),
            site(2, &["10.2.0.0/16"], true),
        ]);
        assert!(b.source_for(&["10.1.0.5".into()]).is_none(), "據點沒有快取");
        let s = b
            .source_for(&["garbage".into(), "10.2.0.5".into()])
            .unwrap();
        assert_eq!((s.cache_id, s.url.as_str()), (20, "https://cache2:8443"));
        assert!(b.source_for(&[]).is_none());
    }
}
