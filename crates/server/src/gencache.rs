//! 依資料庫 generation 判斷過期的記憶體快取（合規規則、派送、更新原則、據點共用）。

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tokio::sync::RwLock;

/// 報到路徑最多每隔這麼久確認一次 generation（變更最多晚幾秒下發）
pub const CHECK_EVERY: Duration = Duration::from_secs(5);

/// 可整份快取、以 generation 判斷是否過期的資料
pub trait Snapshot: Send + Sync + Sized + 'static {
    /// 讀取目前 generation 的 SQL
    const GENERATION_SQL: &'static str;
    fn generation(&self) -> i64;
    /// 尚未載入（generation -1）
    fn empty() -> Self;
    fn load(pool: &PgPool) -> impl Future<Output = Result<Self, sqlx::Error>> + Send;
}

pub struct GenerationCache<T> {
    current: RwLock<Arc<T>>,
    /// 上次確認 generation 的時間
    checked: Mutex<Option<Instant>>,
}

impl<T: Snapshot> Default for GenerationCache<T> {
    fn default() -> Self {
        GenerationCache {
            current: RwLock::new(Arc::new(T::empty())),
            checked: Mutex::new(None),
        }
    }
}

impl<T: Snapshot> GenerationCache<T> {
    /// generation 改變時重新載入
    pub async fn get(&self, pool: &PgPool) -> Result<Arc<T>, sqlx::Error> {
        let generation: i64 = sqlx::query_scalar(T::GENERATION_SQL)
            .fetch_one(pool)
            .await?;
        {
            let cur = self.current.read().await;
            if cur.generation() == generation {
                return Ok(cur.clone());
            }
        }
        let fresh = Arc::new(T::load(pool).await?);
        *self.current.write().await = fresh.clone();
        Ok(fresh)
    }

    /// 報到用：距離上次確認不到 CHECK_EVERY 就直接用快取
    pub async fn get_throttled(&self, pool: &PgPool) -> Result<Arc<T>, sqlx::Error> {
        let fresh_enough = self
            .checked
            .lock()
            .expect("cache lock")
            .is_some_and(|t| t.elapsed() < CHECK_EVERY);
        if fresh_enough {
            return Ok(self.current.read().await.clone());
        }
        let r = self.get(pool).await?;
        *self.checked.lock().expect("cache lock") = Some(Instant::now());
        Ok(r)
    }

    /// 下次報到時重新確認 generation（測試與管理動作後使用）
    pub fn invalidate(&self) {
        *self.checked.lock().expect("cache lock") = None;
    }
}
