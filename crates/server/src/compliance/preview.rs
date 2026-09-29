//! 規則存檔前預覽「會命中幾台」：以同一個評估函式分批跑全部使用中裝置，不寫入。

use sqlx::PgPool;
use uuid::Uuid;

use super::evaluate::{Status, evaluate};
use super::rules::{Rule, RuleSet};
use super::store::load_facts_bulk;

pub const BATCH: i64 = 1000;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PreviewCount {
    pub violating: i64,
    pub unknown: i64,
    pub devices: i64,
}

pub async fn preview(pool: &PgPool, rule: Rule) -> Result<PreviewCount, sqlx::Error> {
    let set = RuleSet {
        generation: 0,
        rules: vec![rule],
    };
    let mut count = PreviewCount::default();
    let mut cursor: Option<Uuid> = None;
    let mut conn = pool.acquire().await?;
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM devices WHERE status = 'active' AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
        )
        .bind(cursor)
        .bind(BATCH)
        .fetch_all(&mut *conn)
        .await?;
        let Some(last) = ids.last().copied() else {
            break;
        };
        for (_, facts) in load_facts_bulk(&mut conn, &ids).await? {
            count.devices += 1;
            for o in evaluate(&facts, &set) {
                match o.status {
                    Status::Violating => count.violating += 1,
                    Status::Unknown => count.unknown += 1,
                    Status::Exempt => {}
                }
            }
        }
        cursor = Some(last);
        tokio::task::yield_now().await;
    }
    Ok(count)
}
