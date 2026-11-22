//! 軟體與修補合規：規則、評估、違規與歷程。

pub mod admin;
pub mod evaluate;
pub mod matcher;
pub mod preview;
pub mod rules;
pub mod store;
pub mod templates;
pub mod worker;

use protocol::Section;
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::gencache::{GenerationCache, Snapshot};
use rules::RuleSet;

/// 啟用中規則的快取；以 compliance_state.generation 判斷是否過期。
pub type RuleCache = GenerationCache<RuleSet>;

pub use crate::gencache::CHECK_EVERY;

impl Snapshot for RuleSet {
    const GENERATION_SQL: &'static str = "SELECT generation FROM compliance_state";
    fn generation(&self) -> i64 {
        self.generation
    }
    fn empty() -> Self {
        RuleSet::empty()
    }
    async fn load(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let mut conn = pool.acquire().await?;
        store::load_ruleset(&mut conn).await
    }
}

/// 管理網頁的時區（「太久沒更新」以這個時區的日期計算天數）
// ponytail: 一個程序只有一個時區；同一程序要跑多個不同時區的 AppState 時改成由呼叫端傳入
static DISPLAY_OFFSET: std::sync::OnceLock<time::UtcOffset> = std::sync::OnceLock::new();

/// 伺服器啟動時設定一次（之後再設定會被忽略）
pub fn set_display_offset(o: time::UtcOffset) {
    let _ = DISPLAY_OFFSET.set(o);
}

fn display_offset() -> time::UtcOffset {
    DISPLAY_OFFSET
        .get()
        .copied()
        .unwrap_or_else(|| time::UtcOffset::from_whole_seconds(8 * 3600).expect("valid offset"))
}

/// 管理網頁時區的今天；沒設定時用 +8（與 AppState 的預設相同）
pub fn today(now: time::OffsetDateTime) -> time::Date {
    now.to_offset(display_offset()).date()
}

/// 違規細節裡給人看的時間（管理網頁時區，到分鐘）
pub fn display_time(t: time::OffsetDateTime) -> String {
    t.to_offset(display_offset())
        .format(time::macros::format_description!(
            "[year]-[month]-[day] [hour]:[minute]"
        ))
        .unwrap_or_default()
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
            | Section::Network
            | Section::Containers
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
