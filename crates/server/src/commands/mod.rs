//! 第六期：遠端指令。

pub mod runs;
pub mod scripts;

/// 執行管理動作的人：權限檢查只需要這些（網頁端從 Session 轉換）
#[derive(Debug, Clone)]
pub struct Actor {
    pub username: String,
    /// 平台管理員：不限範圍、可管理腳本
    pub platform: bool,
    /// 群組管理員的管理範圍
    pub groups: Vec<i64>,
}
