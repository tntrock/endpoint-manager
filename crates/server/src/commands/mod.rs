//! 第六期：遠端指令。

pub mod api;
pub mod runs;
pub mod scripts;
pub mod worker;

/// 給使用者看的錯誤，網頁依種類決定狀態碼；其他錯誤（資料庫等）一律記錄後回 500
#[derive(Debug, thiserror::Error)]
pub enum CmdError {
    /// 權限不足（403）
    #[error("{0}")]
    Forbidden(String),
    /// 輸入不正確（422）
    #[error("{0}")]
    Invalid(String),
    /// 找不到（404）
    #[error("{0}")]
    NotFound(String),
    /// 目前狀態不允許（409）
    #[error("{0}")]
    Conflict(String),
}

/// 條件不成立時回傳指定種類的 CmdError
macro_rules! check {
    ($cond:expr, $kind:ident, $($arg:tt)+) => {
        if !$cond {
            return Err($crate::commands::CmdError::$kind(format!($($arg)+)).into());
        }
    };
}
pub(crate) use check;

pub fn cmd_error_kind(e: &anyhow::Error) -> Option<&CmdError> {
    e.downcast_ref::<CmdError>()
}

pub fn is_forbidden(e: &anyhow::Error) -> bool {
    matches!(cmd_error_kind(e), Some(CmdError::Forbidden(_)))
}

/// 執行管理動作的人：權限檢查只需要這些（網頁端從 Session 轉換）
#[derive(Debug, Clone)]
pub struct Actor {
    pub username: String,
    /// 平台管理員：不限範圍、可管理腳本
    pub platform: bool,
    /// 群組管理員的管理範圍
    pub groups: Vec<i64>,
}
