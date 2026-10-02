//! 遠端指令：清單、對群組下指令、詳情、取消；裝置頁「遠端指令」分頁。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::auth::Session;
use crate::commands::{Actor, is_forbidden};

pub(super) fn actor(s: &Session) -> Actor {
    Actor {
        username: s.username.clone(),
        platform: s.all_devices(),
        groups: s.groups.clone(),
    }
}

/// 權限不足回 403；其他錯誤（輸入、狀態）回指定的狀態碼與訊息
pub(super) fn command_error(e: anyhow::Error, status: StatusCode) -> Response {
    let status = if is_forbidden(&e) {
        StatusCode::FORBIDDEN
    } else {
        status
    };
    (status, format!("{e:#}")).into_response()
}
