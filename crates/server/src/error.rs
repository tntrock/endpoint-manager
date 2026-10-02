use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("too many requests")]
    TooManyRequests,
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    /// 伺服器忙碌（例如同時下載數用完），附 Retry-After
    #[error("busy")]
    Busy,
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    #[error("internal: {0}")]
    Internal(#[from] anyhow::Error),
}

impl From<protocol::ValidationError> for AppError {
    fn from(e: protocol::ValidationError) -> Self {
        AppError::BadRequest(e.to_string())
    }
}

/// 暫時不可用的 SQLSTATE：連線中斷、資源不足（記憶體、磁碟、連線數）、
/// 資料庫關機／重啟、查詢被取消。協定錯誤（08P01）與設定上限（53400）不算。
fn unavailable_sqlstate(code: &str) -> bool {
    matches!(
        code,
        "08000"
            | "08001"
            | "08003"
            | "08004"
            | "08006"
            | "53000"
            | "53100"
            | "53200"
            | "53300"
            | "57P01"
            | "57P02"
            | "57P03"
            | "57014"
    )
}

fn db_unavailable(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::Io(_)
        | sqlx::Error::Tls(_) => true,
        sqlx::Error::Database(d) => d.code().is_some_and(|c| unavailable_sqlstate(&c)),
        _ => false,
    }
}

fn with_retry_after(status: StatusCode) -> Response {
    let mut r = status.into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    r
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m).into_response(),
            AppError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
            AppError::TooManyRequests => with_retry_after(StatusCode::TOO_MANY_REQUESTS),
            AppError::NotFound => StatusCode::NOT_FOUND.into_response(),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m).into_response(),
            AppError::Busy => with_retry_after(StatusCode::SERVICE_UNAVAILABLE),
            AppError::Db(e) if db_unavailable(&e) => {
                tracing::error!(error = %e, "database unavailable");
                with_retry_after(StatusCode::SERVICE_UNAVAILABLE)
            }
            AppError::Db(e) => {
                tracing::error!(error = %e, "database error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            AppError::Internal(e) => {
                tracing::error!(error = %e, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 資料庫在關機、重啟、連線數用盡、查詢被取消時，是暫時不可用（503 + Retry-After），
    /// 不是伺服器程式錯誤（500）；Agent 看到 503 會照 Retry-After 退避。
    #[test]
    fn transient_sqlstates_are_unavailable() {
        for code in [
            "57P01", "57P02", "57P03", "57014", "53300", "53200", "08006",
        ] {
            assert!(unavailable_sqlstate(code), "{code}");
        }
        // 協定錯誤、設定上限、一般錯誤不是暫時狀況：回 500 才會被告警，Agent 也不會無限重試
        for code in ["23505", "22P02", "42P01", "40001", "08P01", "53400"] {
            assert!(!unavailable_sqlstate(code), "{code}");
        }
    }
}
