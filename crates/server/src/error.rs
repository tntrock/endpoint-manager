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

fn db_unavailable(e: &sqlx::Error) -> bool {
    matches!(
        e,
        sqlx::Error::PoolTimedOut
            | sqlx::Error::PoolClosed
            | sqlx::Error::Io(_)
            | sqlx::Error::Tls(_)
    )
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
