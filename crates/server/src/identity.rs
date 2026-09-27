//! 已驗證的 Agent 身分。TLS 握手已證明對方持有憑證私鑰；
//! 這裡再以指紋比對 device_certs，確認憑證是本系統簽發、未撤銷、未過期。

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::tls::PeerCert;

#[derive(Debug, Clone)]
pub struct AuthedDevice {
    pub device_id: Uuid,
    pub cert_not_after: DateTime<Utc>,
}

impl FromRequestParts<AppState> for AuthedDevice {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let peer = parts
            .extensions
            .get::<PeerCert>()
            .ok_or(AppError::Unauthorized)?;
        let row: Option<(Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT device_id, not_after FROM device_certs \
             WHERE fingerprint = $1 AND revoked_at IS NULL AND not_after > now()",
        )
        .bind(&peer.fingerprint)
        .fetch_optional(&state.pool)
        .await?;
        let (device_id, cert_not_after) = row.ok_or(AppError::Unauthorized)?;
        Ok(AuthedDevice {
            device_id,
            cert_not_after,
        })
    }
}
