//! /v1/renew：憑證剩餘效期不足時，以現有 mTLS 身分換發新憑證。
//! 舊憑證保留到原本到期日，避免回應遺失時 Agent 失聯。

use axum::Json;
use axum::extract::State;
use chrono::{Duration, Utc};
use protocol::{RenewRequest, RenewResponse};

use crate::AppState;
use crate::checkin::RENEW_BEFORE_DAYS;
use crate::error::AppError;
use crate::identity::AuthedDevice;

pub async fn renew(
    State(st): State<AppState>,
    device: AuthedDevice,
    Json(req): Json<RenewRequest>,
) -> Result<Json<RenewResponse>, AppError> {
    if device.cert_not_after - Utc::now() >= Duration::days(RENEW_BEFORE_DAYS) {
        return Err(AppError::BadRequest("renewal not due".into()));
    }
    let issued = st
        .ca
        .sign_device_csr(&req.csr_pem, device.device_id, Utc::now())
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    sqlx::query(
        "INSERT INTO device_certs (serial, fingerprint, device_id, not_after) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&issued.serial)
    .bind(&issued.fingerprint)
    .bind(device.device_id)
    .bind(issued.not_after)
    .execute(&st.pool)
    .await?;
    tracing::info!(device_id = %device.device_id, "certificate renewed");
    Ok(Json(RenewResponse {
        certificate_chain_pem: format!("{}{}", issued.pem, st.ca.chain_pem()),
    }))
}
