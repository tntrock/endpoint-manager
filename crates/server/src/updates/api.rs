//! Agent 端：回報 Windows Update 原則的套用狀態。

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use protocol::update::UpdateStatus;

use crate::AppState;
use crate::error::AppError;
use crate::identity::AuthedDevice;

pub async fn status(
    State(st): State<AppState>,
    device: AuthedDevice,
    Json(s): Json<UpdateStatus>,
) -> Result<StatusCode, AppError> {
    s.validate(Utc::now())
        .map_err(|e| AppError::BadRequest(e.into()))?;
    let detail: String = s.detail.chars().filter(|c| !c.is_control()).collect();
    sqlx::query(
        "INSERT INTO update_policy_status (device_id, policy_id, revision, state, detail, \
           reboot_pending, reboot_pending_since, last_patch_date) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (device_id) DO UPDATE SET policy_id = EXCLUDED.policy_id, \
           revision = EXCLUDED.revision, state = EXCLUDED.state, detail = EXCLUDED.detail, \
           reboot_pending = EXCLUDED.reboot_pending, \
           reboot_pending_since = EXCLUDED.reboot_pending_since, \
           last_patch_date = EXCLUDED.last_patch_date, updated_at = now()",
    )
    .bind(device.device_id)
    .bind(s.policy_id)
    .bind(s.revision)
    .bind(s.state.as_str())
    .bind(&detail)
    .bind(s.reboot_pending)
    .bind(s.reboot_pending_since)
    .bind(s.last_patch_date)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
