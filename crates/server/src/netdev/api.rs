//! 快取上傳查詢結果：`POST /v1/cache/netdata`（mTLS，快取憑證）。

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use protocol::netdev::NetData;

use crate::AppState;
use crate::branch::api::AuthedCache;
use crate::error::AppError;

pub async fn netdata(
    State(st): State<AppState>,
    cache: AuthedCache,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    let body = crate::inventory::decode_body(&headers, &body)?;
    let d: NetData = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("invalid netdata: {e}")))?;
    // 只接受這台快取所屬據點的設備（設備改到其他據點後，舊快取的結果不再寫入）
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM net_devices WHERE id = $1 AND site_id = $2 AND enabled)",
    )
    .bind(d.device_id)
    .bind(cache.site_id)
    .fetch_one(&st.pool)
    .await?;
    if !ok {
        return Err(AppError::NotFound);
    }
    super::ingest::store(&st.pool, &d).await?;
    Ok(StatusCode::NO_CONTENT)
}
