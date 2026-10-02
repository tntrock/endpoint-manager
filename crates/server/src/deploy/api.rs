//! Agent 端：下載套件、回報派送結果。只有目前被指派（或暫停前被指派）的裝置能使用。

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use protocol::deploy::{DeployResult, DeployStatus, PackageSpec};
use serde_json::json;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

use super::store::file_path;
use crate::AppState;
use crate::error::AppError;
use crate::identity::AuthedDevice;

const CHUNK: usize = 64 * 1024;

/// (群組, 是否使用中)
async fn device_scope(st: &AppState, device_id: Uuid) -> Result<(Option<i64>, bool), AppError> {
    let (group, status): (Option<i64>, String) =
        sqlx::query_as("SELECT group_id, status FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&st.pool)
            .await?;
    Ok((group, status == "active"))
}

/// 裝置能否下載這個套件：使用中、在某個派送的範圍內。
/// 暫停中的派送仍允許（安裝可能在暫停前就開始了）。中央下載與分點快取授權共用。
pub async fn device_may_download(
    st: &AppState,
    device_id: Uuid,
    package_id: i64,
) -> Result<Option<PackageSpec>, AppError> {
    let (group, active) = device_scope(st, device_id).await?;
    if !active {
        return Ok(None);
    }
    let set = st.deploy.get_throttled(&st.pool).await?;
    Ok(set
        .deployments
        .iter()
        .find(|d| d.package.id == package_id && d.targets(group))
        .map(|d| d.package.clone()))
}

pub async fn download(
    State(st): State<AppState>,
    device: AuthedDevice,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let spec = device_may_download(&st, device.device_id, id)
        .await?
        .ok_or(AppError::NotFound)?;
    stream_package(&st, id, &spec.sha256).await
}

/// 串流套件檔案（端點向中央下載、分點快取補抓都用這個），共用同時下載數上限
pub async fn stream_package(st: &AppState, id: i64, sha256: &str) -> Result<Response, AppError> {
    // 先取許可再開檔：許可跟著串流，串流結束或中斷（連線斷掉）時歸還
    let permit = st
        .downloads
        .clone()
        .try_acquire_owned()
        .map_err(|_| AppError::Busy)?;
    let path = file_path(&st.package_dir, sha256);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::error!(package_id = id, path = %path.display(), "package file missing");
            return Err(AppError::NotFound);
        }
        Err(e) => return Err(AppError::Internal(e.into())),
    };
    let len = file
        .metadata()
        .await
        .map_err(|e| AppError::Internal(e.into()))?
        .len();
    let stream = futures_util::stream::unfold(Some((file, permit)), |state| async move {
        let (mut file, permit) = state?;
        let mut buf = vec![0u8; CHUNK];
        match file.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((
                    Ok::<_, std::io::Error>(Bytes::from(buf)),
                    Some((file, permit)),
                ))
            }
            Err(e) => Some((Err(e), None)),
        }
    });
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_LENGTH, len.to_string()),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}

pub async fn result(
    State(st): State<AppState>,
    device: AuthedDevice,
    Path(id): Path<i64>,
    Json(r): Json<DeployResult>,
) -> Result<StatusCode, AppError> {
    r.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    let (group, active) = device_scope(&st, device.device_id).await?;
    let set = st.deploy.get_throttled(&st.pool).await?;
    // 暫停中的派送仍接受回報：安裝可能在暫停前就開始了
    let dep = set
        .find(id)
        .filter(|d| active && d.targets(group))
        .ok_or(AppError::NotFound)?;
    if r.revision > dep.revision {
        return Err(AppError::BadRequest(
            "revision is newer than the deployment".into(),
        ));
    }
    let message: String = r.message.chars().filter(|c| !c.is_control()).collect();
    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "INSERT INTO deployment_status \
           (deployment_id, device_id, status, exit_code, message, attempts, revision, source) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (deployment_id, device_id) DO UPDATE SET status = EXCLUDED.status, \
           exit_code = EXCLUDED.exit_code, message = EXCLUDED.message, \
           attempts = EXCLUDED.attempts, revision = EXCLUDED.revision, \
           source = EXCLUDED.source, updated_at = now() \
         WHERE deployment_status.revision <= EXCLUDED.revision",
    )
    .bind(dep.id)
    .bind(device.device_id)
    .bind(r.status.as_str())
    .bind(r.exit_code)
    .bind(&message)
    .bind(r.attempts)
    .bind(r.revision)
    .bind(r.source.and_then(|s| s.as_str()))
    .execute(&mut *tx)
    .await
    .map_err(|e| match &e {
        // 派送剛被刪除（快取還沒更新）
        sqlx::Error::Database(d) if d.is_foreign_key_violation() => AppError::NotFound,
        _ => AppError::Db(e),
    })?;
    if r.status == DeployStatus::Failed {
        auto_pause(&mut tx, dep.id).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// 目前 revision 下有實際嘗試過的裝置（不含 compliant）達到最少樣本數，且失敗率超過門檻時暫停。
/// 用 FOR NO KEY UPDATE：寫入 deployment_status 時外鍵已對派送列取 KEY SHARE，
/// FOR UPDATE 會和其他同時回報的交易互等成死結。
async fn auto_pause(conn: &mut sqlx::PgConnection, id: i64) -> Result<(), sqlx::Error> {
    let row: Option<(String, String, i32, i32, i32)> = sqlx::query_as(
        "SELECT name, stage, revision, max_failure_pct, min_samples FROM deployments \
         WHERE id = $1 FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((name, stage, revision, max_pct, min_samples)) = row else {
        return Ok(());
    };
    if stage != "pilot" && stage != "all" {
        return Ok(());
    }
    let (total, failed): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE status = 'failed') FROM deployment_status \
         WHERE deployment_id = $1 AND revision = $2 AND status <> 'compliant'",
    )
    .bind(id)
    .bind(revision)
    .fetch_one(&mut *conn)
    .await?;
    if total < i64::from(min_samples) || failed * 100 <= i64::from(max_pct) * total {
        return Ok(());
    }
    sqlx::query(
        "UPDATE deployments SET stage = 'paused', paused_from = stage, updated_at = now() \
         WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;
    sqlx::query("UPDATE deploy_state SET generation = generation + 1")
        .execute(&mut *conn)
        .await?;
    tracing::warn!(deployment_id = id, failed, total, "deployment auto-paused");
    crate::audit::record(
        conn,
        "system",
        "deployment_auto_pause",
        Some(&name),
        json!({"id": id, "revision": revision, "failed": failed, "samples": total, "max_failure_pct": max_pct}),
    )
    .await
}
