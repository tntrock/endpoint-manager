//! Agent 端：報到時下發待執行的指令、回報結果。

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use protocol::command::{
    Command, CommandAction, CommandResult, MAX_COMMANDS_PER_CHECKIN, ScriptSpec,
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;
use crate::error::AppError;
use crate::identity::AuthedDevice;

type PendingRow = (
    i64,
    String,
    Option<i32>,
    Option<String>,
    Option<String>,
    Option<i32>,
    String,
);

/// 這台還沒完成、沒過期、沒取消的指令（由舊到新最多 10 筆）；收到結果前每次都重送。
/// 沒有指令時只有一次走部分索引的查詢，不寫入。
/// 鎖住選到的指令列並在同一個交易裡改成已送出：同時被取消的指令，
/// 取消先完成時重新檢查後排除，不會送出已取消的指令。
pub async fn pending_for(pool: &PgPool, device: Uuid) -> Result<Vec<Command>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let rows: Vec<PendingRow> = sqlx::query_as(
        "SELECT t.id, r.action, r.delay_minutes, r.script_sha256, r.script_content, \
                r.script_timeout_minutes, t.status \
         FROM command_targets t JOIN command_runs r ON r.id = t.run_id \
         WHERE t.device_id = $1 AND t.status IN ('pending', 'sent') \
           AND r.canceled_at IS NULL AND r.expires_at > now() \
         ORDER BY t.id LIMIT $2 FOR UPDATE OF t",
    )
    .bind(device)
    .bind(MAX_COMMANDS_PER_CHECKIN)
    .fetch_all(&mut *tx)
    .await?;
    let fresh: Vec<i64> = rows
        .iter()
        .filter(|r| r.6 == "pending")
        .map(|r| r.0)
        .collect();
    if !fresh.is_empty() {
        sqlx::query(
            "UPDATE command_targets SET status = 'sent', sent_at = now() \
             WHERE id = ANY($1) AND status = 'pending'",
        )
        .bind(&fresh)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .map(|(id, action, delay, sha, content, timeout, _)| {
            let action = CommandAction::parse(&action);
            Command {
                id,
                action,
                delay_minutes: delay.and_then(|d| u32::try_from(d).ok()),
                script: match (action, sha, content) {
                    (CommandAction::Script, Some(sha256), Some(content)) => Some(ScriptSpec {
                        sha256,
                        content,
                        timeout_minutes: timeout.and_then(|t| u32::try_from(t).ok()).unwrap_or(30),
                    }),
                    _ => None,
                },
            }
        })
        .collect())
}

pub async fn result(
    State(st): State<AppState>,
    device: AuthedDevice,
    Path(id): Path<i64>,
    Json(r): Json<CommandResult>,
) -> Result<StatusCode, AppError> {
    r.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    // 控制字元與格式字元（例如 U+202E 反轉方向）都移除，換行與 Tab 保留
    let output: String = protocol::command::strip_format_chars(&r.output)
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect();
    let updated = sqlx::query(
        "UPDATE command_targets SET status = $3, exit_code = $4, output = $5, finished_at = now() \
         WHERE id = $1 AND device_id = $2 AND status IN ('pending', 'sent')",
    )
    .bind(id)
    .bind(device.device_id)
    .bind(r.status.as_str())
    .bind(r.exit_code)
    .bind(&output)
    .execute(&st.pool)
    .await?
    .rows_affected();
    if updated == 0 {
        // 已有結果、已取消或已過期：忽略；不是這台的指令才回 404
        let mine: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM command_targets WHERE id = $1 AND device_id = $2)",
        )
        .bind(id)
        .bind(device.device_id)
        .fetch_one(&st.pool)
        .await?;
        if !mine {
            return Err(AppError::NotFound);
        }
    }
    Ok(StatusCode::NO_CONTENT)
}
