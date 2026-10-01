//! 背景工作：把過期仍未完成的指令標成「已過期」。

use std::time::Duration;

use sqlx::PgPool;

const EVERY: Duration = Duration::from_secs(300);

/// 回傳標成過期的筆數
pub async fn expire(pool: &PgPool) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query(
        "UPDATE command_targets t SET status = 'expired', finished_at = now() \
         FROM command_runs r \
         WHERE r.id = t.run_id AND t.status IN ('pending', 'sent') AND r.expires_at <= now()",
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub fn spawn(pool: PgPool) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(EVERY);
        loop {
            tick.tick().await;
            match expire(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(expired = n, "remote commands expired"),
                Err(e) => tracing::error!(error = %e, "remote command expiry failed"),
            }
        }
    });
}
