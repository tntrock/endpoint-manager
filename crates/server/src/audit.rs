//! 稽核記錄：誰在什麼時間做了什麼。

use sqlx::PgConnection;

pub async fn record(
    conn: &mut PgConnection,
    actor: &str,
    action: &str,
    target: Option<&str>,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4::jsonb)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(detail.to_string())
    .execute(conn)
    .await?;
    Ok(())
}
