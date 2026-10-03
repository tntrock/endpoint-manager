//! 註冊金鑰。資料庫只存 SHA-256；查詢以 hash 比對，不會有逐字元比較的時序洩漏。

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

/// 金鑰用途：註冊裝置或註冊分點快取，彼此不能混用
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TokenKind {
    #[default]
    Device,
    Cache,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Device => "device",
            TokenKind::Cache => "cache",
        }
    }
}

pub struct NewToken {
    pub name: String,
    pub group_id: Option<i64>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: i32,
    pub created_by: String,
    pub kind: TokenKind,
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub async fn create_token(pool: &PgPool, t: &NewToken) -> Result<(i64, String), sqlx::Error> {
    create_token_in(&mut *pool.acquire().await?, t).await
}

/// 指令列 `token-create`：群組（不存在就建立）、金鑰與稽核記錄在同一個交易；
/// 稽核內容的格式與網頁相同
pub async fn create_token_cli(
    pool: &PgPool,
    name: &str,
    max_uses: i32,
    group: Option<&str>,
    valid_days: Option<i64>,
) -> Result<(i64, String), sqlx::Error> {
    const ACTOR: &str = "cli";
    let mut tx = pool.begin().await?;
    let group_id = match group {
        Some(g) => {
            let created: Option<i64> = sqlx::query_scalar(
                "INSERT INTO device_groups (name) VALUES ($1) ON CONFLICT (name) DO NOTHING \
                 RETURNING id",
            )
            .bind(g)
            .fetch_optional(&mut *tx)
            .await?;
            match created {
                Some(id) => {
                    crate::audit::record(
                        &mut tx,
                        ACTOR,
                        "group_create",
                        Some(g),
                        serde_json::json!({ "id": id }),
                    )
                    .await?;
                    Some(id)
                }
                None => Some(
                    sqlx::query_scalar("SELECT id FROM device_groups WHERE name = $1")
                        .bind(g)
                        .fetch_one(&mut *tx)
                        .await?,
                ),
            }
        }
        None => None,
    };
    let (id, token) = create_token_in(
        &mut tx,
        &NewToken {
            name: name.into(),
            group_id,
            expires_at: valid_days.map(|d| Utc::now() + chrono::Duration::days(d)),
            max_uses,
            created_by: ACTOR.into(),
            kind: TokenKind::Device,
        },
    )
    .await?;
    crate::audit::record(
        &mut tx,
        ACTOR,
        "token_create",
        Some(&id.to_string()),
        serde_json::json!({
            "name": name, "max_uses": max_uses, "group_id": group_id, "valid_days": valid_days,
            "installer": false, "server_url": null
        }),
    )
    .await?;
    tx.commit().await?;
    Ok((id, token))
}

/// 在呼叫端的交易內建立（與稽核記錄一起提交）。
pub async fn create_token_in(
    conn: &mut PgConnection,
    t: &NewToken,
) -> Result<(i64, String), sqlx::Error> {
    let token = generate_token();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO enroll_tokens \
         (name, token_hash, group_id, expires_at, max_uses, created_by, kind) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(&t.name)
    .bind(hash_token(&token))
    .bind(t.group_id)
    .bind(t.expires_at)
    .bind(t.max_uses)
    .bind(&t.created_by)
    .bind(t.kind.as_str())
    .fetch_one(conn)
    .await?;
    Ok((id, token))
}

/// 單一 UPDATE 完成檢查與遞增，並發時也不會超過 max_uses。回傳 (金鑰 id, 群組 id)。
pub async fn consume_token(
    conn: &mut PgConnection,
    token: &str,
    kind: TokenKind,
) -> Result<Option<(i64, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "UPDATE enroll_tokens SET used_count = used_count + 1 \
         WHERE token_hash = $1 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND used_count < max_uses AND kind = $2 \
         RETURNING id, group_id",
    )
    .bind(hash_token(token))
    .bind(kind.as_str())
    .fetch_optional(conn)
    .await
}

pub async fn revoke_token(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE enroll_tokens SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    anyhow::ensure!(n == 1, "token not found or already revoked");
    crate::audit::record(
        &mut tx,
        actor,
        "token_revoke",
        Some(&id.to_string()),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 指令列建立金鑰也要寫稽核記錄（與網頁建立相同的 action）
    #[sqlx::test(migrations = false)]
    async fn cli_token_create_is_audited(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let (id, _) = create_token_cli(&pool, "t", 5, None, None).await.unwrap();
        let (actor, target): (String, Option<String>) =
            sqlx::query_as("SELECT actor, target FROM audit_log WHERE action = 'token_create'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((actor.as_str(), target), ("cli", Some(id.to_string())));
    }

    fn new_token(max_uses: i32, expires_at: Option<DateTime<Utc>>) -> NewToken {
        NewToken {
            name: "t".into(),
            group_id: None,
            expires_at,
            max_uses,
            created_by: "test".into(),
            kind: TokenKind::Device,
        }
    }

    #[sqlx::test(migrations = false)]
    async fn consume_respects_max_uses(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let (id, tok) = create_token(&pool, &new_token(1, None)).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        assert_eq!(
            consume_token(&mut c, &tok, TokenKind::Device)
                .await
                .unwrap(),
            Some((id, None))
        );
        assert_eq!(
            consume_token(&mut c, &tok, TokenKind::Device)
                .await
                .unwrap(),
            None
        );
    }

    #[sqlx::test(migrations = false)]
    async fn expired_revoked_and_wrong_tokens_rejected(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let past = Utc::now() - chrono::Duration::hours(1);
        let (_, expired) = create_token(&pool, &new_token(10, Some(past)))
            .await
            .unwrap();
        let (rid, revoked) = create_token(&pool, &new_token(10, None)).await.unwrap();
        sqlx::query("UPDATE enroll_tokens SET revoked_at = now() WHERE id = $1")
            .bind(rid)
            .execute(&pool)
            .await
            .unwrap();
        let mut c = pool.acquire().await.unwrap();
        assert_eq!(
            consume_token(&mut c, &expired, TokenKind::Device)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            consume_token(&mut c, &revoked, TokenKind::Device)
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            consume_token(&mut c, "nope", TokenKind::Device)
                .await
                .unwrap(),
            None
        );
    }

    #[sqlx::test(migrations = false)]
    async fn plaintext_is_not_stored(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let (_, tok) = create_token(&pool, &new_token(1, None)).await.unwrap();
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM enroll_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stored, tok);
        assert_eq!(stored, hash_token(&tok));
    }
}
