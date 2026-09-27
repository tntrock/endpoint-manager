//! 註冊金鑰。資料庫只存 SHA-256；查詢以 hash 比對，不會有逐字元比較的時序洩漏。

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

pub struct NewToken {
    pub name: String,
    pub group_label: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub max_uses: i32,
    pub created_by: String,
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn generate_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub async fn create_token(pool: &PgPool, t: &NewToken) -> Result<(i64, String), sqlx::Error> {
    let token = generate_token();
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO enroll_tokens (name, token_hash, group_label, expires_at, max_uses, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(&t.name)
    .bind(hash_token(&token))
    .bind(&t.group_label)
    .bind(t.expires_at)
    .bind(t.max_uses)
    .bind(&t.created_by)
    .fetch_one(pool)
    .await?;
    Ok((id, token))
}

/// 單一 UPDATE 完成檢查與遞增，並發時也不會超過 max_uses。
pub async fn consume_token(
    conn: &mut PgConnection,
    token: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE enroll_tokens SET used_count = used_count + 1 \
         WHERE token_hash = $1 AND revoked_at IS NULL \
           AND (expires_at IS NULL OR expires_at > now()) \
           AND used_count < max_uses \
         RETURNING id",
    )
    .bind(hash_token(token))
    .fetch_optional(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_token(max_uses: i32, expires_at: Option<DateTime<Utc>>) -> NewToken {
        NewToken {
            name: "t".into(),
            group_label: None,
            expires_at,
            max_uses,
            created_by: "test".into(),
        }
    }

    #[sqlx::test(migrations = false)]
    async fn consume_respects_max_uses(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let (id, tok) = create_token(&pool, &new_token(1, None)).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        assert_eq!(consume_token(&mut c, &tok).await.unwrap(), Some(id));
        assert_eq!(consume_token(&mut c, &tok).await.unwrap(), None);
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
        assert_eq!(consume_token(&mut c, &expired).await.unwrap(), None);
        assert_eq!(consume_token(&mut c, &revoked).await.unwrap(), None);
        assert_eq!(consume_token(&mut c, "nope").await.unwrap(), None);
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
