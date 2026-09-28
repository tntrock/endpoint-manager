//! 裝置群組：分權的單位。

use sqlx::PgConnection;

pub async fn find_or_create(conn: &mut PgConnection, name: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO device_groups (name) VALUES ($1) \
         ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(name)
    .fetch_one(conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test(migrations = false)]
    async fn find_or_create_is_idempotent(pool: PgPool) {
        crate::db::migrate(&pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let a = find_or_create(&mut c, "高雄廠").await.unwrap();
        let b = find_or_create(&mut c, "高雄廠").await.unwrap();
        assert_eq!(a, b);
    }
}
