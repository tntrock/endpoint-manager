//! 管理員帳號規則。權限（只有平台管理員能呼叫）由網頁層檢查。

use anyhow::{Context, ensure};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::web::auth::{MIN_PASSWORD_LEN, Role, hash_password, verify_password};

pub struct NewAdmin {
    pub username: String,
    pub password: String,
    pub role: Role,
    pub groups: Vec<i64>,
}

fn check_password(pw: &str) -> anyhow::Result<()> {
    ensure!(
        pw.chars().count() >= MIN_PASSWORD_LEN,
        "密碼至少 {MIN_PASSWORD_LEN} 字元"
    );
    Ok(())
}

fn check_role_groups(role: Role, groups: &[i64]) -> anyhow::Result<()> {
    ensure!(
        role == Role::Platform || !groups.is_empty(),
        "群組管理員與唯讀檢視者至少要指派一個群組"
    );
    Ok(())
}

async fn set_groups(
    conn: &mut PgConnection,
    id: i64,
    role: Role,
    groups: &[i64],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM admin_groups WHERE admin_id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    if role != Role::Platform {
        sqlx::query(
            "INSERT INTO admin_groups (admin_id, group_id) SELECT $1, unnest($2::bigint[])",
        )
        .bind(id)
        .bind(groups)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

async fn kill_sessions(conn: &mut PgConnection, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
        .bind(id)
        .execute(conn)
        .await?;
    Ok(())
}

/// 交易結束前確認至少還有一個啟用中的平台管理員。
async fn ensure_platform_admin_left(conn: &mut PgConnection) -> anyhow::Result<()> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admins WHERE role = 'platform_admin' AND disabled_at IS NULL",
    )
    .fetch_one(conn)
    .await?;
    ensure!(n >= 1, "至少要保留一個啟用中的平台管理員");
    Ok(())
}

pub async fn create(pool: &PgPool, a: &NewAdmin, actor: &str) -> anyhow::Result<i64> {
    let username = a.username.trim();
    ensure!(
        !username.is_empty() && username.chars().count() <= 64,
        "帳號必填，最多 64 字"
    );
    check_password(&a.password)?;
    check_role_groups(a.role, &a.groups)?;
    let hash = hash_password(&a.password)?;
    let mut tx = pool.begin().await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO admins (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(username)
    .bind(hash)
    .bind(a.role.as_str())
    .fetch_one(&mut *tx)
    .await
    .context("帳號已存在")?;
    set_groups(&mut tx, id, a.role, &a.groups).await?;
    audit::record(
        &mut tx,
        actor,
        "admin_create",
        Some(username),
        serde_json::json!({ "role": a.role.as_str(), "groups": a.groups }),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update(
    pool: &PgPool,
    id: i64,
    role: Role,
    groups: &[i64],
    actor_id: i64,
    actor: &str,
) -> anyhow::Result<()> {
    check_role_groups(role, groups)?;
    let mut tx = pool.begin().await?;
    let current: String = sqlx::query_scalar("SELECT role FROM admins WHERE id = $1 FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .context("帳號不存在")?;
    ensure!(
        id != actor_id || current == role.as_str(),
        "不能變更自己的角色"
    );
    sqlx::query("UPDATE admins SET role = $2 WHERE id = $1")
        .bind(id)
        .bind(role.as_str())
        .execute(&mut *tx)
        .await?;
    set_groups(&mut tx, id, role, groups).await?;
    if id != actor_id {
        kill_sessions(&mut tx, id).await?;
    }
    ensure_platform_admin_left(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "admin_update",
        Some(&id.to_string()),
        serde_json::json!({ "role": role.as_str(), "groups": groups }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn set_disabled(
    pool: &PgPool,
    id: i64,
    disabled: bool,
    actor_id: i64,
    actor: &str,
) -> anyhow::Result<()> {
    ensure!(id != actor_id, "不能停用或啟用自己");
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE admins SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) ELSE NULL END \
         WHERE id = $1",
    )
    .bind(id)
    .bind(disabled)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    ensure!(n == 1, "帳號不存在");
    kill_sessions(&mut tx, id).await?;
    ensure_platform_admin_left(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        if disabled {
            "admin_disable"
        } else {
            "admin_enable"
        },
        Some(&id.to_string()),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn reset_password(
    pool: &PgPool,
    id: i64,
    new_password: &str,
    actor: &str,
) -> anyhow::Result<()> {
    check_password(new_password)?;
    let hash = hash_password(new_password)?;
    let mut tx = pool.begin().await?;
    let n = sqlx::query(
        "UPDATE admins SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1",
    )
    .bind(id)
    .bind(hash)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    ensure!(n == 1, "帳號不存在");
    kill_sessions(&mut tx, id).await?;
    audit::record(
        &mut tx,
        actor,
        "admin_password_reset",
        Some(&id.to_string()),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn unlock(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let n = sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    ensure!(n == 1, "帳號不存在");
    audit::record(
        &mut tx,
        actor,
        "admin_unlock",
        Some(&id.to_string()),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// 驗證目前密碼後更新；保留目前的工作階段，登出其他裝置上的工作階段。
pub async fn change_own_password(
    pool: &PgPool,
    admin_id: i64,
    current: &str,
    new: &str,
    keep_token_hash: &str,
) -> anyhow::Result<()> {
    check_password(new)?;
    let (username, hash): (String, String) =
        sqlx::query_as("SELECT username, password_hash FROM admins WHERE id = $1")
            .bind(admin_id)
            .fetch_one(pool)
            .await?;
    ensure!(verify_password(current, &hash), "目前密碼錯誤");
    let new_hash = hash_password(new)?;
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE admins SET password_hash = $2 WHERE id = $1")
        .bind(admin_id)
        .bind(new_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE admin_id = $1 AND token_hash <> $2")
        .bind(admin_id)
        .bind(keep_token_hash)
        .execute(&mut *tx)
        .await?;
    audit::record(
        &mut tx,
        &username,
        "password_change",
        None,
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::auth::Role;

    async fn setup(pool: &PgPool) -> (i64, i64) {
        crate::db::migrate(pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let g = crate::groups::find_or_create(&mut c, "台北總部")
            .await
            .unwrap();
        let root = create(
            pool,
            &NewAdmin {
                username: "root".into(),
                password: "root-long-password".into(),
                role: Role::Platform,
                groups: vec![],
            },
            "cli",
        )
        .await
        .unwrap();
        (root, g)
    }

    #[test]
    fn hash_roundtrip() {
        let h = crate::web::auth::hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(crate::web::auth::verify_password(
            "correct horse battery",
            &h
        ));
        assert!(!crate::web::auth::verify_password("wrong password!!", &h));
        assert!(!crate::web::auth::verify_password("x", "not a phc string"));
    }

    #[sqlx::test(migrations = false)]
    async fn create_validates(pool: PgPool) {
        let (_, g) = setup(&pool).await;
        let mk = |pw: &str, role, groups: Vec<i64>| NewAdmin {
            username: "bob".into(),
            password: pw.into(),
            role,
            groups,
        };
        assert!(
            create(&pool, &mk("short", Role::Viewer, vec![g]), "root")
                .await
                .is_err(),
            "密碼太短"
        );
        assert!(
            create(
                &pool,
                &mk("bob-long-password", Role::GroupAdmin, vec![]),
                "root"
            )
            .await
            .is_err(),
            "需要群組"
        );
        create(
            &pool,
            &mk("bob-long-password", Role::GroupAdmin, vec![g]),
            "root",
        )
        .await
        .unwrap();
        assert!(
            create(
                &pool,
                &mk("bob-long-password", Role::Viewer, vec![g]),
                "root"
            )
            .await
            .is_err(),
            "帳號重複"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn last_platform_admin_is_protected(pool: PgPool) {
        let (root, g) = setup(&pool).await;
        assert!(
            set_disabled(&pool, root, true, root, "root").await.is_err(),
            "不能停用自己"
        );
        assert!(
            update(&pool, root, Role::Viewer, &[g], root, "root")
                .await
                .is_err(),
            "不能改自己的角色"
        );
        let other = create(
            &pool,
            &NewAdmin {
                username: "ops".into(),
                password: "ops-long-password".into(),
                role: Role::Platform,
                groups: vec![],
            },
            "root",
        )
        .await
        .unwrap();
        // ops 降級 root 可以（還剩 ops）；再停用 ops 不行（會沒有平台管理員）
        update(&pool, root, Role::Viewer, &[g], other, "ops")
            .await
            .unwrap();
        assert!(
            set_disabled(&pool, other, true, root, "root")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = false)]
    async fn change_own_password_checks_current(pool: PgPool) {
        let (root, _) = setup(&pool).await;
        assert!(
            change_own_password(&pool, root, "wrong-password-xx", "new-long-password", "x")
                .await
                .is_err()
        );
        assert!(
            change_own_password(&pool, root, "root-long-password", "short", "x")
                .await
                .is_err()
        );
        change_own_password(&pool, root, "root-long-password", "new-long-password", "x")
            .await
            .unwrap();
        let hash: String = sqlx::query_scalar("SELECT password_hash FROM admins WHERE id = $1")
            .bind(root)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(crate::web::auth::verify_password(
            "new-long-password",
            &hash
        ));
    }
}
