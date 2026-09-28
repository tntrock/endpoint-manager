//! 管理員帳號規則。權限（只有平台管理員能呼叫）由網頁層檢查。

use anyhow::{Context, ensure};
use sqlx::{PgConnection, PgPool};

use crate::audit;
use crate::web::auth::{MIN_PASSWORD_LEN, Role, hash_password};

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

/// pg_advisory_xact_lock 的鍵：平台管理員數量檢查
const PLATFORM_ADMIN_LOCK: i64 = 0x454d_0001;

/// 交易結束前確認至少還有一個啟用中的平台管理員。
/// 先取得同一把交易鎖依序檢查，避免兩個交易各自只看到自己的變更而同時通過（write skew）。
async fn ensure_platform_admin_left(conn: &mut PgConnection) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(PLATFORM_ADMIN_LOCK)
        .execute(&mut *conn)
        .await?;
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
    let (current, username): (String, String) =
        sqlx::query_as("SELECT role, username FROM admins WHERE id = $1 FOR UPDATE")
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
        Some(&username),
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
    let username: String = sqlx::query_scalar(
        "UPDATE admins SET disabled_at = CASE WHEN $2 THEN coalesce(disabled_at, now()) ELSE NULL END \
         WHERE id = $1 RETURNING username",
    )
    .bind(id)
    .bind(disabled)
    .fetch_optional(&mut *tx)
    .await?
    .context("帳號不存在")?;
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
        Some(&username),
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
    let username: String = sqlx::query_scalar(
        "UPDATE admins SET password_hash = $2, failed_logins = 0, locked_until = NULL \
         WHERE id = $1 RETURNING username",
    )
    .bind(id)
    .bind(hash)
    .fetch_optional(&mut *tx)
    .await?
    .context("帳號不存在")?;
    kill_sessions(&mut tx, id).await?;
    audit::record(
        &mut tx,
        actor,
        "admin_password_reset",
        Some(&username),
        serde_json::json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn unlock(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let username: String = sqlx::query_scalar(
        "UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1 RETURNING username",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .context("帳號不存在")?;
    audit::record(
        &mut tx,
        actor,
        "admin_unlock",
        Some(&username),
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
    let mut tx = pool.begin().await?;
    let (username, hash, locked): (String, String, bool) = sqlx::query_as(
        "SELECT username, password_hash, coalesce(locked_until > now(), false) \
         FROM admins WHERE id = $1 FOR UPDATE",
    )
    .bind(admin_id)
    .fetch_one(&mut *tx)
    .await?;
    ensure!(!locked, "帳號已鎖定，請稍後再試");
    // 目前密碼輸錯與登入共用失敗次數：到上限就鎖定並登出所有工作階段
    if !crate::web::auth::verify_blocking(current, &hash).await {
        if crate::web::auth::record_failure(&mut tx, admin_id).await? {
            kill_sessions(&mut tx, admin_id).await?;
        }
        audit::record(
            &mut tx,
            &username,
            "password_change_failed",
            None,
            serde_json::json!({}),
        )
        .await?;
        tx.commit().await?;
        anyhow::bail!("目前密碼錯誤");
    }
    let new_hash = hash_password(new)?;
    sqlx::query("UPDATE admins SET password_hash = $2, failed_logins = 0 WHERE id = $1")
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

    async fn platform(pool: &PgPool, name: &str) -> i64 {
        create(
            pool,
            &NewAdmin {
                username: name.into(),
                password: format!("{name}-long-password"),
                role: Role::Platform,
                groups: vec![],
            },
            "root",
        )
        .await
        .unwrap()
    }

    /// 兩個平台管理員同時停用對方：各自的交易只看得到自己的變更，檢查都通過，結果一個都不剩。
    #[sqlx::test(migrations = false)]
    async fn concurrent_disables_keep_one_platform_admin(pool: PgPool) {
        let (root, g) = setup(&pool).await;
        for round in 0..10 {
            let a = platform(&pool, &format!("a{round}")).await;
            let b = platform(&pool, &format!("b{round}")).await;
            // 只留 a、b 兩個平台管理員
            sqlx::query("UPDATE admins SET disabled_at = now() WHERE role = 'platform_admin' AND id NOT IN ($1, $2)")
                .bind(a)
                .bind(b)
                .execute(&pool)
                .await
                .unwrap();
            let (_ra, _rb) = tokio::join!(
                set_disabled(&pool, b, true, a, "a"),
                set_disabled(&pool, a, true, b, "b"),
            );
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM admins WHERE role = 'platform_admin' AND disabled_at IS NULL",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(n >= 1, "round {round}: no platform admin left");
            let _ = (root, g);
        }
    }

    /// 稽核記錄的對象用帳號名稱，不是內部數字 id。
    #[sqlx::test(migrations = false)]
    async fn admin_audit_targets_are_usernames(pool: PgPool) {
        let (root, g) = setup(&pool).await;
        let bob = create(
            &pool,
            &NewAdmin {
                username: "bob".into(),
                password: "bob-long-password".into(),
                role: Role::Viewer,
                groups: vec![g],
            },
            "root",
        )
        .await
        .unwrap();
        update(&pool, bob, Role::GroupAdmin, &[g], root, "root")
            .await
            .unwrap();
        set_disabled(&pool, bob, true, root, "root").await.unwrap();
        set_disabled(&pool, bob, false, root, "root").await.unwrap();
        reset_password(&pool, bob, "bob-new-long-password", "root")
            .await
            .unwrap();
        unlock(&pool, bob, "root").await.unwrap();
        let targets: Vec<Option<String>> = sqlx::query_scalar(
            "SELECT target FROM audit_log WHERE action LIKE 'admin_%' AND action <> 'admin_create'",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(targets.len(), 5);
        assert!(
            targets.iter().all(|t| t.as_deref() == Some("bob")),
            "{targets:?}"
        );
    }

    /// 修改密碼時輸錯目前密碼，與登入共用失敗次數：到上限就鎖定並登出所有工作階段。
    #[sqlx::test(migrations = false)]
    async fn wrong_current_password_locks_account(pool: PgPool) {
        let (root, _) = setup(&pool).await;
        sqlx::query(
            "INSERT INTO sessions (token_hash, admin_id, csrf_token, expires_at) \
             VALUES ('h', $1, 'c', now() + interval '1 hour')",
        )
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
        for _ in 0..crate::web::auth::MAX_FAILED_LOGINS {
            assert!(
                change_own_password(&pool, root, "wrong-password-xx", "new-long-password", "h")
                    .await
                    .is_err()
            );
        }
        let (locked, sessions): (bool, i64) = sqlx::query_as(
            "SELECT locked_until > now(), (SELECT count(*) FROM sessions WHERE admin_id = $1) \
             FROM admins WHERE id = $1",
        )
        .bind(root)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(locked, "達到上限要鎖定");
        assert_eq!(sessions, 0, "鎖定時登出所有工作階段");
        // 鎖定中：即使密碼正確也不能改
        assert!(
            change_own_password(&pool, root, "root-long-password", "new-long-password", "h")
                .await
                .is_err()
        );
    }
}
