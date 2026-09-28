//! 管理員角色、密碼、工作階段與 CSRF。

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

pub const MIN_PASSWORD_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Platform,
    GroupAdmin,
    Viewer,
}

impl Role {
    pub const ALL: [Role; 3] = [Role::Platform, Role::GroupAdmin, Role::Viewer];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Platform => "platform_admin",
            Role::GroupAdmin => "group_admin",
            Role::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            Role::Platform => "平台管理員",
            Role::GroupAdmin => "群組管理員",
            Role::Viewer => "唯讀檢視者",
        }
    }
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = Uuid::new_v4().into_bytes();
    Ok(Argon2::default()
        .hash_password_with_salt(pw.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hash: {e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, phc: &str) -> bool {
    PasswordHash::new(phc)
        .is_ok_and(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

pub const SESSION_COOKIE: &str = "em_session";
pub const SESSION_HOURS: i32 = 8;
pub const MAX_FAILED_LOGINS: i32 = 5;
pub const LOCK_MINUTES: i32 = 15;

pub enum LoginOutcome {
    Ok { session_token: String },
    Failed,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub admin_id: i64,
    pub username: String,
    pub csrf: String,
    pub token_hash: String,
    pub role: Role,
    pub groups: Vec<i64>,
}

impl Session {
    /// 平台管理員看得到全部裝置（含未分組）。
    pub fn all_devices(&self) -> bool {
        self.role == Role::Platform
    }

    /// 唯讀檢視者以外都能執行變更動作。
    pub fn can_manage(&self) -> bool {
        self.role != Role::Viewer
    }

    pub fn in_scope(&self, group: Option<i64>) -> bool {
        self.all_devices() || group.is_some_and(|g| self.groups.contains(&g))
    }
}

fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// 帳號不存在時也做一次雜湊，避免以回應時間判斷帳號是否存在。
fn dummy_hash() -> &'static str {
    static H: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    H.get_or_init(|| hash_password("dummy-password-for-timing").expect("hash"))
}

/// 帳號名稱上限；超過的直接當作登入失敗，稽核記錄只存截斷後的值。
pub const MAX_USERNAME_LEN: usize = 64;

/// 同時進行的密碼雜湊運算上限：大量登入請求不會佔滿 tokio 工作執行緒、拖慢 Agent 報到。
static HASH_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// 在 blocking 執行緒上驗證密碼，並限制同時運算數量。
async fn verify_blocking(password: &str, phc: &str) -> bool {
    let Ok(_slot) = HASH_SLOTS.acquire().await else {
        return false;
    };
    let (pw, phc) = (password.to_string(), phc.to_string());
    tokio::task::spawn_blocking(move || verify_password(&pw, &phc))
        .await
        .unwrap_or(false)
}

pub async fn login(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<LoginOutcome> {
    let username: String = username.chars().take(MAX_USERNAME_LEN).collect();
    let mut tx = pool.begin().await?;
    // FOR UPDATE：同一帳號的登入依序處理，平行請求無法繞過失敗次數上限
    let row: Option<(i64, String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT id, password_hash, locked_until FROM admins \
         WHERE username = $1 AND disabled_at IS NULL FOR UPDATE",
    )
    .bind(&username)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((admin_id, hash, locked_until)) = row else {
        verify_blocking(password, dummy_hash()).await;
        crate::audit::record(
            &mut tx,
            &username,
            "login_failed",
            None,
            serde_json::json!({ "reason": "unknown_or_disabled" }),
        )
        .await?;
        tx.commit().await?;
        return Ok(LoginOutcome::Failed);
    };
    let locked = locked_until.is_some_and(|t| t > Utc::now());
    // 鎖定期間仍做一次雜湊（固定耗時），但不採用結果
    let password_ok = verify_blocking(password, &hash).await;
    if locked || !password_ok {
        sqlx::query(
            "UPDATE admins SET \
               locked_until = CASE WHEN failed_logins + 1 >= $2 \
                                   THEN now() + make_interval(mins => $3) ELSE locked_until END, \
               failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END \
             WHERE id = $1 AND NOT $4",
        )
        .bind(admin_id)
        .bind(MAX_FAILED_LOGINS)
        .bind(LOCK_MINUTES)
        .bind(locked)
        .execute(&mut *tx)
        .await?;
        let reason = if locked { "locked" } else { "password" };
        crate::audit::record(
            &mut tx,
            &username,
            "login_failed",
            None,
            serde_json::json!({ "reason": reason }),
        )
        .await?;
        tx.commit().await?;
        return Ok(LoginOutcome::Failed);
    }
    sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO sessions (token_hash, admin_id, csrf_token, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(hours => $4))",
    )
    .bind(sha256_hex(&token))
    .bind(admin_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(SESSION_HOURS)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?;
    crate::audit::record(&mut tx, &username, "login", None, serde_json::json!({})).await?;
    tx.commit().await?;
    Ok(LoginOutcome::Ok {
        session_token: token,
    })
}

pub async fn lookup_session(pool: &PgPool, token: &str) -> Result<Option<Session>, sqlx::Error> {
    let hash = sha256_hex(token);
    let row: Option<(i64, String, String, String, Vec<i64>)> = sqlx::query_as(
        "SELECT a.id, a.username, s.csrf_token, a.role, \
                ARRAY(SELECT group_id FROM admin_groups g WHERE g.admin_id = a.id ORDER BY group_id) \
         FROM sessions s JOIN admins a ON a.id = s.admin_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() AND a.disabled_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(|(admin_id, username, csrf, role, groups)| {
        Some(Session {
            admin_id,
            username,
            csrf,
            token_hash: hash.clone(),
            role: Role::parse(&role)?,
            groups,
        })
    }))
}

pub async fn logout(pool: &PgPool, s: &Session) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&s.token_hash)
        .execute(&mut *tx)
        .await?;
    crate::audit::record(&mut tx, &s.username, "logout", None, serde_json::json!({})).await?;
    tx.commit().await
}

pub fn csrf_ok(expected: &str, got: &str) -> bool {
    expected.len() == got.len()
        && expected
            .bytes()
            .zip(got.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

pub fn session_cookie(token: &str) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        SESSION_HOURS * 3600
    )
}

pub fn clear_cookie() -> &'static str {
    "em_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
}

fn cookie_value(parts: &Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('=').map(str::to_string))
}

/// 已登入的管理員；未登入時轉到登入頁。
pub struct AdminSession(pub Session);

impl FromRequestParts<crate::AppState> for AdminSession {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::AppState,
    ) -> Result<Self, Response> {
        let to_login = || Redirect::to("/login").into_response();
        let token = cookie_value(parts, SESSION_COOKIE).ok_or_else(to_login)?;
        match lookup_session(&state.pool, &token).await {
            Ok(Some(s)) => Ok(AdminSession(s)),
            Ok(None) => Err(to_login()),
            Err(e) => Err(crate::error::AppError::from(e).into_response()),
        }
    }
}

pub fn check_csrf(s: &Session, got: &str) -> Result<(), Response> {
    if csrf_ok(&s.csrf, got) {
        Ok(())
    } else {
        Err(super::forbidden())
    }
}

/// 版面共用資訊。
pub struct Nav {
    pub logged_in: bool,
    pub user: String,
    pub role: &'static str,
    pub csrf: String,
    pub platform: bool,
    pub manage: bool,
}

impl Nav {
    pub fn anonymous() -> Nav {
        Nav {
            logged_in: false,
            user: String::new(),
            role: "",
            csrf: String::new(),
            platform: false,
            manage: false,
        }
    }
}

impl From<&Session> for Nav {
    fn from(s: &Session) -> Nav {
        Nav {
            logged_in: true,
            user: s.username.clone(),
            role: s.role.label(),
            csrf: s.csrf.clone(),
            platform: s.all_devices(),
            manage: s.can_manage(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{NewAdmin, create};

    async fn setup(pool: &PgPool) -> i64 {
        crate::db::migrate(pool).await.unwrap();
        let mut c = pool.acquire().await.unwrap();
        let g = crate::groups::find_or_create(&mut c, "台北總部")
            .await
            .unwrap();
        create(
            pool,
            &NewAdmin {
                username: "alice".into(),
                password: "alice-long-password".into(),
                role: Role::GroupAdmin,
                groups: vec![g],
            },
            "cli",
        )
        .await
        .unwrap();
        g
    }

    async fn ok(pool: &PgPool, pw: &str) -> Option<String> {
        match login(pool, "alice", pw).await.unwrap() {
            LoginOutcome::Ok { session_token } => Some(session_token),
            LoginOutcome::Failed => None,
        }
    }

    #[sqlx::test(migrations = false)]
    async fn login_creates_scoped_session(pool: PgPool) {
        let g = setup(&pool).await;
        let token = ok(&pool, "alice-long-password").await.expect("login");
        let s = lookup_session(&pool, &token).await.unwrap().unwrap();
        assert_eq!((s.username.as_str(), s.role), ("alice", Role::GroupAdmin));
        assert_eq!(s.groups, vec![g]);
        assert!(s.in_scope(Some(g)) && !s.in_scope(Some(g + 1)) && !s.in_scope(None));
        assert!(!s.all_devices() && s.can_manage());
        let stored: String = sqlx::query_scalar("SELECT token_hash FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_ne!(stored, token, "只存 hash");
        logout(&pool, &s).await.unwrap();
        assert!(lookup_session(&pool, &token).await.unwrap().is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn lockout_after_five_failures(pool: PgPool) {
        setup(&pool).await;
        for _ in 0..MAX_FAILED_LOGINS {
            assert!(ok(&pool, "nope-nope-nope").await.is_none());
        }
        assert!(
            ok(&pool, "alice-long-password").await.is_none(),
            "鎖定期間正確密碼也不行"
        );
        sqlx::query("UPDATE admins SET locked_until = now() - interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(ok(&pool, "alice-long-password").await.is_some());
    }

    #[sqlx::test(migrations = false)]
    async fn disabled_unknown_and_expired(pool: PgPool) {
        setup(&pool).await;
        assert!(matches!(
            login(&pool, "mallory", "whatever-password").await.unwrap(),
            LoginOutcome::Failed
        ));
        let token = ok(&pool, "alice-long-password").await.unwrap();
        sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(lookup_session(&pool, &token).await.unwrap().is_none());
        sqlx::query("UPDATE admins SET disabled_at = now()")
            .execute(&pool)
            .await
            .unwrap();
        assert!(ok(&pool, "alice-long-password").await.is_none());
    }

    #[sqlx::test(migrations = false)]
    async fn concurrent_failures_cannot_bypass_lockout(pool: PgPool) {
        setup(&pool).await;
        let attempts = (0..20).map(|_| login(&pool, "alice", "nope-nope-nope"));
        for r in futures_util::future::join_all(attempts).await {
            assert!(matches!(r.unwrap(), LoginOutcome::Failed));
        }
        let checked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action = 'login_failed' \
             AND detail->>'reason' = 'password'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            checked,
            i64::from(MAX_FAILED_LOGINS),
            "只有前 5 次真的比對密碼，其餘因鎖定直接拒絕"
        );
    }

    #[sqlx::test(migrations = false)]
    async fn oversized_username_is_not_stored_verbatim(pool: PgPool) {
        setup(&pool).await;
        let huge = "x".repeat(10_000);
        assert!(matches!(
            login(&pool, &huge, "whatever-password").await.unwrap(),
            LoginOutcome::Failed
        ));
        let len: i32 = sqlx::query_scalar("SELECT max(length(actor)) FROM audit_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(len <= 64, "{len}");
    }

    #[test]
    fn csrf_compare() {
        assert!(csrf_ok("abc", "abc"));
        assert!(!csrf_ok("abc", "abd"));
        assert!(!csrf_ok("abc", ""));
    }
}
