//! 管理員角色、密碼、工作階段與 CSRF。

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::extract::FromRequestParts;
use axum::http::{header, request::Parts};
use axum::response::{IntoResponse, Redirect, Response};
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

/// 等待輸入驗證碼的有效時間與錯誤次數上限
pub const MFA_CHALLENGE_MINUTES: i32 = 5;
pub const MFA_CHALLENGE_TRIES: i32 = 5;
pub const MFA_COOKIE: &str = "em_mfa";

pub enum LoginOutcome {
    Ok {
        session_token: String,
    },
    /// 密碼正確，還要輸入驗證碼
    MfaRequired {
        challenge_token: String,
    },
    Failed,
    /// 密碼正確，但這個帳號只能用單一登入
    SsoOnly,
}

/// 單一登入的結果
#[derive(Debug, PartialEq, Eq)]
pub enum OidcOutcome {
    Ok {
        session_token: String,
    },
    /// 沒有對應（或已停用）的管理帳號
    NoAccount,
    /// 名稱相同的帳號已綁定別的身分提供者使用者
    Conflict,
}

/// 驗證碼步驟的結果
pub enum MfaOutcome {
    Ok {
        session_token: String,
    },
    /// 錯了，可以再試
    Retry,
    /// 挑戰已失效（過期、錯太多次、帳號被鎖定或停用），要重新輸入密碼
    Restart,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub admin_id: i64,
    pub username: String,
    pub csrf: String,
    pub token_hash: String,
    pub role: Role,
    pub groups: Vec<i64>,
    /// 系統要求 MFA、帳號還沒設定：只能到 /mfa 設定或登出
    pub setup_only: bool,
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

pub(crate) fn sha256_hex(s: &str) -> String {
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
pub(crate) async fn verify_blocking(password: &str, phc: &str) -> bool {
    let Ok(_slot) = HASH_SLOTS.acquire().await else {
        return false;
    };
    let (pw, phc) = (password.to_string(), phc.to_string());
    tokio::task::spawn_blocking(move || verify_password(&pw, &phc))
        .await
        .unwrap_or(false)
}

/// 密碼錯誤一次（登入與修改密碼共用）：累計到上限就鎖定並歸零。回傳是否因此被鎖定。
/// 呼叫端須已鎖住該帳號的列（FOR UPDATE）。
pub(crate) async fn record_failure(
    conn: &mut sqlx::PgConnection,
    admin_id: i64,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "UPDATE admins SET \
           locked_until = CASE WHEN failed_logins + 1 >= $2 \
                               THEN now() + make_interval(mins => $3) ELSE locked_until END, \
           failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END \
         WHERE id = $1 RETURNING coalesce(locked_until > now(), false)",
    )
    .bind(admin_id)
    .bind(MAX_FAILED_LOGINS)
    .bind(LOCK_MINUTES)
    .fetch_one(conn)
    .await
}

pub async fn login(pool: &PgPool, username: &str, password: &str) -> anyhow::Result<LoginOutcome> {
    login_checked(pool, username, password, false).await
}

/// id、密碼雜湊、鎖定期限、是否有 MFA、角色
type LoginRow = (i64, String, Option<time::OffsetDateTime>, bool, String);

/// `sso_only`：設定了單一登入且密碼登入只限平台管理員
pub async fn login_checked(
    pool: &PgPool,
    username: &str,
    password: &str,
    sso_only: bool,
) -> anyhow::Result<LoginOutcome> {
    let username: String = username.chars().take(MAX_USERNAME_LEN).collect();
    let mut tx = pool.begin().await?;
    // FOR UPDATE：同一帳號的登入依序處理，平行請求無法繞過失敗次數上限
    let row: Option<LoginRow> = sqlx::query_as(
        "SELECT id, password_hash, locked_until, mfa_secret IS NOT NULL, role FROM admins \
         WHERE username = $1 AND disabled_at IS NULL FOR UPDATE",
    )
    .bind(&username)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((admin_id, hash, locked_until, has_mfa, role)) = row else {
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
    let locked = locked_until.is_some_and(|t| t > time::OffsetDateTime::now_utc());
    // 鎖定期間仍做一次雜湊（固定耗時），但不採用結果
    let password_ok = verify_blocking(password, &hash).await;
    if locked || !password_ok {
        if !locked {
            record_failure(&mut tx, admin_id).await?;
        }
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
    // 密碼正確才告知「只能用單一登入」：密碼錯誤時的回應與其他帳號相同
    if sso_only && role != Role::Platform.as_str() {
        crate::audit::record(
            &mut tx,
            &username,
            "login_failed",
            None,
            serde_json::json!({ "reason": "sso_only" }),
        )
        .await?;
        tx.commit().await?;
        return Ok(LoginOutcome::SsoOnly);
    }
    sqlx::query("DELETE FROM mfa_challenges WHERE expires_at < now()")
        .execute(&mut *tx)
        .await?;
    if has_mfa {
        // 失敗次數留到驗證碼也正確才歸零：猜驗證碼的錯誤繼續累計
        let token = new_token();
        sqlx::query(
            "INSERT INTO mfa_challenges (token_hash, admin_id, expires_at) \
             VALUES ($1, $2, now() + make_interval(mins => $3))",
        )
        .bind(sha256_hex(&token))
        .bind(admin_id)
        .bind(MFA_CHALLENGE_MINUTES)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(LoginOutcome::MfaRequired {
            challenge_token: token,
        });
    }
    sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    let setup_only = crate::mfa::required(pool).await?;
    let token = create_session(&mut tx, admin_id, setup_only).await?;
    crate::audit::record(
        &mut tx,
        &username,
        "login",
        None,
        if setup_only {
            serde_json::json!({ "mfa": "setup_required" })
        } else {
            serde_json::json!({})
        },
    )
    .await?;
    tx.commit().await?;
    Ok(LoginOutcome::Ok {
        session_token: token,
    })
}

pub(crate) fn new_token() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// 單一登入：依綁定或帳號名稱找到管理帳號並建立工作階段（見設計文件 §3 第 5 步）
pub async fn login_oidc(
    pool: &PgPool,
    issuer: &str,
    id: &crate::oidc::Identity,
) -> anyhow::Result<OidcOutcome> {
    let mut tx = pool.begin().await?;
    // 已綁定的帳號即使停用了也算數：不能改用名稱去綁另一個帳號
    let bound: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT id, username, disabled_at IS NOT NULL FROM admins \
         WHERE oidc_issuer = $1 AND oidc_subject = $2 FOR UPDATE",
    )
    .bind(issuer)
    .bind(&id.subject)
    .fetch_optional(&mut *tx)
    .await?;
    let (admin_id, username) = match bound {
        Some((_, username, true)) => {
            crate::audit::record(
                &mut tx,
                &username,
                "login_failed",
                None,
                serde_json::json!({ "reason": "oidc_disabled" }),
            )
            .await?;
            tx.commit().await?;
            return Ok(OidcOutcome::NoAccount);
        }
        Some((admin_id, username, false)) => (admin_id, username),
        None => {
            let by_name: Option<(i64, String, Option<String>)> = sqlx::query_as(
                "SELECT id, username, oidc_subject FROM admins \
                 WHERE lower(username) = lower($1) AND disabled_at IS NULL FOR UPDATE",
            )
            .bind(&id.username)
            .fetch_optional(&mut *tx)
            .await?;
            let outcome = match by_name {
                None => Err((OidcOutcome::NoAccount, "oidc_no_account")),
                Some((_, _, Some(_))) => Err((OidcOutcome::Conflict, "oidc_conflict")),
                Some((admin_id, username, None)) => Ok((admin_id, username)),
            };
            match outcome {
                Ok((admin_id, username)) => {
                    sqlx::query(
                        "UPDATE admins SET oidc_issuer = $2, oidc_subject = $3 WHERE id = $1",
                    )
                    .bind(admin_id)
                    .bind(issuer)
                    .bind(&id.subject)
                    .execute(&mut *tx)
                    .await?;
                    crate::audit::record(
                        &mut tx,
                        &username,
                        "oidc_linked",
                        Some(&username),
                        serde_json::json!({ "issuer": issuer, "subject": id.subject }),
                    )
                    .await?;
                    (admin_id, username)
                }
                Err((outcome, reason)) => {
                    let actor: String = id.username.chars().take(MAX_USERNAME_LEN).collect();
                    crate::audit::record(
                        &mut tx,
                        &actor,
                        "login_failed",
                        None,
                        serde_json::json!({ "reason": reason }),
                    )
                    .await?;
                    tx.commit().await?;
                    return Ok(outcome);
                }
            }
        }
    };
    let token = create_session(&mut tx, admin_id, false).await?;
    crate::audit::record(
        &mut tx,
        &username,
        "login",
        None,
        serde_json::json!({ "method": "oidc" }),
    )
    .await?;
    tx.commit().await?;
    Ok(OidcOutcome::Ok {
        session_token: token,
    })
}

/// 解除帳號的單一登入綁定（平台管理員）；回傳是否有綁定
pub async fn unlink_oidc(pool: &PgPool, admin_id: i64, actor: &str) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT username, oidc_subject FROM admins WHERE id = $1 FOR UPDATE")
            .bind(admin_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((username, Some(subject))) = row else {
        return Ok(false);
    };
    sqlx::query("UPDATE admins SET oidc_issuer = NULL, oidc_subject = NULL WHERE id = $1")
        .bind(admin_id)
        .execute(&mut *tx)
        .await?;
    crate::audit::record(
        &mut tx,
        actor,
        "oidc_unlinked",
        Some(&username),
        serde_json::json!({ "subject": subject }),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

pub const PASSWORD_LOGIN_KEY: &str = "password_login";

/// 密碼登入是否只限平台管理員；讀不到或被改壞時視為所有帳號都可以（預設值）
pub async fn password_login_platform_only(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let v: Option<Option<String>> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM settings WHERE key = $1")
            .bind(PASSWORD_LOGIN_KEY)
            .fetch_optional(pool)
            .await?;
    Ok(v.flatten().as_deref() == Some("platform"))
}

pub async fn set_password_login_platform_only(
    pool: &PgPool,
    on: bool,
    actor: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let old: Option<Option<String>> =
        sqlx::query_scalar("SELECT value #>> '{}' FROM settings WHERE key = $1 FOR UPDATE")
            .bind(PASSWORD_LOGIN_KEY)
            .fetch_optional(&mut *tx)
            .await?;
    let value = if on { "platform" } else { "all" };
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, to_jsonb($2::text)) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(PASSWORD_LOGIN_KEY)
    .bind(value)
    .execute(&mut *tx)
    .await?;
    crate::audit::record(
        &mut tx,
        actor,
        "setting_password_login",
        None,
        serde_json::json!({ "value": value, "old": old.flatten().unwrap_or_else(|| "all".into()) }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn create_session(
    conn: &mut sqlx::PgConnection,
    admin_id: i64,
    setup_only: bool,
) -> Result<String, sqlx::Error> {
    let token = new_token();
    sqlx::query(
        "INSERT INTO sessions (token_hash, admin_id, csrf_token, expires_at, setup_only) \
         VALUES ($1, $2, $3, now() + make_interval(hours => $4), $5)",
    )
    .bind(sha256_hex(&token))
    .bind(admin_id)
    .bind(Uuid::new_v4().simple().to_string())
    .bind(SESSION_HOURS)
    .bind(setup_only)
    .execute(&mut *conn)
    .await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(&mut *conn)
        .await?;
    Ok(token)
}

type ChallengeRow = (
    i64,
    i32,
    String,
    Option<String>,
    Option<i64>,
    Option<time::OffsetDateTime>,
);

/// 登入第二步：以挑戰 token 與驗證碼（或復原碼）換工作階段
pub async fn login_mfa(pool: &PgPool, challenge: &str, code: &str) -> anyhow::Result<MfaOutcome> {
    let challenge_hash = sha256_hex(challenge);
    let mut tx = pool.begin().await?;
    let row: Option<ChallengeRow> = sqlx::query_as(
        "SELECT c.admin_id, c.failures, a.username, a.mfa_secret, a.mfa_last_step, a.locked_until \
         FROM mfa_challenges c JOIN admins a ON a.id = c.admin_id \
         WHERE c.token_hash = $1 AND c.expires_at > now() AND a.disabled_at IS NULL \
         FOR UPDATE OF a, c",
    )
    .bind(&challenge_hash)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((admin_id, failures, username, secret, last_step, locked_until)) = row else {
        return Ok(MfaOutcome::Restart);
    };
    // 期間被鎖定，或 MFA 被重設
    let (Some(secret), false) = (
        secret,
        locked_until.is_some_and(|t| t > time::OffsetDateTime::now_utc()),
    ) else {
        drop_challenge(&mut tx, &challenge_hash).await?;
        crate::audit::record(
            &mut tx,
            &username,
            "login_failed",
            None,
            serde_json::json!({ "reason": "locked" }),
        )
        .await?;
        tx.commit().await?;
        return Ok(MfaOutcome::Restart);
    };
    match crate::mfa::check_code(&mut tx, admin_id, &secret, last_step, code).await? {
        Some(method) => {
            drop_challenge(&mut tx, &challenge_hash).await?;
            sqlx::query("UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1")
                .bind(admin_id)
                .execute(&mut *tx)
                .await?;
            let token = create_session(&mut tx, admin_id, false).await?;
            crate::audit::record(
                &mut tx,
                &username,
                "login",
                None,
                serde_json::json!({ "mfa": method.as_str() }),
            )
            .await?;
            tx.commit().await?;
            Ok(MfaOutcome::Ok {
                session_token: token,
            })
        }
        None => {
            let locked = record_failure(&mut tx, admin_id).await?;
            let restart = locked || failures + 1 >= MFA_CHALLENGE_TRIES;
            if restart {
                drop_challenge(&mut tx, &challenge_hash).await?;
            } else {
                sqlx::query(
                    "UPDATE mfa_challenges SET failures = failures + 1 WHERE token_hash = $1",
                )
                .bind(&challenge_hash)
                .execute(&mut *tx)
                .await?;
            }
            crate::audit::record(
                &mut tx,
                &username,
                "login_failed",
                None,
                serde_json::json!({ "reason": "mfa" }),
            )
            .await?;
            tx.commit().await?;
            Ok(if restart {
                MfaOutcome::Restart
            } else {
                MfaOutcome::Retry
            })
        }
    }
}

async fn drop_challenge(conn: &mut sqlx::PgConnection, hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM mfa_challenges WHERE token_hash = $1")
        .bind(hash)
        .execute(conn)
        .await
        .map(|_| ())
}

pub fn mfa_cookie(token: &str) -> String {
    format!(
        "{MFA_COOKIE}={token}; Path=/login; HttpOnly; Secure; SameSite=Strict; Max-Age={}",
        MFA_CHALLENGE_MINUTES * 60
    )
}

pub fn clear_mfa_cookie() -> String {
    format!("{MFA_COOKIE}=; Path=/login; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

pub async fn lookup_session(pool: &PgPool, token: &str) -> Result<Option<Session>, sqlx::Error> {
    let hash = sha256_hex(token);
    let row: Option<(i64, String, String, String, Vec<i64>, bool)> = sqlx::query_as(
        "SELECT a.id, a.username, s.csrf_token, a.role, \
                ARRAY(SELECT group_id FROM admin_groups g WHERE g.admin_id = a.id ORDER BY group_id), \
                s.setup_only \
         FROM sessions s JOIN admins a ON a.id = s.admin_id \
         WHERE s.token_hash = $1 AND s.expires_at > now() AND a.disabled_at IS NULL",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await?;
    Ok(
        row.and_then(|(admin_id, username, csrf, role, groups, setup_only)| {
            Some(Session {
                admin_id,
                username,
                csrf,
                token_hash: hash.clone(),
                role: Role::parse(&role)?,
                groups,
                setup_only,
            })
        }),
    )
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
    cookie_from(&parts.headers, name)
}

pub fn cookie_from(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('=').map(str::to_string))
}

/// 只能設定 MFA 的工作階段可以用的頁面
fn setup_allowed(path: &str) -> bool {
    path == "/mfa" || path.starts_with("/mfa/") || path == "/logout"
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
            Ok(Some(s)) if s.setup_only && !setup_allowed(parts.uri.path()) => {
                Err(Redirect::to("/mfa").into_response())
            }
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

/// 版面共用資訊。`section` 決定側邊欄標示哪一項（子頁面沿用上層的值）
pub struct Nav {
    pub logged_in: bool,
    pub user: String,
    pub role: &'static str,
    pub csrf: String,
    pub platform: bool,
    pub manage: bool,
    pub section: &'static str,
    pub version: &'static str,
    /// 靜態檔網址的 `?v=`（內容雜湊）
    pub assets: &'static str,
}

impl Nav {
    pub fn new(s: &Session, section: &'static str) -> Nav {
        Nav {
            logged_in: true,
            user: s.username.clone(),
            role: s.role.label(),
            csrf: s.csrf.clone(),
            platform: s.all_devices(),
            manage: s.can_manage(),
            section,
            version: env!("CARGO_PKG_VERSION"),
            assets: super::asset_version(),
        }
    }

    pub fn anonymous() -> Nav {
        Nav {
            logged_in: false,
            user: String::new(),
            role: "",
            csrf: String::new(),
            platform: false,
            manage: false,
            section: "",
            version: env!("CARGO_PKG_VERSION"),
            assets: super::asset_version(),
        }
    }
}

/// 平台管理員才能做的動作（其他角色回 403）
pub fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(super::forbidden())
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
            LoginOutcome::Failed | LoginOutcome::SsoOnly | LoginOutcome::MfaRequired { .. } => None,
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
