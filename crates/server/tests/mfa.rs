//! 管理網頁兩步驟驗證：設定、登入、重放、復原碼、鎖定、要求 MFA、重設。

mod common;

use common::{TestServer, csrf_from};
use endpoint_server::totp;
use endpoint_server::web::auth::{MAX_FAILED_LOGINS, Role};
use sqlx::PgPool;

async fn post(
    s: &TestServer,
    c: &reqwest::Client,
    path: &str,
    form: &[(&str, &str)],
) -> (u16, String, String) {
    let r = c.post(s.web_url(path)).form(form).send().await.unwrap();
    let status = r.status().as_u16();
    let loc = r
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, loc, r.text().await.unwrap())
}

fn now_step() -> i64 {
    totp::step_of(time::OffsetDateTime::now_utc().unix_timestamp())
}

fn code(secret_b32: &str, step: i64) -> String {
    let key = totp::base32_decode(secret_b32).unwrap();
    format!("{:06}", totp::code_at(&key, step, totp::DIGITS))
}

async fn secret_of(s: &TestServer, user: &str, column: &str) -> Option<String> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT {column} FROM admins WHERE username = $1"
    )))
    .bind(user)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

fn recovery_codes(html: &str) -> Vec<String> {
    let start = html
        .find(r#"<pre class="code" id="recovery-codes">"#)
        .expect("codes")
        + 37;
    let end = start + html[start..].find("</pre>").unwrap();
    html[start..end].lines().map(str::to_string).collect()
}

/// 已登入的 client 透過網頁啟用 MFA，回傳 (金鑰, 復原碼)
async fn enable_via_web(s: &TestServer, c: &reqwest::Client, user: &str) -> (String, Vec<String>) {
    let (st, html) = s.page(c, "/mfa").await;
    assert_eq!(st, 200, "{html}");
    let pending = secret_of(s, user, "mfa_pending_secret").await.unwrap();
    assert!(
        html.contains(&pending) && html.contains("<svg"),
        "頁面顯示金鑰與 QR code"
    );
    // 重新整理沿用同一把
    s.page(c, "/mfa").await;
    assert_eq!(
        secret_of(s, user, "mfa_pending_secret").await.unwrap(),
        pending
    );

    let csrf = csrf_from(&html);
    let (st, _, body) = post(s, c, "/mfa/enable", &[("csrf", &csrf), ("code", "000000")]).await;
    assert_eq!(st, 400);
    assert!(body.contains("驗證碼不正確"));
    let (st, _, body) = post(
        s,
        c,
        "/mfa/enable",
        &[("csrf", &csrf), ("code", &code(&pending, now_step()))],
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let codes = recovery_codes(&body);
    assert_eq!(codes.len(), totp::RECOVERY_CODES);
    assert_eq!(secret_of(s, user, "mfa_secret").await.unwrap(), pending);
    assert!(secret_of(s, user, "mfa_pending_secret").await.is_none());
    (pending, codes)
}

/// 帳號密碼登入；回傳 (狀態, Location)
async fn password_step(s: &TestServer, c: &reqwest::Client, user: &str) -> (u16, String) {
    let pw = format!("{user}-long-password");
    let (st, loc, _) = post(s, c, "/login", &[("username", user), ("password", &pw)]).await;
    (st, loc)
}

async fn audit_count(s: &TestServer, action: &str, reason: Option<&str>) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = $1 \
         AND ($2::text IS NULL OR detail->>'reason' = $2 OR detail->>'mfa' = $2)",
    )
    .bind(action)
    .bind(reason)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn enable_then_login_needs_code(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let other = s.login_as("alice", Role::Platform, &[]).await;
    let (secret, _) = enable_via_web(&s, &alice, "alice").await;
    // 啟用後：目前的工作階段保留，其他的登出
    assert_eq!(s.page(&alice, "/").await.0, 200);
    assert_eq!(s.page(&other, "/").await.0, 303);
    let (_, html) = s.page(&alice, "/mfa").await;
    assert!(html.contains("已啟用") && html.contains("10 組"), "{html}");
    let (_, html) = s.page(&alice, "/accounts").await;
    assert!(html.contains(r#"<span class="tag ok">已啟用</span>"#));

    // 只有密碼：沒有工作階段，轉到驗證碼頁
    let c = s.web_client();
    assert_eq!(
        password_step(&s, &c, "alice").await,
        (303, "/login/mfa".into())
    );
    assert_eq!(s.page(&c, "/").await.0, 303, "還沒登入");
    let (st, html) = s.page(&c, "/login/mfa").await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"name="code""#));

    // 錯的碼：可以再試
    let (st, _, body) = post(&s, &c, "/login/mfa", &[("code", "000000")]).await;
    assert_eq!(st, 401);
    assert!(body.contains("驗證碼不正確"));
    // 對的碼（下一步，啟用時已用掉目前這一步）
    let step = now_step() + 1;
    let (st, loc, _) = post(&s, &c, "/login/mfa", &[("code", &code(&secret, step))]).await;
    assert_eq!((st, loc.as_str()), (303, "/"));
    assert_eq!(s.page(&c, "/").await.0, 200);
    assert_eq!(audit_count(&s, "login", Some("totp")).await, 1);

    // 同一個碼不能再用（重放）
    let c2 = s.web_client();
    password_step(&s, &c2, "alice").await;
    let (st, _, _) = post(&s, &c2, "/login/mfa", &[("code", &code(&secret, step))]).await;
    assert_eq!(st, 401);
    let (st, _, _) = post(&s, &c2, "/login/mfa", &[("code", &code(&secret, step - 1))]).await;
    assert_eq!(st, 401, "比最後使用的更舊也不行");
}

#[sqlx::test(migrations = false)]
async fn without_mfa_login_is_unchanged(pool: PgPool) {
    let s = TestServer::start(pool).await;
    s.create_group_token("g", 1).await;
    s.login_as("bob", Role::Viewer, &["g"]).await;
    let c = s.web_client();
    assert_eq!(password_step(&s, &c, "bob").await, (303, "/".into()));
    // 沒有挑戰 cookie 時驗證碼頁轉回登入
    let fresh = s.web_client();
    assert_eq!(s.page(&fresh, "/login/mfa").await.0, 303);
    let (st, _, body) = post(&s, &fresh, "/login/mfa", &[("code", "123456")]).await;
    assert_eq!(st, 401);
    assert!(body.contains("請重新登入"));
}

#[sqlx::test(migrations = false)]
async fn recovery_code_works_once(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let (_, codes) = enable_via_web(&s, &alice, "alice").await;

    let c = s.web_client();
    password_step(&s, &c, "alice").await;
    // 大小寫、空白不影響
    let typed = format!(" {} ", codes[0].to_uppercase());
    let (st, loc, _) = post(&s, &c, "/login/mfa", &[("code", &typed)]).await;
    assert_eq!((st, loc.as_str()), (303, "/"));
    assert_eq!(audit_count(&s, "login", Some("recovery")).await, 1);

    let c = s.web_client();
    password_step(&s, &c, "alice").await;
    let (st, _, _) = post(&s, &c, "/login/mfa", &[("code", &codes[0])]).await;
    assert_eq!(st, 401, "用過的復原碼");
    let (_, html) = s.page(&alice, "/mfa").await;
    assert!(html.contains("9 組"), "{html}");
}

#[sqlx::test(migrations = false)]
async fn wrong_codes_count_toward_lockout(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let (secret, _) = enable_via_web(&s, &alice, "alice").await;

    let c = s.web_client();
    password_step(&s, &c, "alice").await;
    for i in 0..MAX_FAILED_LOGINS {
        let (st, _, body) = post(&s, &c, "/login/mfa", &[("code", "000000")]).await;
        assert_eq!(st, 401);
        let last = i + 1 == MAX_FAILED_LOGINS;
        assert_eq!(body.contains("請重新登入"), last, "第 {} 次", i + 1);
    }
    assert_eq!(audit_count(&s, "login_failed", Some("mfa")).await, 5);
    // 帳號已鎖定：正確的密碼加正確的碼也不行
    let c = s.web_client();
    let (st, _) = password_step(&s, &c, "alice").await;
    assert_eq!(st, 401, "鎖定期間密碼步驟就失敗");
    sqlx::query("UPDATE admins SET locked_until = NULL")
        .execute(&s.pool)
        .await
        .unwrap();
    password_step(&s, &c, "alice").await;
    let (st, _, _) = post(
        &s,
        &c,
        "/login/mfa",
        &[("code", &code(&secret, now_step() + 1))],
    )
    .await;
    assert_eq!(st, 303);
}

#[sqlx::test(migrations = false)]
async fn challenge_expires_and_dies_with_reset(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let (secret, _) = enable_via_web(&s, &alice, "alice").await;

    let c = s.web_client();
    password_step(&s, &c, "alice").await;
    sqlx::query("UPDATE mfa_challenges SET expires_at = now() - interval '1 second'")
        .execute(&s.pool)
        .await
        .unwrap();
    let (st, _, body) = post(
        &s,
        &c,
        "/login/mfa",
        &[("code", &code(&secret, now_step() + 1))],
    )
    .await;
    assert_eq!(st, 401);
    assert!(body.contains("請重新登入"));

    // 挑戰期間被重設：挑戰作廢
    password_step(&s, &c, "alice").await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = 'alice'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    endpoint_server::mfa::reset(&s.pool, id, "test")
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM mfa_challenges")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn disable_and_regenerate_need_a_code(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let (secret, old_codes) = enable_via_web(&s, &alice, "alice").await;
    let (_, html) = s.page(&alice, "/mfa").await;
    let csrf = csrf_from(&html);

    let (st, _, body) = post(
        &s,
        &alice,
        "/mfa/recovery",
        &[("csrf", &csrf), ("code", "000000")],
    )
    .await;
    assert_eq!(st, 400, "{body}");
    let (st, _, body) = post(
        &s,
        &alice,
        "/mfa/recovery",
        &[("csrf", &csrf), ("code", &code(&secret, now_step() + 1))],
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let new_codes = recovery_codes(&body);
    assert!(new_codes.iter().all(|c| !old_codes.contains(c)));

    // 舊的復原碼已作廢，新的可以拿來停用
    let (st, _, _) = post(
        &s,
        &alice,
        "/mfa/disable",
        &[("csrf", &csrf), ("code", &old_codes[1])],
    )
    .await;
    assert_eq!(st, 400);
    let (st, _, body) = post(
        &s,
        &alice,
        "/mfa/disable",
        &[("csrf", &csrf), ("code", &new_codes[0])],
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("已停用"));
    assert!(secret_of(&s, "alice", "mfa_secret").await.is_none());
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_recovery_codes")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let c = s.web_client();
    assert_eq!(password_step(&s, &c, "alice").await, (303, "/".into()));
    // CSRF
    let (st, _, _) = post(
        &s,
        &alice,
        "/mfa/disable",
        &[("csrf", "x"), ("code", "123456")],
    )
    .await;
    assert_eq!(st, 403);
}

#[sqlx::test(migrations = false)]
async fn required_forces_setup_first(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    s.create_group_token("g", 1).await;
    s.login_as("bob", Role::Viewer, &["g"]).await;

    let (_, html) = s.page(&admin, "/accounts").await;
    let (st, loc, _) = post(
        &s,
        &admin,
        "/accounts/mfa-required",
        &[("csrf", &csrf_from(&html)), ("on", "1")],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/accounts"));
    let (_, html) = s.page(&admin, "/accounts").await;
    assert!(html.contains(r#"name="on" value="1" checked"#));
    // 已登入的工作階段不受影響
    assert_eq!(s.page(&admin, "/devices").await.0, 200);

    // 沒設定的帳號登入後只能到 /mfa
    let bob = s.web_client();
    assert_eq!(password_step(&s, &bob, "bob").await, (303, "/".into()));
    for path in ["/", "/devices", "/password"] {
        let r = bob.get(s.web_url(path)).send().await.unwrap();
        assert_eq!(r.status(), 303, "{path}");
        assert_eq!(r.headers()["location"], "/mfa", "{path}");
    }
    let (st, html) = s.page(&bob, "/mfa").await;
    assert_eq!(st, 200);
    assert!(html.contains("系統要求所有帳號使用兩步驟驗證"), "{html}");
    let pending = secret_of(&s, "bob", "mfa_pending_secret").await.unwrap();
    let (st, _, body) = post(
        &s,
        &bob,
        "/mfa/enable",
        &[
            ("csrf", &csrf_from(&html)),
            ("code", &code(&pending, now_step())),
        ],
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("我已保存，前往管理網頁"));
    // 同一個工作階段升級成一般的
    assert_eq!(s.page(&bob, "/devices").await.0, 200);
    // 要求期間不能停用
    let (_, html) = s.page(&bob, "/mfa").await;
    assert!(!html.contains("/mfa/disable"));
    let (st, _, body) = post(
        &s,
        &bob,
        "/mfa/disable",
        &[
            ("csrf", &csrf_from(&html)),
            ("code", &code(&pending, now_step() + 1)),
        ],
    )
    .await;
    assert_eq!(st, 400);
    assert!(body.contains("不能停用"));
    assert_eq!(audit_count(&s, "mfa_required_changed", None).await, 1);
}

#[sqlx::test(migrations = false)]
async fn platform_admin_resets_someone_else(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    s.create_group_token("g", 1).await;
    let bob = s.login_as("bob", Role::Viewer, &["g"]).await;
    enable_via_web(&s, &bob, "bob").await;
    let bob_id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = 'bob'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM admins WHERE username = 'admin'")
        .fetch_one(&s.pool)
        .await
        .unwrap();

    let (_, html) = s.page(&admin, &format!("/accounts/{bob_id}")).await;
    assert!(html.contains("重設兩步驟驗證"), "{html}");
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/accounts/{bob_id}/mfa-reset"),
        &[("csrf", &csrf_from(&html))],
    )
    .await;
    assert_eq!(st, 303);
    assert!(secret_of(&s, "bob", "mfa_secret").await.is_none());
    assert_eq!(s.page(&bob, "/").await.0, 303, "被登出");
    assert_eq!(audit_count(&s, "mfa_reset", None).await, 1);
    let c = s.web_client();
    assert_eq!(password_step(&s, &c, "bob").await, (303, "/".into()));

    // 不能重設自己；非平台管理員不能重設
    let (_, html) = s.page(&admin, &format!("/accounts/{admin_id}")).await;
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/accounts/{admin_id}/mfa-reset"),
        &[("csrf", &csrf_from(&html))],
    )
    .await;
    assert_eq!(st, 409);
    let (_, html) = s.page(&c, "/").await;
    let (st, _, _) = post(
        &s,
        &c,
        &format!("/accounts/{admin_id}/mfa-reset"),
        &[("csrf", &csrf_from(&html))],
    )
    .await;
    assert_eq!(st, 403);
}

#[sqlx::test(migrations = false)]
async fn cli_reset_by_username(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    enable_via_web(&s, &alice, "alice").await;
    endpoint_server::mfa::reset_by_username(&s.pool, "alice")
        .await
        .unwrap();
    assert!(secret_of(&s, "alice", "mfa_secret").await.is_none());
    let actor: String =
        sqlx::query_scalar("SELECT actor FROM audit_log WHERE action = 'mfa_reset'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(actor, "cli");
    assert!(
        endpoint_server::mfa::reset_by_username(&s.pool, "nobody")
            .await
            .is_err()
    );
}
