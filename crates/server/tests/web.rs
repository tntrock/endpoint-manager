mod common;

use common::{TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

#[sqlx::test(migrations = false)]
async fn pages_require_login(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    for path in [
        "/",
        "/devices",
        "/software",
        "/tokens",
        "/groups",
        "/accounts",
        "/audit",
        "/password",
    ] {
        let r = c.get(s.web_url(path)).send().await.unwrap();
        assert_eq!(r.status(), 303, "{path}");
        assert_eq!(r.headers()["location"], "/login", "{path}");
    }
    let (status, html) = s.page(&c, "/login").await;
    assert_eq!(status, 200);
    assert!(html.contains("登入"));
}

#[sqlx::test(migrations = false)]
async fn login_logout_roundtrip_and_security_headers(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let r = c.get(s.web_url("/")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'")
    );
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["cache-control"], "no-store");
    let html = r.text().await.unwrap();
    assert!(html.contains("儀表板") && html.contains("平台管理員"));

    let csrf = csrf_from(&html);
    let r = c
        .post(s.web_url("/logout"))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(
        c.get(s.web_url("/")).send().await.unwrap().status(),
        303,
        "logged out"
    );
}

#[sqlx::test(migrations = false)]
async fn wrong_password_and_locked_show_generic_error(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.admin_client().await;
    let try_login = |pw: &'static str| {
        let c = s.web_client();
        let url = s.web_url("/login");
        async move {
            let r = c
                .post(url)
                .form(&[("username", "admin"), ("password", pw)])
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    let (status, html) = try_login("wrong-password-xx").await;
    assert_eq!(status, 401);
    assert!(html.contains("帳號或密碼錯誤"));
    sqlx::query("UPDATE admins SET locked_until = now() + interval '10 minutes'")
        .execute(&s.pool)
        .await
        .unwrap();
    let (status, html) = try_login("admin-long-password").await;
    assert_eq!(status, 401);
    assert!(html.contains("帳號或密碼錯誤"));
}

#[sqlx::test(migrations = false)]
async fn post_without_csrf_is_403(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let r = c
        .post(s.web_url("/logout"))
        .form(&[("csrf", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(
        c.get(s.web_url("/")).send().await.unwrap().status(),
        200,
        "session still valid"
    );
}

#[sqlx::test(migrations = false)]
async fn nav_depends_on_role(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let v = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&v, "/").await;
    assert!(!html.contains(r#"href="/tokens""#) && !html.contains(r#"href="/accounts""#));
    let g = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&g, "/").await;
    assert!(html.contains(r#"href="/tokens""#) && !html.contains(r#"href="/accounts""#));
}

#[sqlx::test(migrations = false)]
async fn static_assets_served(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    let r = c
        .get(s.web_url("/static/htmx.min.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("javascript")
    );
    let r = c.get(s.web_url("/static/app.css")).send().await.unwrap();
    assert!(
        r.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("css")
    );
}
