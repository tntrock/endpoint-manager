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

#[sqlx::test(migrations = false)]
async fn dashboard_counts_and_device_list(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 5).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("裝置總數"));
    let (status, html) = s.page(&c, "/devices").await;
    assert_eq!(status, 200);
    assert!(html.contains("PC-001") && html.contains("台北總部"));
    assert!(html.contains(&format!("/devices/{}", a.device_id)));
}

#[sqlx::test(migrations = false)]
async fn group_admin_sees_only_own_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 1).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    let mine = s.enroll_ok(&tp, None, None).await;
    let other = s.enroll_ok(&kh, None, None).await;
    let c = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;

    let (_, html) = s.page(&c, "/devices").await;
    assert!(html.contains(&mine.device_id.to_string()));
    assert!(!html.contains(&other.device_id.to_string()));
    let (_, html) = s.page(&c, "/devices?status=all").await;
    assert!(!html.contains(&other.device_id.to_string()));
    let (_, html) = s.page(&c, "/").await;
    assert!(
        html.contains("裝置總數<b>1</b>"),
        "儀表板只算自己群組：{html}"
    );
}

#[sqlx::test(migrations = false)]
async fn hostile_hostname_is_escaped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE devices SET hostname = '<script>alert(1)</script>', logged_on_user = '\"><img src=x onerror=alert(1)>' WHERE id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices").await;
    assert!(!html.contains("<script>alert(1)"));
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&#60;script&#62;"));
}

#[sqlx::test(migrations = false)]
async fn search_treats_wildcards_literally(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    for (id, name) in [(a.device_id, "SALES_01"), (b.device_id, "SALESX01")] {
        sqlx::query("UPDATE devices SET hostname = $2 WHERE id = $1")
            .bind(id)
            .bind(name)
            .execute(&s.pool)
            .await
            .unwrap();
    }
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices?q=SALES_").await;
    assert!(html.contains("SALES_01"));
    assert!(!html.contains("SALESX01"));
}

#[sqlx::test(migrations = false)]
async fn approvals_respect_role_and_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 5).await;
    let kh = s.create_group_token("高雄廠", 5).await;
    let _ = s.enroll_ok(&tp, Some("UUID-T"), Some("SN-T")).await;
    let tp_new = s.enroll_ok(&tp, Some("UUID-T"), Some("SN-T")).await;
    let _ = s.enroll_ok(&kh, Some("UUID-K"), Some("SN-K")).await;
    let kh_new = s.enroll_ok(&kh, Some("UUID-K"), Some("SN-K")).await;

    let viewer = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&viewer, "/").await;
    let r = viewer
        .post(s.web_url(&format!("/devices/{}/approve", tp_new.device_id)))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "檢視者不能核准");

    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&gary, "/").await;
    let csrf = csrf_from(&html);
    let r = gary
        .post(s.web_url(&format!("/devices/{}/approve", kh_new.device_id)))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "別的群組當作不存在");
    let r = gary
        .post(s.web_url("/devices/approve-all"))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let pending: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM devices WHERE status = 'pending_approval'")
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(pending, vec![kh_new.device_id], "只核准自己群組的");
}
