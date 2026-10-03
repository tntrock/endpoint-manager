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
        "/registry",
        "/deployments",
        "/packages",
        "/compliance",
        "/compliance/rules",
        "/compliance/violations",
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
        .form(&[("csrf", csrf.as_str()), ("confirm", "1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let pending: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM devices WHERE status = 'pending_approval'")
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(pending, vec![kh_new.device_id], "只核准自己群組的");
}

async fn upload_software(s: &TestServer, a: &common::TestAgent, name: &str, ver: &str) {
    let up = protocol::InventoryUpload {
        schema_version: protocol::SCHEMA_VERSION,
        payload: protocol::InventoryPayload::Software(vec![protocol::SoftwareItem {
            name: name.into(),
            version: Some(ver.into()),
            publisher: None,
            install_date: None,
            arch: protocol::Arch::X64,
        }]),
    };
    let r = s
        .client(Some(a))
        .put(s.url("/v1/inventory/software"))
        .json(&up)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn device_detail_and_tabs(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    upload_software(&s, &a, "<b>7-Zip</b>", "23.01").await;
    let c = s.admin_client().await;
    let (status, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert_eq!(status, 200);
    assert!(html.contains("PC-001"));
    assert!(html.contains(&format!("/devices/{}/tab/software", a.device_id)));
    let (status, frag) = s
        .page(&c, &format!("/devices/{}/tab/software", a.device_id))
        .await;
    assert_eq!(status, 200);
    assert!(frag.contains("&#60;b&#62;7-Zip&#60;/b&#62;"), "{frag}");
    assert!(!frag.contains("<html"));
    assert_eq!(
        s.page(&c, &format!("/devices/{}/tab/nope", a.device_id))
            .await
            .0,
        404
    );
    assert_eq!(
        s.page(&c, &format!("/devices/{}", uuid::Uuid::new_v4()))
            .await
            .0,
        404
    );
}

#[sqlx::test(migrations = false)]
async fn group_admin_cannot_open_other_group_device(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    let other = s.enroll_ok(&kh, None, None).await;
    let c = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    assert_eq!(
        s.page(&c, &format!("/devices/{}", other.device_id)).await.0,
        404
    );
    assert_eq!(
        s.page(&c, &format!("/devices/{}/tab/software", other.device_id))
            .await
            .0,
        404
    );
    let (_, html) = s.page(&c, "/").await;
    let r = c
        .post(s.web_url(&format!("/devices/{}/retire", other.device_id)))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[sqlx::test(migrations = false)]
async fn retire_requires_csrf_role_and_revokes(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let path = format!("/devices/{}/retire", a.device_id);

    let viewer = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&viewer, &format!("/devices/{}", a.device_id)).await;
    assert!(!html.contains("除役（"), "檢視者看不到除役按鈕");
    let r = viewer
        .post(s.web_url(&path))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let c = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let r = c
        .post(s.web_url(&path))
        .form(&[("csrf", "forged")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    let r = c
        .post(s.web_url(&path))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(status, "retired");
}

#[sqlx::test(migrations = false)]
async fn only_platform_admin_moves_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北總部", 1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let kh = s.group_id("高雄廠").await;
    let path = format!("/devices/{}/group", a.device_id);

    let gary = s
        .login_as("gary", Role::GroupAdmin, &["台北總部", "高雄廠"])
        .await;
    let (_, html) = s.page(&gary, "/").await;
    let r = gary
        .post(s.web_url(&path))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("group", &kh.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    let r = c
        .post(s.web_url(&path))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("group", &kh.to_string()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let kate = s.login_as("kate", Role::GroupAdmin, &["高雄廠"]).await;
    assert_eq!(
        s.page(&kate, &format!("/devices/{}", a.device_id)).await.0,
        200
    );
}

#[sqlx::test(migrations = false)]
async fn software_search_is_scoped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 2).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    let a = s.enroll_ok(&tp, None, None).await;
    let b = s.enroll_ok(&tp, None, None).await;
    let k = s.enroll_ok(&kh, None, None).await;
    upload_software(&s, &a, "Google Chrome", "120").await;
    upload_software(&s, &b, "Google Chrome", "121").await;
    upload_software(&s, &k, "Google Chrome", "121").await;

    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/software?q=chrome").await;
    assert!(
        html.contains("/devices?software=Google%20Chrome&#38;version=121\">2<"),
        "{html}"
    );

    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&gary, "/software?q=chrome").await;
    assert!(
        html.contains("/devices?software=Google%20Chrome&#38;version=121\">1<"),
        "只算自己群組：{html}"
    );
}

fn new_token_from(html: &str) -> String {
    let marker = r#"<code id="new-token">"#;
    let start = html.find(marker).expect("token shown once") + marker.len();
    html[start..start + 64].to_string()
}

#[sqlx::test(migrations = false)]
async fn token_created_in_web_can_enroll_and_be_revoked(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北總部").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "IT pilot"),
            ("max_uses", "2"),
            ("group", &tp.to_string()),
            ("valid_days", "7"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let token = new_token_from(&r.text().await.unwrap());
    let a = s.enroll_ok(&token, None, None).await;
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, Some(tp));

    let detail: String =
        sqlx::query_scalar("SELECT detail::text FROM audit_log WHERE action = 'token_create'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(!detail.contains(&token), "明碼不可寫進稽核記錄");

    let id: i64 = sqlx::query_scalar("SELECT id FROM enroll_tokens WHERE name = 'IT pilot'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&c, "/tokens").await;
    assert!(!html.contains(&token), "列表不顯示明碼");
    let r = c
        .post(s.web_url(&format!("/tokens/{id}/revoke")))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(s.enroll(&token, None, None).await.status(), 401);
}

#[sqlx::test(migrations = false)]
async fn group_admin_tokens_are_scoped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let kh = s.group_id("高雄廠").await;
    let _ = s.create_group_token("高雄廠", 1).await;
    let kh_token_id: i64 = sqlx::query_scalar("SELECT id FROM enroll_tokens")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (status, html) = s.page(&gary, "/tokens").await;
    assert_eq!(status, 200);
    assert!(!html.contains("高雄廠 token"), "看不到別的群組的金鑰");
    let csrf = csrf_from(&html);

    let r = gary
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("name", "x"),
            ("max_uses", "1"),
            ("group", &kh.to_string()),
            ("valid_days", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "不能替別的群組建立金鑰");
    let r = gary
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("name", "x"),
            ("max_uses", "1"),
            ("group", ""),
            ("valid_days", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "不能建立未分組的金鑰");
    let r = gary
        .post(s.web_url(&format!("/tokens/{kh_token_id}/revoke")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    let viewer = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    assert_eq!(s.page(&viewer, "/tokens").await.0, 403);
}

#[sqlx::test(migrations = false)]
async fn token_form_validates_input(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", ""),
            ("max_uses", "0"),
            ("group", ""),
            ("valid_days", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_tokens")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

async fn admin_id(s: &TestServer, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM admins WHERE username = $1")
        .bind(name)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn non_platform_cannot_open_admin_pages(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    for path in ["/groups", "/accounts", "/audit"] {
        assert_eq!(s.page(&gary, path).await.0, 403, "{path}");
    }
}

#[sqlx::test(migrations = false)]
async fn platform_admin_manages_groups(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/groups").await;
    let csrf = csrf_from(&html);
    let r = c
        .post(s.web_url("/groups"))
        .form(&[("csrf", csrf.as_str()), ("name", "新竹辦公室")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let id: i64 = sqlx::query_scalar("SELECT id FROM device_groups WHERE name = '新竹辦公室'")
        .fetch_one(&s.pool)
        .await
        .unwrap();

    let _ = s.create_group_token("台北總部", 1).await;
    let busy = s.group_id("台北總部").await;
    let r = c
        .post(s.web_url(&format!("/groups/{busy}/delete")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409, "有金鑰的群組不能刪");
    let r = c
        .post(s.web_url(&format!("/groups/{id}/delete")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
}

#[sqlx::test(migrations = false)]
async fn platform_admin_creates_group_admin_who_can_log_in(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北總部").await;
    let kh = s.group_id("高雄廠").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/accounts").await;
    let body = format!(
        "csrf={}&username=henry&role=group_admin&groups={tp}&groups={kh}&password=henry-long-password",
        csrf_from(&html)
    );
    let r = c
        .post(s.web_url("/accounts"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let groups: Vec<i64> = sqlx::query_scalar(
        "SELECT group_id FROM admin_groups JOIN admins a ON a.id = admin_id \
         WHERE a.username = 'henry' ORDER BY group_id",
    )
    .fetch_all(&s.pool)
    .await
    .unwrap();
    let mut expected = vec![tp, kh];
    expected.sort();
    assert_eq!(groups, expected);

    let r = s
        .web_client()
        .post(s.web_url("/login"))
        .form(&[("username", "henry"), ("password", "henry-long-password")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
}

#[sqlx::test(migrations = false)]
async fn disable_kills_sessions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    assert_eq!(s.page(&gary, "/").await.0, 200);
    let id = admin_id(&s, "gary").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/accounts/{id}")).await;
    let r = c
        .post(s.web_url(&format!("/accounts/{id}/disable")))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(s.page(&gary, "/").await.0, 303, "被停用後立即登出");
}

#[sqlx::test(migrations = false)]
async fn platform_admin_cannot_disable_self(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let id = admin_id(&s, "admin").await;
    let (_, html) = s.page(&c, &format!("/accounts/{id}")).await;
    let r = c
        .post(s.web_url(&format!("/accounts/{id}/disable")))
        .form(&[("csrf", csrf_from(&html).as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
}

#[sqlx::test(migrations = false)]
async fn reset_password_unlocks_and_user_changes_own(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    sqlx::query(
        "UPDATE admins SET locked_until = now() + interval '10 minutes' WHERE username = 'gary'",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let id = admin_id(&s, "gary").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/accounts/{id}")).await;
    let r = c
        .post(s.web_url(&format!("/accounts/{id}/password")))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("password", "temporary-password-1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);

    let g = s.web_client();
    let r = g
        .post(s.web_url("/login"))
        .form(&[("username", "gary"), ("password", "temporary-password-1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303, "重設後可登入（鎖定已解除）");
    let (_, html) = s.page(&g, "/password").await;
    let csrf = csrf_from(&html);
    let r = g
        .post(s.web_url("/password"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("current", "wrong-password-xx"),
            ("new", "gary-new-password"),
            ("confirm", "gary-new-password"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = g
        .post(s.web_url("/password"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("current", "temporary-password-1"),
            ("new", "gary-new-password"),
            ("confirm", "gary-new-password"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        s.page(&g, "/").await.0,
        200,
        "改自己的密碼不會登出目前的工作階段"
    );
}

#[sqlx::test(migrations = false)]
async fn audit_page_lists_logins_and_failures(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let _ = s
        .web_client()
        .post(s.web_url("/login"))
        .form(&[("username", "ghost"), ("password", "<script>x</script>")])
        .send()
        .await
        .unwrap();
    let c = s.admin_client().await;
    let (status, html) = s.page(&c, "/audit").await;
    assert_eq!(status, 200);
    assert!(html.contains("登入成功") && html.contains("登入失敗") && html.contains("ghost"));
    assert!(!html.contains("<script>x"), "密碼不應出現在稽核記錄");
}

#[sqlx::test(migrations = false)]
async fn login_is_rate_limited_per_ip(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    let mut statuses = vec![];
    for _ in 0..(endpoint_server::LOGIN_PER_IP_PER_MINUTE + 1) {
        let r = c
            .post(s.web_url("/login"))
            .form(&[("username", "ghost"), ("password", "whatever-password")])
            .send()
            .await
            .unwrap();
        statuses.push(r.status().as_u16());
    }
    assert!(statuses[..statuses.len() - 1].iter().all(|&s| s == 401));
    assert_eq!(*statuses.last().unwrap(), 429);
}

#[sqlx::test(migrations = false)]
async fn installer_download_embeds_token_url_and_root(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北總部").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    assert!(html.contains("建立並下載安裝檔"));
    assert!(html.contains(r#"value="https://localhost:8443""#));
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "MSI pilot"),
            ("max_uses", "5"),
            ("group", &tp.to_string()),
            ("valid_days", "30"),
            ("server_url", "https://localhost:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment")
    );
    let bytes = r.bytes().await.unwrap();
    let p = endpoint_server::installer::read_properties(&bytes).unwrap();
    assert_eq!(p["SERVER_URL"], "https://localhost:8443");
    assert_eq!(
        p["ROOT_CA"],
        endpoint_server::installer::root_b64(&s.root_pem)
    );
    // 包進去的金鑰可以註冊，且電腦歸入該群組
    let a = s.enroll_ok(&p["ENROLL_TOKEN"], None, None).await;
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, Some(tp));
    let detail: serde_json::Value =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'token_create'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(detail["installer"], true);
    assert_eq!(detail["server_url"], "https://localhost:8443");
    assert!(
        !detail.to_string().contains(&p["ENROLL_TOKEN"]),
        "明碼不可寫進稽核記錄"
    );
}

#[sqlx::test(migrations = false)]
async fn installer_with_wrong_host_is_rejected_without_creating_token(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "wrong host"),
            ("max_uses", "5"),
            ("valid_days", "30"),
            ("server_url", "https://10.9.9.9:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("不在伺服器憑證的名稱內"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_tokens WHERE name = 'wrong host'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn group_admin_downloads_only_for_own_group(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let ks = s.group_id("高雄廠").await;
    let g = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&g, "/tokens").await;
    let r = g
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "other group"),
            ("max_uses", "5"),
            ("group", &ks.to_string()),
            ("server_url", "https://localhost:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

/// 安裝檔會被 Windows 快取在 C:\Windows\Installer（一般使用者可讀），裡面的金鑰必須有期限。
#[sqlx::test(migrations = false)]
async fn installer_token_requires_bounded_validity(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    for days in ["", "91"] {
        let (_, html) = s.page(&c, "/tokens").await;
        let r = c
            .post(s.web_url("/tokens"))
            .form(&[
                ("csrf", csrf_from(&html).as_str()),
                ("name", "no expiry"),
                ("max_uses", "5"),
                ("valid_days", days),
                ("server_url", "https://localhost:8443"),
                ("download", "1"),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "valid_days={days:?}");
        assert!(r.text().await.unwrap().contains("有效天數"));
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM enroll_tokens WHERE name = 'no expiry'")
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[sqlx::test(migrations = false)]
async fn malformed_template_is_rejected_before_creating_token(pool: PgPool) {
    let s = TestServer::start(pool).await;
    std::fs::write(
        s.state.agent_msi.as_ref().unwrap(),
        endpoint_server::installer::template_with(&[("KEEP", "me")]),
    )
    .unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    let r = c
        .post(s.web_url("/tokens"))
        .form(&[
            ("csrf", csrf_from(&html).as_str()),
            ("name", "bad template"),
            ("max_uses", "5"),
            ("valid_days", "30"),
            ("server_url", "https://localhost:8443"),
            ("download", "1"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 503);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM enroll_tokens WHERE name = 'bad template'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(n, 0, "範本不正確時不可留下金鑰");
}

#[sqlx::test(migrations = false)]
async fn missing_template_hides_download_button(pool: PgPool) {
    let s = TestServer::start(pool).await;
    std::fs::remove_file(s.state.agent_msi.as_ref().unwrap()).unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/tokens").await;
    assert!(!html.contains("建立並下載安裝檔"));
}

/// 指令列建立金鑰：新群組寫 group_create 稽核，金鑰稽核格式與網頁相同
#[sqlx::test(migrations = false)]
async fn cli_token_audits_group_and_token(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let detail = |action: &'static str| {
        let pool = s.pool.clone();
        async move {
            sqlx::query_scalar::<_, serde_json::Value>(
                "SELECT detail FROM audit_log WHERE action = $1 AND actor = 'cli' ORDER BY id",
            )
            .bind(action)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    endpoint_server::tokens::create_token_cli(&s.pool, "分公司", 5, Some("新群組"), Some(7))
        .await
        .unwrap();
    endpoint_server::tokens::create_token_cli(&s.pool, "分公司2", 5, Some("新群組"), None)
        .await
        .unwrap();
    assert_eq!(
        detail("group_create").await.len(),
        1,
        "已存在的群組不再記錄"
    );
    let t = detail("token_create").await;
    assert_eq!(t.len(), 2);
    assert_eq!(t[0]["valid_days"], 7, "{}", t[0]);
    assert_eq!(t[0]["installer"], false, "{}", t[0]);
    assert!(t[0].get("expires_at").is_none(), "{}", t[0]);
    assert!(t[0]["group_id"].is_i64(), "{}", t[0]);
}
