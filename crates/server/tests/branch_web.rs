mod common;

use common::{TestServer, csrf_from};
use endpoint_server::web::auth::Role;
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

async fn csrf(s: &TestServer, c: &reqwest::Client, path: &str) -> String {
    let (st, html) = s.page(c, path).await;
    assert_eq!(st, 200, "{path}");
    csrf_from(&html)
}

async fn site_id(s: &TestServer, name: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM sites WHERE name = $1")
        .bind(name)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn audits(s: &TestServer, action: &str, actor: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action = $1 AND actor = $2")
        .bind(action)
        .bind(actor)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn insert_cache(s: &TestServer, site: i64, name: &str, status: &str) -> i64 {
    let id = sqlx::query_scalar(
        "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, poll_secret_hash, status) \
         VALUES ($1, $2, 'https://cache.corp:8443', ARRAY['cache.corp'], 'csr', 'x', $3) \
         RETURNING id",
    )
    .bind(name)
    .bind(site)
    .bind(status)
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query("UPDATE branch_state SET generation = generation + 1")
        .execute(&s.pool)
        .await
        .unwrap();
    id
}

#[sqlx::test(migrations = false)]
async fn site_crud_and_validation(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let t = csrf(&s, &admin, "/sites/new").await;
    let (st, loc, _) = post(
        &s,
        &admin,
        "/sites",
        &[
            ("csrf", &t),
            ("name", "台北"),
            ("cidrs", "10.1.2.3/16\r\n\r\n10.9.0.0/16"),
            ("fallback", "1"),
            ("bandwidth", "50"),
            ("disk_gb", "200"),
        ],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/sites"));
    let (_, html) = s.page(&admin, "/sites").await;
    assert!(
        html.contains("台北") && html.contains("10.1.0.0/16") && html.contains("10.9.0.0/16"),
        "{html}"
    );
    assert_eq!(audits(&s, "site_create", "admin").await, 1);

    // 錯誤：422，顯示原因並保留輸入
    for (form, needle) in [
        (
            vec![
                ("name", "高雄"),
                ("cidrs", "10.1.0.0/16"),
                ("disk_gb", "100"),
            ],
            "台北",
        ),
        (
            vec![
                ("name", "高雄"),
                ("cidrs", "10.0.0.0/33"),
                ("disk_gb", "100"),
            ],
            "10.0.0.0/33",
        ),
        (
            vec![
                ("name", "高雄"),
                ("cidrs", "10.2.0.0/16"),
                ("bandwidth", "abc"),
                ("disk_gb", "100"),
            ],
            "頻寬",
        ),
        (
            vec![("name", "高雄"), ("cidrs", "10.2.0.0/16"), ("disk_gb", "")],
            "磁碟",
        ),
    ] {
        let mut f = vec![("csrf", t.as_str())];
        f.extend(form);
        let (st, _, html) = post(&s, &admin, "/sites", &f).await;
        assert_eq!(st, 422, "{html}");
        assert!(html.contains(needle), "{needle}: {html}");
        assert!(html.contains("value=\"高雄\""), "保留輸入：{html}");
    }

    let tp = site_id(&s, "台北").await;
    let (st, html) = s.page(&admin, &format!("/sites/{tp}/edit")).await;
    assert_eq!(st, 200);
    assert!(html.contains("10.1.0.0/16"));
    let (st, loc, _) = post(
        &s,
        &admin,
        &format!("/sites/{tp}"),
        &[
            ("csrf", &t),
            ("name", "台北總部"),
            ("cidrs", "10.1.0.0/16"),
            ("bandwidth", ""),
            ("disk_gb", "100"),
        ],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/sites"));
    let (fallback, bw): (bool, Option<i32>) =
        sqlx::query_as("SELECT fallback_to_central, bandwidth_limit_mbps FROM sites WHERE id = $1")
            .bind(tp)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(
        (fallback, bw),
        (false, None),
        "沒勾選＝不改向中央；空白＝不限頻寬"
    );
    assert_eq!(s.page(&admin, "/sites/99999/edit").await.0, 404);

    let cache = insert_cache(&s, tp, "快取", "active").await;
    let (st, loc, _) = post(&s, &admin, &format!("/sites/{tp}/delete"), &[("csrf", &t)]).await;
    assert_eq!((st, loc.as_str()), (303, "/sites"));
    let site: Option<i64> = sqlx::query_scalar("SELECT site_id FROM caches WHERE id = $1")
        .bind(cache)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(site, None, "快取保留，據點清空");
    assert_eq!(audits(&s, "site_update", "admin").await, 1);
    assert_eq!(audits(&s, "site_delete", "admin").await, 1);
}

#[sqlx::test(migrations = false)]
async fn device_counts_and_device_page(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let tok = s.create_token(10).await;
    let mut ids = vec![];
    for ip in ["10.1.2.3", "", "fe80::1%12", "garbage", "192.168.1.1"] {
        let a = s.enroll_ok(&tok, None, None).await;
        sqlx::query("UPDATE devices SET last_ip = NULLIF($1, 'NULL') WHERE id = $2")
            .bind(ip)
            .bind(a.device_id)
            .execute(&s.pool)
            .await
            .unwrap();
        ids.push(a.device_id);
    }
    let t = csrf(&s, &admin, "/sites/new").await;
    for (name, cidr) in [("台北", "10.1.0.0/16"), ("台北二樓", "10.1.2.0/24")] {
        let (st, _, html) = post(
            &s,
            &admin,
            "/sites",
            &[
                ("csrf", &t),
                ("name", name),
                ("cidrs", cidr),
                ("disk_gb", "100"),
            ],
        )
        .await;
        assert_eq!(st, 303, "{html}");
    }
    let (st, html) = s.page(&admin, "/sites").await;
    assert_eq!(st, 200, "IP 格式不對的裝置不讓頁面出錯");
    assert!(html.contains("<td class=\"num\">1</td>"), "{html}");

    // 裝置頁：最精確的據點；快取狀態
    let page = |id: uuid::Uuid| {
        let (s, admin) = (&s, &admin);
        async move { s.page(admin, &format!("/devices/{id}")).await.1 }
    };
    let html = page(ids[0]).await;
    assert!(html.contains("台北二樓"), "{html}");
    assert!(html.contains("無（向中央下載）"), "{html}");
    let floor = site_id(&s, "台北二樓").await;
    let cache = insert_cache(&s, floor, "二樓快取", "active").await;
    let html = page(ids[0]).await;
    assert!(
        html.contains("二樓快取") && html.contains("使用中"),
        "{html}"
    );
    sqlx::query("UPDATE caches SET status = 'disabled' WHERE id = $1")
        .bind(cache)
        .execute(&s.pool)
        .await
        .unwrap();
    let html = page(ids[0]).await;
    assert!(html.contains("已停用"), "{html}");
    for id in &ids[1..] {
        let html = page(*id).await;
        assert!(html.contains("<th>據點</th><td>—</td>"), "{html}");
    }
}

#[sqlx::test(migrations = false)]
async fn sites_are_platform_only(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let t = csrf(&s, &admin, "/sites/new").await;
    post(
        &s,
        &admin,
        "/sites",
        &[
            ("csrf", &t),
            ("name", "台北"),
            ("cidrs", "10.1.0.0/16"),
            ("disk_gb", "100"),
        ],
    )
    .await;
    let tp = site_id(&s, "台北").await;
    // 沒有 CSRF
    let (st, _, _) = post(&s, &admin, &format!("/sites/{tp}/delete"), &[("csrf", "x")]).await;
    assert_ne!(st, 303, "沒有 CSRF 的 POST 被拒");
    for (who, role) in [("gary", Role::GroupAdmin), ("vera", Role::Viewer)] {
        let c = s.login_as(who, role, &["台北"]).await;
        let (_, html) = s.page(&c, "/devices").await;
        let t = csrf_from(&html);
        for path in ["/sites", "/sites/new", &format!("/sites/{tp}/edit")] {
            assert_eq!(s.page(&c, path).await.0, 403, "{who} GET {path}");
        }
        for path in [
            "/sites".to_string(),
            format!("/sites/{tp}"),
            format!("/sites/{tp}/delete"),
        ] {
            let (st, _, _) = post(
                &s,
                &c,
                &path,
                &[
                    ("csrf", &t),
                    ("name", "x"),
                    ("cidrs", "10.5.0.0/16"),
                    ("disk_gb", "1"),
                ],
            )
            .await;
            assert_eq!(st, 403, "{who} POST {path}");
        }
        assert!(
            !s.page(&c, "/").await.1.contains("href=\"/sites\""),
            "選單不顯示"
        );
    }
    assert_eq!(site_id(&s, "台北").await, tp, "沒有被刪除");
    assert!(s.page(&admin, "/").await.1.contains("href=\"/sites\""));
}
