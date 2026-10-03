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
    assert!(html.contains("已停用，向中央下載"), "{html}");
    assert!(html.contains("依最後回報的 IP"), "{html}");
    for id in &ids[1..] {
        let html = page(*id).await;
        assert!(
            html.contains("<th>據點（依最後回報的 IP）</th><td>—</td>"),
            "{html}"
        );
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

fn new_token_from(html: &str) -> String {
    let marker = r#"<code id="new-token">"#;
    let start = html.find(marker).expect("new token shown") + marker.len();
    html[start..].split('<').next().unwrap().to_string()
}

async fn create_site(s: &TestServer, name: &str, cidr: &str) -> i64 {
    endpoint_server::branch::sites::create_site(
        &s.pool,
        &endpoint_server::branch::sites::SiteInput {
            name: name.into(),
            cidrs: vec![cidr.into()],
            fallback_to_central: true,
            bandwidth_limit_mbps: None,
            disk_limit_gb: 100,
        },
        "admin",
    )
    .await
    .unwrap()
}

async fn enroll_cache(s: &TestServer, token: &str, name: &str) -> i64 {
    let (csr, _) = common::make_csr();
    let r = s
        .client(None)
        .post(s.url("/v1/cache/enroll"))
        .json(&protocol::branch::CacheEnrollRequest {
            token: token.into(),
            name: name.into(),
            url: "https://cache-tp.test:8443".into(),
            dns_names: vec!["cache-tp.test".into()],
            csr_pem: csr,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json::<protocol::branch::CacheEnrollResponse>()
        .await
        .unwrap()
        .cache_id
}

async fn cache_status(s: &TestServer, id: i64) -> String {
    sqlx::query_scalar("SELECT status FROM caches WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn package_source(
    s: &TestServer,
    a: &common::TestAgent,
) -> Option<protocol::branch::PackageSource> {
    s.state.branch.invalidate();
    let r: protocol::CheckinResponse = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.7.0".into(),
            boot_time: chrono::Utc::now(),
            logged_on_user: None,
            ip_addresses: vec!["10.1.0.5".into()],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    r.package_source
}

#[sqlx::test(migrations = false)]
async fn cache_tokens_and_lifecycle(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let t = csrf(&s, &admin, "/caches").await;

    // 快取註冊金鑰：明碼顯示一次、kind = cache、不出現在 /tokens
    let (st, _, html) = post(
        &s,
        &admin,
        "/caches/tokens",
        &[
            ("csrf", &t),
            ("name", "台北快取金鑰"),
            ("max_uses", "2"),
            ("valid_days", "7"),
        ],
    )
    .await;
    assert_eq!(st, 200, "{html}");
    let token = new_token_from(&html);
    assert!(html.contains("endpoint-cache enroll"), "{html}");
    let (tid, kind): (i64, String) =
        sqlx::query_as("SELECT id, kind FROM enroll_tokens WHERE name = '台北快取金鑰'")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!(kind, "cache");
    assert!(!s.page(&admin, "/tokens").await.1.contains("台北快取金鑰"));
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/tokens/{tid}/revoke"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!(st, 404, "/tokens 不能作廢快取金鑰");

    // 註冊與核准：下拉選單只有還沒有快取的據點
    let free = create_site(&s, "台北", "10.1.0.0/16").await;
    let taken = create_site(&s, "高雄", "10.2.0.0/16").await;
    insert_cache(&s, taken, "高雄快取", "active").await;
    let id = enroll_cache(&s, &token, "台北快取").await;
    let (_, html) = s.page(&admin, "/caches").await;
    assert!(
        html.contains("台北快取") && html.contains("待核准"),
        "{html}"
    );
    assert!(
        html.contains(&format!("<option value=\"{free}\">台北</option>")),
        "{html}"
    );
    assert!(
        !html.contains(&format!("<option value=\"{taken}\">")),
        "已有快取的據點不在選單：{html}"
    );
    let (st, _, html) = post(
        &s,
        &admin,
        &format!("/caches/{id}/approve"),
        &[("csrf", &t), ("site", &taken.to_string())],
    )
    .await;
    assert_eq!(st, 409, "{html}");
    let (st, loc, _) = post(
        &s,
        &admin,
        &format!("/caches/{id}/approve"),
        &[("csrf", &t), ("site", &free.to_string())],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/caches"));
    assert_eq!(cache_status(&s, id).await, "active");
    assert_eq!(audits(&s, "cache_approve", "admin").await, 1);
    let (st, _, _) = post(&s, &admin, &format!("/caches/{id}/reject"), &[("csrf", &t)]).await;
    assert_eq!(st, 409, "使用中的快取不能拒絕");

    // 停用、啟用：報到下發跟著變
    let agent = s.enroll_ok(&s.create_token(1).await, None, None).await;
    assert!(package_source(&s, &agent).await.is_some());
    post(
        &s,
        &admin,
        &format!("/caches/{id}/disable"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!(cache_status(&s, id).await, "disabled");
    assert!(s.page(&admin, "/caches").await.1.contains("已停用"));
    assert!(package_source(&s, &agent).await.is_none());
    post(&s, &admin, &format!("/caches/{id}/enable"), &[("csrf", &t)]).await;
    assert_eq!(cache_status(&s, id).await, "active");
    assert!(package_source(&s, &agent).await.is_some());

    // 預先下載進度
    sqlx::query(
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by) \
         VALUES ('App', '1', 'exe', 'a.exe', 10, repeat('a', 64), '/S', 'App*', 'admin')",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT 'D', max(id), 'install', 'all', 10, 20, 'admin' FROM packages",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO cache_packages (cache_id, package_id, size) SELECT $1, max(id), 10 FROM packages")
        .bind(id)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(s.page(&admin, "/caches").await.1.contains("已存 1／應有 1"));

    // 改據點為不指定、刪除
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/caches/{id}/site"),
        &[("csrf", &t), ("site", "")],
    )
    .await;
    assert_eq!(st, 303);
    let site: Option<i64> = sqlx::query_scalar("SELECT site_id FROM caches WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(site, None);
    let (st, _, _) = post(&s, &admin, &format!("/caches/{id}/delete"), &[("csrf", &t)]).await;
    assert_eq!(st, 303);
    assert!(
        !s.page(&admin, "/caches")
            .await
            .1
            .contains("<td>台北快取</td>")
    );
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/caches/{id}/disable"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!(st, 404, "已刪除");

    // 作廢快取金鑰
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/caches/tokens/{tid}/revoke"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!(st, 303);
    let revoked: bool =
        sqlx::query_scalar("SELECT revoked_at IS NOT NULL FROM enroll_tokens WHERE id = $1")
            .bind(tid)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert!(revoked);
    assert_eq!(audits(&s, "token_revoke", "admin").await, 1);
}

#[sqlx::test(migrations = false)]
async fn caches_are_platform_only(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let site = create_site(&s, "台北", "10.1.0.0/16").await;
    let id = insert_cache(&s, site, "台北快取", "active").await;
    let admin = s.admin_client().await;
    assert!(
        s.page(&admin, "/sites")
            .await
            .1
            .contains("href=\"/caches\"")
    );
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/caches/{id}/disable"),
        &[("csrf", "x")],
    )
    .await;
    assert_ne!(st, 303, "沒有 CSRF 的 POST 被拒");
    for (who, role) in [("gary", Role::GroupAdmin), ("vera", Role::Viewer)] {
        let c = s.login_as(who, role, &["台北"]).await;
        let (_, html) = s.page(&c, "/devices").await;
        let t = csrf_from(&html);
        assert_eq!(s.page(&c, "/caches").await.0, 403, "{who}");
        for action in ["approve", "reject", "disable", "enable", "site", "delete"] {
            let (st, _, _) = post(
                &s,
                &c,
                &format!("/caches/{id}/{action}"),
                &[("csrf", &t), ("site", "")],
            )
            .await;
            assert_eq!(st, 403, "{who} {action}");
        }
        let (st, _, _) = post(
            &s,
            &c,
            "/caches/tokens",
            &[("csrf", &t), ("name", "x"), ("max_uses", "1")],
        )
        .await;
        assert_eq!(st, 403, "{who} tokens");
        assert!(!s.page(&c, "/").await.1.contains("href=\"/caches\""));
    }
    assert_eq!(cache_status(&s, id).await, "active");
}

#[sqlx::test(migrations = false)]
async fn deployment_detail_shows_source(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    sqlx::query(
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by) \
         VALUES ('App', '1', 'exe', 'a.exe', 10, repeat('a', 64), '/S', 'App*', 'admin')",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let d: i64 = sqlx::query_scalar(
        "INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT 'D', max(id), 'install', 'all', 10, 20, 'admin' FROM packages RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    for (dev, source) in [(a.device_id, Some("cache")), (b.device_id, None)] {
        sqlx::query(
            "INSERT INTO deployment_status (deployment_id, device_id, status, revision, source) \
             VALUES ($1, $2, 'succeeded', 1, $3)",
        )
        .bind(d)
        .bind(dev)
        .bind(source)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    let (_, html) = s.page(&admin, &format!("/deployments/{d}")).await;
    assert!(html.contains("<th>來源</th>"), "{html}");
    assert!(html.contains("<td>快取</td>"), "{html}");
}

#[sqlx::test(migrations = false)]
async fn site_delete_errors(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let t = csrf(&s, &admin, "/sites/new").await;
    let id = create_site(&s, "台北", "10.1.0.0/16").await;
    let (st, _, _) = post(&s, &admin, "/sites/999999/delete", &[("csrf", &t)]).await;
    assert_eq!(st, 404);
    // 資料庫錯誤不是「不存在」
    sqlx::raw_sql(
        "CREATE FUNCTION fail_site_delete() RETURNS trigger LANGUAGE plpgsql AS \
         $$ BEGIN RAISE EXCEPTION 'boom'; END $$; \
         CREATE TRIGGER fail_site_delete BEFORE DELETE ON sites \
         FOR EACH ROW EXECUTE FUNCTION fail_site_delete();",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let (st, _, body) = post(&s, &admin, &format!("/sites/{id}/delete"), &[("csrf", &t)]).await;
    assert_eq!(st, 500, "{body}");
    assert!(!body.contains("boom"), "{body}");
}

#[sqlx::test(migrations = false)]
async fn sites_tabs_mark_current(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/caches").await;
    assert!(
        html.contains(r#"<a href="/caches" class="on" aria-current="page">快取</a>"#),
        "{html}"
    );
    assert!(
        html.contains(r#"<a href="/sites" class="on" aria-current="page">"#),
        "側邊欄標示據點與快取：{html}"
    );
}
