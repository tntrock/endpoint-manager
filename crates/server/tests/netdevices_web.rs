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

async fn site(s: &TestServer, name: &str, cidr: &str) -> i64 {
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

async fn one<T>(s: &TestServer, sql: &str) -> T
where
    T: for<'r> sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres> + Send + Unpin,
{
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_string()))
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

fn v3_form<'a>(t: &'a str, name: &'a str, auth_pass: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("csrf", t),
        ("name", name),
        ("version", "v3"),
        ("user", "monitor"),
        ("auth", "sha256"),
        ("auth_pass", auth_pass),
        ("privacy", "aes256c"),
        ("priv_pass", "privpass123"),
    ]
}

#[sqlx::test(migrations = false)]
async fn credentials_are_encrypted_and_write_only(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let t = csrf(&s, &admin, "/netdevices/credentials/new").await;

    // 驗證錯誤：重新顯示表單，不回填密碼
    let (st, _, html) = post(
        &s,
        &admin,
        "/netdevices/credentials",
        &v3_form(&t, "總公司", "short"),
    )
    .await;
    assert_eq!(st, 422);
    assert!(html.contains("驗證密碼要 8–255 個字元"));
    assert!(html.contains(r#"value="monitor""#));
    assert!(!html.contains("privpass123"));

    let (st, loc, _) = post(
        &s,
        &admin,
        "/netdevices/credentials",
        &v3_form(&t, "總公司", "authpass123"),
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/netdevices#credentials"));
    let (id, version, user, enc): (i64, String, Option<String>, Vec<u8>) = sqlx::query_as(
        "SELECT id, version, username, secret_enc FROM snmp_credentials WHERE name = '總公司'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!((version.as_str(), user.as_deref()), ("v3", Some("monitor")));
    assert!(!enc.windows(11).any(|w| w == b"authpass123"), "加密保存");
    // 稽核紀錄不含機密
    let detail: String = one(
        &s,
        "SELECT detail::text FROM audit_log WHERE action = 'snmp_credential_create'",
    )
    .await;
    assert!(!detail.contains("authpass123") && !detail.contains("privpass123"));

    // 名稱重複
    let (st, _, html) = post(
        &s,
        &admin,
        "/netdevices/credentials",
        &v3_form(&t, "總公司", "authpass123"),
    )
    .await;
    assert_eq!(st, 422);
    assert!(html.contains("帳密名稱已存在"));

    // 編輯頁：演算法回填、密碼不顯示
    let (st, html) = s
        .page(&admin, &format!("/netdevices/credentials/{id}/edit"))
        .await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"value="aes256c" selected"#));
    assert!(html.contains(r#"value="monitor""#));
    assert!(!html.contains("authpass123") && !html.contains("privpass123"));

    // 留空沿用舊密碼，只改名稱
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/netdevices/credentials/{id}"),
        &v3_form(&t, "總公司唯讀", ""),
    )
    .await;
    assert_eq!(st, 303);
    let enc: Vec<u8> = one(&s, "SELECT secret_enc FROM snmp_credentials").await;
    let c = endpoint_server::netdev::open(s.state.secrets.as_deref().unwrap(), &enc).unwrap();
    assert!(
        matches!(c, protocol::netdev::SnmpCredential::V3 { ref auth_pass, .. }
        if auth_pass == "authpass123")
    );

    // 改成 v2c：要填 community
    let (st, _, html) = post(
        &s,
        &admin,
        &format!("/netdevices/credentials/{id}"),
        &[("csrf", &t), ("name", "總公司唯讀"), ("version", "v2c")],
    )
    .await;
    assert_eq!(st, 422);
    assert!(html.contains("Community必填"));
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/netdevices/credentials/{id}"),
        &[
            ("csrf", &t),
            ("name", "總公司唯讀"),
            ("version", "v2c"),
            ("community", "public"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    let (st, html) = s.page(&admin, "/netdevices").await;
    assert_eq!(st, 200);
    assert!(html.contains("總公司唯讀") && html.contains("v2c"));
    assert!(!html.contains("public"));
    let (st, html) = s
        .page(&admin, &format!("/netdevices/credentials/{id}/edit"))
        .await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"value="v2c" checked"#));

    // 不存在
    assert_eq!(
        post(
            &s,
            &admin,
            "/netdevices/credentials/9999",
            &v3_form(&t, "x", "authpass123")
        )
        .await
        .0,
        404
    );
    assert_eq!(
        s.page(&admin, "/netdevices/credentials/9999/edit").await.0,
        404
    );
    assert_eq!(
        post(
            &s,
            &admin,
            "/netdevices/credentials/9999/delete",
            &[("csrf", &t)]
        )
        .await
        .0,
        404
    );

    // 刪除
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/netdevices/credentials/{id}/delete"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!(st, 303);
    let n: i64 = one(&s, "SELECT count(*) FROM snmp_credentials").await;
    assert_eq!(n, 0);
    let n: i64 = one(
        &s,
        "SELECT count(*) FROM audit_log WHERE action LIKE 'snmp_credential_%'",
    )
    .await;
    assert_eq!(n, 4);
}

#[sqlx::test(migrations = false)]
async fn devices_crud_and_detail(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let tp = site(&s, "台北", "10.1.0.0/16").await;
    let tc = site(&s, "台中", "10.2.0.0/16").await;

    // 還沒有帳密
    let (st, html) = s.page(&admin, "/netdevices/new").await;
    assert_eq!(st, 200);
    assert!(html.contains("還沒有 SNMP 帳密"));
    let t = csrf_from(&html);
    post(
        &s,
        &admin,
        "/netdevices/credentials",
        &v3_form(&t, "唯讀", "authpass123"),
    )
    .await;
    let cred: i64 = one(&s, "SELECT id FROM snmp_credentials").await;
    let cred_s = cred.to_string();
    let tp_s = tp.to_string();

    let form = |name: &'static str, addr: &'static str, port: &'static str| {
        vec![
            ("csrf", t.clone()),
            ("name", name.to_string()),
            ("site_id", tp_s.clone()),
            ("address", addr.to_string()),
            ("port", port.to_string()),
            ("credential_id", cred_s.clone()),
            ("enabled", "1".to_string()),
            ("cisco_vlan", "auto".to_string()),
        ]
    };
    let send = |f: Vec<(&'static str, String)>, path: String| {
        let admin = admin.clone();
        let url = s.web_url(&path);
        async move {
            let r = admin.post(url).form(&f).send().await.unwrap();
            let st = r.status().as_u16();
            let loc = r
                .headers()
                .get("location")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default();
            (st, loc, r.text().await.unwrap())
        }
    };

    // 驗證錯誤
    let (st, _, html) = send(form("核心", "not a host", ""), "/netdevices".into()).await;
    assert_eq!(st, 422);
    assert!(html.contains("不是 IP 位址或主機名稱"));
    assert!(html.contains(r#"value="核心""#), "回填");
    let mut bad = form("核心", "10.1.0.1", "");
    bad[2].1 = "9999".into();
    let (st, _, html) = send(bad, "/netdevices".into()).await;
    assert_eq!(st, 422);
    assert!(html.contains("請選擇據點"));
    let mut bad = form("核心", "10.1.0.1", "");
    bad[5].1 = "9999".into();
    let (st, _, html) = send(bad, "/netdevices".into()).await;
    assert_eq!(st, 422);
    assert!(html.contains("請選擇 SNMP 帳密"));

    let (st, loc, _) = send(form("核心", "10.1.0.1", ""), "/netdevices".into()).await;
    assert_eq!(st, 303);
    let id: i64 = one(&s, "SELECT id FROM net_devices").await;
    assert_eq!(loc, format!("/netdevices/{id}"));
    let (port, requested): (i32, bool) =
        sqlx::query_as("SELECT port, poll_requested FROM net_devices")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((port, requested), (161, true));

    // 同據點、同位址與埠號
    let (st, _, html) = send(form("重複", "10.1.0.1", "161"), "/netdevices".into()).await;
    assert_eq!(st, 422);
    assert!(html.contains("相同位址與埠號"));

    // 清單：據點沒有快取
    let (st, html) = s.page(&admin, "/netdevices").await;
    assert_eq!(st, 200);
    assert!(html.contains("核心") && html.contains("據點沒有快取"));
    assert!(!html.contains("EM_SECRET_KEY_FILE"));

    // 模擬快取查詢過的結果
    sqlx::query(
        "UPDATE net_devices SET last_polled_at = now(), last_ok_at = now(), \
         model = 'C9300-48P', firmware = '17.9.4', uptime_secs = 90000, sys_name = 'core-sw' \
         WHERE id = $1",
    )
    .bind(id)
    .execute(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO net_interfaces (device_id, if_index, name, alias, if_type, admin_up, oper_up, \
                speed_mbps, mac, pvid, role, lldp) VALUES \
         ($1, 1, 'Gi1/0/1', '會議室', 6, true, true, 1000, 'aa:bb:cc:00:00:01', 10, 'auto_edge', '[]'), \
         ($1, 48, 'Te1/1/1', '', 6, true, true, 10000, NULL, NULL, 'auto_uplink', \
          '[{\"sys_name\":\"dist-sw\",\"port_id\":\"Te1/0/5\",\"port_descr\":\"\",\"chassis_id\":\"\"}]'), \
         ($1, 2, 'Gi1/0/2', '', 6, false, false, NULL, NULL, NULL, 'auto_edge', '[]')",
    )
    .bind(id)
    .execute(&s.pool)
    .await
    .unwrap();
    let insert_cache = "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, \
                        poll_secret_hash, status) VALUES ('tp', $1, 'https://c:8443', \
                        ARRAY['c'], 'csr', 'x', 'active')";
    sqlx::query(insert_cache)
        .bind(tp)
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&admin, "/netdevices").await;
    assert!(html.contains("C9300-48P") && html.contains("17.9.4"));
    assert!(html.contains("1 天 1 小時"));
    assert!(html.contains("2 / 3"), "連線埠");
    assert!(html.contains(">正常<"));

    let (st, html) = s.page(&admin, &format!("/netdevices/{id}")).await;
    assert_eq!(st, 200);
    assert!(html.contains("core-sw") && html.contains("C9300-48P"));
    assert!(html.contains("會議室") && html.contains("1 Gbps") && html.contains("10 Gbps"));
    assert!(html.contains("dist-sw Te1/0/5"));
    assert!(html.contains(">上行<"));
    assert!(html.contains(">停用<") && html.contains(">連線<"));
    assert_eq!(s.page(&admin, "/netdevices/9999").await.0, 404);

    // 立即查詢
    sqlx::query("UPDATE net_devices SET poll_requested = false")
        .execute(&s.pool)
        .await
        .unwrap();
    let (st, loc, _) = post(
        &s,
        &admin,
        &format!("/netdevices/{id}/poll"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!((st, loc), (303, format!("/netdevices/{id}?polling=true")));
    assert!(one::<bool>(&s, "SELECT poll_requested FROM net_devices").await);
    let (_, html) = s.page(&admin, &loc_of(id)).await;
    assert!(html.contains("已排入查詢"));
    assert_eq!(
        post(&s, &admin, "/netdevices/9999/poll", &[("csrf", &t)])
            .await
            .0,
        404
    );

    // 連續失敗：無法連線、總覽的需要處理、篩選
    sqlx::query(
        "UPDATE net_devices SET consecutive_failures = 3, last_error = '逾時：測試', \
         last_polled_at = now()",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let (_, html) = s.page(&admin, &format!("/netdevices/{id}")).await;
    assert!(html.contains("無法連線") && html.contains("逾時：測試"));
    let (_, html) = s.page(&admin, "/").await;
    assert!(html.contains("網路設備無法連線"));
    assert!(html.contains("/netdevices?status=down"));
    let (_, html) = s.page(&admin, "/netdevices?status=down").await;
    assert!(html.contains("核心"));
    let (_, html) = s.page(&admin, &format!("/netdevices?site={tc}")).await;
    assert!(html.contains("沒有網路設備"));

    // 編輯：改據點與埠號
    let (st, html) = s.page(&admin, &format!("/netdevices/{id}/edit")).await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"value="10.1.0.1""#));
    let mut f = form("核心", "10.1.0.1", "1161");
    f[2].1 = tc.to_string();
    f[6].1 = String::new();
    let f: Vec<_> = f.into_iter().filter(|(k, _)| *k != "enabled").collect();
    let (st, _, _) = send(f, format!("/netdevices/{id}")).await;
    assert_eq!(st, 303);
    let (site_id, port, enabled): (i64, i32, bool) =
        sqlx::query_as("SELECT site_id, port, enabled FROM net_devices")
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((site_id, port, enabled), (tc, 1161, false));
    let (_, html) = s.page(&admin, "/netdevices").await;
    assert!(html.contains("10.1.0.1:1161") && html.contains("已停用"));
    let (st, _, html) = send(form("x", "bad host!", ""), format!("/netdevices/{id}")).await;
    assert_eq!(st, 422);
    assert!(html.contains("編輯網路設備"));
    assert_eq!(
        send(form("x", "10.0.0.1", ""), "/netdevices/9999".into())
            .await
            .0,
        404
    );
    assert_eq!(s.page(&admin, "/netdevices/9999/edit").await.0, 404);

    // 使用中的帳密、有設備的據點不能刪
    let (st, _, body) = post(
        &s,
        &admin,
        &format!("/netdevices/credentials/{cred}/delete"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!(st, 409);
    assert!(body.contains("還有 1 台網路設備使用這組帳密"));
    let (st, _, body) = post(&s, &admin, &format!("/sites/{tc}/delete"), &[("csrf", &t)]).await;
    assert_eq!(st, 409);
    assert!(body.contains("還有 1 台網路設備"));

    // 刪除設備：介面一併刪除
    let (st, loc, _) = post(
        &s,
        &admin,
        &format!("/netdevices/{id}/delete"),
        &[("csrf", &t)],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/netdevices"));
    let n: i64 = one(&s, "SELECT count(*) FROM net_interfaces").await;
    assert_eq!(n, 0);
    assert_eq!(
        post(&s, &admin, "/netdevices/9999/delete", &[("csrf", &t)])
            .await
            .0,
        404
    );
    let n: i64 = one(
        &s,
        "SELECT count(*) FROM audit_log WHERE action LIKE 'netdevice_%'",
    )
    .await;
    assert_eq!(n, 3, "建立、修改、刪除");
}

fn loc_of(id: i64) -> String {
    format!("/netdevices/{id}?polling=true")
}

#[sqlx::test(migrations = false)]
async fn intervals_and_permissions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/netdevices").await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"name="system_min" value="15""#));
    assert!(html.contains(r#"name="table_min" value="5""#));
    assert!(html.contains("/netdevices\"") || html.contains("網路設備"));
    let t = csrf_from(&html);
    let (st, loc, _) = post(
        &s,
        &admin,
        "/netdevices/settings",
        &[("csrf", &t), ("system_min", "30"), ("table_min", "2")],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/netdevices?saved=true"));
    assert_eq!(
        endpoint_server::netdev::intervals(&s.pool).await.unwrap(),
        (1800, 120)
    );
    let (_, html) = s.page(&admin, "/netdevices?saved=true").await;
    assert!(html.contains("已儲存"));
    for (a, b) in [("0", "5"), ("15", "1441"), ("x", "5")] {
        let (st, _, html) = post(
            &s,
            &admin,
            "/netdevices/settings",
            &[("csrf", &t), ("system_min", a), ("table_min", b)],
        )
        .await;
        assert_eq!(st, 422, "{a} {b}");
        assert!(html.contains("查詢間隔"));
    }
    // 設定值被改壞時用預設
    sqlx::query("UPDATE settings SET value = '\"x\"' WHERE key = 'snmp_table_interval_secs'")
        .execute(&s.pool)
        .await
        .unwrap();
    assert_eq!(
        endpoint_server::netdev::intervals(&s.pool).await.unwrap(),
        (1800, 300)
    );

    // CSRF
    assert_eq!(
        post(
            &s,
            &admin,
            "/netdevices/settings",
            &[("csrf", "bad"), ("system_min", "15"), ("table_min", "5")]
        )
        .await
        .0,
        403
    );
    // 群組管理員與檢視者：看不到也不能改
    for (name, role) in [("ga", Role::GroupAdmin), ("viewer", Role::Viewer)] {
        let c = s.login_as(name, role, &["A"]).await;
        let (_, home) = s.page(&c, "/").await;
        assert!(!home.contains("/netdevices"), "{name}");
        for path in [
            "/netdevices",
            "/netdevices/new",
            "/netdevices/credentials/new",
            "/netdevices/1",
            "/netdevices/1/edit",
            "/netdevices/credentials/1/edit",
        ] {
            assert_eq!(s.page(&c, path).await.0, 403, "{name} {path}");
        }
        let t = csrf(&s, &c, "/").await;
        for path in [
            "/netdevices",
            "/netdevices/settings",
            "/netdevices/credentials",
            "/netdevices/1",
            "/netdevices/1/delete",
            "/netdevices/1/poll",
            "/netdevices/credentials/1",
            "/netdevices/credentials/1/delete",
        ] {
            assert_eq!(
                post(&s, &c, path, &[("csrf", &t)]).await.0,
                403,
                "{name} {path}"
            );
        }
    }
}

#[sqlx::test(migrations = false)]
async fn without_secret_key(pool: PgPool) {
    let s = TestServer::start_without_secrets(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/netdevices").await;
    assert_eq!(st, 200);
    assert!(html.contains("EM_SECRET_KEY_FILE"));
    let t = csrf_from(&html);
    let (st, html) = s.page(&admin, "/netdevices/credentials/new").await;
    assert_eq!(st, 200);
    assert!(html.contains("不能保存帳密"));
    let (st, _, html) = post(
        &s,
        &admin,
        "/netdevices/credentials",
        &v3_form(&t, "x", "authpass123"),
    )
    .await;
    assert_eq!(st, 422);
    assert!(html.contains("沒有設定加密金鑰"));
    // 金鑰後來拿掉：編輯頁照樣能開（不回填使用者名稱）
    sqlx::query(
        "INSERT INTO snmp_credentials (name, version, username, secret_enc) \
         VALUES ('舊', 'v3', 'mon', '\\x00')",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let id: i64 = one(&s, "SELECT id FROM snmp_credentials").await;
    let (st, html) = s
        .page(&admin, &format!("/netdevices/credentials/{id}/edit"))
        .await;
    assert_eq!(st, 200);
    assert!(html.contains(r#"value="舊""#));
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/netdevices/credentials/{id}"),
        &v3_form(&t, "舊", ""),
    )
    .await;
    assert_eq!(st, 422);
}
