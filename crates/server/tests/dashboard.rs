mod common;

use common::{TestAgent, TestServer};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;
use time::{Date, Duration, OffsetDateTime};

struct Fixture {
    a: TestAgent,
    b: TestAgent,
    c: TestAgent,
    k: TestAgent,
    high_rule: i64,
    deployment: i64,
}

fn today(s: &TestServer) -> Date {
    OffsetDateTime::now_utc()
        .to_offset(s.state.display_offset)
        .date()
}

async fn exec(s: &TestServer, sql: &str) {
    sqlx::query(sqlx::AssertSqlSafe(sql.to_string()))
        .execute(&s.pool)
        .await
        .unwrap();
}

/// 台北總部 A、B、C，高雄廠 K。
/// A、K 違反高風險規則，B 違反中風險規則並派送失敗，C 離線 10 天。
async fn fixture(s: &TestServer) -> Fixture {
    let tp = s.create_group_token("台北總部", 5).await;
    let kh = s.create_group_token("高雄廠", 5).await;
    let a = s.enroll_ok(&tp, None, None).await;
    let b = s.enroll_ok(&tp, None, None).await;
    let c = s.enroll_ok(&tp, None, None).await;
    let k = s.enroll_ok(&kh, None, None).await;
    for (agent, name, ip, seen) in [
        (&a, "TP-A", "10.1.2.5", "now()"),
        (&b, "TP-B", "10.1.3.3", "now()"),
        (&c, "TP-C", "not-an-ip", "now() - interval '10 days'"),
        (&k, "KH-K", "10.9.0.1", "now()"),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE devices SET hostname = $2, last_ip = $3, last_seen_at = {seen} WHERE id = $1"
        )))
        .bind(agent.device_id)
        .bind(name)
        .bind(ip)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    let rule = |name: &'static str, sev: &'static str| {
        let pool = s.pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
                 VALUES ($1, 'forbidden_software', $2, '{\"name\":\"x\"}'::jsonb, 't') RETURNING id",
            )
            .bind(name)
            .bind(sev)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let high_rule = rule("禁用軟體X", "high").await;
    let medium_rule = rule("舊版壓縮工具", "medium").await;
    for (dev, r) in [
        (a.device_id, high_rule),
        (k.device_id, high_rule),
        (b.device_id, medium_rule),
    ] {
        sqlx::query(
            "INSERT INTO device_violations (device_id, rule_id, status, detail) \
             VALUES ($1, $2, 'violating', '{}'::jsonb)",
        )
        .bind(dev)
        .bind(r)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    exec(
        s,
        "INSERT INTO sites (name, cidrs) VALUES ('台北', '{10.1.0.0/16}'), ('台北機房', '{10.1.2.0/24}')",
    )
    .await;
    exec(
        s,
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by) \
         VALUES ('App', '1', 'exe', 'a.exe', 10, repeat('a', 64), '/S', 'App*', 'admin')",
    )
    .await;
    let deployment: i64 = sqlx::query_scalar(
        "INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT '安裝 App', max(id), 'install', 'all', 10, 20, 'admin' FROM packages RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO deployment_status (deployment_id, device_id, status, revision) VALUES ($1, $2, 'failed', 1)",
    )
    .bind(deployment)
    .bind(b.device_id)
    .execute(&s.pool)
    .await
    .unwrap();
    Fixture {
        a,
        b,
        c,
        k,
        high_rule,
        deployment,
    }
}

async fn daily(s: &TestServer, day: Date) -> Vec<(i64, i32, i32, i32, i32)> {
    sqlx::query_as(
        "SELECT group_id, managed, seen, compliant, high_risk FROM device_daily \
         WHERE day = $1 ORDER BY group_id",
    )
    .bind(day)
    .fetch_all(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn snapshot_counts_per_group_and_overwrites(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fixture(&s).await;
    let (tp, kh) = (s.group_id("台北總部").await, s.group_id("高雄廠").await);
    let day = today(&s);
    endpoint_server::stats::snapshot(&s.pool, day)
        .await
        .unwrap();
    let mut want = vec![(tp, 3, 2, 1, 1), (kh, 1, 1, 0, 1)];
    want.sort();
    assert_eq!(daily(&s, day).await, want);

    // 同一天重寫：高雄廠已沒有受管裝置，舊列被清掉
    endpoint_server::devices::retire(&s.pool, f.k.device_id, "admin")
        .await
        .unwrap();
    endpoint_server::stats::snapshot(&s.pool, day)
        .await
        .unwrap();
    assert_eq!(daily(&s, day).await, vec![(tp, 3, 2, 1, 1)]);

    // 清理只刪保留期間以前的
    endpoint_server::stats::snapshot(&s.pool, day - Duration::days(40))
        .await
        .unwrap();
    endpoint_server::stats::cleanup(&s.pool, day, 30)
        .await
        .unwrap();
    assert!(daily(&s, day - Duration::days(40)).await.is_empty());
    assert_eq!(daily(&s, day).await.len(), 1);
}

#[sqlx::test(migrations = false)]
async fn dashboard_shows_kpis_todo_sites_and_rules(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fixture(&s).await;
    let tp = s.group_id("台北總部").await;
    let day = today(&s);
    endpoint_server::stats::snapshot(&s.pool, day)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO device_daily (day, group_id, managed, seen, compliant, high_risk) \
         VALUES ($1, $2, 2, 2, 2, 0)",
    )
    .bind(day - Duration::days(7))
    .bind(tp)
    .execute(&s.pool)
    .await
    .unwrap();

    let admin = s.admin_client().await;
    let (status, html) = s.page(&admin, "/").await;
    assert_eq!(status, 200);
    assert!(
        html.contains(r#"裝置總數</div><div class="kpi-value num">4</div>"#),
        "{html}"
    );
    assert!(html.contains(r#"高風險裝置</div><div class="kpi-value num error">2</div>"#));
    assert!(html.contains("▲ 2 台"), "與 7 天前比較：{html}");
    assert!(html.contains(r#"class="chart""#), "兩天的資料就有趨勢圖");
    assert!(html.contains("全部裝置"));
    // 需要處理
    assert!(html.contains(&format!(
        r#"href="/compliance/violations?rule={}&amp;status=violating""#,
        f.high_rule
    )));
    assert!(html.contains(&format!(r#"href="/deployments/{}""#, f.deployment)));
    assert!(html.contains(r#"href="/devices?status=stale""#));
    assert!(!html.contains(r#"href="/devices?status=duplicate_suspect""#));
    // 據點：A 對到較精確的「台北機房」，C（IP 無效）與 K 歸在其他
    assert!(html.contains("<b>台北機房</b>") && html.contains("<b>台北</b>"));
    assert!(html.contains("<b>其他</b>"));
    // 違規最多的規則：兩條都在，高風險（2 台）在前
    let hi = html
        .find(r#"class="name">禁用軟體X"#)
        .expect("high rule bar");
    let mid = html
        .find(r#"class="name">舊版壓縮工具"#)
        .expect("medium rule bar");
    assert!(hi < mid);
    assert!(!html.contains(" style="), "CSP 不允許 inline style");

    // 期間切換
    let (_, html) = s.page(&admin, "/?days=7").await;
    assert!(html.contains(r#"<strong aria-current="true">7 天</strong>"#));
    assert!(html.contains(r#"href="/report?days=7""#));
    let (status, _) = s.page(&admin, "/?days=abc").await;
    assert_eq!(status, 200);
}

#[sqlx::test(migrations = false)]
async fn dashboard_and_report_respect_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fixture(&s).await;
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&gary, "/").await;
    assert!(
        html.contains(r#"裝置總數</div><div class="kpi-value num">3</div>"#),
        "{html}"
    );
    assert!(html.contains(r#"高風險裝置</div><div class="kpi-value num error">1</div>"#));
    assert!(html.contains(r#"<div class="sub">台北總部</div>"#));

    let kh_viewer = s.login_as("vera", Role::Viewer, &["高雄廠"]).await;
    let (_, html) = s.page(&kh_viewer, "/").await;
    assert!(html.contains(r#"裝置總數</div><div class="kpi-value num">1</div>"#));
    assert!(
        !html.contains(&format!("/deployments/{}", f.deployment)),
        "別的群組的派送失敗不顯示"
    );
    assert!(!html.contains("舊版壓縮工具"));

    let (status, html) = s.page(&kh_viewer, "/report").await;
    assert_eq!(status, 200);
    assert!(html.contains("端點管理報告") && html.contains("高雄廠"));
    assert!(!html.contains("安裝 App"), "沒有範圍內裝置的派送不列出");
    assert!(!html.contains(" style="));

    let admin = s.admin_client().await;
    let (status, html) = s.page(&admin, "/report?days=90").await;
    assert_eq!(status, 200);
    assert!(html.contains("（90 天）"));
    assert!(html.contains("安裝 App") && html.contains("台北機房"));
    assert!(html.contains("data-print"));
}

#[sqlx::test(migrations = false)]
async fn device_list_stale_filter(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let f = fixture(&s).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/devices?status=stale").await;
    assert!(html.contains(&f.c.device_id.to_string()));
    for other in [&f.a, &f.b, &f.k] {
        assert!(!html.contains(&other.device_id.to_string()));
    }
    assert!(html.contains("離線超過 7 天"));
}

/// 分點快取：總覽列出每台的狀態，離線與待核准列進「需要處理」；只給平台管理員
#[sqlx::test(migrations = false)]
async fn dashboard_shows_branch_caches(pool: PgPool) {
    let s = TestServer::start(pool).await;
    fixture(&s).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/").await;
    assert!(!html.contains("分點快取"), "沒有快取時不顯示");

    exec(
        &s,
        "INSERT INTO caches (name, site_id, url, dns_names, csr_pem, poll_secret_hash, status, \
                             last_seen, version, disk_used_bytes) VALUES \
         ('ok-cache', (SELECT id FROM sites WHERE name = '台北'), 'https://a:8443', ARRAY['a'], 'c', 'x', \
          'active', now(), '0.12.0', 2147483648), \
         ('down-cache', (SELECT id FROM sites WHERE name = '台北機房'), 'https://b:8443', ARRAY['b'], 'c', 'x', \
          'active', now() - interval '2 hours', '0.11.0', NULL), \
         ('new-cache', NULL, 'https://c:8443', ARRAY['c'], 'c', 'x', 'pending', NULL, NULL, NULL), \
         ('bad-cache', NULL, 'https://d:8443', ARRAY['d'], 'c', 'x', 'rejected', NULL, NULL, NULL)",
    )
    .await;
    let (status, html) = s.page(&admin, "/").await;
    assert_eq!(status, 200);
    assert!(html.contains("<h2>分點快取</h2>"), "{html}");
    assert!(html.contains(r#"<span class="tag ok">正常</span>"#));
    assert!(html.contains(r#"<span class="tag bad">離線 2 小時</span>"#));
    assert!(html.contains(r#"<span class="tag warn">待核准</span>"#));
    assert!(html.contains("2.0 / 100 GB"), "磁碟：已用／據點上限");
    assert!(html.contains("（未指定據點）"));
    assert!(!html.contains("bad-cache"), "已拒絕的不列");
    assert!(html.contains("<span class=\"t\">分點快取離線</span>"));
    assert!(html.contains("<span class=\"t\">分點快取待核准</span>"));
    assert!(!html.contains(" style="));

    // 快取設定頁用同樣的判斷：使用中但太久沒回報顯示離線
    let (_, html) = s.page(&admin, "/caches").await;
    assert!(
        html.contains(r#"<span class="tag bad">離線 2 小時</span>"#),
        "{html}"
    );

    // 群組管理員看不到快取（快取設定只限平台管理員）
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&gary, "/").await;
    assert!(!html.contains("分點快取"));
}
