mod common;

use common::{TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;
use uuid::Uuid;

async fn set_host(s: &TestServer, id: Uuid, name: &str, minutes_ago: i64) {
    sqlx::query(
        "UPDATE devices SET hostname = $2, last_seen_at = now() - make_interval(mins => $3) \
         WHERE id = $1",
    )
    .bind(id)
    .bind(name)
    .bind(minutes_ago as i32)
    .execute(&s.pool)
    .await
    .unwrap();
}

/// 名稱在 HTML 裡出現的先後
fn order(html: &str, names: &[&str]) -> Vec<usize> {
    // 只看表格（篩選的下拉選單也有名稱）
    let html = &html[html.find("<table").expect("table")..];
    let mut pos: Vec<(usize, usize)> = names
        .iter()
        .enumerate()
        .map(|(i, n)| (html.find(n).unwrap_or_else(|| panic!("{n}: {html}")), i))
        .collect();
    pos.sort();
    pos.into_iter().map(|p| p.1).collect()
}

async fn rule(s: &TestServer, name: &str, severity: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
         VALUES ($1, 'forbidden_software', $2, '{\"name\":\"x\"}'::jsonb, 't') RETURNING id",
    )
    .bind(name)
    .bind(severity)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

async fn violate(s: &TestServer, device: Uuid, rule: i64) {
    sqlx::query(
        "INSERT INTO device_violations (device_id, rule_id, status, detail) VALUES ($1, $2, 'violating', '{}'::jsonb)",
    )
    .bind(device)
    .bind(rule)
    .execute(&s.pool)
    .await
    .unwrap();
}

async fn post(
    s: &TestServer,
    c: &reqwest::Client,
    path: &str,
    form: &[(&str, String)],
) -> (u16, String, Option<String>) {
    let r = c.post(s.web_url(path)).form(form).send().await.unwrap();
    let status = r.status().as_u16();
    let loc = r
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string());
    (status, r.text().await.unwrap(), loc)
}

async fn status_of(s: &TestServer, id: Uuid) -> String {
    sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn device_list_sorts(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(3).await;
    let ids: Vec<Uuid> = {
        let mut v = vec![];
        for _ in 0..3 {
            v.push(s.enroll_ok(&tok, None, None).await.device_id);
        }
        v
    };
    set_host(&s, ids[0], "HOST-B", 5).await;
    set_host(&s, ids[1], "HOST-A", 50).await;
    set_host(&s, ids[2], "HOST-C", 1).await;
    let c = s.admin_client().await;
    let names = ["HOST-A", "HOST-B", "HOST-C"];

    let (_, html) = s.page(&c, "/devices").await;
    assert_eq!(order(&html, &names), vec![0, 1, 2]);
    assert!(html.contains(r#"aria-sort="ascending"><a class="sort" href="/devices?q=&#38;status=&#38;group=&#38;os=&#38;software=&#38;version=&#38;sort=-hostname&#38;page=0">電腦名稱 ▲</a>"#), "{html}");
    let (_, html) = s.page(&c, "/devices?sort=-hostname").await;
    assert_eq!(order(&html, &names), vec![2, 1, 0]);
    // 最後報到：新到舊
    let (_, html) = s.page(&c, "/devices?sort=-last_seen").await;
    assert_eq!(order(&html, &names), vec![2, 1, 0]);
    let (_, html) = s.page(&c, "/devices?sort=last_seen").await;
    assert_eq!(order(&html, &names), vec![0, 1, 2]);
    // 不認得的欄位用預設；搜尋表單保留排序
    let (st, html) = s.page(&c, "/devices?sort=d.id;DROP").await;
    assert_eq!(st, 200);
    assert_eq!(order(&html, &names), vec![0, 1, 2]);
    let (_, html) = s.page(&c, "/devices?sort=-ip&q=HOST").await;
    assert!(html.contains(r#"<input type="hidden" name="sort" value="-ip">"#));
    // 檢視者沒有批次操作
    let v = s.login_as("vera", Role::Viewer, &["檢視群組"]).await;
    let (_, html) = s.page(&v, "/devices").await;
    assert!(!html.contains("bulk-bar") && !html.contains(r#"name="ids""#));
}

#[sqlx::test(migrations = false)]
async fn violation_list_sorts_by_severity(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let id = s.enroll_ok(&tok, None, None).await.device_id;
    let low = rule(&s, "低風險規則", "low").await;
    let high = rule(&s, "高風險規則", "high").await;
    violate(&s, id, low).await;
    violate(&s, id, high).await;
    let c = s.admin_client().await;
    let names = ["高風險規則", "低風險規則"];
    let (_, html) = s.page(&c, "/compliance/violations?sort=severity").await;
    assert_eq!(order(&html, &names), vec![0, 1]);
    let (_, html) = s.page(&c, "/compliance/violations?sort=-severity").await;
    assert_eq!(order(&html, &names), vec![1, 0]);
    assert!(html.contains(r#"aria-sort="descending""#));
    // 翻頁連結保留排序與篩選
    let (_, html) = s
        .page(&c, "/compliance/violations?sort=rule&severity=high")
        .await;
    assert!(
        html.contains("severity=high&#38;status=&#38;group=&#38;q=&#38;sort=-rule&#38;page=0"),
        "{html}"
    );
}

#[sqlx::test(migrations = false)]
async fn deployment_filters_and_detail_sort(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let a = s.enroll_ok(&tok, None, None).await.device_id;
    let b = s.enroll_ok(&tok, None, None).await.device_id;
    set_host(&s, a, "DEP-A", 1).await;
    set_host(&s, b, "DEP-B", 1).await;
    sqlx::query(
        "INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by) \
         VALUES ('App', '1', 'exe', 'a.exe', 10, repeat('a', 64), '/S', 'App*', 'admin')",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    let dep: i64 = sqlx::query_scalar(
        "INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT '進行中的派送', max(id), 'install', 'all', 10, 20, 'admin' FROM packages RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by) \
         SELECT '停止的派送', max(id), 'install', 'stopped', 10, 20, 'admin' FROM packages",
    )
    .execute(&s.pool)
    .await
    .unwrap();
    // A 成功、B 失敗
    for (d, st) in [(a, "succeeded"), (b, "failed")] {
        sqlx::query(
            "INSERT INTO deployment_status (deployment_id, device_id, status, revision) VALUES ($1, $2, $3, 1)",
        )
        .bind(dep)
        .bind(d)
        .bind(st)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/deployments?stage=stopped").await;
    assert!(html.contains("停止的派送") && !html.contains("進行中的派送"));
    assert!(html.contains("<strong>已停止：1</strong>"));
    let (_, html) = s.page(&c, "/deployments?stage=active").await;
    assert!(!html.contains("停止的派送") && html.contains("進行中的派送"));
    let (_, html) = s.page(&c, "/deployments").await;
    assert!(html.contains("停止的派送") && html.contains("進行中的派送"));

    let names = ["DEP-A", "DEP-B"];
    let (_, html) = s.page(&c, &format!("/deployments/{dep}")).await;
    assert_eq!(order(&html, &names), vec![0, 1]);
    // 狀態排序：failed 在 succeeded 前
    let (_, html) = s.page(&c, &format!("/deployments/{dep}?sort=status")).await;
    assert_eq!(order(&html, &names), vec![1, 0]);
    let (_, html) = s
        .page(&c, &format!("/deployments/{dep}?sort=-hostname"))
        .await;
    assert_eq!(order(&html, &names), vec![1, 0]);
    // 篩選連結保留排序
    assert!(html.contains("sort=-hostname&#38;status=failed"), "{html}");
}

#[sqlx::test(migrations = false)]
async fn command_list_filters(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let id = s.enroll_ok(&tok, None, None).await.device_id;
    for (action, label, status) in [
        ("reboot", "對象甲", "failed"),
        ("collect", "對象乙", "succeeded"),
    ] {
        sqlx::query(
            "WITH r AS (INSERT INTO command_runs (action, target_label, created_by, expires_at) \
             VALUES ($1, $2, 'admin', now() + interval '1 day') RETURNING id) \
             INSERT INTO command_targets (run_id, device_id, status) SELECT r.id, $3, $4 FROM r",
        )
        .bind(action)
        .bind(label)
        .bind(id)
        .bind(status)
        .execute(&s.pool)
        .await
        .unwrap();
    }
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/commands").await;
    assert!(html.contains("對象甲") && html.contains("對象乙"));
    let (_, html) = s.page(&c, "/commands?action=collect").await;
    assert!(!html.contains("對象甲") && html.contains("對象乙"));
    assert!(html.contains(r#"<option value="collect" selected>"#));
    let (_, html) = s.page(&c, "/commands?failed=1").await;
    assert!(html.contains("對象甲") && !html.contains("對象乙"));
    let (st, html) = s.page(&c, "/commands?action=nope").await;
    assert_eq!(st, 200);
    assert!(html.contains("對象甲") && html.contains("對象乙"));
}

#[sqlx::test(migrations = false)]
async fn bulk_move_and_retire(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北", 3).await;
    let kh = s.create_group_token("高雄", 1).await;
    let a = s.enroll_ok(&tp, None, None).await.device_id;
    let b = s.enroll_ok(&tp, None, None).await.device_id;
    let other = s.enroll_ok(&kh, None, None).await.device_id;
    let kh_id = s.group_id("高雄").await;

    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/devices").await;
    let csrf = csrf_from(&html);
    let form = |op: &str, ids: &[Uuid], extra: &[(&'static str, &str)]| {
        let mut f = vec![
            ("csrf", csrf.clone()),
            ("op", op.to_string()),
            ("back", "/devices?status=all&sort=-hostname".to_string()),
        ];
        f.extend(ids.iter().map(|i| ("ids", i.to_string())));
        f.extend(extra.iter().map(|(k, v)| (*k, v.to_string())));
        f
    };
    let ghost = Uuid::new_v4();
    let (st, html, _) = post(
        &s,
        &admin,
        "/devices/bulk",
        &form("move", &[a, b, ghost], &[("group", &kh_id.to_string())]),
    )
    .await;
    assert_eq!(st, 200, "{html}");
    assert!(html.contains("已移動 2 台，略過 1 台"), "{html}");
    // 回到原本的清單條件
    assert!(html.contains(r#"<input type="hidden" name="sort" value="-hostname">"#));
    let in_kh: i64 = sqlx::query_scalar("SELECT count(*) FROM devices WHERE group_id = $1")
        .bind(kh_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(in_kh, 3);
    let (st, _, _) = post(
        &s,
        &admin,
        "/devices/bulk",
        &form("move", &[a], &[("group", "999999")]),
    )
    .await;
    assert_eq!(st, 400);

    // 群組管理員（台北，現在是空的）：不能移群組；除役範圍外的裝置被略過
    sqlx::query("UPDATE devices SET group_id = (SELECT id FROM device_groups WHERE name = '台北') WHERE id = $1")
        .bind(a)
        .execute(&s.pool)
        .await
        .unwrap();
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&gary, "/devices").await;
    let gcsrf = csrf_from(&html);
    assert!(!html.contains(r#"value="move""#), "群組管理員沒有移群組");
    let gform = |op: &str, ids: &[Uuid], extra: &[(&'static str, &str)]| {
        let mut f = vec![("csrf", gcsrf.clone()), ("op", op.to_string())];
        f.extend(ids.iter().map(|i| ("ids", i.to_string())));
        f.extend(extra.iter().map(|(k, v)| (*k, v.to_string())));
        f
    };
    let (st, _, _) = post(
        &s,
        &gary,
        "/devices/bulk",
        &gform("move", &[a], &[("group", "")]),
    )
    .await;
    assert_eq!(st, 403);
    let (st, html, _) = post(
        &s,
        &gary,
        "/devices/bulk",
        &gform("retire", &[a, other], &[]),
    )
    .await;
    assert_eq!(st, 400, "沒勾確認");
    assert!(html.contains("除役前請勾選確認"));
    assert_eq!(status_of(&s, a).await, "active");
    let (st, html, _) = post(
        &s,
        &gary,
        "/devices/bulk",
        &gform("retire", &[a, other], &[("confirm", "1")]),
    )
    .await;
    assert_eq!(st, 200);
    assert!(html.contains("已除役 1 台，略過 1 台"), "{html}");
    assert_eq!(status_of(&s, a).await, "retired");
    assert_eq!(status_of(&s, other).await, "active", "範圍外不受影響");

    // 檢視者、錯誤的 CSRF
    let vera = s.login_as("vera", Role::Viewer, &["台北"]).await;
    let (_, html) = s.page(&vera, "/devices").await;
    let vcsrf = csrf_from(&html);
    let (st, _, _) = post(
        &s,
        &vera,
        "/devices/bulk",
        &[
            ("csrf", vcsrf),
            ("op", "retire".into()),
            ("ids", b.to_string()),
            ("confirm", "1".into()),
        ],
    )
    .await;
    assert_eq!(st, 403);
    let (st, _, _) = post(
        &s,
        &admin,
        "/devices/bulk",
        &[
            ("csrf", "wrong".into()),
            ("op", "retire".into()),
            ("ids", b.to_string()),
            ("confirm", "1".into()),
        ],
    )
    .await;
    assert_eq!(st, 403);
    assert_eq!(status_of(&s, b).await, "active");
    // 沒選、格式錯誤
    let (st, html, _) = post(&s, &admin, "/devices/bulk", &form("retire", &[], &[])).await;
    assert_eq!(st, 400);
    assert!(html.contains("沒有選取任何裝置"));
    let (st, _, _) = post(
        &s,
        &admin,
        "/devices/bulk",
        &[
            ("csrf", csrf.clone()),
            ("op", "retire".into()),
            ("ids", "not-a-uuid".into()),
        ],
    )
    .await;
    assert_eq!(st, 400);
    let (st, _, _) = post(&s, &admin, "/devices/bulk", &form("nope", &[b], &[])).await;
    assert_eq!(st, 400);
}

#[sqlx::test(migrations = false)]
async fn bulk_command_targets_only_scoped_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北", 2).await;
    let kh = s.create_group_token("高雄", 1).await;
    let win = s.enroll_ok(&tp, None, None).await.device_id;
    let linux = s.enroll_ok(&tp, None, None).await.device_id;
    let other = s.enroll_ok(&kh, None, None).await.device_id;
    sqlx::query("UPDATE devices SET os_family = 'linux' WHERE id = $1")
        .bind(linux)
        .execute(&s.pool)
        .await
        .unwrap();
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&gary, "/devices").await;
    let csrf = csrf_from(&html);
    let form = |action: &str, ids: &[Uuid]| {
        let mut f = vec![
            ("csrf", csrf.clone()),
            ("op", "command".to_string()),
            ("action", action.to_string()),
            ("delay_minutes", "5".to_string()),
        ];
        f.extend(ids.iter().map(|i| ("ids", i.to_string())));
        f
    };
    // 「立即套用」只派給 Windows：Linux 略過、範圍外不建立
    let (st, _, loc) = post(
        &s,
        &gary,
        "/devices/bulk",
        &form("apply", &[win, linux, other]),
    )
    .await;
    assert_eq!(st, 303);
    let run: i64 = loc
        .unwrap()
        .trim_start_matches("/commands/")
        .parse()
        .unwrap();
    let (label, skipped): (String, i32) =
        sqlx::query_as("SELECT target_label, skipped_os FROM command_runs WHERE id = $1")
            .bind(run)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((label.as_str(), skipped), ("1 台裝置", 1));
    let targets: Vec<Uuid> =
        sqlx::query_scalar("SELECT device_id FROM command_targets WHERE run_id = $1")
            .bind(run)
            .fetch_all(&s.pool)
            .await
            .unwrap();
    assert_eq!(targets, vec![win]);
    // 全部在範圍外；全部作業系統不符；群組管理員執行腳本
    let (st, html, _) = post(&s, &gary, "/devices/bulk", &form("reboot", &[other])).await;
    assert_eq!(st, 422);
    assert!(html.contains("不在管理範圍內"), "{html}");
    let (st, html, _) = post(&s, &gary, "/devices/bulk", &form("apply", &[linux])).await;
    assert_eq!(st, 422);
    assert!(html.contains("作業系統都不支援"), "{html}");
    let (st, _, _) = post(&s, &gary, "/devices/bulk", &form("script", &[win])).await;
    assert_eq!(st, 403);
    let mut bad = form("reboot", &[win]);
    bad.retain(|(k, _)| *k != "delay_minutes");
    bad.push(("delay_minutes", "soon".into()));
    let (st, _, _) = post(&s, &gary, "/devices/bulk", &bad).await;
    assert_eq!(st, 422);
}

#[sqlx::test(migrations = false)]
async fn bulk_exemptions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 2).await;
    let a = s.enroll_ok(&tok, None, None).await.device_id;
    let b = s.enroll_ok(&tok, None, None).await.device_id;
    let r = rule(&s, "禁用軟體X", "high").await;
    violate(&s, a, r).await;
    violate(&s, b, r).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/compliance/violations").await;
    assert!(
        html.contains(&format!(r#"name="keys" value="{a}:{r}""#)),
        "{html}"
    );
    let csrf = csrf_from(&html);
    let form = |reason: &str, days: &str, keys: &[String]| {
        let mut f = vec![
            ("csrf", csrf.clone()),
            ("reason", reason.to_string()),
            ("days", days.to_string()),
            (
                "back",
                "/compliance/violations?severity=high&sort=rule".to_string(),
            ),
        ];
        f.extend(keys.iter().map(|k| ("keys", k.clone())));
        f
    };
    let keys = vec![
        format!("{a}:{r}"),
        format!("{b}:{r}"),
        "garbage".to_string(),
        format!("{}:{r}", Uuid::new_v4()),
    ];
    let (st, html, _) = post(
        &s,
        &admin,
        "/compliance/violations/exempt",
        &form("已核准例外", "30", &keys),
    )
    .await;
    assert_eq!(st, 200, "{html}");
    assert!(
        html.contains("已建立或更新 2 筆豁免，30 天後到期。略過 2 筆"),
        "{html}"
    );
    assert!(html.contains(r#"<input type="hidden" name="sort" value="rule">"#));
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM compliance_exemptions WHERE reason = '已核准例外'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(n, 2);

    let (st, _, _) = post(
        &s,
        &admin,
        "/compliance/violations/exempt",
        &form("  ", "30", &keys),
    )
    .await;
    assert_eq!(st, 400);
    let (st, _, _) = post(
        &s,
        &admin,
        "/compliance/violations/exempt",
        &form("x", "0", &keys),
    )
    .await;
    assert_eq!(st, 400);
    let (st, _, _) = post(
        &s,
        &admin,
        "/compliance/violations/exempt",
        &form("x", "30", &[]),
    )
    .await;
    assert_eq!(st, 400);

    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&gary, "/compliance/violations").await;
    assert!(!html.contains(r#"name="keys""#));
    let gcsrf = csrf_from(&html);
    let (st, _, _) = post(
        &s,
        &gary,
        "/compliance/violations/exempt",
        &[
            ("csrf", gcsrf),
            ("reason", "x".into()),
            ("days", "30".into()),
            ("keys", format!("{a}:{r}")),
        ],
    )
    .await;
    assert_eq!(st, 403);
}

#[sqlx::test(migrations = false)]
async fn bulk_edge_cases(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let id = s.enroll_ok(&tok, None, None).await.device_id;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/devices").await;
    let csrf = csrf_from(&html);
    // 回到的網址格式不對時用預設清單；不認得的欄位忽略
    let (st, html, _) = post(
        &s,
        &admin,
        "/devices/bulk",
        &[
            ("csrf", csrf.clone()),
            ("op", "retire".into()),
            ("ids", id.to_string()),
            ("back", "/devices?page=abc".into()),
            ("extra", "1".into()),
        ],
    )
    .await;
    assert_eq!(st, 400);
    assert!(html.contains("除役前請勾選確認"));
    assert!(html.contains(r#"<input type="hidden" name="sort" value="hostname">"#));

    let mut form = vec![
        ("csrf", csrf),
        ("reason", "r".to_string()),
        ("days", "30".to_string()),
        (
            "back",
            "/compliance/violations?page=x&severity=high".to_string(),
        ),
        ("extra", "1".to_string()),
    ];
    form.extend((0..201).map(|i| ("keys", format!("{}:{i}", Uuid::new_v4()))));
    let (st, html, _) = post(&s, &admin, "/compliance/violations/exempt", &form).await;
    assert_eq!(st, 400);
    assert!(html.contains("一次最多 200 筆"), "{html}");
}
