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

/// 頁面上顯示的完整 sha256（<code class="sha">…</code>）
fn page_sha(html: &str) -> String {
    let start = html.find("<code class=\"sha\">").expect("sha on page") + 18;
    html[start..start + 64].to_string()
}

async fn script_status(s: &TestServer, id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM scripts WHERE id = $1")
        .bind(id.parse::<i64>().unwrap())
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn scripts_two_person_flow(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let bob = s.login_as("bob", Role::Platform, &[]).await;
    let (st, html) = s.page(&alice, "/scripts/new").await;
    assert_eq!(st, 200);
    let csrf = csrf_from(&html);
    let evil = "Write-Output '<script>alert(1)</script>'";
    let (st, _, html) = post(
        &s,
        &alice,
        "/scripts",
        &[
            ("csrf", &csrf),
            ("name", " "),
            ("content", evil),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 422);
    assert!(html.contains("&#60;script&#62;"), "保留輸入：{html}");
    let (st, loc, _) = post(
        &s,
        &alice,
        "/scripts",
        &[
            ("csrf", &csrf),
            ("name", "清暫存"),
            ("description", ""),
            ("content", evil),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    let id = loc.rsplit('/').next().unwrap().to_string();
    let (_, html) = s.page(&alice, &loc).await;
    assert!(
        html.contains("&#60;script&#62;alert(1)") && !html.contains("<script>alert(1)"),
        "{html}"
    );
    assert!(
        html.contains("需由另一位平台管理員核准") && !html.contains("/approve"),
        "{html}"
    );

    // bob 看到的版本被 alice 改掉：用舊 sha 核准失敗
    let (_, html) = s.page(&bob, &loc).await;
    let bcsrf = csrf_from(&html);
    let seen = page_sha(&html);
    let (st, _, _) = post(
        &s,
        &alice,
        &format!("/scripts/{id}/edit"),
        &[
            ("csrf", &csrf),
            ("name", "清暫存"),
            ("description", ""),
            ("content", "Remove-Item C:\\ -Recurse"),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    let (st, _, body) = post(
        &s,
        &bob,
        &format!("/scripts/{id}/approve"),
        &[("csrf", &bcsrf), ("sha256", &seen)],
    )
    .await;
    assert_eq!(st, 409);
    assert!(body.contains("內容已變更"), "{body}");
    assert_eq!(script_status(&s, &id).await, "pending");
    let (_, html) = s.page(&bob, &loc).await;
    let (st, _, _) = post(
        &s,
        &bob,
        &format!("/scripts/{id}/approve"),
        &[
            ("csrf", &bcsrf),
            ("sha256", &page_sha(&html)),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    assert_eq!(script_status(&s, &id).await, "approved");
    // alice 直接 POST 核准自己的（已核准狀態不能再核准；就算是 pending 也是 403）
    let (st, _, _) = post(
        &s,
        &alice,
        &format!("/scripts/{id}/edit"),
        &[
            ("csrf", &csrf),
            ("name", "清暫存"),
            ("description", ""),
            ("content", "dir"),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    let (_, html) = s.page(&alice, &loc).await;
    let (st, _, _) = post(
        &s,
        &alice,
        &format!("/scripts/{id}/approve"),
        &[
            ("csrf", &csrf),
            ("sha256", &page_sha(&html)),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 403);
    // 沒有 CSRF
    let (st, _, _) = post(&s, &bob, &format!("/scripts/{id}/disable"), &[]).await;
    assert!(st >= 400, "{st}");
}

#[sqlx::test(migrations = false)]
async fn scripts_settings_and_permissions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/scripts").await;
    assert_eq!(st, 200);
    assert!(html.contains("腳本需要第二位平台管理員核准"), "{html}");
    let csrf = csrf_from(&html);
    let (st, _, _) = post(&s, &admin, "/scripts/settings", &[("csrf", &csrf)]).await;
    assert_eq!(st, 303);
    assert!(
        !endpoint_server::commands::scripts::require_second_approver(&s.pool)
            .await
            .unwrap()
    );
    let (st, _, _) = post(
        &s,
        &admin,
        "/scripts/settings",
        &[("csrf", &csrf), ("require", "1")],
    )
    .await;
    assert_eq!(st, 303);
    assert!(
        endpoint_server::commands::scripts::require_second_approver(&s.pool)
            .await
            .unwrap()
    );
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    assert_eq!(s.page(&g, "/scripts").await.0, 403);
    assert_eq!(s.page(&g, "/scripts/new").await.0, 403);
    let (_, ghtml) = s.page(&g, "/devices").await;
    let gcsrf = csrf_from(&ghtml);
    let (st, _, _) = post(&s, &g, "/scripts/settings", &[("csrf", &gcsrf)]).await;
    assert_eq!(st, 403);
}

async fn run_of_target_device(s: &TestServer, device: uuid::Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT run_id FROM command_targets WHERE device_id = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(device)
    .fetch_one(&s.pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = false)]
async fn command_pages_scope_and_actions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp_tok = s.create_group_token("台北", 2).await;
    let tp1 = s.enroll_ok(&tp_tok, None, None).await;
    let _tp2 = s.enroll_ok(&tp_tok, None, None).await;
    let ks = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    let tp = s.group_id("台北").await.to_string();
    let kg = s.group_id("高雄").await.to_string();
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/commands").await;
    assert_eq!(st, 200);
    let csrf = csrf_from(&html);
    let (st, loc, _) = post(
        &s,
        &admin,
        "/commands",
        &[
            ("csrf", &csrf),
            ("action", "collect"),
            ("group_id", &tp),
            ("expires_hours", "24"),
        ],
    )
    .await;
    assert_eq!(st, 303, "{loc}");
    let first: i64 = loc.rsplit('/').next().unwrap().parse().unwrap();
    let (_, html) = s.page(&admin, "/commands").await;
    assert!(html.contains("群組 台北"), "{html}");

    // 群組管理員：範圍外或腳本 403，範圍內可以
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, ghtml) = s.page(&gary, "/commands").await;
    let gcsrf = csrf_from(&ghtml);
    for form in [
        vec![("action", "collect"), ("group_id", kg.as_str())],
        vec![
            ("action", "script"),
            ("group_id", tp.as_str()),
            ("script_id", "1"),
        ],
    ] {
        let mut f = vec![("csrf", gcsrf.as_str()), ("expires_hours", "24")];
        f.extend(form);
        let (st, _, body) = post(&s, &gary, "/commands", &f).await;
        assert_eq!(st, 403, "{body}");
    }
    let (st, _, _) = post(
        &s,
        &gary,
        "/commands",
        &[
            ("csrf", &gcsrf),
            ("action", "reboot"),
            ("group_id", &tp),
            ("delay_minutes", "10"),
            ("expires_hours", "24"),
        ],
    )
    .await;
    assert_eq!(st, 303);

    // 只含高雄的指令：群組管理員看不到
    let (st, loc, _) = post(
        &s,
        &admin,
        &format!("/devices/{}/commands", ks.device_id),
        &[("csrf", &csrf), ("action", "apply")],
    )
    .await;
    assert_eq!((st, loc), (303, format!("/devices/{}", ks.device_id)));
    let ks_run = run_of_target_device(&s, ks.device_id).await;
    let (_, ghtml) = s.page(&gary, "/commands").await;
    assert!(!ghtml.contains(&format!("/commands/{ks_run}\"")), "{ghtml}");
    assert_eq!(s.page(&gary, &format!("/commands/{ks_run}")).await.0, 404);

    // 同時含台北與高雄的指令：群組管理員只看到台北那台；輸出要跳脫
    let mixed: i64 = sqlx::query_scalar(
        "INSERT INTO command_runs (action, target_label, created_by, expires_at) \
         VALUES ('collect', '混合', 'admin', now() + interval '1 day') RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO command_targets (run_id, device_id) VALUES ($1, $2), ($1, $3)")
        .bind(mixed)
        .bind(tp1.device_id)
        .bind(ks.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let ks_target: i64 =
        sqlx::query_scalar("SELECT id FROM command_targets WHERE run_id = $1 AND device_id = $2")
            .bind(mixed)
            .bind(ks.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    let r = s
        .client(Some(&ks))
        .post(s.url(&format!("/v1/commands/{ks_target}/result")))
        .json(&serde_json::json!({"status": "succeeded", "exit_code": 0, "output": "<b>hi</b>"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let (_, html) = s.page(&admin, &format!("/commands/{mixed}")).await;
    assert!(
        html.contains("&#60;b&#62;hi") && !html.contains("<b>hi</b>"),
        "{html}"
    );
    let (st, ghtml) = s.page(&gary, &format!("/commands/{mixed}")).await;
    assert_eq!(st, 200);
    assert!(
        ghtml.contains(&tp1.device_id.to_string()) && !ghtml.contains(&ks.device_id.to_string()),
        "{ghtml}"
    );

    // 裝置分頁：平台管理員有執行腳本；群組管理員只有固定動作；檢視者沒有按鈕
    let tab = format!("/devices/{}/tab/commands", tp1.device_id);
    let (st, html) = s.page(&admin, &tab).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("執行腳本") && html.contains("重新收集"),
        "{html}"
    );
    let (_, html) = s.page(&gary, &tab).await;
    assert!(
        html.contains("重新收集") && !html.contains("執行腳本"),
        "{html}"
    );
    let vera = s.login_as("vera", Role::Viewer, &["台北"]).await;
    let (st, html) = s.page(&vera, &tab).await;
    assert_eq!(st, 200);
    assert!(
        !html.contains("/commands\" method") && !html.contains("<form"),
        "{html}"
    );
    let (_, vhtml) = s.page(&vera, "/devices").await;
    let vcsrf = csrf_from(&vhtml);
    let (st, _, _) = post(
        &s,
        &vera,
        &format!("/devices/{}/commands", tp1.device_id),
        &[("csrf", &vcsrf), ("action", "collect")],
    )
    .await;
    assert_eq!(st, 403);
    let (st, _, _) = post(
        &s,
        &vera,
        "/commands",
        &[
            ("csrf", &vcsrf),
            ("action", "collect"),
            ("group_id", &tp),
            ("expires_hours", "24"),
        ],
    )
    .await;
    assert_eq!(st, 403);

    // 取消：群組管理員不能取消平台管理員建立的；建立者可以
    let (st, _, _) = post(
        &s,
        &gary,
        &format!("/commands/{first}/cancel"),
        &[("csrf", &gcsrf)],
    )
    .await;
    assert_eq!(st, 403);
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/commands/{first}/cancel"),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(st, 303);
    let (_, html) = s.page(&admin, &format!("/commands/{first}")).await;
    assert!(html.contains("已取消"), "{html}");
    // 沒有 CSRF
    let (st, _, _) = post(
        &s,
        &admin,
        "/commands",
        &[("action", "collect"), ("group_id", &tp)],
    )
    .await;
    assert!(st >= 400, "{st}");
}

/// 核准者看到逾時 30，別人在核准前改成 120（內容雜湊不變）：不能核准沒看過的版本
#[sqlx::test(migrations = false)]
async fn approve_rejects_changed_timeout(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let alice = s.login_as("alice", Role::Platform, &[]).await;
    let bob = s.login_as("bob", Role::Platform, &[]).await;
    let (_, html) = s.page(&alice, "/scripts/new").await;
    let csrf = csrf_from(&html);
    let form = |timeout: &'static str| {
        vec![
            ("csrf", csrf.clone()),
            ("name", "清暫存".to_string()),
            ("description", String::new()),
            ("content", "dir".to_string()),
            ("timeout_minutes", timeout.to_string()),
        ]
    };
    let f = form("30");
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (_, loc, _) = post(&s, &alice, "/scripts", &f).await;
    let id = loc.rsplit('/').next().unwrap().to_string();
    let (_, html) = s.page(&bob, &loc).await;
    let bcsrf = csrf_from(&html);
    let seen_sha = page_sha(&html);
    assert!(
        html.contains("name=\"timeout_minutes\" value=\"30\""),
        "核准表單帶上顯示的逾時：{html}"
    );
    let f = form("120");
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (st, _, _) = post(&s, &alice, &format!("/scripts/{id}/edit"), &f).await;
    assert_eq!(st, 303);
    let (st, _, body) = post(
        &s,
        &bob,
        &format!("/scripts/{id}/approve"),
        &[
            ("csrf", &bcsrf),
            ("sha256", &seen_sha),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 409, "{body}");
    assert!(body.contains("內容已變更"), "{body}");
    assert_eq!(script_status(&s, &id).await, "pending");
}

/// 指令清單分頁：先挑出這一頁的指令再計數，結果與逐筆相同
#[sqlx::test(migrations = false)]
async fn command_list_paginates(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let a = s
        .enroll_ok(&s.create_group_token("台北", 1).await, None, None)
        .await;
    sqlx::query(
        "WITH r AS (INSERT INTO command_runs (action, target_label, created_by, expires_at) \
           SELECT 'collect', '第' || i || '筆', 'admin', now() + interval '1 day' \
           FROM generate_series(1, 55) i RETURNING id) \
         INSERT INTO command_targets (run_id, device_id) SELECT id, $1 FROM r",
    )
    .bind(a.device_id)
    .execute(&s.pool)
    .await
    .unwrap();
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/commands").await;
    assert_eq!(html.matches("<a href=\"/commands/").count(), 50);
    assert!(
        html.contains("第55筆") && !html.contains("第5筆<"),
        "{html}"
    );
    assert!(html.contains("/commands?page=1"));
    let (_, html) = s.page(&admin, "/commands?page=1").await;
    assert_eq!(html.matches("<a href=\"/commands/").count(), 5);
    assert!(html.contains("第1筆<") && html.contains("第5筆<"), "{html}");
}

/// 讓某張表的 INSERT 一定失敗（模擬資料庫錯誤；錯誤訊息含內部細節）
async fn break_inserts(s: &TestServer, table: &str) {
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE OR REPLACE FUNCTION fail_insert() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'internal secret detail'; END $$; \
         CREATE TRIGGER fail_insert BEFORE INSERT ON {table} \
         FOR EACH ROW EXECUTE FUNCTION fail_insert();"
    )))
    .execute(&s.pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn internal_errors_are_500_and_input_errors_422(pool: PgPool) {
    let s = TestServer::start(pool).await;
    s.enroll_ok(&s.create_group_token("台北", 1).await, None, None)
        .await;
    let tp = s.group_id("台北").await.to_string();
    let admin = s.admin_client().await;
    let csrf = csrf_from(&s.page(&admin, "/commands").await.1);
    // 延遲不是整數
    let (st, _, body) = post(
        &s,
        &admin,
        "/commands",
        &[
            ("csrf", &csrf),
            ("action", "reboot"),
            ("group_id", &tp),
            ("delay_minutes", "abc"),
            ("expires_hours", "24"),
        ],
    )
    .await;
    assert_eq!(st, 422, "{body}");
    assert!(body.contains("延遲"), "{body}");
    // 資料庫錯誤：500，不顯示內部細節
    break_inserts(&s, "command_runs").await;
    let (st, _, body) = post(
        &s,
        &admin,
        "/commands",
        &[
            ("csrf", &csrf),
            ("action", "collect"),
            ("group_id", &tp),
            ("expires_hours", "24"),
        ],
    )
    .await;
    assert_eq!(st, 500, "{body}");
    assert!(!body.contains("secret"), "{body}");
    break_inserts(&s, "scripts").await;
    let (st, _, body) = post(
        &s,
        &admin,
        "/scripts",
        &[
            ("csrf", &csrf),
            ("name", "x"),
            ("description", ""),
            ("content", "dir"),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 500, "{body}");
    assert!(!body.contains("secret"), "{body}");
}

async fn report(s: &TestServer, a: &common::TestAgent, target: i64, output: &str) {
    let st = s
        .client(Some(a))
        .post(s.url(&format!("/v1/commands/{target}/result")))
        .json(&serde_json::json!({"status": "succeeded", "exit_code": 0, "output": output}))
        .send()
        .await
        .unwrap()
        .status();
    assert_eq!(st, 204);
}

async fn target_of(s: &TestServer, run: i64, device: uuid::Uuid) -> i64 {
    sqlx::query_scalar("SELECT id FROM command_targets WHERE run_id = $1 AND device_id = $2")
        .bind(run)
        .bind(device)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn detail_filters_cancel_and_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 3).await;
    let mut devs = vec![];
    for _ in 0..3 {
        devs.push(s.enroll_ok(&tok, None, None).await);
    }
    let tp = s.group_id("台北").await.to_string();
    let admin = s.admin_client().await;
    let csrf = csrf_from(&s.page(&admin, "/commands").await.1);
    let (_, loc, _) = post(
        &s,
        &admin,
        "/commands",
        &[
            ("csrf", &csrf),
            ("action", "collect"),
            ("group_id", &tp),
            ("expires_hours", "24"),
        ],
    )
    .await;
    let run: i64 = loc.rsplit('/').next().unwrap().parse().unwrap();
    // 一台回報成功（輸出含 <script>）
    let t0 = target_of(&s, run, devs[0].device_id).await;
    report(&s, &devs[0], t0, "<script>alert(1)</script>").await;
    // 等待中篩選：只列另外兩台
    let (_, html) = s.page(&admin, &format!("{loc}?status=waiting")).await;
    assert!(html.contains("等待中：2"), "{html}");
    assert!(!html.contains(&devs[0].device_id.to_string()), "{html}");
    assert!(html.contains(&devs[1].device_id.to_string()));
    let (_, html) = s.page(&admin, &format!("{loc}?status=succeeded")).await;
    assert!(
        html.contains("&#60;script&#62;alert(1)") && !html.contains("<script>alert(1)"),
        "輸出要跳脫：{html}"
    );
    // 混合範圍：一台移到高雄後，台北的群組管理員只看到 2 台
    let kg = s.group_id("高雄").await;
    sqlx::query("UPDATE devices SET group_id = $1 WHERE id = $2")
        .bind(kg)
        .bind(devs[2].device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&gary, &loc).await;
    assert!(html.contains("全部：2"), "{html}");
    assert!(!html.contains(&devs[2].device_id.to_string()), "{html}");
    let (_, html) = s.page(&admin, &loc).await;
    assert!(html.contains("全部：3"), "{html}");
    // 全部完成後沒有取消按鈕，POST 取消 409
    sqlx::query(
        "UPDATE command_targets SET status = 'succeeded', finished_at = now() WHERE run_id = $1",
    )
    .bind(run)
    .execute(&s.pool)
    .await
    .unwrap();
    let (_, html) = s.page(&admin, &loc).await;
    assert!(!html.contains("/cancel"), "{html}");
    let (st, _, _) = post(&s, &admin, &format!("{loc}/cancel"), &[("csrf", &csrf)]).await;
    assert_eq!(st, 409);
}

#[sqlx::test(migrations = false)]
async fn list_shows_canceled_and_runs_without_devices(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 2).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let b = s.enroll_ok(&tok, None, None).await;
    let admin = s.admin_client().await;
    let csrf = csrf_from(&s.page(&admin, "/commands").await.1);
    let mut runs = vec![];
    for d in [&a, &b] {
        let (st, loc, _) = post(
            &s,
            &admin,
            &format!("/devices/{}/commands", d.device_id),
            &[
                ("csrf", &csrf),
                ("action", "collect"),
                ("expires_hours", "24"),
            ],
        )
        .await;
        assert_eq!(st, 303, "{loc}");
        runs.push(run_of_target_device(&s, d.device_id).await);
    }
    // 取消第一個：清單標示已取消
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/commands/{}/cancel", runs[0]),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(st, 303);
    let (_, html) = s.page(&admin, "/commands").await;
    assert!(html.contains("（已取消）"), "{html}");
    // 第二個的裝置被刪除：平台管理員仍看得到，群組管理員看不到
    // 產品中只有核准重灌時會刪除裝置（憑證先移給原裝置）
    for q in [
        "DELETE FROM device_certs WHERE device_id = $1",
        "DELETE FROM devices WHERE id = $1",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(q))
            .bind(b.device_id)
            .execute(&s.pool)
            .await
            .unwrap();
    }
    let (_, html) = s.page(&admin, "/commands").await;
    assert!(html.contains(&format!("/commands/{}\"", runs[1])), "{html}");
    assert_eq!(
        s.page(&admin, &format!("/commands/{}", runs[1])).await.0,
        200
    );
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    assert_eq!(
        s.page(&gary, &format!("/commands/{}", runs[1])).await.0,
        404
    );
}

#[sqlx::test(migrations = false)]
async fn script_content_keeps_leading_newline(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let csrf = csrf_from(&s.page(&admin, "/scripts/new").await.1);
    let (st, loc, _) = post(
        &s,
        &admin,
        "/scripts",
        &[
            ("csrf", &csrf),
            ("name", "開頭換行"),
            ("description", ""),
            ("content", "\nWrite-Output hi"),
            ("timeout_minutes", "30"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    let (_, html) = s.page(&admin, &format!("{loc}/edit")).await;
    // 瀏覽器會忽略 <textarea> 後的第一個換行：範本多放一個，內容開頭的換行才保留
    let start = html.find("<textarea name=\"content\"").unwrap();
    let after = &html[html[start..].find('>').unwrap() + start + 1..];
    assert!(
        after.starts_with("\n\nWrite-Output hi"),
        "{:?}",
        &after[..30]
    );
}
