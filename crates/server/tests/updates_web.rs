mod common;

use common::{TestServer, csrf_from};
use endpoint_server::updates::admin::{self, PolicyInput};
use endpoint_server::updates::policy::PolicySettings;
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

async fn settings(s: &TestServer, id: i64) -> (i32, PolicySettings) {
    let (rev, json): (i32, String) =
        sqlx::query_as("SELECT revision, settings::text FROM update_policies WHERE id = $1")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    (rev, serde_json::from_str(&json).unwrap())
}

fn today(s: &TestServer) -> chrono::NaiveDate {
    chrono::Utc::now()
        .with_timezone(&s.state.display_offset)
        .date_naive()
}

#[sqlx::test(migrations = false)]
async fn create_edit_pause_delete(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/updates/new").await;
    assert_eq!(st, 200);
    assert!(html.contains("台北"), "{html}");
    let csrf = csrf_from(&html);
    let g = tp.to_string();
    let (st, _, html) = post(
        &s,
        &admin,
        "/updates",
        &[
            ("csrf", &csrf),
            ("name", "一般電腦"),
            ("groups", &g),
            ("quality_defer_days", "31"),
        ],
    )
    .await;
    assert_eq!(st, 422);
    assert!(
        html.contains("一般電腦") && html.contains("品質更新延後必須是 0–30 天"),
        "{html}"
    );
    let (st, loc, _) = post(
        &s,
        &admin,
        "/updates",
        &[
            ("csrf", &csrf),
            ("name", "一般電腦"),
            ("groups", &g),
            ("quality_defer_days", "7"),
            ("quality_deadline", "3"),
            ("quality_grace", ""),
            ("active_start", "8"),
            ("active_end", "18"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    let id: i64 = loc.rsplit('/').next().unwrap().parse().unwrap();
    let (_, set) = settings(&s, id).await;
    assert_eq!(set.quality_defer_days, Some(7));
    assert_eq!(
        set.quality_deadline.map(|d| (d.days, d.grace)),
        Some((3, 2)),
        "寬限沒填用 2"
    );
    let (st, html) = s.page(&admin, &loc).await;
    assert_eq!(st, 200);
    assert!(html.contains("品質更新延後 7 天"), "{html}");

    // 編輯：帶入目前的值
    let (st, html) = s.page(&admin, &format!("/updates/{id}/edit")).await;
    assert_eq!(st, 200);
    assert!(
        html.contains(r#"name="quality_defer_days" value="7""#),
        "{html}"
    );
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/updates/{id}/edit"),
        &[
            ("csrf", &csrf),
            ("name", "一般電腦"),
            ("groups", &g),
            ("quality_defer_days", "14"),
        ],
    )
    .await;
    assert_eq!(st, 303);
    assert_eq!(settings(&s, id).await.0, 2);

    // 暫停由伺服器決定開始日（顯示時區的今天）
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/updates/{id}/pause-quality"),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(st, 303);
    assert_eq!(
        settings(&s, id).await.1.quality_pause_start,
        Some(today(&s))
    );
    let (_, html) = s.page(&admin, "/updates").await;
    assert!(html.contains("品質更新暫停中"), "{html}");
    let (st, _, _) = post(
        &s,
        &admin,
        &format!("/updates/{id}/resume-quality"),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(st, 303);
    assert_eq!(settings(&s, id).await.1.quality_pause_start, None);

    // 暫停過期（set_pause 只接受最近 35 天內的日期，直接改資料）
    sqlx::query(
        "UPDATE update_policies \
         SET settings = settings || jsonb_build_object('feature_pause_start', $2::text) \
         WHERE id = $1",
    )
    .bind(id)
    .bind((today(&s) - chrono::Duration::days(40)).to_string())
    .execute(&s.pool)
    .await
    .unwrap();
    let (_, html) = s.page(&admin, "/updates").await;
    assert!(html.contains("功能更新暫停已過期"), "{html}");

    // 沒有 CSRF
    let (st, _, _) = post(&s, &admin, &format!("/updates/{id}/delete"), &[]).await;
    assert!(st >= 400, "{st}");
    let (st, loc, _) = post(
        &s,
        &admin,
        &format!("/updates/{id}/delete"),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!((st, loc.as_str()), (303, "/updates"));
    assert_eq!(s.page(&admin, &format!("/updates/{id}")).await.0, 404);
}

async fn put_status(s: &TestServer, a: &common::TestAgent, body: serde_json::Value) {
    let r = s
        .client(Some(a))
        .put(s.url("/v1/update-status"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

fn status(policy: Option<i64>, revision: Option<i32>, state: &str) -> serde_json::Value {
    serde_json::json!({
        "policy_id": policy, "revision": revision, "state": state, "detail": "boom",
        "reboot_pending": false, "reboot_pending_since": null, "last_patch_date": null
    })
}

#[sqlx::test(migrations = false)]
async fn detail_counts_and_group_admin_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp_tok = s.create_group_token("台北", 4).await;
    let a1 = s.enroll_ok(&tp_tok, None, None).await;
    let a2 = s.enroll_ok(&tp_tok, None, None).await;
    let a3 = s.enroll_ok(&tp_tok, None, None).await;
    let _a4 = s.enroll_ok(&tp_tok, None, None).await;
    let ks = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    let tp = s.group_id("台北").await;
    let kg = s.group_id("高雄").await;
    let id = admin::create_policy(
        &s.pool,
        &PolicyInput {
            name: "一般電腦".into(),
            settings: PolicySettings {
                quality_defer_days: Some(7),
                ..Default::default()
            },
            groups: vec![tp, kg],
        },
        "admin",
    )
    .await
    .unwrap();
    admin::set_pause(&s.pool, id, admin::PauseKind::Quality, None, "admin")
        .await
        .unwrap(); // revision 2
    put_status(&s, &a1, status(Some(id), Some(2), "applied")).await;
    put_status(&s, &a2, status(Some(id), Some(1), "applied")).await; // 舊 revision：尚未回報
    put_status(&s, &a3, status(None, None, "error")).await; // 第一次套用就失敗
    put_status(&s, &ks, status(Some(id), Some(2), "conflict")).await;

    let admin_c = s.admin_client().await;
    let loc = format!("/updates/{id}");
    let (_, html) = s.page(&admin_c, &loc).await;
    assert!(
        html.contains("已套用：1")
            && html.contains("衝突：1")
            && html.contains("錯誤：1")
            && html.contains("尚未回報：2"),
        "{html}"
    );
    let (_, html) = s.page(&admin_c, &format!("{loc}?state=error")).await;
    assert!(html.contains(&a3.device_id.to_string()), "{html}");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (st, html) = s.page(&g, "/updates").await;
    assert_eq!(st, 200);
    assert!(
        html.contains("一般電腦") && !html.contains("高雄"),
        "{html}"
    );
    let (_, html) = s.page(&g, &loc).await;
    assert!(html.contains("衝突：0") && !html.contains("高雄"), "{html}");
    assert_eq!(s.page(&g, "/updates/new").await.0, 403);
    assert_eq!(s.page(&g, &format!("/updates/{id}/edit")).await.0, 403);
    let gcsrf = csrf_from(&html);
    for path in [
        "/updates".to_string(),
        format!("/updates/{id}/pause-quality"),
        format!("/updates/{id}/delete"),
    ] {
        let (st, _, _) = post(&s, &g, &path, &[("csrf", &gcsrf), ("name", "x")]).await;
        assert_eq!(st, 403, "{path}");
    }
}

async fn set_build(s: &TestServer, a: &common::TestAgent, build: &str, ubr: i32) {
    sqlx::query("UPDATE devices SET os_build = $2, os_ubr = $3 WHERE id = $1")
        .bind(a.device_id)
        .bind(build)
        .bind(ubr)
        .execute(&s.pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn overview_ubr_and_reboot(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp_tok = s.create_group_token("台北", 3).await;
    let a1 = s.enroll_ok(&tp_tok, None, None).await;
    let a2 = s.enroll_ok(&tp_tok, None, None).await;
    let a3 = s.enroll_ok(&tp_tok, None, None).await;
    let ks = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    set_build(&s, &a1, "19045", 5000).await;
    set_build(&s, &a2, "19045", 5000).await;
    set_build(&s, &a3, "22631", 4000).await;
    set_build(&s, &ks, "26100", 1742).await;
    let since = (chrono::Utc::now() - chrono::Duration::days(3)).to_rfc3339();
    let mut b = status(None, None, "unmanaged");
    b["reboot_pending"] = true.into();
    b["reboot_pending_since"] = since.into();
    put_status(&s, &a3, b.clone()).await;
    put_status(&s, &ks, b).await;

    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/updates/overview").await;
    assert_eq!(st, 200);
    assert!(
        html.contains("<td>19045</td><td>5000</td><td>2</td>")
            && html.contains("<td>22631</td><td>4000</td><td>1</td>"),
        "{html}"
    );
    assert!(
        html.contains(&a3.device_id.to_string()) && html.contains("3 天"),
        "{html}"
    );
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&g, "/updates/overview").await;
    assert!(
        !html.contains("26100") && !html.contains(&ks.device_id.to_string()),
        "{html}"
    );
}

#[sqlx::test(migrations = false)]
async fn device_tab_shows_policy_and_report(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let a = s
        .enroll_ok(&s.create_group_token("台北", 1).await, None, None)
        .await;
    let tp = s.group_id("台北").await;
    let id = admin::create_policy(
        &s.pool,
        &PolicyInput {
            name: "一般電腦".into(),
            settings: PolicySettings {
                quality_defer_days: Some(7),
                ..Default::default()
            },
            groups: vec![tp],
        },
        "admin",
    )
    .await
    .unwrap();
    let mut b = status(Some(id), Some(1), "conflict");
    b["detail"] = "DeferQualityUpdatesPeriodInDays".into();
    put_status(&s, &a, b).await;
    s.state.updates.invalidate();
    let admin_c = s.admin_client().await;
    let tab = format!("/devices/{}/tab/updates", a.device_id);
    let (st, html) = s.page(&admin_c, &tab).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("一般電腦")
            && html.contains("DeferQualityUpdatesPeriodInDays = 7")
            && html.contains("衝突")
            && html.contains("DeferQualityUpdatesPeriodInDays"),
        "{html}"
    );
    admin::delete_policy(&s.pool, id, "admin").await.unwrap();
    s.state.updates.invalidate();
    let (st, html) = s.page(&admin_c, &tab).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("不受管") && html.contains("已刪除的原則"),
        "{html}"
    );
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &tab).await.0, 404);
}

async fn policy_for(s: &TestServer, group: i64) -> i64 {
    admin::create_policy(
        &s.pool,
        &PolicyInput {
            name: "一般電腦".into(),
            settings: PolicySettings {
                quality_defer_days: Some(7),
                ..Default::default()
            },
            groups: vec![group],
        },
        "admin",
    )
    .await
    .unwrap()
}

/// 編輯頁的 revision 隱藏欄位
fn revision_from(html: &str) -> String {
    let key = r#"name="revision" value=""#;
    let i = html.find(key).expect("revision field") + key.len();
    html[i..].chars().take_while(char::is_ascii_digit).collect()
}

#[sqlx::test(migrations = false)]
async fn classification_checks_policy_and_revision(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_group_token("台北", 3).await;
    let a1 = s.enroll_ok(&tok, None, None).await;
    let a2 = s.enroll_ok(&tok, None, None).await;
    let a3 = s.enroll_ok(&tok, None, None).await;
    let id = policy_for(&s, s.group_id("台北").await).await;
    admin::set_pause(&s.pool, id, admin::PauseKind::Quality, None, "admin")
        .await
        .unwrap(); // revision 2
    put_status(&s, &a1, status(Some(id), Some(1), "conflict")).await; // 舊 revision 的衝突
    put_status(&s, &a2, status(Some(id + 1000), Some(1), "error")).await; // 別的原則的錯誤
    put_status(&s, &a3, status(None, None, "error")).await; // 第一次套用就失敗
    let admin_c = s.admin_client().await;
    let (_, html) = s.page(&admin_c, &format!("/updates/{id}")).await;
    assert!(
        html.contains("衝突：0") && html.contains("錯誤：1") && html.contains("尚未回報：2"),
        "{html}"
    );
    let (_, html) = s
        .page(&admin_c, &format!("/updates/{id}?state=error"))
        .await;
    assert!(
        html.contains(&a3.device_id.to_string()) && !html.contains(&a2.device_id.to_string()),
        "{html}"
    );
}

#[sqlx::test(migrations = false)]
async fn missing_policy_is_404(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await.to_string();
    let admin_c = s.admin_client().await;
    let (_, html) = s.page(&admin_c, "/updates").await;
    let csrf = csrf_from(&html);
    let (st, _, _) = post(
        &s,
        &admin_c,
        "/updates/999999/edit",
        &[
            ("csrf", &csrf),
            ("name", "x"),
            ("groups", &tp),
            ("revision", "1"),
        ],
    )
    .await;
    assert_eq!(st, 404);
    for a in ["pause-quality", "resume-feature", "delete"] {
        let (st, _, _) = post(
            &s,
            &admin_c,
            &format!("/updates/999999/{a}"),
            &[("csrf", &csrf)],
        )
        .await;
        assert_eq!(st, 404, "{a}");
    }
}

#[sqlx::test(migrations = false)]
async fn retired_device_tab_says_retired(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let a = s
        .enroll_ok(&s.create_group_token("台北", 1).await, None, None)
        .await;
    policy_for(&s, s.group_id("台北").await).await;
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(a.device_id)
        .execute(&s.pool)
        .await
        .unwrap();
    s.state.updates.invalidate();
    let admin_c = s.admin_client().await;
    let (st, html) = s
        .page(&admin_c, &format!("/devices/{}/tab/updates", a.device_id))
        .await;
    assert_eq!(st, 200);
    assert!(
        html.contains("已除役") && !html.contains("不受管"),
        "{html}"
    );
}

#[sqlx::test(migrations = false)]
async fn unparseable_settings_are_shown_and_fixable(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let id = policy_for(&s, tp).await;
    sqlx::query(
        r#"UPDATE update_policies SET settings = '{"quality_defer_days":"x"}' WHERE id = $1"#,
    )
    .bind(id)
    .execute(&s.pool)
    .await
    .unwrap();
    let admin_c = s.admin_client().await;
    let (_, html) = s.page(&admin_c, &format!("/updates/{id}")).await;
    assert!(html.contains("設定無法解析"), "{html}");
    let (st, html) = s.page(&admin_c, &format!("/updates/{id}/edit")).await;
    assert_eq!(st, 200);
    let (csrf, rev, g) = (csrf_from(&html), revision_from(&html), tp.to_string());
    let (st, _, html) = post(
        &s,
        &admin_c,
        &format!("/updates/{id}/edit"),
        &[
            ("csrf", &csrf),
            ("name", "一般電腦"),
            ("groups", &g),
            ("revision", &rev),
            ("quality_defer_days", "5"),
        ],
    )
    .await;
    assert_eq!(st, 303, "{html}");
    assert_eq!(settings(&s, id).await.1.quality_defer_days, Some(5));
}

#[sqlx::test(migrations = false)]
async fn stale_form_is_409(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.group_id("台北").await;
    let id = policy_for(&s, tp).await;
    let admin_c = s.admin_client().await;
    let edit = format!("/updates/{id}/edit");
    let (_, html) = s.page(&admin_c, &edit).await;
    let (csrf, old, g) = (csrf_from(&html), revision_from(&html), tp.to_string());
    // 別人在這之間暫停了品質更新（revision + 1）
    admin::set_pause(
        &s.pool,
        id,
        admin::PauseKind::Quality,
        Some(today(&s)),
        "bob",
    )
    .await
    .unwrap();
    let form = |rev: &str| {
        vec![
            ("csrf", csrf.clone()),
            ("name", "一般電腦".to_string()),
            ("groups", g.clone()),
            ("revision", rev.to_string()),
            ("quality_defer_days", "9".to_string()),
        ]
    };
    let f = form(&old);
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (st, _, html) = post(&s, &admin_c, &edit, &f).await;
    assert_eq!(st, 409, "{html}");
    assert!(html.contains("最新內容"), "{html}");
    assert_eq!(settings(&s, id).await.1.quality_defer_days, Some(7));
    // 409 頁面顯示資料庫的最新內容與 revision：使用者重新修改後可直接送出
    let (rev_now, _) = settings(&s, id).await;
    assert_eq!(revision_from(&html), rev_now.to_string(), "{html}");
    assert!(
        html.contains(r#"name="quality_defer_days" value="7""#),
        "{html}"
    );
    let (_, html) = s.page(&admin_c, &edit).await;
    let f = form(&revision_from(&html));
    let f: Vec<(&str, &str)> = f.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (st, _, _) = post(&s, &admin_c, &edit, &f).await;
    assert_eq!(st, 303);
    let (_, set) = settings(&s, id).await;
    assert_eq!(set.quality_defer_days, Some(9));
    assert!(set.quality_pause_start.is_some(), "暫停保留");
}

#[sqlx::test(migrations = false)]
async fn groups_column_names_policies(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin_c = s.admin_client().await;
    let (_, html) = s.page(&admin_c, "/groups").await;
    assert!(html.contains("規則、派送與原則"), "{html}");
}
