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
        &[("csrf", &bcsrf), ("sha256", &page_sha(&html))],
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
        &[("csrf", &csrf), ("sha256", &page_sha(&html))],
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
