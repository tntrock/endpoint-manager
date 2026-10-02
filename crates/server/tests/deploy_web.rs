mod common;

use common::{TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;

fn msi_bytes() -> Vec<u8> {
    endpoint_server::installer::template_with(&[
        ("ProductName", "Foo App"),
        ("ProductVersion", "1.2.3"),
        ("ProductCode", "{12345678-1234-1234-1234-123456789012}"),
        ("Manufacturer", "ACME"),
    ])
}

async fn upload(
    s: &TestServer,
    c: &reqwest::Client,
    csrf: &str,
    name: &str,
    body: Vec<u8>,
) -> (u16, String) {
    let r = c
        .put(s.web_url("/packages/upload"))
        .header("X-CSRF-Token", csrf)
        .header("X-File-Name", endpoint_server::web::enc(name))
        .body(body)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

fn files(s: &TestServer) -> usize {
    std::fs::read_dir(&s.state.package_dir)
        .map(|d| d.count())
        .unwrap_or(0)
}

#[sqlx::test(migrations = false)]
async fn upload_msi_prefills_and_edits(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/packages/upload").await;
    assert_eq!(st, 200);
    assert!(html.contains("/static/upload.js"), "{html}");
    let csrf = csrf_from(&html);
    let (st, body) = upload(&s, &admin, &csrf, "Foo 安裝檔.msi", msi_bytes()).await;
    assert_eq!(st, 201, "{body}");
    let id: i64 = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let (st, html) = s.page(&admin, &format!("/packages/{id}")).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("Foo App") && html.contains("1.2.3") && html.contains("ACME"),
        "{html}"
    );
    assert!(html.contains("{12345678-1234-1234-1234-123456789012}"));
    let r = admin
        .post(s.web_url(&format!("/packages/{id}")))
        .form(&[
            ("csrf", csrf.as_str()),
            ("name", "Foo"),
            ("version", "1.2.3"),
            ("install_args", "ALLUSERS=1"),
            ("uninstall_args", ""),
            ("success_codes", "7, 8"),
            ("detect_name", "Foo App*"),
            ("detect_publisher", "ACME"),
            ("detect_min_version", "1.2"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303, "成功後導回清單");
    let (args, codes): (String, Vec<i32>) =
        sqlx::query_as("SELECT install_args, success_codes FROM packages WHERE id = $1")
            .bind(id)
            .fetch_one(&s.pool)
            .await
            .unwrap();
    assert_eq!((args.as_str(), codes), ("ALLUSERS=1", vec![7, 8]));
    let (_, html) = s.page(&admin, "/packages").await;
    assert!(html.contains("Foo") && html.contains("MSI"), "{html}");
    // EXE：以檔名預填
    let (st, body) = upload(&s, &admin, &csrf, "setup-7z.exe", b"MZ exe".to_vec()).await;
    assert_eq!(st, 201, "{body}");
}

#[sqlx::test(migrations = false)]
async fn upload_rejections_leave_no_files(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/packages/upload").await;
    let csrf = csrf_from(&html);
    assert_eq!(
        upload(&s, &admin, "wrong", "a.msi", msi_bytes()).await.0,
        403
    );
    assert_eq!(
        upload(&s, &admin, &csrf, "a.zip", b"PK".to_vec()).await.0,
        400
    );
    let (st, body) = upload(&s, &admin, &csrf, "fake.msi", b"not an msi".to_vec()).await;
    assert_eq!(st, 400);
    assert!(body.contains("MSI"), "{body}");
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, ghtml) = s.page(&g, "/devices").await;
    let gcsrf = csrf_from(&ghtml);
    assert_eq!(upload(&s, &g, &gcsrf, "a.msi", msi_bytes()).await.0, 403);
    assert_eq!(s.page(&g, "/packages").await.0, 403);
    assert_eq!(files(&s), 0, "被拒絕的上傳不留檔");
}

#[sqlx::test(migrations = false)]
async fn delete_package_via_web(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/packages/upload").await;
    let csrf = csrf_from(&html);
    let (_, body) = upload(&s, &admin, &csrf, "a.exe", b"MZ a".to_vec()).await;
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let r = admin
        .post(s.web_url(&format!("/packages/{id}/delete")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303, "成功後導回清單");
    assert_eq!(files(&s), 0);
    assert_eq!(s.page(&admin, &format!("/packages/{id}")).await.0, 404);
}

use endpoint_server::deploy::{admin as dadmin, store};

async fn server_package(s: &TestServer) -> i64 {
    let chunk: Result<axum::body::Bytes, std::io::Error> =
        Ok(axum::body::Bytes::from_static(b"MZ web test"));
    let st = store::save(
        &s.state.package_dir,
        futures_util::stream::iter(vec![chunk]),
    )
    .await
    .unwrap();
    dadmin::create_package(
        &s.pool,
        &s.state.package_dir,
        &st,
        "app.exe",
        None,
        &dadmin::PackageInput {
            name: "Web App".into(),
            version: "1.0".into(),
            kind: "exe".into(),
            install_args: "/S".into(),
            uninstall_args: String::new(),
            success_codes: vec![],
            detect_name: "Web App*".into(),
            detect_publisher: String::new(),
            detect_min_version: String::new(),
        },
        "admin",
    )
    .await
    .unwrap()
}

async fn fail_result(s: &TestServer, a: &common::TestAgent, d: i64, msg: &str) {
    s.state.deploy.invalidate();
    let r = s
        .client(Some(a))
        .post(s.url(&format!("/v1/deployments/{d}/result")))
        .json(&protocol::deploy::DeployResult {
            revision: 1,
            status: protocol::deploy::DeployStatus::Failed,
            exit_code: Some(1603),
            message: msg.into(),
            attempts: 1,
            source: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn deployment_pages_scope_counts_and_actions(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s).await;
    let tp_tok = s.create_group_token("台北", 2).await;
    let tp1 = s.enroll_ok(&tp_tok, None, None).await;
    let _tp2 = s.enroll_ok(&tp_tok, None, None).await;
    let ks = s
        .enroll_ok(&s.create_group_token("高雄", 1).await, None, None)
        .await;
    let admin = s.admin_client().await;
    let (st, html) = s.page(&admin, "/deployments/new").await;
    assert_eq!(st, 200);
    assert!(html.contains("Web App"), "{html}");
    let csrf = csrf_from(&html);
    let r = admin
        .post(s.web_url("/deployments"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("name", "Web App 全公司"),
            ("package_id", &pkg.to_string()),
            ("action", "install"),
            ("pilot_group_id", ""),
            ("max_failure_pct", "50"),
            ("min_samples", "100"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    let d: i64 = loc.rsplit('/').next().unwrap().parse().unwrap();
    fail_result(&s, &tp1, d, "安裝失敗：磁碟空間不足").await;
    fail_result(&s, &ks, d, "高雄的錯誤").await;

    let (_, html) = s.page(&admin, &loc).await;
    assert!(
        html.contains("等待中：1") && html.contains("失敗：2"),
        "{html}"
    );
    assert!(html.contains("磁碟空間不足"), "失敗原因統計");
    let (_, html) = s.page(&admin, &format!("{loc}?status=failed")).await;
    assert!(html.contains(&tp1.device_id.to_string()) && html.contains(&ks.device_id.to_string()));

    // 群組管理員：只算範圍內的裝置，看不到範圍外的裝置與錯誤
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (st, html) = s.page(&g, "/deployments").await;
    assert_eq!(st, 200);
    assert!(html.contains("Web App 全公司"), "{html}");
    let (_, html) = s.page(&g, &loc).await;
    assert!(
        html.contains("等待中：1") && html.contains("失敗：1"),
        "{html}"
    );
    assert!(!html.contains("高雄的錯誤"), "{html}");
    let (_, html) = s.page(&g, &format!("{loc}?status=failed")).await;
    assert!(!html.contains(&ks.device_id.to_string()));
    assert_eq!(s.page(&g, "/deployments/new").await.0, 403);
    let (_, ghtml) = s.page(&g, "/deployments").await;
    let gcsrf = csrf_from(&ghtml);
    let r = g
        .post(s.web_url(&format!("/deployments/{d}/pause")))
        .form(&[("csrf", gcsrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // 平台管理員的動作；暫停後提示先重試失敗
    for action in ["pause", "resume", "pause"] {
        let r = admin
            .post(s.web_url(&format!("/deployments/{d}/{action}")))
            .form(&[("csrf", csrf.as_str())])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 303, "{action}");
    }
    let (_, html) = s.page(&admin, &loc).await;
    assert!(
        html.contains("已暫停") && html.contains("重試失敗"),
        "{html}"
    );
    let r = admin
        .post(s.web_url(&format!("/deployments/{d}/expand")))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409, "不合法的切換顯示錯誤");
}

#[sqlx::test(migrations = false)]
async fn device_tab_lists_deployments(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s).await;
    let a = s
        .enroll_ok(&s.create_group_token("台北", 1).await, None, None)
        .await;
    let d = dadmin::create_deployment(
        &s.pool,
        &dadmin::DeploymentInput {
            name: "Tab 測試".into(),
            package_id: pkg,
            action: "install".into(),
            include: vec![],
            exclude: vec![],
            pilot_group_id: None,
            max_failure_pct: 10,
            min_samples: 20,
        },
        "admin",
    )
    .await
    .unwrap();
    fail_result(&s, &a, d, "boom").await;
    let admin = s.admin_client().await;
    let tab = format!("/devices/{}/tab/deployments", a.device_id);
    let (st, html) = s.page(&admin, &tab).await;
    assert_eq!(st, 200);
    assert!(
        html.contains("Tab 測試") && html.contains("失敗") && html.contains("boom"),
        "{html}"
    );
    let other = s.login_as("olga", Role::GroupAdmin, &["高雄"]).await;
    assert_eq!(s.page(&other, &tab).await.0, 404);
}

/// 已停止的派送只算有結果的裝置（試點中停止時不能膨脹成全部裝置）；
/// 試點群組名稱只給平台管理員看
#[sqlx::test(migrations = false)]
async fn stopped_pilot_counts_and_pilot_name_visibility(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s).await;
    let pilot_dev = s
        .enroll_ok(&s.create_group_token("試點", 1).await, None, None)
        .await;
    let tp_tok = s.create_group_token("台北", 3).await;
    for _ in 0..3 {
        s.enroll_ok(&tp_tok, None, None).await;
    }
    let pilot = s.group_id("試點").await;
    let d = dadmin::create_deployment(
        &s.pool,
        &dadmin::DeploymentInput {
            name: "試點停止".into(),
            package_id: pkg,
            action: "install".into(),
            include: vec![],
            exclude: vec![],
            pilot_group_id: Some(pilot),
            max_failure_pct: 50,
            min_samples: 100,
        },
        "admin",
    )
    .await
    .unwrap();
    fail_result(&s, &pilot_dev, d, "x").await;
    dadmin::set_stage(&s.pool, d, dadmin::Transition::Stop, "admin")
        .await
        .unwrap();
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, &format!("/deployments/{d}")).await;
    assert!(
        html.contains("全部：1") && html.contains("等待中：0"),
        "{html}"
    );
    assert!(html.contains("試點群組：試點"));
    let g = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let (_, html) = s.page(&g, &format!("/deployments/{d}")).await;
    assert!(!html.contains("試點群組：試點"), "範圍外的群組名稱：{html}");
}

#[sqlx::test(migrations = false)]
async fn package_form_error_keeps_success_codes_input(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/packages/upload").await;
    let csrf = csrf_from(&html);
    let (_, body) = upload(&s, &admin, &csrf, "a.exe", b"MZ keep".to_vec()).await;
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let r = admin
        .post(s.web_url(&format!("/packages/{id}")))
        .form(&[
            ("csrf", csrf.as_str()),
            ("name", "A"),
            ("version", ""),
            ("install_args", "/S"),
            ("uninstall_args", ""),
            ("success_codes", "1, x"),
            ("detect_name", "A*"),
            ("detect_publisher", ""),
            ("detect_min_version", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 422);
    assert!(
        r.text().await.unwrap().contains(r#"value="1, x""#),
        "保留輸入"
    );
}

async fn fail_at(s: &TestServer, a: &common::TestAgent, d: i64, revision: i32, msg: &str) {
    s.state.deploy.invalidate();
    let r = s
        .client(Some(a))
        .post(s.url(&format!("/v1/deployments/{d}/result")))
        .json(&protocol::deploy::DeployResult {
            revision,
            status: protocol::deploy::DeployStatus::Failed,
            exit_code: Some(1603),
            message: msg.into(),
            attempts: 1,
            source: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[sqlx::test(migrations = false)]
async fn retry_counts_only_current_revision(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let pkg = server_package(&s).await;
    let tok = s.create_group_token("台北", 2).await;
    let a1 = s.enroll_ok(&tok, None, None).await;
    let a2 = s.enroll_ok(&tok, None, None).await;
    let d = dadmin::create_deployment(
        &s.pool,
        &dadmin::DeploymentInput {
            name: "重試".into(),
            package_id: pkg,
            action: "install".into(),
            include: vec![],
            exclude: vec![],
            pilot_group_id: None,
            max_failure_pct: 100,
            min_samples: 100,
        },
        "admin",
    )
    .await
    .unwrap();
    fail_at(&s, &a1, d, 1, "第一輪失敗").await;
    fail_at(&s, &a2, d, 1, "第一輪失敗").await;
    dadmin::retry_failed(&s.pool, d, "admin").await.unwrap();
    fail_at(&s, &a1, d, 2, "第二輪失敗").await;

    let admin = s.admin_client().await;
    let loc = format!("/deployments/{d}");
    let (_, html) = s.page(&admin, &loc).await;
    assert!(
        html.contains("失敗：1") && html.contains("等待中：1"),
        "{html}"
    );
    let summary = html.split("<h2>裝置</h2>").next().unwrap();
    assert!(
        summary.contains("<td>第二輪失敗</td><td>1</td>") && !summary.contains("第一輪失敗"),
        "主要失敗原因只算目前這一輪：{html}"
    );
    let (_, html) = s.page(&admin, "/deployments").await;
    assert!(html.contains(r#"<span class="error">1</span>"#), "{html}");
    let (_, html) = s.page(&admin, &format!("{loc}?status=pending")).await;
    assert!(
        html.contains(&a2.device_id.to_string()) && html.contains("上一輪"),
        "{html}"
    );
    assert!(!html.contains(&a1.device_id.to_string()), "{html}");
}
