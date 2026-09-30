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
