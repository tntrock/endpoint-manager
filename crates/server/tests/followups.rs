//! 延後項目的回歸測試：裝置核准、群組刪除、計數、分頁、索引。

mod common;

use common::{TestAgent, TestServer, csrf_from};
use endpoint_server::web::auth::Role;
use sqlx::PgPool;
use uuid::Uuid;

async fn upload_software(s: &TestServer, a: &TestAgent, name: &str, ver: &str) {
    let up = protocol::InventoryUpload {
        schema_version: protocol::SCHEMA_VERSION,
        payload: protocol::InventoryPayload::Software(vec![protocol::SoftwareItem {
            name: name.into(),
            version: Some(ver.into()),
            publisher: None,
            install_date: None,
            arch: protocol::Arch::X64,
        }]),
    };
    let r = s
        .client(Some(a))
        .put(s.url("/v1/inventory/software"))
        .json(&up)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

async fn status(s: &TestServer, id: Uuid) -> Option<String> {
    sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(id)
        .fetch_optional(&s.pool)
        .await
        .unwrap()
}

/// 待核准期間原裝置被除役：核准不能讓它復活。
#[sqlx::test(migrations = false)]
async fn approve_refuses_when_original_was_retired(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let t = s.create_token(5).await;
    let old = s.enroll_ok(&t, Some("UUID-R"), Some("SN-R")).await;
    let new = s.enroll_ok(&t, Some("UUID-R"), Some("SN-R")).await;
    endpoint_server::devices::retire(&s.pool, old.device_id, "admin")
        .await
        .unwrap();
    assert!(
        endpoint_server::devices::approve(&s.pool, new.device_id, "admin")
            .await
            .is_err()
    );
    assert_eq!(status(&s, old.device_id).await.as_deref(), Some("retired"));
    assert_eq!(
        status(&s, new.device_id).await.as_deref(),
        Some("pending_approval")
    );
}

/// 核准會刪除待核准的裝置記錄，它自己的變更歷史也一併刪除，不留孤兒資料。
#[sqlx::test(migrations = false)]
async fn approve_removes_pending_change_history(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let t = s.create_token(5).await;
    let _old = s.enroll_ok(&t, Some("UUID-H"), Some("SN-H")).await;
    let new = s.enroll_ok(&t, Some("UUID-H"), Some("SN-H")).await;
    upload_software(&s, &new, "App", "1").await;
    upload_software(&s, &new, "App", "2").await;
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM inventory_changes WHERE device_id = $1")
            .bind(new.device_id)
            .fetch_one(&s.pool)
            .await
            .unwrap()
    };
    assert!(count().await > 0, "前提：待核准裝置有變更歷史");
    endpoint_server::devices::approve(&s.pool, new.device_id, "admin")
        .await
        .unwrap();
    assert_eq!(count().await, 0);
}

/// 全部核准：需要勾選確認；其中一台無法核准時，其餘照常核准。
#[sqlx::test(migrations = false)]
async fn approve_all_requires_confirmation_and_skips_failures(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let t = s.create_token(10).await;
    let a_old = s.enroll_ok(&t, Some("UUID-A"), Some("SN-A")).await;
    let a_new = s.enroll_ok(&t, Some("UUID-A"), Some("SN-A")).await;
    let _b_old = s.enroll_ok(&t, Some("UUID-B"), Some("SN-B")).await;
    let b_new = s.enroll_ok(&t, Some("UUID-B"), Some("SN-B")).await;
    endpoint_server::devices::retire(&s.pool, a_old.device_id, "admin")
        .await
        .unwrap();

    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains(r#"name="confirm""#), "要有確認勾選");
    let csrf = csrf_from(&html);
    let r = c
        .post(s.web_url("/devices/approve-all"))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400, "沒勾確認");
    assert_eq!(
        status(&s, b_new.device_id).await.as_deref(),
        Some("pending_approval")
    );

    let r = c
        .post(s.web_url("/devices/approve-all"))
        .form(&[("csrf", csrf.as_str()), ("confirm", "1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(status(&s, b_new.device_id).await, None, "B 已核准");
    assert_eq!(
        status(&s, a_new.device_id).await.as_deref(),
        Some("pending_approval"),
        "A 的原裝置已除役，留待處理"
    );
}

/// 待核准的裝置是既有裝置的重複，不計入裝置總數與軟體台數。
#[sqlx::test(migrations = false)]
async fn pending_devices_are_not_counted(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let t = s.create_token(5).await;
    let old = s.enroll_ok(&t, Some("UUID-C"), Some("SN-C")).await;
    let new = s.enroll_ok(&t, Some("UUID-C"), Some("SN-C")).await;
    upload_software(&s, &old, "CountMe", "1").await;
    upload_software(&s, &new, "CountMe", "1").await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/").await;
    assert!(html.contains("裝置總數<b>1</b>"), "{html}");
    let (_, html) = s.page(&c, "/software?q=CountMe").await;
    assert!(
        html.contains(">1</a>") && !html.contains(">2</a>"),
        "{html}"
    );
}

/// 極大的頁碼不能讓伺服器出錯。
#[sqlx::test(migrations = false)]
async fn huge_page_numbers_are_clamped(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.admin_client().await;
    for path in [
        "/devices?page=9223372036854775807",
        "/audit?page=9223372036854775807",
    ] {
        assert_eq!(s.page(&c, path).await.0, 200, "{path}");
    }
}

/// 刪除群組：只有已除役裝置、已失效金鑰時可以刪（它們改為未分組）；
/// 還有管理員被指派這個群組時不能刪（否則管理員可能沒有任何群組）。
#[sqlx::test(migrations = false)]
async fn group_delete_rules(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let t = s.create_group_token("舊廠", 5).await;
    let dev = s.enroll_ok(&t, Some("UUID-G"), Some("SN-G")).await;
    endpoint_server::devices::retire(&s.pool, dev.device_id, "admin")
        .await
        .unwrap();
    let old = s.group_id("舊廠").await;
    sqlx::query("UPDATE enroll_tokens SET revoked_at = now() WHERE group_id = $1")
        .bind(old)
        .execute(&s.pool)
        .await
        .unwrap();
    endpoint_server::groups::delete(&s.pool, old, "admin")
        .await
        .unwrap();
    let g: Option<i64> = sqlx::query_scalar("SELECT group_id FROM devices WHERE id = $1")
        .bind(dev.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(g, None);

    let _gary = s.login_as("gary", Role::GroupAdmin, &["新廠"]).await;
    let busy = s.group_id("新廠").await;
    let e = endpoint_server::groups::delete(&s.pool, busy, "admin")
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("管理員"), "{e:#}");
}

#[sqlx::test(migrations = false)]
async fn lookup_indexes_exist(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let names: Vec<String> = sqlx::query_scalar("SELECT indexname::text FROM pg_indexes")
        .fetch_all(&s.pool)
        .await
        .unwrap();
    for want in ["devices_reenroll_of_idx", "device_software_name_trgm_idx"] {
        assert!(names.iter().any(|n| n == want), "{want} missing");
    }
}
