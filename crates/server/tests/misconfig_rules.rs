//! 錯誤設定偵測：服務路徑沒加引號（Windows）、多餘的 UID 0 帳號（Linux）、規則的適用平台（第一期），
//! 開放的共用（第二期）。
mod common;

use std::collections::BTreeMap;

use common::{TestAgent, TestServer};
use endpoint_server::compliance::admin::{self, RuleInput};
use endpoint_server::compliance::rules::{Params, Rule, Severity};
use endpoint_server::compliance::{preview, worker};
use protocol::{
    AccountsInfo, CheckinRequest, InventoryPayload, InventoryUpload, OsFamily, PrincipalKind,
    PrivilegeEntry, SCHEMA_VERSION, ServiceItem, ShareAccess, ShareItem, SharesInfo,
};
use serde_json::{Value, json};
use sqlx::PgPool;

async fn put(s: &TestServer, a: &TestAgent, p: InventoryPayload) {
    let section = p.section().as_str();
    let r = s
        .client(Some(a))
        .put(s.url(&format!("/v1/inventory/{section}")))
        .json(&InventoryUpload {
            schema_version: SCHEMA_VERSION,
            payload: p,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

async fn checkin_linux(s: &TestServer, a: &TestAgent) {
    let r = s
        .client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&CheckinRequest {
            os_family: Some(OsFamily::Linux),
            signing_keys: vec![],
            journal_id: None,
            events: vec![],
            schema_version: SCHEMA_VERSION,
            agent_version: "0.14.0".into(),
            boot_time: time::OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: BTreeMap::new(),
            section_errors: BTreeMap::new(),
        })
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

fn input(name: &str, kind: &str, params: Value) -> RuleInput {
    RuleInput {
        name: name.into(),
        description: String::new(),
        kind: kind.into(),
        severity: "high".into(),
        enabled: true,
        params,
        include: vec![],
        exclude: vec![],
        template_key: None,
    }
}

async fn results(s: &TestServer, a: &TestAgent) -> Vec<(i64, String, Value)> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT rule_id, status, detail::text FROM device_violations \
         WHERE device_id = $1 ORDER BY rule_id",
    )
    .bind(a.device_id)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    rows.into_iter()
        .map(|(id, st, d)| (id, st, serde_json::from_str(&d).unwrap()))
        .collect()
}

fn svc(name: &str, path: Option<&str>) -> ServiceItem {
    ServiceItem {
        name: name.into(),
        display_name: None,
        start_mode: "Auto".into(),
        state: "Running".into(),
        binary_path: path.map(Into::into),
    }
}

fn root(name: &str, source: &str) -> PrivilegeEntry {
    PrivilegeEntry {
        principal: name.into(),
        kind: PrincipalKind::User,
        source: source.into(),
    }
}

#[sqlx::test(migrations = false)]
async fn misconfig_rules_by_platform(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;

    let unquoted = admin::create_rule(
        &s.pool,
        &input(
            "引號",
            "unquoted_service_path",
            json!({"except_services": ["Legacy*"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    let uid0 = admin::create_rule(
        &s.pool,
        &input("UID 0", "extra_root_account", json!({})),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    // 還沒有資料：各自只在適用的平台上是「未知」
    let w = results(&s, &win).await;
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!((w[0].0, w[0].1.as_str()), (unquoted, "unknown"));
    let l = results(&s, &lin).await;
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!((l[0].0, l[0].1.as_str()), (uid0, "unknown"));

    put(
        &s,
        &win,
        InventoryPayload::Services(vec![
            svc("Spooler", Some(r"C:\Windows\System32\spoolsv.exe")),
            svc(
                "VendorSvc",
                Some(r"C:\Program Files\Vendor App\svc.exe -service"),
            ),
            svc("LegacyAgent", Some(r"C:\Old Tools\agent.exe")),
            svc("Quoted", Some(r#""C:\Program Files\Q\q.exe""#)),
            svc("NoPath", None),
        ]),
    )
    .await;
    let w = results(&s, &win).await;
    assert_eq!(w.len(), 1, "{w:?}");
    assert_eq!(w[0].1, "violating");
    assert_eq!(
        w[0].2,
        json!({"total": 1, "unquoted": [
            {"service": "VendorSvc", "path": r"C:\Program Files\Vendor App\svc.exe -service"}
        ]})
    );

    put(
        &s,
        &lin,
        InventoryPayload::Accounts(AccountsInfo {
            users: vec![],
            system_user_count: 20,
            privileged: vec![
                root("root", "uid0"),
                root("toor", "uid0"),
                root("alice", "/etc/sudoers"),
            ],
            sudoers_unparsed: vec![],
        }),
    )
    .await;
    let l = results(&s, &lin).await;
    assert_eq!(l.len(), 1, "{l:?}");
    assert_eq!(l[0].1, "violating");
    assert_eq!(l[0].2, json!({"total": 1, "root_accounts": ["toor"]}));

    // 網頁：違規摘要與規則表單的適用平台
    let c = s.admin_client().await;
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", win.device_id))
        .await;
    assert!(
        html.contains(
            r"服務路徑沒加引號：VendorSvc（C:\Program Files\Vendor App\svc.exe -service）"
        ),
        "{html}"
    );
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", lin.device_id))
        .await;
    assert!(html.contains("root 以外的 UID 0 帳號：toor"), "{html}");
    let (st, html) = s
        .page(&c, "/compliance/rules/new?kind=extra_root_account")
        .await;
    assert_eq!(st, 200);
    assert!(html.contains("適用於：Linux"), "{html}");
    assert!(html.contains("p_except_names"), "{html}");
    let (_, html) = s.page(&c, &format!("/compliance/rules/{unquoted}")).await;
    assert!(html.contains("適用於：Windows"), "{html}");
    assert!(html.contains("Legacy*"), "{html}");
    let (_, html) = s.page(&c, "/compliance/rules").await;
    assert!(
        html.contains("服務路徑沒加引號 <span class=\"faint\">Windows</span>"),
        "{html}"
    );

    // 修好之後恢復
    put(
        &s,
        &win,
        InventoryPayload::Services(vec![svc("NoPath", None)]),
    )
    .await;
    assert!(results(&s, &win).await.is_empty());

    // 預覽只算適用的平台
    let rule = |kind: &str| Rule {
        id: 0,
        name: "x".into(),
        severity: Severity::High,
        include: vec![],
        exclude: vec![],
        check: Ok(Params::parse(kind, &json!({})).unwrap().compile()),
    };
    let p = preview::preview(&s.pool, rule("extra_root_account"))
        .await
        .unwrap();
    assert_eq!((p.devices, p.violating), (1, 1));
    let p = preview::preview(&s.pool, rule("unquoted_service_path"))
        .await
        .unwrap();
    assert_eq!((p.devices, p.violating), (1, 0));
}

fn share(kind: &str, name: &str, anon: ShareAccess, users: ShareAccess) -> ShareItem {
    ShareItem {
        kind: kind.into(),
        name: name.into(),
        path: format!("/srv/{name}"),
        anonymous: anon,
        all_users: users,
        no_root_squash: false,
        clients: vec![],
    }
}

#[sqlx::test(migrations = false)]
async fn open_shares(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(2).await;
    let lin = s.enroll_ok(&tok, None, None).await;
    let win = s.enroll_ok(&tok, None, None).await;
    checkin_linux(&s, &lin).await;
    let rule = admin::create_rule(
        &s.pool,
        &input(
            "共用",
            "open_share",
            json!({"anonymous": true, "all_users": true, "no_root_squash": true,
                   "except_shares": ["dept*"]}),
        ),
        "admin",
    )
    .await
    .unwrap();
    worker::recompute_all(&s.pool).await.unwrap();
    // 兩邊都適用：還沒有資料時都是未知
    for a in [&lin, &win] {
        let r = results(&s, a).await;
        assert_eq!((r.len(), r[0].1.as_str()), (1, "unknown"), "{r:?}");
    }

    put(
        &s,
        &win,
        InventoryPayload::Shares(SharesInfo {
            shares: vec![
                share("smb", "public", ShareAccess::Read, ShareAccess::Write),
                share("smb", "dept-sales", ShareAccess::None, ShareAccess::Write),
                share("smb", "docs", ShareAccess::None, ShareAccess::Read),
            ],
            errors: vec![],
        }),
    )
    .await;
    let r = results(&s, &win).await;
    assert_eq!((r[0].0, r[0].1.as_str()), (rule, "violating"));
    assert_eq!(
        r[0].2,
        json!({"total": 1, "shares": [
            {"name": "public", "kind": "smb", "path": "/srv/public", "issues": ["所有使用者可寫入"]}
        ]}),
        "匿名只能讀不算（只算可寫入）；部門共用在例外"
    );

    let mut nfs = share("nfs", "/export", ShareAccess::None, ShareAccess::Read);
    nfs.no_root_squash = true;
    nfs.clients = vec!["10.0.0.0/8".into()];
    put(
        &s,
        &lin,
        InventoryPayload::Shares(SharesInfo {
            shares: vec![nfs],
            errors: vec!["無法讀取 Samba 設定：x".into()],
        }),
    )
    .await;
    let r = results(&s, &lin).await;
    assert_eq!(r[0].1, "violating");
    assert_eq!(r[0].2["shares"][0]["issues"], json!(["no_root_squash"]));

    // 裝置頁：Windows 在「安全」分頁、Linux 在「帳號與權限」分頁
    let c = s.admin_client().await;
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/security", win.device_id))
        .await;
    assert!(
        html.contains("共用資料夾") && html.contains("id=\"shares\""),
        "{html}"
    );
    assert!(
        html.contains("<span class=\"tag bad\">開放</span> public"),
        "{html}"
    );
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/accounts", lin.device_id))
        .await;
    assert!(html.contains("來源：10.0.0.0/8；no_root_squash"), "{html}");
    assert!(html.contains("讀取失敗：無法讀取 Samba 設定：x"), "{html}");
    let (_, html) = s
        .page(&c, &format!("/devices/{}/tab/compliance", lin.device_id))
        .await;
    assert!(
        html.contains("開放的共用：/export（no_root_squash）"),
        "{html}"
    );

    // 規則表單
    let (_, html) = s.page(&c, &format!("/compliance/rules/{rule}")).await;
    assert!(html.contains("適用於：Windows、Linux"), "{html}");
    assert!(html.contains("dept*"), "{html}");

    // 修好之後恢復；只剩讀取失敗：未知
    put(
        &s,
        &lin,
        InventoryPayload::Shares(SharesInfo {
            shares: vec![],
            errors: vec!["無法讀取 Samba 設定：x".into()],
        }),
    )
    .await;
    assert_eq!(results(&s, &lin).await[0].1, "unknown");
    put(&s, &win, InventoryPayload::Shares(SharesInfo::default())).await;
    assert!(results(&s, &win).await.is_empty());
}
