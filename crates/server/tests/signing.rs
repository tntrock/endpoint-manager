//! 腳本與套件簽章：端點回報公鑰、簽章請求、上傳與預先檢查、下發、內容變更清除簽章。

mod common;

use common::{TestAgent, TestServer, csrf_from};
use endpoint_server::commands::Actor;
use endpoint_server::commands::runs::{self, RunInput, Target};
use endpoint_server::commands::scripts::{self, ScriptInput};
use endpoint_server::deploy::admin::{self, DeploymentInput, PackageInput};
use endpoint_server::deploy::store;
use endpoint_server::web::auth::Role;
use protocol::signing::{SigningRequest, encode_public_key, format_signature, key_id};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sqlx::PgPool;

struct Key {
    pair: Ed25519KeyPair,
    public: String,
    id: String,
}

fn key() -> Key {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let raw: [u8; 32] = pair.public_key().as_ref().try_into().unwrap();
    Key {
        public: encode_public_key(&raw),
        id: key_id(&raw),
        pair,
    }
}

fn sign(k: &Key, req: &SigningRequest) -> String {
    format_signature(&k.id, k.pair.sign(&req.payload.signed_bytes()).as_ref())
}

fn alice() -> Actor {
    Actor {
        username: "alice".into(),
        platform: true,
        groups: vec![],
    }
}

async fn checkin(s: &TestServer, a: &TestAgent, keys: Vec<String>) -> protocol::CheckinResponse {
    // 派送清單每 5 秒才重新確認一次：測試裡要立即看到變更
    s.state.deploy.invalidate();
    s.client(Some(a))
        .post(s.url("/v1/checkin"))
        .json(&protocol::CheckinRequest {
            os_family: None,
            signing_keys: keys,
            schema_version: protocol::SCHEMA_VERSION,
            agent_version: "0.9.0".into(),
            boot_time: time::OffsetDateTime::now_utc(),
            logged_on_user: None,
            ip_addresses: vec![],
            section_hashes: Default::default(),
            section_errors: Default::default(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn post(
    s: &TestServer,
    c: &reqwest::Client,
    path: &str,
    form: &[(&str, &str)],
) -> (u16, String) {
    let r = c.post(s.web_url(path)).form(form).send().await.unwrap();
    let status = r.status().as_u16();
    let loc = r
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    (status, loc)
}

async fn download_request(s: &TestServer, c: &reqwest::Client, path: &str) -> SigningRequest {
    let r = c.get(s.web_url(path)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert!(
        r.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment;")
    );
    r.json().await.unwrap()
}

/// 已核准的 PowerShell 腳本
async fn approved_script(s: &TestServer, content: &str) -> i64 {
    let id = scripts::create_script(
        &s.pool,
        &ScriptInput {
            name: "清暫存".into(),
            description: String::new(),
            content: content.into(),
            timeout_minutes: 30,
            language: Default::default(),
        },
        &alice(),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE scripts SET status = 'approved', approved_by = 'bob' WHERE id = $1")
        .bind(id)
        .execute(&s.pool)
        .await
        .unwrap();
    id
}

async fn script_signature(s: &TestServer, id: i64) -> Option<String> {
    sqlx::query_scalar("SELECT signature FROM scripts WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = false)]
async fn checkin_records_reported_keys(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let k = key();
    checkin(
        &s,
        &a,
        vec![k.public.clone(), "garbage".into(), k.public.clone()],
    )
    .await;
    let stored: Vec<String> = sqlx::query_scalar("SELECT signing_keys FROM devices WHERE id = $1")
        .bind(a.device_id)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert_eq!(stored, vec![k.public.clone()], "格式錯誤的丟掉、重複的合併");

    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, &format!("/devices/{}", a.device_id)).await;
    assert!(
        html.contains(&format!(
            "<span class=\"tag ok\">是</span> 金鑰 <code>{}</code>",
            k.id
        )),
        "{html}"
    );
    checkin(&s, &a, vec![]).await;
    let (_, html) = s.page(&admin, &format!("/devices/{}", a.device_id)).await;
    assert!(
        html.contains("<th>要求簽章</th><td colspan=\"3\">否</td>"),
        "{html}"
    );
}

#[sqlx::test(migrations = false)]
async fn script_signing_flow(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let content = "Remove-Item $env:TEMP\\* -Recurse -Force\r\n";
    let id = approved_script(&s, content).await;
    let k = key();

    // 簽章請求：附上內容，雜湊與欄位對得上
    let req = download_request(&s, &admin, &format!("/scripts/{id}/signing-request.json")).await;
    assert_eq!(req.kind, SigningRequest::TYPE);
    assert_eq!(req.content.as_deref(), Some(content));

    // 還沒有端點回報公鑰：只檢查格式，存下來
    let (_, html) = s.page(&admin, &format!("/scripts/{id}")).await;
    let csrf = csrf_from(&html);
    assert!(
        html.contains("未簽章") && html.contains("下載簽章請求"),
        "{html}"
    );
    let (st, loc) = post(
        &s,
        &admin,
        &format!("/scripts/{id}/signature"),
        &[("csrf", &csrf), ("signature", "nope")],
    )
    .await;
    assert_eq!(st, 303);
    assert!(loc.contains("sig_error="), "{loc}");
    assert!(script_signature(&s, id).await.is_none());
    let sig = sign(&k, &req);
    let (_, loc) = post(
        &s,
        &admin,
        &format!("/scripts/{id}/signature"),
        &[("csrf", &csrf), ("signature", &sig)],
    )
    .await;
    assert_eq!(loc, format!("/scripts/{id}?sig=unverifiable"));
    assert_eq!(
        script_signature(&s, id).await.as_deref(),
        Some(sig.as_str())
    );

    // 有端點回報公鑰後：用別的金鑰簽的會被擋
    let tok = s.create_token(1).await;
    let dev = s.enroll_ok(&tok, None, None).await;
    checkin(&s, &dev, vec![k.public.clone()]).await;
    let other = key();
    let (_, loc) = post(
        &s,
        &admin,
        &format!("/scripts/{id}/signature"),
        &[("csrf", &csrf), ("signature", &sign(&other, &req))],
    )
    .await;
    assert!(loc.contains("sig_error="), "{loc}");
    assert_eq!(
        script_signature(&s, id).await.as_deref(),
        Some(sig.as_str()),
        "失敗時保留原本的簽章"
    );
    let (_, loc) = post(
        &s,
        &admin,
        &format!("/scripts/{id}/signature"),
        &[("csrf", &csrf), ("signature", &sig)],
    )
    .await;
    assert_eq!(loc, format!("/scripts/{id}?sig=verified"));
    let (_, html) = s.page(&admin, &loc).await;
    assert!(html.contains("驗證通過") && html.contains(&k.id), "{html}");
    assert!(html.contains("1 台端點要求簽章"), "{html}");

    // 下發的指令帶簽章，Agent 驗得過
    runs::create_run(
        &s.pool,
        &RunInput {
            action: "script".into(),
            target: Target::Device(dev.device_id),
            delay_minutes: None,
            script_id: Some(id),
            expires_hours: 24,
        },
        &alice(),
    )
    .await
    .unwrap();
    let r = checkin(&s, &dev, vec![k.public.clone()]).await;
    let spec = r.commands[0].script.as_ref().unwrap();
    assert_eq!(spec.signature.as_deref(), Some(sig.as_str()));
    assert!(protocol::signing::verify_script(std::slice::from_ref(&k.public), spec).is_ok());

    // 改內容：簽章清除（已建立的指令保留當時的快照）
    scripts::update_script(
        &s.pool,
        id,
        &ScriptInput {
            name: "清暫存".into(),
            description: String::new(),
            content: "Remove-Item $env:TEMP\\* -Recurse\r\n".into(),
            timeout_minutes: 30,
            language: Default::default(),
        },
        &alice(),
    )
    .await
    .unwrap();
    assert!(script_signature(&s, id).await.is_none());
    let r = checkin(&s, &dev, vec![k.public.clone()]).await;
    assert_eq!(
        r.commands[0].script.as_ref().unwrap().signature.as_deref(),
        Some(sig.as_str())
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE action = 'script_signed' \
         AND (detail->>'verified')::bool",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[sqlx::test(migrations = false)]
async fn unapproved_scripts_cannot_be_signed(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let id = approved_script(&s, "dir").await;
    sqlx::query("UPDATE scripts SET status = 'pending' WHERE id = $1")
        .bind(id)
        .execute(&s.pool)
        .await
        .unwrap();
    let (_, html) = s.page(&admin, &format!("/scripts/{id}")).await;
    assert!(html.contains("腳本核准後才能上傳簽章"), "{html}");
    let req = download_request(&s, &admin, &format!("/scripts/{id}/signing-request.json")).await;
    let (_, loc) = post(
        &s,
        &admin,
        &format!("/scripts/{id}/signature"),
        &[
            ("csrf", &csrf_from(&html)),
            ("signature", &sign(&key(), &req)),
        ],
    )
    .await;
    assert!(loc.contains("sig_error="), "{loc}");
    assert!(script_signature(&s, id).await.is_none());
}

#[sqlx::test(migrations = false)]
async fn signing_is_platform_only(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let id = approved_script(&s, "dir").await;
    s.create_group_token("台北", 1).await;
    let gary = s.login_as("gary", Role::GroupAdmin, &["台北"]).await;
    let r = gary
        .get(s.web_url(&format!("/scripts/{id}/signing-request.json")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let (_, html) = s.page(&gary, "/").await;
    let (st, _) = post(
        &s,
        &gary,
        &format!("/scripts/{id}/signature"),
        &[
            ("csrf", &csrf_from(&html)),
            ("signature", "0123456789abcdef:AAAA"),
        ],
    )
    .await;
    assert_eq!(st, 403);
    let admin = s.admin_client().await;
    let r = admin
        .get(s.web_url("/scripts/999999/signing-request.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

fn chunks(
    data: &[u8],
) -> impl futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Unpin {
    futures_util::stream::iter(vec![Ok(axum::body::Bytes::copy_from_slice(data))])
}

fn pkg_input(install_args: &str) -> PackageInput {
    PackageInput {
        name: "7-Zip".into(),
        version: "23.01".into(),
        kind: "exe".into(),
        install_args: install_args.into(),
        uninstall_args: String::new(),
        success_codes: vec![],
        detect_name: "7-Zip*".into(),
        detect_publisher: String::new(),
        detect_min_version: String::new(),
    }
}

#[sqlx::test(migrations = false)]
async fn package_signing_flow(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let dir = &s.state.package_dir;
    let stored = store::save(dir, chunks(b"MZ installer")).await.unwrap();
    let pkg = admin::create_package(
        &s.pool,
        dir,
        &stored,
        "7z.exe",
        None,
        &pkg_input("/S"),
        "admin",
    )
    .await
    .unwrap();
    let k = key();
    let tok = s.create_token(1).await;
    let dev = s.enroll_ok(&tok, None, None).await;
    checkin(&s, &dev, vec![k.public.clone()]).await;
    admin::create_deployment(
        &s.pool,
        &DeploymentInput {
            name: "7-Zip".into(),
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

    // 派送表單標出未簽章（有端點要求簽章）
    let (_, html) = s.page(&admin, "/deployments/new").await;
    assert!(html.contains("7-Zip 23.01（EXE，未簽章）"), "{html}");

    let req = download_request(&s, &admin, &format!("/packages/{pkg}/signing-request.json")).await;
    assert!(req.content.is_none());
    let (_, html) = s.page(&admin, &format!("/packages/{pkg}")).await;
    let (_, loc) = post(
        &s,
        &admin,
        &format!("/packages/{pkg}/signature"),
        &[("csrf", &csrf_from(&html)), ("signature", &sign(&k, &req))],
    )
    .await;
    assert_eq!(loc, format!("/packages/{pkg}?sig=verified"));

    // 下發的派送帶簽章，Agent 驗得過
    let r = checkin(&s, &dev, vec![k.public.clone()]).await;
    let spec = &r.deployments[0].package;
    assert!(protocol::signing::verify_package(std::slice::from_ref(&k.public), spec).is_ok());
    let (_, html) = s.page(&admin, "/deployments/new").await;
    assert!(html.contains("7-Zip 23.01（EXE）"), "{html}");

    // 只改名稱：簽章保留；改安裝參數：簽章清除，下次報到就不帶
    admin::update_package(
        &s.pool,
        pkg,
        &PackageInput {
            name: "7-Zip x64".into(),
            ..pkg_input("/S")
        },
        "admin",
    )
    .await
    .unwrap();
    let sig: Option<String> = sqlx::query_scalar("SELECT signature FROM packages WHERE id = $1")
        .bind(pkg)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    assert!(sig.is_some());
    admin::update_package(&s.pool, pkg, &pkg_input("/S /D=C:\\x"), "admin")
        .await
        .unwrap();
    let r = checkin(&s, &dev, vec![k.public.clone()]).await;
    assert!(r.deployments[0].package.signature.is_none());
}
