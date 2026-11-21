mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use common::{TestServer, csrf_from};
use endpoint_server::accounts::{NewAdmin, create};
use endpoint_server::oidc::{OidcConfig, code_challenge};
use endpoint_server::web::auth::Role;
use serde_json::{Value, json};
use sqlx::PgPool;

/// 假的身分提供者：測試先登記「授權碼 → (PKCE challenge, ID Token 內容)」
#[derive(Clone, Default)]
struct Idp {
    issuer: String,
    codes: Arc<Mutex<HashMap<String, (String, Value)>>>,
}

impl Idp {
    async fn start() -> Idp {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let idp = Idp {
            issuer: format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port()),
            codes: Default::default(),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/token", post(token))
            .with_state(idp.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        idp
    }

    fn config(&self) -> OidcConfig {
        OidcConfig {
            issuer: self.issuer.clone(),
            client_id: "em-client".into(),
            client_secret: "s3cret:&value".into(),
            redirect_url: "https://localhost/login/oidc/callback".into(),
            username_claim: "email".into(),
            label: "使用公司帳號登入".into(),
        }
    }

    fn claims(&self, nonce: &str, sub: &str, email: &str) -> Value {
        json!({
            "iss": self.issuer,
            "aud": "em-client",
            "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 300,
            "iat": time::OffsetDateTime::now_utc().unix_timestamp(),
            "nonce": nonce,
            "sub": sub,
            "email": email,
        })
    }
}

async fn discovery(State(idp): State<Idp>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/auth", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
    }))
}

async fn token(State(idp): State<Idp>, headers: HeaderMap, body: String) -> Response {
    // client_secret_basic：帳號與密碼先 form 編碼
    let want = format!("Basic {}", STANDARD.encode("em-client:s3cret%3A%26value"));
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(want.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let form: HashMap<String, String> = form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    let Some((challenge, claims)) = idp
        .codes
        .lock()
        .unwrap()
        .remove(form.get("code").map(String::as_str).unwrap_or(""))
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
    if code_challenge(&verifier) != challenge
        || form.get("redirect_uri").map(String::as_str)
            != Some("https://localhost/login/oidc/callback")
        || form.get("grant_type").map(String::as_str) != Some("authorization_code")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    let jwt = format!(
        "{}.{}.sig",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    Json(json!({"id_token": jwt, "token_type": "Bearer", "access_token": "x"})).into_response()
}

/// 授權網址裡的參數
struct Started {
    state: String,
    nonce: String,
    challenge: String,
}

async fn start(s: &TestServer, c: &reqwest::Client, idp: &Idp) -> Started {
    let r = c.get(s.web_url("/login/oidc")).send().await.unwrap();
    assert_eq!(r.status(), 303);
    let loc = r.headers()["location"].to_str().unwrap().to_string();
    assert!(loc.starts_with(&format!("{}/auth?", idp.issuer)), "{loc}");
    let q: HashMap<String, String> =
        form_urlencoded::parse(loc.split_once('?').unwrap().1.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(q["client_id"], "em-client");
    assert_eq!(q["code_challenge_method"], "S256");
    assert_eq!(q["scope"], "openid profile email");
    Started {
        state: q["state"].clone(),
        nonce: q["nonce"].clone(),
        challenge: q["code_challenge"].clone(),
    }
}

async fn callback(s: &TestServer, c: &reqwest::Client, code: &str, state: &str) -> (u16, String) {
    let url = format!(
        "{}?code={code}&state={}",
        s.web_url("/login/oidc/callback"),
        form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>()
    );
    let r = c.get(url).send().await.unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

/// 完整走一次：開始 → 登記授權碼 → 回呼
async fn sso(
    s: &TestServer,
    c: &reqwest::Client,
    idp: &Idp,
    sub: &str,
    email: &str,
) -> (u16, String) {
    let st = start(s, c, idp).await;
    let code = uuid::Uuid::new_v4().to_string();
    idp.codes.lock().unwrap().insert(
        code.clone(),
        (st.challenge.clone(), idp.claims(&st.nonce, sub, email)),
    );
    callback(s, c, &code, &st.state).await
}

async fn account(s: &TestServer, name: &str, role: Role, groups: &[&str]) -> i64 {
    let mut ids = vec![];
    for g in groups {
        ids.push(s.group_id(g).await);
    }
    create(
        &s.pool,
        &NewAdmin {
            username: name.into(),
            password: format!("{name}-long-password"),
            role,
            groups: ids,
        },
        "test",
    )
    .await
    .unwrap()
}

async fn subject(s: &TestServer, id: i64) -> Option<String> {
    sqlx::query_scalar("SELECT oidc_subject FROM admins WHERE id = $1")
        .bind(id)
        .fetch_one(&s.pool)
        .await
        .unwrap()
}

async fn logged_in(s: &TestServer, c: &reqwest::Client) -> bool {
    s.page(c, "/devices").await.0 == 200
}

#[sqlx::test(migrations = false)]
async fn login_links_and_reuses_binding(pool: PgPool) {
    let idp = Idp::start().await;
    let s = TestServer::start_oidc(pool, idp.config()).await;
    let alice = account(&s, "alice@corp.example", Role::Viewer, &["台北"]).await;

    let (_, html) = s.page(&s.web_client(), "/login").await;
    assert!(html.contains(r#"href="/login/oidc""#), "{html}");
    assert!(html.contains("使用公司帳號登入"));

    // 第一次：名稱不分大小寫對應，並綁定
    let c = s.web_client();
    let (st, body) = sso(&s, &c, &idp, "sub-alice", "Alice@Corp.Example").await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains(r#"http-equiv="refresh""#), "{body}");
    assert!(logged_in(&s, &c).await);
    assert_eq!(subject(&s, alice).await.as_deref(), Some("sub-alice"));
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action || ' ' || detail::text FROM audit_log \
         WHERE action IN ('oidc_linked', 'login') ORDER BY id",
    )
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert!(actions[0].starts_with("oidc_linked"), "{actions:?}");
    assert!(actions[1].contains(r#""method": "oidc""#), "{actions:?}");

    // 之後以綁定為準：公司帳號改了 email 也能登入同一個帳號
    let c2 = s.web_client();
    let (st, _) = sso(&s, &c2, &idp, "sub-alice", "alice.new@corp.example").await;
    assert_eq!(st, 200);
    assert!(logged_in(&s, &c2).await);

    // 停用後不能登入，也不會改綁到別的帳號
    sqlx::query("UPDATE admins SET disabled_at = now() WHERE id = $1")
        .bind(alice)
        .execute(&s.pool)
        .await
        .unwrap();
    let (st, body) = sso(&s, &s.web_client(), &idp, "sub-alice", "alice@corp.example").await;
    assert_eq!(st, 401);
    assert!(body.contains("沒有對應的管理帳號"), "{body}");
}

#[sqlx::test(migrations = false)]
async fn rejects_bad_flows(pool: PgPool) {
    let idp = Idp::start().await;
    let s = TestServer::start_oidc(pool, idp.config()).await;
    account(&s, "bob@corp.example", Role::Viewer, &["台北"]).await;
    let flow_error = "登入逾時或連結無效";

    // state 不符
    let c = s.web_client();
    let st = start(&s, &c, &idp).await;
    idp.codes.lock().unwrap().insert(
        "c-state".into(),
        (
            st.challenge.clone(),
            idp.claims(&st.nonce, "sub-bob", "bob@corp.example"),
        ),
    );
    let (code, body) = callback(&s, &c, "c-state", "not-the-state").await;
    assert_eq!(code, 401);
    assert!(body.contains(flow_error), "{body}");
    // 那一筆已作廢：即使改用正確的 state 也不行
    let (code, _) = callback(&s, &c, "c-state", &st.state).await;
    assert_eq!(code, 401);

    // 別的瀏覽器（沒有 cookie）完成別人開始的流程
    let st = start(&s, &s.web_client(), &idp).await;
    idp.codes.lock().unwrap().insert(
        "c-csrf".into(),
        (
            st.challenge.clone(),
            idp.claims(&st.nonce, "sub-bob", "bob@corp.example"),
        ),
    );
    let other = s.web_client();
    let (code, body) = callback(&s, &other, "c-csrf", &st.state).await;
    assert_eq!(code, 401);
    assert!(body.contains(flow_error));
    assert!(!logged_in(&s, &other).await);

    // nonce 不符
    let c = s.web_client();
    let st = start(&s, &c, &idp).await;
    idp.codes.lock().unwrap().insert(
        "c-nonce".into(),
        (
            st.challenge.clone(),
            idp.claims("other-nonce", "sub-bob", "bob@corp.example"),
        ),
    );
    let (code, body) = callback(&s, &c, "c-nonce", &st.state).await;
    assert_eq!(code, 401);
    assert!(body.contains("無法向身分提供者確認身分"), "{body}");
    assert!(!logged_in(&s, &c).await);

    // 回呼重放：成功一次後再送同一個網址
    let c = s.web_client();
    let st = start(&s, &c, &idp).await;
    idp.codes.lock().unwrap().insert(
        "c-ok".into(),
        (
            st.challenge.clone(),
            idp.claims(&st.nonce, "sub-bob", "bob@corp.example"),
        ),
    );
    assert_eq!(callback(&s, &c, "c-ok", &st.state).await.0, 200);
    let (code, body) = callback(&s, &c, "c-ok", &st.state).await;
    assert_eq!(code, 401);
    assert!(body.contains(flow_error));

    // 使用者在身分提供者取消（沒有 code）
    let c = s.web_client();
    let st = start(&s, &c, &idp).await;
    let url = format!(
        "{}?error=access_denied&state={}",
        s.web_url("/login/oidc/callback"),
        st.state
    );
    let r = c.get(url).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.text().await.unwrap().contains("身分提供者沒有完成登入"));

    let reasons: Vec<String> = sqlx::query_scalar(
        "SELECT detail->>'reason' FROM audit_log WHERE action = 'login_failed' ORDER BY id",
    )
    .fetch_all(&s.pool)
    .await
    .unwrap();
    assert!(reasons.contains(&"oidc_flow".to_string()), "{reasons:?}");
    assert!(reasons.contains(&"oidc_token".to_string()), "{reasons:?}");
    assert!(reasons.contains(&"oidc_denied".to_string()), "{reasons:?}");
}

#[sqlx::test(migrations = false)]
async fn unknown_or_conflicting_accounts(pool: PgPool) {
    let idp = Idp::start().await;
    let s = TestServer::start_oidc(pool, idp.config()).await;

    let (st, body) = sso(&s, &s.web_client(), &idp, "sub-x", "nobody@corp.example").await;
    assert_eq!(st, 401);
    assert!(body.contains("沒有對應的管理帳號"), "{body}");

    let carol = account(&s, "carol@corp.example", Role::Viewer, &["台北"]).await;
    assert_eq!(
        sso(&s, &s.web_client(), &idp, "sub-carol", "carol@corp.example")
            .await
            .0,
        200
    );
    // 另一個公司帳號宣稱同樣的 email
    let c = s.web_client();
    let (st, body) = sso(&s, &c, &idp, "sub-impostor", "carol@corp.example").await;
    assert_eq!(st, 401);
    assert!(body.contains("已綁定另一個公司帳號"), "{body}");
    assert!(!logged_in(&s, &c).await);
    assert_eq!(subject(&s, carol).await.as_deref(), Some("sub-carol"));

    // 平台管理員解除綁定後，新的公司帳號可以綁定
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, &format!("/accounts/{carol}")).await;
    assert!(html.contains("解除綁定"), "{html}");
    let r = admin
        .post(s.web_url(&format!("/accounts/{carol}/oidc-unlink")))
        .form(&[("csrf", csrf_from(&html))])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
    assert_eq!(subject(&s, carol).await, None);
    assert_eq!(
        sso(
            &s,
            &s.web_client(),
            &idp,
            "sub-carol-2",
            "carol@corp.example"
        )
        .await
        .0,
        200
    );
    assert_eq!(subject(&s, carol).await.as_deref(), Some("sub-carol-2"));
}

#[sqlx::test(migrations = false)]
async fn password_login_can_be_limited_to_platform_admins(pool: PgPool) {
    let idp = Idp::start().await;
    let s = TestServer::start_oidc(pool, idp.config()).await;
    account(&s, "dave", Role::GroupAdmin, &["台北"]).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/accounts").await;
    assert!(html.contains("密碼登入只限平台管理員"), "{html}");
    let r = admin
        .post(s.web_url("/accounts/password-login"))
        .form(&[("csrf", csrf_from(&html).as_str()), ("on", "1")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);

    let login = |user: &'static str, pw: &'static str| {
        let c = s.web_client();
        let url = s.web_url("/login");
        async move {
            let r = c
                .post(url)
                .form(&[("username", user), ("password", pw)])
                .send()
                .await
                .unwrap();
            (r.status().as_u16(), r.text().await.unwrap())
        }
    };
    let (st, body) = login("dave", "dave-long-password").await;
    assert_eq!(st, 401);
    assert!(body.contains("只能用單一登入"), "{body}");
    // 密碼錯誤時不透露
    let (st, body) = login("dave", "wrong-password-123").await;
    assert_eq!(st, 401);
    assert!(body.contains("帳號或密碼錯誤"), "{body}");
    // 平台管理員保留密碼登入
    assert_eq!(login("admin", "admin-long-password").await.0, 303);
}

#[sqlx::test(migrations = false)]
async fn not_configured(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let c = s.web_client();
    let (_, html) = s.page(&c, "/login").await;
    assert!(!html.contains(r#"href="/login/oidc""#));
    assert_eq!(s.page(&c, "/login/oidc").await.0, 404);
    assert_eq!(
        s.page(&c, "/login/oidc/callback?code=x&state=y").await.0,
        404
    );
    // 帳號頁不顯示單一登入的設定；密碼登入設定不生效
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/accounts").await;
    assert!(!html.contains(r#"action="/accounts/password-login""#));
}
