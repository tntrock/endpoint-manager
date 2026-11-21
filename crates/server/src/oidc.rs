//! 管理網頁單一登入（OpenID Connect 授權碼流程 + PKCE）。
//!
//! ID Token 由伺服器透過 TLS 直接向 token 端點取得，依 OpenID Connect Core 3.1.3.7
//! 以 TLS 伺服器驗證取代簽章驗證；其餘欄位（iss、aud、azp、exp、nonce）都會檢查。

use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::web::auth::{new_token, sha256_hex};

/// 進行中的登入流程有效時間
pub const LOGIN_MINUTES: i32 = 10;
/// ID Token 時間的容許誤差（秒）
const SKEW_SECS: i64 = 60;
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);
const TIMEOUT: Duration = Duration::from_secs(10);
pub const COOKIE: &str = "em_oidc";
pub const CALLBACK_PATH: &str = "/login/oidc/callback";
pub const DEFAULT_LABEL: &str = "使用公司帳號登入";
pub const DEFAULT_USERNAME_CLAIM: &str = "email";

#[derive(Clone, PartialEq)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub username_claim: String,
    pub label: String,
}

/// 不輸出 client secret
impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("redirect_url", &self.redirect_url)
            .field("username_claim", &self.username_claim)
            .finish_non_exhaustive()
    }
}

impl OidcConfig {
    /// `EM_OIDC_ISSUER` 沒設定時回 None；設定了但其他必填值缺少或網址不合法時回錯誤。
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Option<Self>> {
        let get = |k: &str| {
            get(k)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let Some(issuer) = get("EM_OIDC_ISSUER") else {
            return Ok(None);
        };
        let issuer = issuer.trim_end_matches('/').to_string();
        let need = |k: &str| get(k).with_context(|| format!("{k} is required with EM_OIDC_ISSUER"));
        let cfg = OidcConfig {
            client_id: need("EM_OIDC_CLIENT_ID")?,
            client_secret: need("EM_OIDC_CLIENT_SECRET")?,
            redirect_url: need("EM_OIDC_REDIRECT_URL")?,
            username_claim: get("EM_OIDC_USERNAME_CLAIM")
                .unwrap_or_else(|| DEFAULT_USERNAME_CLAIM.into()),
            label: get("EM_OIDC_LABEL").unwrap_or_else(|| DEFAULT_LABEL.into()),
            issuer,
        };
        anyhow::ensure!(allowed_url(&cfg.issuer), "EM_OIDC_ISSUER must be https://");
        anyhow::ensure!(
            allowed_url(&cfg.redirect_url) && cfg.redirect_url.ends_with(CALLBACK_PATH),
            "EM_OIDC_REDIRECT_URL must be https://<host>{CALLBACK_PATH}"
        );
        Ok(Some(cfg))
    }
}

/// https://，或本機的 http://（測試用）
pub fn allowed_url(u: &str) -> bool {
    if u.starts_with("https://") {
        return u.len() > "https://".len();
    }
    let Some(rest) = u.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(h, _)| h),
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

#[derive(Debug, Clone, Deserialize)]
pub struct Discovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
}

/// 身分提供者用戶端：探索文件快取與 HTTP 連線
pub struct Provider {
    pub cfg: OidcConfig,
    http: reqwest::Client,
    discovery: tokio::sync::Mutex<Option<(Instant, Discovery)>>,
}

impl Provider {
    pub fn new(cfg: OidcConfig) -> anyhow::Result<Self> {
        let native = rustls_native_certs::load_native_certs();
        let roots: Vec<reqwest::Certificate> = native
            .certs
            .iter()
            .filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok())
            .collect();
        let http = reqwest::Client::builder()
            .tls_certs_only(roots)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()?;
        Ok(Self {
            cfg,
            http,
            discovery: tokio::sync::Mutex::new(None),
        })
    }

    pub async fn discovery(&self) -> anyhow::Result<Discovery> {
        let mut cache = self.discovery.lock().await;
        if let Some((at, d)) = cache.as_ref()
            && at.elapsed() < DISCOVERY_TTL
        {
            return Ok(d.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
        let resp = self.http.get(&url).send().await.context("discovery")?;
        anyhow::ensure!(
            resp.status().is_success(),
            "discovery returned {}",
            resp.status()
        );
        let d: Discovery = resp.json().await.context("discovery document")?;
        anyhow::ensure!(
            d.issuer.trim_end_matches('/') == self.cfg.issuer,
            "discovery issuer {:?} does not match EM_OIDC_ISSUER",
            d.issuer
        );
        anyhow::ensure!(
            allowed_url(&d.authorization_endpoint) && allowed_url(&d.token_endpoint),
            "discovery endpoints must be https://"
        );
        *cache = Some((Instant::now(), d.clone()));
        Ok(d)
    }

    /// 以授權碼換 ID Token（client_secret_basic）
    async fn exchange(&self, d: &Discovery, code: &str, verifier: &str) -> anyhow::Result<String> {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", &self.cfg.redirect_url)
            .append_pair("code_verifier", verifier)
            .finish();
        // RFC 6749 2.3.1：帳號與密碼先做 form 編碼再 Base64
        let enc = |s: &str| form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
        let basic = STANDARD.encode(format!(
            "{}:{}",
            enc(&self.cfg.client_id),
            enc(&self.cfg.client_secret)
        ));
        let resp = self
            .http
            .post(&d.token_endpoint)
            .header("authorization", format!("Basic {basic}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("accept", "application/json")
            .body(body)
            .send()
            .await
            .context("token request")?;
        let status = resp.status();
        let v: Value = resp.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            // 只記錄 error 代碼，不記錄可能含敏感資料的描述
            let err = v.get("error").and_then(Value::as_str).unwrap_or("unknown");
            bail!("token endpoint returned {status} ({err})");
        }
        v.get("id_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .context("token response has no id_token")
    }
}

/// PKCE S256
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

pub fn authorization_url(
    d: &Discovery,
    cfg: &OidcConfig,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> String {
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &cfg.client_id)
        .append_pair("redirect_uri", &cfg.redirect_url)
        .append_pair("scope", "openid profile email")
        .append_pair("state", state)
        .append_pair("nonce", nonce)
        .append_pair("code_challenge", &code_challenge(verifier))
        .append_pair("code_challenge_method", "S256")
        .finish();
    let sep = if d.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{sep}{query}", d.authorization_endpoint)
}

/// 開始登入：記下 state／nonce／verifier，回傳 (cookie 值, 導向網址)
pub async fn start(pool: &PgPool, p: &Provider) -> anyhow::Result<(String, String)> {
    let d = p.discovery().await?;
    let (id, state, nonce, verifier) = (new_token(), new_token(), new_token(), new_token());
    sqlx::query("DELETE FROM oidc_logins WHERE expires_at < now()")
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO oidc_logins (id_hash, state, nonce, code_verifier, expires_at) \
         VALUES ($1, $2, $3, $4, now() + make_interval(mins => $5))",
    )
    .bind(sha256_hex(&id))
    .bind(&state)
    .bind(&nonce)
    .bind(&verifier)
    .bind(LOGIN_MINUTES)
    .execute(pool)
    .await?;
    Ok((id, authorization_url(&d, &p.cfg, &state, &nonce, &verifier)))
}

/// 身分提供者認定的使用者
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub subject: String,
    pub username: String,
}

/// 回呼失敗的原因（給稽核記錄與使用者看的訊息）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// cookie 遺失、過期、state 不符或已使用過
    Flow,
    /// 身分提供者回報錯誤（例如使用者取消）
    Denied,
    /// 換 token 或 ID Token 驗證失敗
    Token,
}

impl Failure {
    pub fn reason(self) -> &'static str {
        match self {
            Failure::Flow => "oidc_flow",
            Failure::Denied => "oidc_denied",
            Failure::Token => "oidc_token",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Failure::Flow => "登入逾時或連結無效，請重新登入",
            Failure::Denied => "身分提供者沒有完成登入",
            Failure::Token => "無法向身分提供者確認身分，請稍後再試或聯絡平台管理員",
        }
    }
}

/// 完成登入：檢查流程並換得身分
pub async fn finish(
    pool: &PgPool,
    p: &Provider,
    cookie: Option<&str>,
    state: &str,
    code: Option<&str>,
) -> Result<Identity, Failure> {
    let Some(cookie) = cookie.filter(|c| !c.is_empty()) else {
        return Err(Failure::Flow);
    };
    // 只能用一次：先刪除再處理
    let row: Option<(String, String, String)> = sqlx::query_as(
        "DELETE FROM oidc_logins WHERE id_hash = $1 AND expires_at > now() \
         RETURNING state, nonce, code_verifier",
    )
    .bind(sha256_hex(cookie))
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "oidc login lookup failed");
        Failure::Flow
    })?;
    let Some((want_state, nonce, verifier)) = row else {
        return Err(Failure::Flow);
    };
    if sha256_hex(state) != sha256_hex(&want_state) {
        return Err(Failure::Flow);
    }
    let Some(code) = code.filter(|c| !c.is_empty()) else {
        return Err(Failure::Denied);
    };
    let token = async {
        let d = p.discovery().await?;
        p.exchange(&d, code, &verifier).await
    }
    .await
    .map_err(|e| {
        tracing::warn!(error = %format!("{e:#}"), "oidc token exchange failed");
        Failure::Token
    })?;
    validate_id_token(
        &token,
        &p.cfg,
        &nonce,
        time::OffsetDateTime::now_utc().unix_timestamp(),
    )
    .map_err(|why| {
        tracing::warn!(why, "oidc id token rejected");
        Failure::Token
    })
}

/// 檢查 ID Token 的內容（不含簽章，見模組說明）
pub fn validate_id_token(
    token: &str,
    cfg: &OidcConfig,
    nonce: &str,
    now: i64,
) -> Result<Identity, &'static str> {
    let mut parts = token.split('.');
    let (Some(_header), Some(payload), Some(_sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a JWT");
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| "payload is not base64url")?;
    let c: Value = serde_json::from_slice(&bytes).map_err(|_| "payload is not JSON")?;
    let s = |k: &str| c.get(k).and_then(Value::as_str);

    if s("iss").map(|i| i.trim_end_matches('/')) != Some(cfg.issuer.as_str()) {
        return Err("iss mismatch");
    }
    match c.get("aud") {
        Some(Value::String(a)) if *a == cfg.client_id => {}
        Some(Value::Array(a)) if a.iter().any(|x| x.as_str() == Some(&cfg.client_id)) => {
            if a.len() > 1 && s("azp") != Some(cfg.client_id.as_str()) {
                return Err("azp mismatch");
            }
        }
        _ => return Err("aud mismatch"),
    }
    if let Some(azp) = s("azp")
        && azp != cfg.client_id
    {
        return Err("azp mismatch");
    }
    let exp = c.get("exp").and_then(Value::as_i64).ok_or("no exp")?;
    if exp + SKEW_SECS < now {
        return Err("expired");
    }
    if c.get("nbf")
        .and_then(Value::as_i64)
        .is_some_and(|nbf| nbf - SKEW_SECS > now)
    {
        return Err("not yet valid");
    }
    if s("nonce") != Some(nonce) {
        return Err("nonce mismatch");
    }
    let subject = s("sub").filter(|v| !v.is_empty()).ok_or("no sub")?;
    let username = s(&cfg.username_claim)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or("no username claim")?;
    if cfg.username_claim == "email" && c.get("email_verified") == Some(&Value::Bool(false)) {
        return Err("email not verified");
    }
    Ok(Identity {
        subject: subject.to_string(),
        username: username.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn cfg() -> OidcConfig {
        OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "em".into(),
            client_secret: "s3cret".into(),
            redirect_url: "https://em.example.com/login/oidc/callback".into(),
            username_claim: "email".into(),
            label: DEFAULT_LABEL.into(),
        }
    }

    fn jwt(claims: Value) -> String {
        format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256"}"#),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        )
    }

    fn good() -> Value {
        json!({
            "iss": "https://idp.example.com",
            "aud": "em",
            "exp": 2_000,
            "iat": 1_000,
            "nonce": "n1",
            "sub": "user-1",
            "email": "Alice@corp.example",
        })
    }

    fn check(claims: Value) -> Result<Identity, &'static str> {
        validate_id_token(&jwt(claims), &cfg(), "n1", 1_500)
    }

    fn with(k: &str, v: Value) -> Value {
        let mut c = good();
        c[k] = v;
        c
    }

    fn without(k: &str) -> Value {
        let mut c = good();
        c.as_object_mut().unwrap().remove(k);
        c
    }

    #[test]
    fn accepts_valid_token() {
        assert_eq!(
            check(good()),
            Ok(Identity {
                subject: "user-1".into(),
                username: "Alice@corp.example".into()
            })
        );
        assert!(check(with("aud", json!(["em"]))).is_ok());
        assert!(check(with("aud", json!(["other", "em"]))).is_err());
        let mut multi = with("aud", json!(["other", "em"]));
        multi["azp"] = json!("em");
        assert!(check(multi).is_ok());
        assert!(check(with("iss", json!("https://idp.example.com/"))).is_ok());
        assert!(check(with("email_verified", json!(true))).is_ok());
        // 容許 60 秒誤差
        assert!(check(with("exp", json!(1_450))).is_ok());
    }

    #[test]
    fn rejects_each_bad_field() {
        assert_eq!(
            check(with("iss", json!("https://evil.example"))),
            Err("iss mismatch")
        );
        assert_eq!(check(without("iss")), Err("iss mismatch"));
        assert_eq!(check(with("aud", json!("other"))), Err("aud mismatch"));
        assert_eq!(check(with("aud", json!(["other"]))), Err("aud mismatch"));
        assert_eq!(check(with("azp", json!("other"))), Err("azp mismatch"));
        assert_eq!(check(with("exp", json!(1_400))), Err("expired"));
        assert_eq!(check(without("exp")), Err("no exp"));
        assert_eq!(check(with("nbf", json!(1_600))), Err("not yet valid"));
        assert_eq!(check(with("nonce", json!("n2"))), Err("nonce mismatch"));
        assert_eq!(check(without("nonce")), Err("nonce mismatch"));
        assert_eq!(check(with("sub", json!(""))), Err("no sub"));
        assert_eq!(check(without("email")), Err("no username claim"));
        assert_eq!(
            check(with("email_verified", json!(false))),
            Err("email not verified")
        );
        assert_eq!(
            validate_id_token("a.b", &cfg(), "n1", 1_500),
            Err("not a JWT")
        );
        assert_eq!(
            validate_id_token("a.%%%.c", &cfg(), "n1", 1_500),
            Err("payload is not base64url")
        );
    }

    #[test]
    fn other_username_claim() {
        let mut c = cfg();
        c.username_claim = "preferred_username".into();
        let mut claims = with("email_verified", json!(false));
        claims["preferred_username"] = json!("alice");
        assert_eq!(
            validate_id_token(&jwt(claims), &c, "n1", 1_500)
                .unwrap()
                .username,
            "alice"
        );
    }

    #[test]
    fn pkce_and_authorization_url() {
        // RFC 7636 附錄 B
        assert_eq!(
            code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let d = Discovery {
            issuer: "https://idp.example.com".into(),
            authorization_endpoint: "https://idp.example.com/auth?tenant=1".into(),
            token_endpoint: "https://idp.example.com/token".into(),
        };
        let u = authorization_url(&d, &cfg(), "st", "nn", "ver");
        assert!(u.starts_with("https://idp.example.com/auth?tenant=1&response_type=code&client_id=em&redirect_uri=https%3A%2F%2Fem.example.com%2Flogin%2Foidc%2Fcallback&scope=openid+profile+email&state=st&nonce=nn&code_challenge="), "{u}");
        assert!(u.ends_with("&code_challenge_method=S256"), "{u}");
    }

    #[test]
    fn url_rules() {
        assert!(allowed_url("https://idp.example.com"));
        assert!(allowed_url("http://127.0.0.1:8080/x"));
        assert!(allowed_url("http://localhost/x"));
        assert!(allowed_url("http://[::1]:9/x"));
        assert!(!allowed_url("http://idp.example.com"));
        assert!(!allowed_url("http://localhost.evil.com/x"));
        assert!(!allowed_url("https://"));
        assert!(!allowed_url("ftp://x"));
    }

    #[test]
    fn config_from_env() {
        let env = |pairs: Vec<(&'static str, &'static str)>| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert_eq!(OidcConfig::from_lookup(env(vec![])).unwrap(), None);
        let full = vec![
            ("EM_OIDC_ISSUER", "https://idp.example.com/"),
            ("EM_OIDC_CLIENT_ID", "em"),
            ("EM_OIDC_CLIENT_SECRET", "s3cret"),
            (
                "EM_OIDC_REDIRECT_URL",
                "https://em.example.com/login/oidc/callback",
            ),
        ];
        assert_eq!(
            OidcConfig::from_lookup(env(full.clone())).unwrap(),
            Some(cfg())
        );
        let mut missing = full.clone();
        missing.retain(|(k, _)| *k != "EM_OIDC_CLIENT_SECRET");
        assert!(OidcConfig::from_lookup(env(missing)).is_err());
        let mut http = full.clone();
        http[0] = ("EM_OIDC_ISSUER", "http://idp.example.com");
        assert!(OidcConfig::from_lookup(env(http)).is_err());
        let mut wrong_path = full;
        wrong_path[3] = ("EM_OIDC_REDIRECT_URL", "https://em.example.com/");
        assert!(OidcConfig::from_lookup(env(wrong_path)).is_err());
    }
}
