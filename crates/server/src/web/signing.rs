//! 腳本與套件簽章：下載簽章請求、上傳簽章（只限平台管理員）。

use axum::Form;
use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, check_csrf, platform};
use super::{enc, not_found};
use crate::AppState;
use crate::error::AppError;
use crate::signing::{self, Precheck, SignError};

/// 詳細頁上顯示的簽章區塊
pub struct SignatureView {
    /// /scripts/{id} 或 /packages/{id}
    pub base: String,
    /// 已簽章：金鑰 ID
    pub key_id: Option<String>,
    /// 要求簽章的使用中端點數
    pub enforcing: i64,
    pub message: Option<&'static str>,
    pub error: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct SigQuery {
    #[serde(default)]
    pub sig: String,
    #[serde(default)]
    pub sig_error: String,
}

impl SignatureView {
    pub async fn load(
        st: &AppState,
        base: String,
        signature: Option<&str>,
        q: &SigQuery,
    ) -> Result<SignatureView, sqlx::Error> {
        Ok(SignatureView {
            base,
            key_id: signing::signature_label(signature),
            enforcing: signing::enforcing_devices(&st.pool).await?,
            message: match q.sig.as_str() {
                "verified" => Some("已儲存簽章，並以端點回報的公鑰驗證通過"),
                "unverifiable" => {
                    Some("已儲存簽章。目前沒有端點回報公鑰，無法預先驗證；端點收到時會自行驗證")
                }
                _ => None,
            },
            error: (!q.sig_error.is_empty()).then(|| q.sig_error.chars().take(300).collect()),
        })
    }
}

fn download(req: &protocol::signing::SigningRequest, name: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        serde_json::to_vec_pretty(req).expect("request serializes"),
    )
        .into_response()
}

fn result_redirect(base: &str, r: Result<Precheck, SignError>) -> Result<Response, AppError> {
    let to = match r {
        Ok(Precheck::Verified(_)) => format!("{base}?sig=verified"),
        Ok(Precheck::Unverifiable(_)) => format!("{base}?sig=unverifiable"),
        Err(SignError::Invalid(e)) => format!("{base}?sig_error={}", enc(&e)),
        Err(SignError::NotFound) => return Ok(not_found()),
        Err(SignError::Db(e)) => return Err(e.into()),
    };
    Ok(Redirect::to(&to).into_response())
}

fn request_error(e: SignError) -> Response {
    match e {
        SignError::Db(e) => AppError::from(e).into_response(),
        _ => not_found(),
    }
}

pub async fn script_request(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let req = signing::script_request(&st.pool, id)
        .await
        .map_err(request_error)?;
    Ok(download(&req, signing::request_file_name("script", id)))
}

pub async fn package_request(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let req = signing::package_request(&st.pool, id)
        .await
        .map_err(request_error)?;
    Ok(download(&req, signing::request_file_name("package", id)))
}

#[derive(Deserialize)]
pub struct SignatureForm {
    csrf: String,
    signature: String,
}

pub async fn sign_script(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<SignatureForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let r = signing::sign_script(&st.pool, id, &f.signature, &s.username).await;
    result_redirect(&format!("/scripts/{id}"), r).map_err(IntoResponse::into_response)
}

pub async fn sign_package(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Form(f): Form<SignatureForm>,
) -> Result<Response, Response> {
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let r = signing::sign_package(&st.pool, id, &f.signature, &s.username).await;
    result_redirect(&format!("/packages/{id}"), r).map_err(IntoResponse::into_response)
}
