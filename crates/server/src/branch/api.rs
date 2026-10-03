//! 分點快取呼叫的 API：註冊（金鑰）、輪詢核准結果（poll_secret）、換發憑證（mTLS）。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Instant;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::response::Response;
use chrono::{DateTime, Duration, Utc};
use protocol::branch::{
    CacheAuthorize, CacheAuthorizeResponse, CacheCheckin, CacheCheckinResponse, CacheEnrollPoll,
    CacheEnrollPollResponse, CacheEnrollRequest, CacheEnrollResponse, CacheEnrollState,
    CachePackage, MAX_STORED, same_host,
};
use protocol::{RenewRequest, RenewResponse};
use serde_json::json;
use uuid::Uuid;

use crate::AppState;
use crate::checkin::RENEW_BEFORE_DAYS;
use crate::error::AppError;
use crate::tls::PeerCert;
use crate::tokens::{self, TokenKind};

/// 已驗證的快取：憑證指紋在 cache_certs（未撤銷、未過期），快取本身是使用中
#[derive(Debug, Clone)]
pub struct AuthedCache {
    pub cache_id: i64,
    pub site_id: Option<i64>,
    pub cert_not_after: DateTime<Utc>,
}

impl FromRequestParts<AppState> for AuthedCache {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, AppError> {
        let peer = parts
            .extensions
            .get::<PeerCert>()
            .ok_or(AppError::Unauthorized)?;
        let row: Option<(i64, Option<i64>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT c.id, c.site_id, k.not_after FROM cache_certs k JOIN caches c ON c.id = k.cache_id \
             WHERE k.fingerprint = $1 AND k.revoked_at IS NULL AND k.not_after > now() \
               AND c.status = 'active'",
        )
        .bind(&peer.fingerprint)
        .fetch_optional(&state.pool)
        .await?;
        let (cache_id, site_id, cert_not_after) = row.ok_or(AppError::Unauthorized)?;
        Ok(AuthedCache {
            cache_id,
            site_id,
            cert_not_after,
        })
    }
}

pub async fn enroll(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(mut req): Json<CacheEnrollRequest>,
) -> Result<Json<CacheEnrollResponse>, AppError> {
    if !st.enroll_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    req.normalize();
    req.validate().map_err(|e| AppError::BadRequest(e.into()))?;
    // 快取憑證有 serverAuth、由同一個 CA 簽發：拿到中央伺服器的名稱就能冒充中央
    if req
        .dns_names
        .iter()
        .any(|d| st.server_names.iter().any(|s| same_host(d, s)))
    {
        return Err(AppError::BadRequest(
            "dns_names must not include the central server's names".into(),
        ));
    }
    // 只看 CSR 能不能解析；憑證要等核准時才簽發
    rcgen::CertificateSigningRequestParams::from_pem(&req.csr_pem)
        .map_err(|_| AppError::BadRequest("invalid CSR".into()))?;

    let mut tx = st.pool.begin().await?;
    let (token_id, _) = tokens::consume_token(&mut tx, &req.token, TokenKind::Cache)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let poll_secret = tokens::generate_token();
    let name = req.name.trim();
    let cache_id: i64 = sqlx::query_scalar(
        "INSERT INTO caches (name, url, dns_names, csr_pem, poll_secret_hash, status, enroll_token_id) \
         VALUES ($1, $2, $3, $4, $5, 'pending', $6) RETURNING id",
    )
    .bind(name)
    .bind(&req.url)
    .bind(&req.dns_names)
    .bind(&req.csr_pem)
    .bind(tokens::hash_token(&poll_secret))
    .bind(token_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => {
            AppError::Conflict("cache name already exists".into())
        }
        _ => e.into(),
    })?;
    crate::audit::record(
        &mut tx,
        &format!("token:{token_id}"),
        "cache_enroll",
        Some(name),
        json!({"id": cache_id, "url": req.url, "dns_names": req.dns_names}),
    )
    .await?;
    tx.commit().await?;
    tracing::info!(cache_id, "cache enrolled, waiting for approval");
    Ok(Json(CacheEnrollResponse {
        cache_id,
        poll_secret,
    }))
}

pub async fn poll(
    State(st): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<CacheEnrollPoll>,
) -> Result<Json<CacheEnrollPollResponse>, AppError> {
    // 與註冊共用每 IP 的速率限制：poll_secret 不能被大量猜測
    if !st.enroll_limiter.check(remote.ip(), Instant::now()) {
        return Err(AppError::TooManyRequests);
    }
    // 以雜湊比對，不會有逐字元比較的時序洩漏
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM caches WHERE id = $1 AND poll_secret_hash = $2")
            .bind(req.cache_id)
            .bind(tokens::hash_token(&req.poll_secret))
            .fetch_optional(&st.pool)
            .await?;
    let state = match status.ok_or(AppError::Unauthorized)?.as_str() {
        "pending" => CacheEnrollState::Pending,
        "rejected" => CacheEnrollState::Rejected,
        _ => CacheEnrollState::Approved,
    };
    let mut resp = CacheEnrollPollResponse {
        state,
        certificate_chain_pem: None,
        root_pem: None,
    };
    if state == CacheEnrollState::Approved {
        // 停用中沒有有效憑證：只回 Approved，等管理員重新啟用
        let pem: Option<String> = sqlx::query_scalar(
            "SELECT pem FROM cache_certs \
             WHERE cache_id = $1 AND revoked_at IS NULL AND not_after > now() \
             ORDER BY not_after DESC LIMIT 1",
        )
        .bind(req.cache_id)
        .fetch_optional(&st.pool)
        .await?;
        resp.certificate_chain_pem = pem.map(|p| format!("{p}{}", st.ca.chain_pem()));
        resp.root_pem = Some(st.ca.root_pem().to_string());
    }
    Ok(Json(resp))
}

pub async fn renew(
    State(st): State<AppState>,
    cache: AuthedCache,
    Json(req): Json<RenewRequest>,
) -> Result<Json<RenewResponse>, AppError> {
    if cache.cert_not_after - Utc::now() >= Duration::days(RENEW_BEFORE_DAYS) {
        return Err(AppError::BadRequest("renewal not due".into()));
    }
    let mut tx = st.pool.begin().await?;
    // 鎖住快取列並重新確認狀態：與停用（撤銷所有憑證）互斥，停用後不會再多出一張有效憑證
    let row: Option<(String, Vec<String>)> =
        sqlx::query_as("SELECT status, dns_names FROM caches WHERE id = $1 FOR UPDATE")
            .bind(cache.cache_id)
            .fetch_optional(&mut *tx)
            .await?;
    let dns = match row {
        Some((status, dns)) if status == "active" => dns,
        _ => return Err(AppError::Unauthorized),
    };
    let issued = st
        .ca
        .sign_cache_csr(&req.csr_pem, cache.cache_id, &dns, Utc::now())
        .map_err(|e| AppError::BadRequest(format!("{e:#}")))?;
    super::caches::insert_cert(&mut tx, cache.cache_id, &issued).await?;
    // 之後重新啟用時用新的金鑰簽發
    sqlx::query("UPDATE caches SET csr_pem = $2 WHERE id = $1")
        .bind(cache.cache_id)
        .bind(&req.csr_pem)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(cache_id = cache.cache_id, "cache certificate renewed");
    Ok(Json(RenewResponse {
        certificate_chain_pem: format!("{}{}", issued.pem, st.ca.chain_pem()),
    }))
}

const DEFAULT_DISK_LIMIT_GB: u32 = 100;

pub async fn checkin(
    State(st): State<AppState>,
    cache: AuthedCache,
    Json(req): Json<CacheCheckin>,
) -> Result<Json<CacheCheckinResponse>, AppError> {
    if req.stored.len() > MAX_STORED {
        return Err(AppError::BadRequest("too many stored packages".into()));
    }
    if req.version.chars().count() > 50 || req.version.chars().any(char::is_control) {
        return Err(AppError::BadRequest("invalid version".into()));
    }
    // 同一個套件回報兩次時取最後一筆（ON CONFLICT 不能在同一句更新同一列兩次）
    let stored: BTreeMap<i64, i64> = req
        .stored
        .iter()
        .map(|p| (p.package_id, i64::try_from(p.size).unwrap_or(i64::MAX)))
        .collect();
    let (ids, sizes): (Vec<i64>, Vec<i64>) = stored.into_iter().unzip();

    let mut tx = st.pool.begin().await?;
    sqlx::query(
        "UPDATE caches SET last_seen = now(), version = $2, disk_used_bytes = $3 WHERE id = $1",
    )
    .bind(cache.cache_id)
    .bind(&req.version)
    .bind(i64::try_from(req.disk_used_bytes).unwrap_or(i64::MAX))
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM cache_packages WHERE cache_id = $1 AND package_id <> ALL($2)")
        .bind(cache.cache_id)
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    // JOIN packages：已刪除或不存在的套件直接略過，不會因外鍵失敗
    sqlx::query(
        "INSERT INTO cache_packages (cache_id, package_id, size) \
         SELECT $1, u.id, u.size FROM UNNEST($2::bigint[], $3::bigint[]) AS u(id, size) \
         JOIN packages p ON p.id = u.id \
         ON CONFLICT (cache_id, package_id) DO UPDATE SET size = EXCLUDED.size, updated_at = now() \
         WHERE cache_packages.size <> EXCLUDED.size",
    )
    .bind(cache.cache_id)
    .bind(&ids)
    .bind(&sizes)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let packages: Vec<(i64, String, i64)> = sqlx::query_as(
        // 未停止的派送用到的套件：快取應預先下載，也只提供這些
        "SELECT DISTINCT p.id, p.sha256, p.size FROM packages p \
         JOIN deployments d ON d.package_id = p.id WHERE d.stage <> 'stopped' ORDER BY p.id",
    )
    .fetch_all(&st.pool)
    .await?;
    let limits: Option<(Option<i32>, i32)> = match cache.site_id {
        Some(site) => {
            sqlx::query_as("SELECT bandwidth_limit_mbps, disk_limit_gb FROM sites WHERE id = $1")
                .bind(site)
                .fetch_optional(&st.pool)
                .await?
        }
        None => None,
    };
    let (bandwidth, disk) = limits.unwrap_or((None, DEFAULT_DISK_LIMIT_GB as i32));
    Ok(Json(CacheCheckinResponse {
        packages: packages
            .into_iter()
            .map(|(id, sha256, size)| CachePackage {
                id,
                sha256,
                size: size.max(0) as u64,
            })
            .collect(),
        bandwidth_limit_mbps: bandwidth.map(|b| b.max(1) as u32),
        disk_limit_gb: disk.max(1) as u32,
        renew_certificate: cache.cert_not_after - Utc::now() < Duration::days(RENEW_BEFORE_DAYS),
    }))
}

pub async fn package_content(
    State(st): State<AppState>,
    _cache: AuthedCache,
    Path(id): Path<i64>,
) -> Result<Response, AppError> {
    let sha: Option<String> = sqlx::query_scalar(
        "SELECT p.sha256 FROM packages p WHERE p.id = $1 AND EXISTS \
         (SELECT 1 FROM deployments d WHERE d.package_id = p.id AND d.stage <> 'stopped')",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let sha = sha.ok_or(AppError::NotFound)?;
    crate::deploy::api::stream_package(&st, id, &sha).await
}

pub async fn authorize(
    State(st): State<AppState>,
    _cache: AuthedCache,
    Json(req): Json<CacheAuthorize>,
) -> Result<Json<CacheAuthorizeResponse>, AppError> {
    let fp = &req.device_cert_fingerprint;
    if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest("invalid fingerprint".into()));
    }
    let device: Option<Uuid> = sqlx::query_scalar(
        "SELECT device_id FROM device_certs \
         WHERE fingerprint = $1 AND revoked_at IS NULL AND not_after > now()",
    )
    .bind(fp.to_ascii_lowercase())
    .fetch_optional(&st.pool)
    .await?;
    let allowed = match device {
        Some(d) => crate::deploy::api::device_may_download(&st, d, req.package_id)
            .await?
            .is_some(),
        None => false,
    };
    Ok(Json(CacheAuthorizeResponse { allowed }))
}
