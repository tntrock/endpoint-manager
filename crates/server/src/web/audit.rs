//! 稽核記錄頁（平台管理員）。

use askama::Template;
use axum::extract::{Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf, platform};
use super::{fmt_time, forbidden, render};
use crate::AppState;
use crate::error::AppError;
use crate::retention::{self, MAX_DAYS, MIN_AUDIT_DAYS, MIN_COMMAND_DAYS, Retention};

const PAGE_SIZE: i64 = 50;

fn label(action: &str) -> &str {
    match action {
        "login" => "登入成功",
        "login_failed" => "登入失敗",
        "logout" => "登出",
        "password_change" => "修改自己的密碼",
        "token_create" => "建立註冊金鑰",
        "token_revoke" => "作廢註冊金鑰",
        "device_retire" => "除役裝置",
        "device_approve" => "核准重新註冊",
        "device_reject" => "拒絕重新註冊",
        "device_move" => "移動裝置群組",
        "group_create" => "建立群組",
        "group_delete" => "刪除群組",
        "admin_create" => "建立帳號",
        "admin_update" => "變更帳號角色／群組",
        "admin_disable" => "停用帳號",
        "admin_enable" => "啟用帳號",
        "admin_password_reset" => "重設帳號密碼",
        "admin_unlock" => "解除帳號鎖定",
        "rule_create" => "建立合規規則",
        "rule_update" => "修改合規規則",
        "rule_delete" => "刪除合規規則",
        "exemption_create" => "新增豁免",
        "exemption_revoke" => "撤銷豁免",
        "exemption_expire" => "豁免到期",
        "compliance_export" => "匯出違規清單",
        "notify_settings" => "修改通知設定",
        "setting_retention" => "修改資料保留",
        "retention_purge" => "清除過期資料",
        "oidc_linked" => "綁定單一登入",
        "oidc_unlinked" => "解除單一登入綁定",
        "setting_password_login" => "修改密碼登入範圍",
        other => other,
    }
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    page: i64,
    #[serde(default)]
    saved: bool,
}

pub struct AuditRow {
    pub at: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditPage {
    nav: Nav,
    rows: Vec<AuditRow>,
    page: i64,
    has_next: bool,
    /// 表單上的保留天數（驗證失敗時是使用者輸入的原值）
    command_days: String,
    audit_days: String,
    error: Option<String>,
    saved: bool,
    min_command: i32,
    min_audit: i32,
    max_days: i32,
}

type Row = (DateTime<Utc>, String, String, Option<String>, String);

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !s.all_devices() {
        return Ok(forbidden());
    }
    let r = retention::load(&st.pool).await?;
    let form = (r.command_days.to_string(), r.audit_days.to_string());
    Ok(render(&build(&st, &s, q.page, form, None, q.saved).await?))
}

async fn build(
    st: &AppState,
    s: &Session,
    page: i64,
    (command_days, audit_days): (String, String),
    error: Option<String>,
    saved: bool,
) -> Result<AuditPage, AppError> {
    let page = page.clamp(0, super::devices::MAX_PAGE);
    let mut rows: Vec<Row> = sqlx::query_as(
        "SELECT at, actor, action, target, detail::text FROM audit_log \
         ORDER BY id DESC LIMIT $1 OFFSET $2",
    )
    .bind(PAGE_SIZE + 1)
    .bind(page * PAGE_SIZE)
    .fetch_all(&st.pool)
    .await?;
    let has_next = rows.len() as i64 > PAGE_SIZE;
    rows.truncate(PAGE_SIZE as usize);
    Ok(AuditPage {
        nav: Nav::new(s, "audit"),
        rows: rows
            .into_iter()
            .map(|(at, actor, action, target, detail)| AuditRow {
                at: fmt_time(st, Some(at)),
                actor,
                action: label(&action).to_string(),
                target: target.unwrap_or_default(),
                detail: if detail == "{}" {
                    String::new()
                } else {
                    detail
                },
            })
            .collect(),
        page,
        has_next,
        command_days,
        audit_days,
        error,
        saved,
        min_command: MIN_COMMAND_DAYS,
        min_audit: MIN_AUDIT_DAYS,
        max_days: MAX_DAYS,
    })
}

/// 修改資料保留天數（平台管理員）
pub async fn retention(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (mut csrf, mut command_days, mut audit_days) =
        (String::new(), String::new(), String::new());
    for (k, v) in form_urlencoded::parse(&raw) {
        match k.as_ref() {
            "csrf" => csrf = v.into_owned(),
            "command_days" => command_days = v.trim().to_string(),
            "audit_days" => audit_days = v.trim().to_string(),
            _ => {}
        }
    }
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let parsed = (command_days.parse::<i32>(), audit_days.parse::<i32>());
    let error = match parsed {
        (Ok(c), _) if !retention::valid(c, MIN_COMMAND_DAYS) => Some(format!(
            "遠端指令的保留天數須為 0（永久保留）或 {MIN_COMMAND_DAYS}–{MAX_DAYS}"
        )),
        (_, Ok(a)) if !retention::valid(a, MIN_AUDIT_DAYS) => Some(format!(
            "稽核記錄的保留天數須為 0（永久保留）或 {MIN_AUDIT_DAYS}–{MAX_DAYS}"
        )),
        (Ok(_), Ok(_)) => None,
        _ => Some("保留天數須為整數".to_string()),
    };
    if let Some(e) = error {
        let page = build(&st, &s, 0, (command_days, audit_days), Some(e), false)
            .await
            .map_err(IntoResponse::into_response)?;
        return Err((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
    }
    let new = Retention {
        command_days: parsed.0.unwrap_or_default(),
        audit_days: parsed.1.unwrap_or_default(),
    };
    retention::save(&st.pool, new, &super::commands::actor(&s))
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "saving retention failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "伺服器錯誤，請稍後再試").into_response()
        })?;
    Ok(Redirect::to("/audit?saved=true").into_response())
}
