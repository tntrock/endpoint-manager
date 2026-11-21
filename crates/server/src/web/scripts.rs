//! 腳本管理（只限平台管理員）：清單與雙人核准設定、新增／編輯、詳情、核准／停用／啟用／刪除。

use askama::Template;
use axum::extract::{Path, Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf, platform};
use super::commands::{actor, command_error, language_label};
use crate::commands::{CmdError, cmd_error_kind};

/// 輸入或狀態問題：重新顯示表單；權限與其他錯誤交給 command_error
fn is_form_error(e: &anyhow::Error) -> bool {
    matches!(
        cmd_error_kind(e),
        Some(CmdError::Invalid(_) | CmdError::Conflict(_) | CmdError::NotFound(_))
    )
}
use super::devices::db_error;
use super::{fmt_time, not_found, render};
use crate::AppState;
use crate::commands::scripts::{self, ScriptInput, approval_is_independent};
use protocol::command::ScriptLanguage;

pub fn status_label(status: &str) -> &'static str {
    match status {
        "pending" => "待核准",
        "approved" => "已核准",
        "disabled" => "已停用",
        _ => "未知",
    }
}

pub struct ListRow {
    pub id: i64,
    pub name: String,
    pub language: &'static str,
    pub status: &'static str,
    pub sha_short: String,
    pub updated_by: String,
    pub approved_by: String,
}

#[derive(Template)]
#[template(path = "scripts.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<ListRow>,
    require_second: bool,
    /// 語言篩選：（顯示文字、網址、目前選取）
    filters: Vec<(&'static str, &'static str, bool)>,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    lang: String,
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    let lang = ScriptLanguage::parse(&q.lang).map(ScriptLanguage::as_str);
    type Row = (i64, String, String, String, String, String, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT id, name, language, status, sha256, updated_by, approved_by FROM scripts \
         WHERE $1::text IS NULL OR language = $1 \
         ORDER BY lower(name), id",
    )
    .bind(lang)
    .fetch_all(&st.pool)
    .await
    .map_err(db_error)?;
    let require_second = scripts::require_second_approver(&st.pool)
        .await
        .map_err(db_error)?;
    Ok(render(&ListPage {
        nav: Nav::new(&s, "scripts"),
        rows: rows
            .into_iter()
            .map(
                |(id, name, language, status, sha, updated_by, approved_by)| ListRow {
                    id,
                    name,
                    language: language_label(&language),
                    status: status_label(&status),
                    sha_short: sha.chars().take(12).collect(),
                    updated_by,
                    approved_by: approved_by.unwrap_or_default(),
                },
            )
            .collect(),
        require_second,
        filters: vec![
            ("全部", "/scripts", lang.is_none()),
            (
                "PowerShell",
                "/scripts?lang=powershell",
                lang == Some("powershell"),
            ),
            ("sh", "/scripts?lang=sh", lang == Some("sh")),
        ],
    }))
}

pub async fn settings(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let mut csrf = String::new();
    let mut require = false;
    for (k, v) in form_urlencoded::parse(&raw) {
        match k.as_ref() {
            "csrf" => csrf = v.into_owned(),
            "require" => require = v == "1",
            _ => {}
        }
    }
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    scripts::set_require_second_approver(&st.pool, require, &actor(&s))
        .await
        .map_err(command_error)?;
    Ok(Redirect::to("/scripts").into_response())
}

/// 表單原始值（驗證失敗時原樣顯示）
#[derive(Debug, Clone, Default)]
pub struct FormFields {
    pub name: String,
    pub description: String,
    pub content: String,
    pub timeout_minutes: String,
    pub language: String,
}

fn parse_form(raw: &[u8]) -> (String, FormFields) {
    let mut csrf = String::new();
    let mut f = FormFields::default();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.into_owned();
        match k.as_ref() {
            "csrf" => csrf = v,
            "name" => f.name = v,
            "description" => f.description = v,
            "content" => f.content = v,
            "timeout_minutes" => f.timeout_minutes = v,
            "language" => f.language = v,
            _ => {}
        }
    }
    (csrf, f)
}

impl FormFields {
    fn to_input(&self) -> Result<ScriptInput, String> {
        let timeout = self.timeout_minutes.trim();
        let timeout_minutes = if timeout.is_empty() {
            30
        } else {
            timeout
                .parse()
                .map_err(|_| "逾時必須是 1–120 分鐘".to_string())?
        };
        let language = ScriptLanguage::parse(self.language.trim()).unwrap_or_default();
        Ok(ScriptInput {
            name: self.name.clone(),
            description: self.description.clone(),
            // 瀏覽器送出的換行是 CRLF。PowerShell 原樣保存；sh 的 \r 會變成指令的一部分，
            // 改成 LF（雜湊以保存的內容計算）
            content: match language {
                ScriptLanguage::PowerShell => self.content.clone(),
                ScriptLanguage::Sh => self.content.replace("\r\n", "\n"),
            },
            timeout_minutes,
            language,
        })
    }
}

#[derive(Template)]
#[template(path = "script_form.html")]
struct FormPage {
    nav: Nav,
    id: Option<i64>,
    f: FormFields,
    error: Option<String>,
}

fn invalid(s: &Session, id: Option<i64>, f: FormFields, e: String) -> Response {
    let page = FormPage {
        nav: Nav::new(s, "scripts"),
        id,
        f,
        error: Some(e),
    };
    (StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response()
}

pub async fn new_form(AdminSession(s): AdminSession) -> Result<Response, Response> {
    platform(&s)?;
    Ok(render(&FormPage {
        nav: Nav::new(&s, "scripts"),
        id: None,
        f: FormFields {
            timeout_minutes: "30".into(),
            language: ScriptLanguage::default().as_str().into(),
            ..Default::default()
        },
        error: None,
    }))
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, f) = parse_form(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let input = match f.to_input() {
        Ok(i) => i,
        Err(e) => return Ok(invalid(&s, None, f, e)),
    };
    match scripts::create_script(&st.pool, &input, &actor(&s)).await {
        Ok(id) => Ok(Redirect::to(&format!("/scripts/{id}")).into_response()),
        Err(e) if is_form_error(&e) => Ok(invalid(&s, None, f, format!("{e:#}"))),
        Err(e) => Err(command_error(e)),
    }
}

type DetailRow = (
    String,
    String,
    String,
    String,
    i32,
    String,
    String,
    time::OffsetDateTime,
    String,
    time::OffsetDateTime,
    Option<String>,
    Option<time::OffsetDateTime>,
    Vec<String>,
    String,
    Option<String>,
);

#[derive(Template)]
#[template(path = "script_detail.html")]
struct DetailPage {
    nav: Nav,
    id: i64,
    name: String,
    description: String,
    content: String,
    sha256: String,
    language: &'static str,
    timeout_minutes: i32,
    status: String,
    status_label: &'static str,
    created: String,
    updated: String,
    approved: String,
    used: i64,
    /// 目前使用者可以核准
    can_approve: bool,
    /// 等待核准，但目前使用者是修改者之一
    needs_other: bool,
    sig: super::signing::SignatureView,
}

async fn load(st: &AppState, id: i64) -> Result<Option<DetailRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT name, description, content, sha256, timeout_minutes, status, created_by, \
                created_at, updated_by, updated_at, approved_by, approved_at, editors, language, \
                signature \
         FROM scripts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
}

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    Query(q): Query<super::signing::SigQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    let Some(r) = load(&st, id).await.map_err(db_error)? else {
        return Err(not_found());
    };
    let (name, description, content, sha256, timeout_minutes, status) =
        (r.0, r.1, r.2, r.3, r.4, r.5);
    let (created_by, created_at, updated_by, updated_at, approved_by, approved_at, editors) =
        (r.6, r.7, r.8, r.9, r.10, r.11, r.12);
    let language = language_label(&r.13);
    let sig =
        super::signing::SignatureView::load(&st, format!("/scripts/{id}"), r.14.as_deref(), &q)
            .await
            .map_err(db_error)?;
    let used: i64 = sqlx::query_scalar("SELECT count(*) FROM command_runs WHERE script_id = $1")
        .bind(id)
        .fetch_one(&st.pool)
        .await
        .map_err(db_error)?;
    let second = scripts::require_second_approver(&st.pool)
        .await
        .map_err(db_error)?;
    let awaiting = status == "pending"
        || (second
            && status == "approved"
            && !approval_is_independent(approved_by.as_deref(), &editors));
    let mine = second && editors.contains(&s.username);
    Ok(render(&DetailPage {
        nav: Nav::new(&s, "scripts"),
        id,
        name,
        description,
        content,
        sha256,
        language,
        timeout_minutes,
        status_label: status_label(&status),
        status,
        created: format!("{created_by}（{}）", fmt_time(&st, Some(created_at))),
        updated: format!("{updated_by}（{}）", fmt_time(&st, Some(updated_at))),
        approved: approved_by
            .map(|a| format!("{a}（{}）", fmt_time(&st, approved_at)))
            .unwrap_or_else(|| "—".into()),
        used,
        can_approve: awaiting && !mine,
        needs_other: awaiting && mine,
        sig,
    }))
}

pub async fn edit_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let Some(r) = load(&st, id).await.map_err(db_error)? else {
        return Err(not_found());
    };
    Ok(render(&FormPage {
        nav: Nav::new(&s, "scripts"),
        id: Some(id),
        f: FormFields {
            name: r.0,
            description: r.1,
            content: r.2,
            timeout_minutes: r.4.to_string(),
            language: r.13,
        },
        error: None,
    }))
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let (csrf, mut f) = parse_form(&raw);
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    // 語言建立後不能改：以資料庫為準（決定換行怎麼處理），不信任表單
    let language: Option<String> = sqlx::query_scalar("SELECT language FROM scripts WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await
        .map_err(db_error)?;
    f.language = language.ok_or_else(not_found)?;
    let input = match f.to_input() {
        Ok(i) => i,
        Err(e) => return Ok(invalid(&s, Some(id), f, e)),
    };
    match scripts::update_script(&st.pool, id, &input, &actor(&s)).await {
        Ok(()) => Ok(Redirect::to(&format!("/scripts/{id}")).into_response()),
        Err(e) if is_form_error(&e) => Ok(invalid(&s, Some(id), f, format!("{e:#}"))),
        Err(e) => Err(command_error(e)),
    }
}

pub async fn act(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path((id, action)): Path<(i64, String)>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let mut csrf = String::new();
    let mut sha = String::new();
    let mut timeout: Option<i32> = None;
    for (k, v) in form_urlencoded::parse(&raw) {
        match k.as_ref() {
            "csrf" => csrf = v.into_owned(),
            "sha256" => sha = v.into_owned(),
            "timeout_minutes" => timeout = v.trim().parse().ok(),
            _ => {}
        }
    }
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let a = actor(&s);
    let pool = &st.pool;
    let r = match action.as_str() {
        // 核准畫面上看到的版本：內容雜湊與逾時都要相符（表單沒帶逾時就不核准）
        "approve" => match timeout {
            Some(t) => scripts::approve_version(pool, id, &sha, Some(t), &a).await,
            None => Err(CmdError::Conflict("腳本內容已變更，請重新檢視後再核准".into()).into()),
        },
        "disable" => scripts::set_disabled(pool, id, true, &a).await,
        "enable" => scripts::set_disabled(pool, id, false, &a).await,
        "delete" => {
            scripts::delete_script(pool, id, &a)
                .await
                .map_err(command_error)?;
            return Ok(Redirect::to("/scripts").into_response());
        }
        _ => return Err(not_found()),
    };
    r.map_err(command_error)?;
    Ok(Redirect::to(&format!("/scripts/{id}")).into_response())
}
