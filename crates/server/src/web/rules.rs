//! 合規規則：清單（所有人可看）、新增／編輯／刪除與預覽（平台管理員）。

use std::time::Duration;

use askama::Template;
use axum::extract::{Path, Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{AdminSession, Nav, Session, check_csrf};
use super::devices::{SelectOption, db_error};
use super::{forbidden, not_found, render};
use crate::AppState;
use crate::compliance::admin::{self, RuleInput};
use crate::compliance::rules::{KINDS, Params, Rule, Severity, kind_label};
use crate::error::AppError;

/// 表單原始欄位（include／exclude 可重複）。
#[derive(Debug, Default)]
pub struct RuleForm {
    pub csrf: String,
    pub name: String,
    pub description: String,
    pub kind: String,
    pub severity: String,
    pub enabled: bool,
    pub include: Vec<i64>,
    pub exclude: Vec<i64>,
    pub p: ParamFields,
}

/// 各類型參數在表單上的欄位（全部是字串，方便回填）。
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ParamFields {
    pub name: String,
    pub publisher: String,
    pub version: String,
    pub entries: String,
    pub min_build: String,
    pub build: String,
    pub min_ubr: String,
    pub kb: String,
    pub reg_path: String,
    pub reg_name: String,
    pub reg_op: String,
    pub reg_expected: String,
    pub reg_absent_ok: bool,
    pub svc_name: String,
    pub svc_require: String,
    pub fw_domain: bool,
    pub fw_private: bool,
    pub fw_public: bool,
    pub bl_scope: String,
    pub df_realtime: bool,
    pub df_days: String,
    pub df_tamper: bool,
    pub pw_min_length: String,
    pub pw_max_age: String,
    pub pw_max_lockout: String,
    /// 每行一個
    pub admins_allowed: String,
}

pub fn parse_form(raw: &[u8]) -> RuleForm {
    let mut f = RuleForm::default();
    for (k, v) in form_urlencoded::parse(raw) {
        let v = v.into_owned();
        match k.as_ref() {
            "csrf" => f.csrf = v,
            "name" => f.name = v,
            "description" => f.description = v,
            "kind" => f.kind = v,
            "severity" => f.severity = v,
            "enabled" => f.enabled = v == "1",
            "include" => f.include.extend(v.parse::<i64>().ok()),
            "exclude" => f.exclude.extend(v.parse::<i64>().ok()),
            "p_name" => f.p.name = v,
            "p_publisher" => f.p.publisher = v,
            "p_version" => f.p.version = v,
            "p_entries" => f.p.entries = v,
            "p_min_build" => f.p.min_build = v,
            "p_build" => f.p.build = v,
            "p_min_ubr" => f.p.min_ubr = v,
            "p_kb" => f.p.kb = v,
            "p_reg_path" => f.p.reg_path = v,
            "p_reg_name" => f.p.reg_name = v,
            "p_reg_op" => f.p.reg_op = v,
            "p_reg_expected" => f.p.reg_expected = v,
            "p_reg_absent_ok" => f.p.reg_absent_ok = v == "1",
            "p_svc_name" => f.p.svc_name = v,
            "p_svc_require" => f.p.svc_require = v,
            "p_fw_domain" => f.p.fw_domain = v == "1",
            "p_fw_private" => f.p.fw_private = v == "1",
            "p_fw_public" => f.p.fw_public = v == "1",
            "p_bl_scope" => f.p.bl_scope = v,
            "p_df_realtime" => f.p.df_realtime = v == "1",
            "p_df_days" => f.p.df_days = v,
            "p_df_tamper" => f.p.df_tamper = v == "1",
            "p_pw_min_length" => f.p.pw_min_length = v,
            "p_pw_max_age" => f.p.pw_max_age = v,
            "p_pw_max_lockout" => f.p.pw_max_lockout = v,
            "p_admins_allowed" => f.p.admins_allowed = v,
            _ => {}
        }
    }
    f
}

fn num(field: &str, v: &str) -> Result<Option<u32>, String> {
    let v = v.trim();
    if v.is_empty() {
        return Ok(None);
    }
    v.parse::<u32>()
        .map(Some)
        .map_err(|_| format!("{field}必須是正整數"))
}

/// 表單欄位轉成 admin 的輸入；驗證與正規化交給 Params::parse。
pub fn form_to_input(f: &RuleForm) -> Result<RuleInput, String> {
    let p = &f.p;
    let params = match f.kind.as_str() {
        "forbidden_software" => {
            json!({"name": p.name, "publisher": p.publisher, "below_version": p.version})
        }
        "required_software" => {
            json!({"name": p.name, "publisher": p.publisher, "min_version": p.version})
        }
        "software_allowlist" => {
            let entries: Vec<Value> = p
                .entries
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| {
                    let (name, publisher) = l.split_once('|').unwrap_or((l, ""));
                    json!({"name": name.trim(), "publisher": publisher.trim()})
                })
                .collect();
            json!({ "entries": entries })
        }
        "os_build" => {
            let mut m = serde_json::Map::new();
            for (key, label, v) in [
                ("min_build", "最低組建主號", &p.min_build),
                ("build", "組建主號", &p.build),
                ("min_ubr", "最低 UBR", &p.min_ubr),
            ] {
                if let Some(n) = num(label, v)? {
                    m.insert(key.into(), json!(n));
                }
            }
            Value::Object(m)
        }
        "required_kb" => json!({ "kb": p.kb }),
        "registry_value" => {
            let mut m = serde_json::Map::new();
            m.insert("path".into(), json!(p.reg_path));
            m.insert("name".into(), json!(p.reg_name));
            m.insert("op".into(), json!(p.reg_op));
            if !matches!(p.reg_op.as_str(), "exists" | "not_exists") {
                m.insert("expected".into(), json!(p.reg_expected));
            }
            m.insert("absent_ok".into(), json!(p.reg_absent_ok));
            Value::Object(m)
        }
        "service_state" => json!({"name": p.svc_name, "require": p.svc_require}),
        "firewall" => {
            let profiles: Vec<&str> = [
                ("domain", p.fw_domain),
                ("private", p.fw_private),
                ("public", p.fw_public),
            ]
            .into_iter()
            .filter_map(|(n, on)| on.then_some(n))
            .collect();
            json!({ "profiles": profiles })
        }
        "bitlocker" => json!({ "scope": p.bl_scope }),
        "defender" => json!({
            "realtime": p.df_realtime,
            "tamper": p.df_tamper,
            "max_signature_age_days": num("病毒碼天數", &p.df_days)?,
        }),
        "password_policy" => json!({
            "min_length": num("最短長度", &p.pw_min_length)?,
            "max_age_days": num("最長使用天數", &p.pw_max_age)?,
            "max_lockout_threshold": num("鎖定門檻", &p.pw_max_lockout)?,
        }),
        "local_admins" => {
            let allowed: Vec<&str> = p
                .admins_allowed
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            json!({ "allowed": allowed })
        }
        other => return Err(format!("未知的規則類型：{other}")),
    };
    Ok(RuleInput {
        name: f.name.clone(),
        description: f.description.clone(),
        kind: f.kind.clone(),
        severity: f.severity.clone(),
        enabled: f.enabled,
        params,
        include: f.include.clone(),
        exclude: f.exclude.clone(),
        template_key: None,
    })
}

/// 資料庫裡的參數回填到表單欄位（編輯用）。
pub fn params_to_form(kind: &str, v: &Value) -> ParamFields {
    let s = |k: &str| match &v[k] {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let b = |k: &str| v[k].as_bool().unwrap_or(false);
    let profile = |p: &str| {
        v["profiles"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x == p))
    };
    ParamFields {
        reg_path: s("path"),
        reg_name: if kind == "registry_value" {
            s("name")
        } else {
            String::new()
        },
        reg_op: s("op"),
        reg_expected: s("expected"),
        reg_absent_ok: b("absent_ok"),
        svc_name: if kind == "service_state" {
            s("name")
        } else {
            String::new()
        },
        svc_require: s("require"),
        fw_domain: profile("domain"),
        fw_private: profile("private"),
        fw_public: profile("public"),
        bl_scope: s("scope"),
        df_realtime: b("realtime"),
        df_days: s("max_signature_age_days"),
        df_tamper: b("tamper"),
        pw_min_length: s("min_length"),
        pw_max_age: s("max_age_days"),
        pw_max_lockout: s("max_lockout_threshold"),
        admins_allowed: v["allowed"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        name: s("name"),
        publisher: s("publisher"),
        version: if kind == "required_software" {
            s("min_version")
        } else {
            s("below_version")
        },
        entries: v["entries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|e| {
                        let n = e["name"].as_str().unwrap_or("");
                        match e["publisher"].as_str() {
                            Some(p) => format!("{n} | {p}"),
                            None => n.to_string(),
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        min_build: s("min_build"),
        build: s("build"),
        min_ubr: s("min_ubr"),
        kb: s("kb"),
    }
}

pub struct TemplateRow {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub source: &'static str,
    pub used: bool,
}

#[derive(Template)]
#[template(path = "rule_templates.html")]
struct TemplatesPage {
    nav: Nav,
    /// (分類, 範本)
    groups: Vec<(&'static str, Vec<TemplateRow>)>,
    message: Option<String>,
    failed: Vec<(String, String)>,
}

async fn render_templates(
    st: &AppState,
    s: &Session,
    message: Option<String>,
    failed: Vec<(String, String)>,
) -> Result<Response, Response> {
    let used = crate::compliance::templates::used_keys(&st.pool)
        .await
        .map_err(db_error)?;
    let mut groups: Vec<(&'static str, Vec<TemplateRow>)> = vec![];
    for t in crate::compliance::templates::all() {
        let sev = Severity::parse(&t.severity).unwrap_or(Severity::Medium);
        let row = TemplateRow {
            key: &t.key,
            name: &t.name,
            description: &t.description,
            severity: sev.label(),
            severity_class: sev.as_str(),
            source: &t.source,
            used: used.contains(&t.key),
        };
        match groups.iter_mut().find(|g| g.0 == t.category) {
            Some(g) => g.1.push(row),
            None => groups.push((&t.category, vec![row])),
        }
    }
    Ok(render(&TemplatesPage {
        nav: Nav::from(s),
        groups,
        message,
        failed,
    }))
}

pub async fn templates_page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, Response> {
    platform(&s)?;
    render_templates(&st, &s, None, vec![]).await
}

pub async fn create_from_templates(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let mut csrf = String::new();
    let mut keys = vec![];
    for (k, v) in form_urlencoded::parse(&raw) {
        match k.as_ref() {
            "csrf" => csrf = v.into_owned(),
            "key" => keys.push(v.into_owned()),
            _ => {}
        }
    }
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let r = crate::compliance::templates::create(&st.pool, &keys, &s.username)
        .await
        .map_err(db_error)?;
    let mut msg = format!(
        "已建立 {} 條、略過 {} 條（已存在）",
        r.created.len(),
        r.skipped.len()
    );
    if !r.failed.is_empty() {
        msg.push_str(&format!("、失敗 {} 條", r.failed.len()));
    }
    render_templates(&st, &s, Some(msg), r.failed).await
}

fn platform(s: &Session) -> Result<(), Response> {
    if s.all_devices() {
        Ok(())
    } else {
        Err(forbidden())
    }
}

fn conflict(e: impl std::fmt::Display) -> Response {
    (StatusCode::CONFLICT, e.to_string()).into_response()
}

pub struct RuleRow {
    pub id: i64,
    pub name: String,
    pub kind: &'static str,
    pub severity: &'static str,
    pub severity_class: &'static str,
    pub enabled: bool,
    pub scope: String,
    pub violating: i64,
    pub unknown: i64,
    pub exempt: i64,
}

#[derive(Template)]
#[template(path = "rules.html")]
struct RulesPage {
    nav: Nav,
    rows: Vec<RuleRow>,
    kinds: Vec<(&'static str, &'static str)>,
}

type RuleListRow = (i64, String, String, String, bool, i64, i64, i64);

/// 違規數依管理員的群組範圍計算；平台管理員不需要範圍條件（省掉每列的 EXISTS 檢查）。
const RULE_COUNTS_ALL: &str = "SELECT r.id, r.name, r.kind, r.severity, r.enabled, \
       count(v.rule_id) FILTER (WHERE v.status = 'violating'), \
       count(v.rule_id) FILTER (WHERE v.status = 'unknown'), \
       count(v.rule_id) FILTER (WHERE v.status = 'exempt') \
     FROM compliance_rules r LEFT JOIN device_violations v ON v.rule_id = r.id \
     GROUP BY r.id ORDER BY r.name, r.id";
const RULE_COUNTS_SCOPED: &str = "SELECT r.id, r.name, r.kind, r.severity, r.enabled, \
       count(v.rule_id) FILTER (WHERE v.status = 'violating'), \
       count(v.rule_id) FILTER (WHERE v.status = 'unknown'), \
       count(v.rule_id) FILTER (WHERE v.status = 'exempt') \
     FROM compliance_rules r \
     LEFT JOIN device_violations v ON v.rule_id = r.id AND EXISTS ( \
          SELECT 1 FROM devices d WHERE d.id = v.device_id \
          AND d.group_id = ANY($1::bigint[])) \
     GROUP BY r.id ORDER BY r.name, r.id";

/// 規則的範圍文字；範圍外的群組只顯示數量，不顯示名稱。
fn scope_text(s: &Session, groups: &[(String, i64, String)]) -> String {
    let part = |mode: &str| {
        let all: Vec<&(String, i64, String)> = groups.iter().filter(|g| g.0 == mode).collect();
        let names: Vec<&str> = all
            .iter()
            .filter(|g| s.in_scope(Some(g.1)))
            .map(|g| g.2.as_str())
            .collect();
        let hidden = all.len() - names.len();
        let mut text = names.join("、");
        if hidden > 0 {
            if !text.is_empty() {
                text.push('、');
            }
            text.push_str(&format!("另 {hidden} 個群組"));
        }
        (all.is_empty(), text)
    };
    let (no_include, include) = part("include");
    let (no_exclude, exclude) = part("exclude");
    let mut scope = if no_include {
        "全部裝置".to_string()
    } else {
        format!("只套用：{include}")
    };
    if !no_exclude {
        scope.push_str(&format!("；排除：{exclude}"));
    }
    scope
}

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    let rows: Vec<RuleListRow> = if s.all_devices() {
        sqlx::query_as(RULE_COUNTS_ALL).fetch_all(&st.pool).await?
    } else {
        sqlx::query_as(RULE_COUNTS_SCOPED)
            .bind(&s.groups)
            .fetch_all(&st.pool)
            .await?
    };
    let groups: Vec<(i64, String, i64, String)> = sqlx::query_as(
        "SELECT rg.rule_id, rg.mode, g.id, g.name FROM compliance_rule_groups rg \
         JOIN device_groups g ON g.id = rg.group_id ORDER BY g.name",
    )
    .fetch_all(&st.pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(
            |(id, name, kind, severity, enabled, violating, unknown, exempt)| {
                let sev = Severity::parse(&severity).unwrap_or(Severity::Medium);
                let mine: Vec<(String, i64, String)> = groups
                    .iter()
                    .filter(|g| g.0 == id)
                    .map(|g| (g.1.clone(), g.2, g.3.clone()))
                    .collect();
                RuleRow {
                    id,
                    name,
                    kind: kind_label(&kind),
                    severity: sev.label(),
                    severity_class: sev.as_str(),
                    enabled,
                    scope: scope_text(&s, &mine),
                    violating,
                    unknown,
                    exempt,
                }
            },
        )
        .collect();
    Ok(render(&RulesPage {
        nav: Nav::from(&s),
        rows,
        kinds: KINDS.iter().map(|k| (*k, kind_label(k))).collect(),
    }))
}

#[derive(Template)]
#[template(path = "rule_form.html")]
struct RuleFormPage {
    nav: Nav,
    /// None 表示新增
    id: Option<i64>,
    kind: String,
    kind_label: &'static str,
    name: String,
    description: String,
    enabled: bool,
    severities: Vec<SelectOption>,
    include: Vec<SelectOption>,
    exclude: Vec<SelectOption>,
    p: ParamFields,
    /// 驗證失敗時顯示在表單上方
    error: Option<String>,
}

pub(super) async fn group_checks(
    st: &AppState,
    selected: &[i64],
) -> Result<Vec<SelectOption>, sqlx::Error> {
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, name FROM device_groups ORDER BY name")
            .fetch_all(&st.pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name)| SelectOption {
            selected: selected.contains(&id),
            value: id.to_string(),
            label: name,
        })
        .collect())
}

fn severities(current: &str) -> Vec<SelectOption> {
    Severity::ALL
        .into_iter()
        .map(|x| SelectOption {
            value: x.as_str().into(),
            label: x.label().into(),
            selected: x.as_str() == current,
        })
        .collect()
}

#[derive(Deserialize)]
pub struct NewQuery {
    #[serde(default)]
    kind: String,
}

pub async fn new_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<NewQuery>,
) -> Result<Response, Response> {
    platform(&s)?;
    if !KINDS.contains(&q.kind.as_str()) {
        return Err(not_found());
    }
    Ok(render(&RuleFormPage {
        nav: Nav::from(&s),
        id: None,
        kind_label: kind_label(&q.kind),
        kind: q.kind,
        name: String::new(),
        description: String::new(),
        enabled: true,
        severities: severities("medium"),
        include: group_checks(&st, &[]).await.map_err(db_error)?,
        exclude: group_checks(&st, &[]).await.map_err(db_error)?,
        p: ParamFields::default(),
        error: None,
    }))
}

type RuleEditRow = (
    String,
    String,
    String,
    String,
    bool,
    String,
    Vec<i64>,
    Vec<i64>,
);

pub async fn edit_form(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
) -> Result<Response, Response> {
    platform(&s)?;
    let row: Option<RuleEditRow> = sqlx::query_as(
        "SELECT name, description, kind, severity, enabled, params::text, \
           ARRAY(SELECT group_id FROM compliance_rule_groups \
                 WHERE rule_id = r.id AND mode = 'include'), \
           ARRAY(SELECT group_id FROM compliance_rule_groups \
                 WHERE rule_id = r.id AND mode = 'exclude') \
         FROM compliance_rules r WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await
    .map_err(db_error)?;
    let Some((name, description, kind, severity, enabled, params, include, exclude)) = row else {
        return Err(not_found());
    };
    let params: Value = serde_json::from_str(&params).unwrap_or(Value::Null);
    Ok(render(&RuleFormPage {
        nav: Nav::from(&s),
        id: Some(id),
        kind_label: kind_label(&kind),
        p: params_to_form(&kind, &params),
        kind,
        name,
        description,
        enabled,
        severities: severities(&severity),
        include: group_checks(&st, &include).await.map_err(db_error)?,
        exclude: group_checks(&st, &exclude).await.map_err(db_error)?,
        error: None,
    }))
}

pub async fn create(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let result = match form_to_input(&f) {
        Ok(input) => admin::create_rule(&st.pool, &input, &s.username)
            .await
            .map(|_| ()),
        Err(e) => Err(anyhow::anyhow!(e)),
    };
    saved_or_form(&st, &s, None, f, result).await
}

pub async fn update(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let result = match form_to_input(&f) {
        Ok(input) => admin::update_rule(&st.pool, id, &input, &s.username).await,
        Err(e) => Err(anyhow::anyhow!(e)),
    };
    saved_or_form(&st, &s, Some(id), f, result).await
}

pub async fn delete(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Path(id): Path<i64>,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    admin::delete_rule(&st.pool, id, &s.username)
        .await
        .map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/rules").into_response())
}

/// 存檔成功回規則清單；驗證失敗重新顯示表單（保留已輸入的內容）；資料庫錯誤回 500。
async fn saved_or_form(
    st: &AppState,
    s: &Session,
    id: Option<i64>,
    f: RuleForm,
    result: anyhow::Result<()>,
) -> Result<Response, Response> {
    let err = match result {
        Ok(()) => return Ok(Redirect::to("/compliance/rules").into_response()),
        Err(e) => match e.downcast::<sqlx::Error>() {
            Ok(db) => return Err(db_error(db)),
            Err(e) => format!("{e:#}"),
        },
    };
    if !KINDS.contains(&f.kind.as_str()) {
        return Err(conflict(err));
    }
    let page = RuleFormPage {
        nav: Nav::from(s),
        id,
        kind_label: kind_label(&f.kind),
        severities: severities(&f.severity),
        include: group_checks(st, &f.include).await.map_err(db_error)?,
        exclude: group_checks(st, &f.exclude).await.map_err(db_error)?,
        kind: f.kind,
        name: f.name,
        description: f.description,
        enabled: f.enabled,
        p: f.p,
        error: Some(err),
    };
    Ok((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response())
}

/// 同時只允許一個預覽：每次都會掃過全部裝置
static PREVIEW_SLOT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
pub const PREVIEW_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn preview(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let f = parse_form(&raw);
    check_csrf(&s, &f.csrf)?;
    platform(&s)?;
    let parsed = form_to_input(&f).and_then(|i| Params::parse(&i.kind, &i.params).map(|p| (i, p)));
    let msg = match parsed {
        Err(e) => format!("參數有誤：{e}"),
        Ok((i, p)) => match PREVIEW_SLOT.try_acquire() {
            Err(_) => "另一個預覽正在執行，請稍後再試".into(),
            Ok(_slot) => {
                let rule = Rule {
                    id: 0,
                    name: i.name,
                    severity: Severity::Medium,
                    include: i.include,
                    exclude: i.exclude,
                    check: Ok(p.compile()),
                };
                let run = crate::compliance::preview::preview(&st.pool, rule);
                match tokio::time::timeout(PREVIEW_TIMEOUT, run).await {
                    Err(_) => "預覽逾時（超過 30 秒），請直接存檔，背景重算完成後再看結果".into(),
                    Ok(Err(e)) => return Err(db_error(e)),
                    Ok(Ok(c)) => format!(
                        "目前會命中 {} 台（另有 {} 台無法判斷），共評估 {} 台使用中裝置；未計入豁免。",
                        c.violating, c.unknown, c.devices
                    ),
                }
            }
        },
    };
    // askama 以外的輸出要自己跳脫
    Ok(Html(format!("<p class=\"notice\">{}</p>", html_escape(&msg))).into_response())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn form(kind: &str, pairs: &[(&str, &str)]) -> RuleForm {
        let mut raw = format!("csrf=x&name=r&severity=high&enabled=1&kind={kind}");
        for (k, v) in pairs {
            raw.push_str(&format!("&{k}={}", crate::web::enc(v)));
        }
        parse_form(raw.as_bytes())
    }

    #[test]
    fn form_to_params_by_kind() {
        let i = form_to_input(&form(
            "forbidden_software",
            &[("p_name", "*TeamViewer*"), ("p_version", "15")],
        ))
        .unwrap();
        assert_eq!(
            i.params,
            json!({"name": "*TeamViewer*", "publisher": "", "below_version": "15"})
        );
        let i = form_to_input(&form(
            "required_software",
            &[("p_name", "Falcon"), ("p_version", "7")],
        ))
        .unwrap();
        assert_eq!(i.params["min_version"], "7");
        let i = form_to_input(&form(
            "software_allowlist",
            &[(
                "p_entries",
                "Office | Microsoft*\r\n\r\n| Adobe*\nNotepad++",
            )],
        ))
        .unwrap();
        assert_eq!(
            i.params,
            json!({"entries": [
                {"name": "Office", "publisher": "Microsoft*"},
                {"name": "", "publisher": "Adobe*"},
                {"name": "Notepad++", "publisher": ""}
            ]})
        );
        let i = form_to_input(&form(
            "os_build",
            &[
                ("p_build", "22631"),
                ("p_min_ubr", "4317"),
                ("p_min_build", ""),
            ],
        ))
        .unwrap();
        assert_eq!(i.params, json!({"build": 22631, "min_ubr": 4317}));
        assert!(form_to_input(&form("os_build", &[("p_min_build", "abc")])).is_err());
        let i = form_to_input(&form("required_kb", &[("p_kb", "kb5034439")])).unwrap();
        assert_eq!(
            i.params,
            json!({"kb": "kb5034439"}),
            "正規化交給 Params::parse"
        );
        let i = form_to_input(&form(
            "required_kb",
            &[("include", "3"), ("include", "4"), ("exclude", "5")],
        ))
        .unwrap();
        assert_eq!(
            (i.include, i.exclude, i.enabled),
            (vec![3, 4], vec![5], true)
        );
    }

    #[test]
    fn config_kinds_roundtrip_through_form() {
        let cases = [
            (
                "registry_value",
                json!({"path": r"HKLM\SOFTWARE\X", "name": "Y", "op": "gte", "expected": "5", "absent_ok": true}),
            ),
            (
                "registry_value",
                json!({"path": r"HKLM\SOFTWARE\X", "name": "", "op": "not_exists"}),
            ),
            (
                "service_state",
                json!({"name": "RemoteRegistry", "require": "disabled"}),
            ),
            ("firewall", json!({"profiles": ["domain", "public"]})),
            ("bitlocker", json!({"scope": "all_fixed"})),
            (
                "defender",
                json!({"realtime": true, "max_signature_age_days": 7}),
            ),
            (
                "password_policy",
                json!({"min_length": 12, "max_lockout_threshold": 10}),
            ),
            (
                "local_admins",
                json!({"allowed": ["*\\Administrator", "CORP\\Domain Admins"]}),
            ),
        ];
        for (kind, params) in cases {
            let f = RuleForm {
                kind: kind.into(),
                name: "r".into(),
                severity: "high".into(),
                enabled: true,
                p: params_to_form(kind, &params),
                ..Default::default()
            };
            let input = form_to_input(&f).unwrap();
            let back = Params::parse(kind, &input.params).unwrap().to_json();
            assert_eq!(back, params, "{kind}");
        }
    }

    /// 表單送出的原始欄位（核取方塊、多行）能正確解析
    #[test]
    fn config_form_fields_parse() {
        let i = form_to_input(&form(
            "firewall",
            &[("p_fw_private", "1"), ("p_fw_public", "1")],
        ))
        .unwrap();
        assert_eq!(i.params, json!({"profiles": ["private", "public"]}));
        let i = form_to_input(&form(
            "local_admins",
            &[("p_admins_allowed", " *\\Administrator \r\n\r\nCORP\\IT\n")],
        ))
        .unwrap();
        assert_eq!(
            i.params,
            json!({"allowed": ["*\\Administrator", "CORP\\IT"]})
        );
        let i = form_to_input(&form(
            "registry_value",
            &[
                ("p_reg_path", r"HKLM\X"),
                ("p_reg_op", "exists"),
                ("p_reg_expected", "ignored"),
            ],
        ))
        .unwrap();
        assert!(i.params.get("expected").is_none(), "{}", i.params);
        assert!(form_to_input(&form("defender", &[("p_df_days", "x")])).is_err());
    }

    #[test]
    fn params_roundtrip_to_form() {
        let f = params_to_form(
            "software_allowlist",
            &json!({"entries": [{"name": "Office", "publisher": "Microsoft*"}, {"publisher": "Adobe*"}]}),
        );
        assert_eq!(f.entries, "Office | Microsoft*\n | Adobe*");
        let f = params_to_form("os_build", &json!({"min_build": 19045}));
        assert_eq!((f.min_build.as_str(), f.build.as_str()), ("19045", ""));
        let f = params_to_form(
            "forbidden_software",
            &json!({"name": "x", "below_version": "2"}),
        );
        assert_eq!((f.name.as_str(), f.version.as_str()), ("x", "2"));
    }
}
