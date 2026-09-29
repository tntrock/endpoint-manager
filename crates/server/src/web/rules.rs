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
    })
}

/// 資料庫裡的參數回填到表單欄位（編輯用）。
pub fn params_to_form(kind: &str, v: &Value) -> ParamFields {
    let s = |k: &str| match &v[k] {
        Value::String(x) => x.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    ParamFields {
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

type RuleListRow = (
    i64,
    String,
    String,
    String,
    bool,
    Option<String>,
    Option<String>,
    i64,
    i64,
    i64,
);

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
) -> Result<Response, AppError> {
    // 數字依管理員的群組範圍計算
    let rows: Vec<RuleListRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.kind, r.severity, r.enabled, \
           (SELECT string_agg(g.name, '、' ORDER BY g.name) FROM compliance_rule_groups rg \
              JOIN device_groups g ON g.id = rg.group_id \
              WHERE rg.rule_id = r.id AND rg.mode = 'include'), \
           (SELECT string_agg(g.name, '、' ORDER BY g.name) FROM compliance_rule_groups rg \
              JOIN device_groups g ON g.id = rg.group_id \
              WHERE rg.rule_id = r.id AND rg.mode = 'exclude'), \
           count(v.rule_id) FILTER (WHERE v.status = 'violating'), \
           count(v.rule_id) FILTER (WHERE v.status = 'unknown'), \
           count(v.rule_id) FILTER (WHERE v.status = 'exempt') \
         FROM compliance_rules r \
         LEFT JOIN device_violations v ON v.rule_id = r.id AND EXISTS ( \
              SELECT 1 FROM devices d WHERE d.id = v.device_id \
              AND ($1::bool OR d.group_id = ANY($2::bigint[]))) \
         GROUP BY r.id ORDER BY r.name, r.id",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_all(&st.pool)
    .await?;
    let rows = rows
        .into_iter()
        .map(
            |(id, name, kind, severity, enabled, include, exclude, violating, unknown, exempt)| {
                let sev = Severity::parse(&severity).unwrap_or(Severity::Medium);
                let mut scope = include
                    .map(|g| format!("只套用：{g}"))
                    .unwrap_or_else(|| "全部裝置".into());
                if let Some(ex) = exclude {
                    scope.push_str(&format!("；排除：{ex}"));
                }
                RuleRow {
                    id,
                    name,
                    kind: kind_label(&kind),
                    severity: sev.label(),
                    severity_class: sev.as_str(),
                    enabled,
                    scope,
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
}

async fn group_checks(st: &AppState, selected: &[i64]) -> Result<Vec<SelectOption>, sqlx::Error> {
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
    let input = form_to_input(&f).map_err(conflict)?;
    admin::create_rule(&st.pool, &input, &s.username)
        .await
        .map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/rules").into_response())
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
    let input = form_to_input(&f).map_err(conflict)?;
    admin::update_rule(&st.pool, id, &input, &s.username)
        .await
        .map_err(|e| conflict(format!("{e:#}")))?;
    Ok(Redirect::to("/compliance/rules").into_response())
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
