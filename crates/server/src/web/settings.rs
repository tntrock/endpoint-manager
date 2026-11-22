//! 「報到與收集」設定頁（平台管理員）：報到間隔與各區段的收集間隔（網路規格 §7）。

use askama::Template;
use axum::extract::{Query, RawForm, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use super::auth::{AdminSession, Nav, Session, check_csrf, platform};
use super::{forbidden, render};
use crate::AppState;
use crate::db::{INTERVALS, MAX_INTERVAL_SECS, load_settings, save_intervals};
use crate::error::AppError;

pub struct Field {
    pub key: &'static str,
    pub label: &'static str,
    /// 表單上的值（報到以秒、收集以分鐘；驗證失敗時是使用者輸入的原值）
    pub value: String,
    pub unit: &'static str,
    pub min: u32,
    pub max: u32,
    pub default: String,
    /// 依目前的值估算的負載
    pub estimate: String,
}

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    nav: Nav,
    fields: Vec<Field>,
    error: Option<String>,
    saved: bool,
}

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    saved: bool,
}

/// 報到以秒填，收集以分鐘填（收集下限 5 分鐘、上限 7 天，用秒不好填）
fn unit_secs(i: usize) -> u32 {
    if i == 0 { 1 } else { 60 }
}

/// 千分位
pub fn group_digits(n: i64) -> String {
    let s = n.unsigned_abs().to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if n < 0 { format!("-{out}") } else { out }
}

/// 估算：報到是全部裝置每秒幾次；收集是每台每天幾次（內容沒變就不上傳）
pub fn estimate(i: usize, secs: u32, devices: i64) -> String {
    if secs == 0 {
        return String::new();
    }
    if i == 0 {
        let per_sec = devices as f64 / f64::from(secs);
        let rate = if per_sec >= 10.0 {
            format!("{per_sec:.0}")
        } else {
            format!("{per_sec:.1}")
        };
        format!(
            "目前 {} 台，約每秒 {rate} 次報到；超過 {}沒報到算離線",
            group_digits(devices),
            crate::network::duration_label(time::Duration::seconds(3 * i64::from(secs)))
        )
    } else {
        let per_day = 86_400.0 / f64::from(secs);
        if per_day >= 1.0 {
            format!("每台每天約收集 {per_day:.0} 次")
        } else {
            format!("每台約每 {:.0} 天收集 1 次", 1.0 / per_day)
        }
    }
}

fn fields(values: &[String; 7], devices: i64) -> Vec<Field> {
    INTERVALS
        .iter()
        .enumerate()
        .map(|(i, (key, label, default, min))| {
            let u = unit_secs(i);
            Field {
                key,
                label,
                value: values[i].clone(),
                unit: if u == 1 { "秒" } else { "分鐘" },
                min: min / u,
                max: MAX_INTERVAL_SECS / u,
                default: crate::network::duration_label(time::Duration::seconds((*default).into())),
                estimate: values[i]
                    .parse::<u32>()
                    .map(|v| estimate(i, v.saturating_mul(u), devices))
                    .unwrap_or_default(),
            }
        })
        .collect()
}

async fn devices(st: &AppState) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM devices WHERE status = 'active'")
        .fetch_one(&st.pool)
        .await
}

pub async fn page(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<PageQuery>,
) -> Result<Response, AppError> {
    if !s.all_devices() {
        return Ok(forbidden());
    }
    let current = load_settings(&st.pool).await?.values();
    let values: [String; 7] = std::array::from_fn(|i| (current[i] / unit_secs(i)).to_string());
    Ok(render(&build(&st, &s, &values, None, q.saved).await?))
}

async fn build(
    st: &AppState,
    s: &Session,
    values: &[String; 7],
    error: Option<String>,
    saved: bool,
) -> Result<SettingsPage, AppError> {
    let n = devices(st).await?;
    Ok(SettingsPage {
        nav: Nav::new(s, "settings"),
        fields: fields(values, n),
        error,
        saved,
    })
}

/// 表單的值轉成秒；格式錯誤回給使用者看的訊息
pub fn parse_values(values: &[String; 7]) -> Result<[u32; 7], String> {
    let mut out = [0u32; 7];
    for (i, v) in values.iter().enumerate() {
        let n: u32 = v
            .trim()
            .parse()
            .map_err(|_| format!("{}的間隔必須是正整數", INTERVALS[i].1))?;
        out[i] = n.saturating_mul(unit_secs(i));
    }
    crate::db::validate_intervals(&out)?;
    Ok(out)
}

pub async fn save(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    RawForm(raw): RawForm,
) -> Result<Response, Response> {
    let mut csrf = String::new();
    let mut values: [String; 7] = Default::default();
    for (k, v) in form_urlencoded::parse(&raw) {
        if k == "csrf" {
            csrf = v.into_owned();
        } else if let Some(i) = INTERVALS.iter().position(|f| f.0 == k) {
            values[i] = v.trim().to_string();
        }
    }
    check_csrf(&s, &csrf)?;
    platform(&s)?;
    let secs = match parse_values(&values) {
        Ok(v) => v,
        Err(e) => {
            let page = build(&st, &s, &values, Some(e), false)
                .await
                .map_err(IntoResponse::into_response)?;
            return Err((StatusCode::UNPROCESSABLE_ENTITY, render(&page)).into_response());
        }
    };
    save_intervals(&st.pool, secs, &super::commands::actor(&s))
        .await
        .map_err(|e| {
            tracing::error!(error = %format!("{e:#}"), "saving intervals failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "伺服器錯誤，請稍後再試").into_response()
        })?;
    Ok(Redirect::to("/settings?saved=true").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digits_and_estimates() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1200), "1,200");
        assert_eq!(group_digits(1_234_567), "1,234,567");
        assert_eq!(group_digits(-1200), "-1,200");
        assert_eq!(
            estimate(0, 60, 1200),
            "目前 1,200 台，約每秒 20 次報到；超過 3 分鐘沒報到算離線"
        );
        assert!(estimate(0, 60, 30).contains("每秒 0.5 次"));
        assert_eq!(estimate(1, 3600, 5), "每台每天約收集 24 次");
        assert_eq!(estimate(1, 7 * 86_400, 5), "每台約每 7 天收集 1 次");
        assert_eq!(estimate(1, 0, 5), "");
    }

    #[test]
    fn form_values_use_minutes_for_collection() {
        let v = |a: [&str; 7]| a.map(String::from);
        assert_eq!(
            parse_values(&v(["60", "60", "60", "60", "1440", "60", "60"])),
            Ok([60, 3600, 3600, 3600, 86_400, 3600, 3600])
        );
        assert!(
            parse_values(&v(["x", "60", "60", "60", "60", "60", "60"]))
                .unwrap_err()
                .contains("正整數")
        );
        assert!(
            parse_values(&v(["60", "4", "60", "60", "60", "60", "60"]))
                .unwrap_err()
                .starts_with("軟體")
        );
    }
}
