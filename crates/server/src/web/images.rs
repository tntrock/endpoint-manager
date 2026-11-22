//! 「容器映像」頁 `/containers`：全公司的主機上跑了哪些映像（容器規格 §5.3）。
//!
//! 容器存在 `device_containers.data`（jsonb），這裡用 `jsonb_array_elements` 展開。
//! 映像以「倉庫與名稱」分組（去掉版本標籤與 digest）。

use askama::Template;
use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;
use uuid::Uuid;

use super::auth::{AdminSession, Nav};
use super::devices::{SelectOption, group_options};
use super::sort::{self, Column, Sort};
use super::{enc, escape_like, fmt_time, render};
use crate::AppState;
use crate::error::AppError;

/// 清單最多列幾個映像
const LIMIT: i64 = 500;
/// 每個映像最多列幾個版本標籤
const MAX_TAGS: usize = 5;
/// 明細最多列幾個容器
const DETAIL_LIMIT: i64 = 2000;

/// 範圍內每個容器一列：主機、執行環境、映像（倉庫與名稱、標籤）、狀態。
/// $1 全部裝置、$2 範圍內的群組、$3 群組篩選（NULL＝全部、-1＝未分組）、$4 執行環境（空白＝全部）
const ROWS: &str = "WITH c AS ( \
       SELECT d.id, d.hostname, x->>'runtime' AS runtime, x->>'name' AS name, \
              coalesce(x->>'image', '') AS image, x->>'state' AS state, \
              (x->>'started_at')::timestamptz AS started, \
              CASE WHEN x->'k8s' IS NOT NULL \
                   THEN (x->'k8s'->>'namespace') || '／' || (x->'k8s'->>'pod') END AS pod \
       FROM device_containers dc \
       JOIN devices d ON d.id = dc.device_id AND d.status NOT IN ('retired', 'pending_approval') \
       CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(dc.data->'containers') = 'array' \
                                                    THEN dc.data->'containers' ELSE '[]' END) x \
       WHERE ($1::bool OR d.group_id = ANY($2::bigint[])) \
         AND ($3::bigint IS NULL OR d.group_id = $3 OR ($3 = -1 AND d.group_id IS NULL)) \
         AND ($4 = '' OR x->>'runtime' = $4)), \
     r AS ( \
       SELECT *, regexp_replace(split_part(image, '@', 1), ':[^/:]*$', '') AS repo, \
              CASE WHEN image LIKE '%@%' THEN '@' || left(split_part(image, '@', 2), 19) \
                   ELSE coalesce(substring(split_part(image, '@', 1) from ':([^/:]*)$'), '') END AS tag, \
              state IN ('running', 'paused', 'restarting') AS running \
       FROM c)";

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    q: String,
    #[serde(default)]
    runtime: String,
    #[serde(default)]
    group: String,
    /// 只看執行中
    #[serde(default)]
    running: bool,
}

/// 執行環境篩選值
fn runtime_filter(r: &str) -> &'static str {
    match r {
        "docker" => "docker",
        "podman" => "podman",
        "containerd" => "containerd",
        "incus" => "incus",
        "lxc" => "lxc",
        _ => "",
    }
}

pub struct ImageRow {
    pub repo: String,
    pub tags: Vec<String>,
    /// 沒列出的標籤數
    pub more_tags: i64,
    pub hosts: i64,
    pub running: i64,
    pub url: String,
}

#[derive(Template)]
#[template(path = "images.html")]
struct ImagesPage {
    nav: Nav,
    q: String,
    running_only: bool,
    runtimes: Vec<SelectOption>,
    groups: Vec<SelectOption>,
    rows: Vec<ImageRow>,
    truncated: bool,
}

fn runtime_options(current: &str) -> Vec<SelectOption> {
    [
        ("", "所有執行環境"),
        ("docker", "Docker"),
        ("podman", "Podman"),
        ("containerd", "containerd"),
        ("incus", "Incus"),
        ("lxc", "LXD"),
    ]
    .into_iter()
    .map(|(v, l)| SelectOption {
        value: v.into(),
        label: l.into(),
        selected: current == v,
    })
    .collect()
}

/// 標籤清單：空白的（沒有指定標籤，例如系統容器的映像說明）顯示成「—」
fn tag_label(t: &str) -> String {
    if t.is_empty() {
        "—".into()
    } else {
        t.to_string()
    }
}

type ImageDbRow = (String, Vec<String>, i64, i64, i64);

pub async fn list(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<ListQuery>,
) -> Result<Response, AppError> {
    let runtime = runtime_filter(&q.runtime);
    let group: Option<i64> = if q.group == "none" {
        Some(-1)
    } else {
        q.group.parse().ok()
    };
    let mut rows: Vec<ImageDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{ROWS} \
         SELECT repo, (array_agg(DISTINCT tag ORDER BY tag))[1:{MAX_TAGS}], \
                count(DISTINCT tag), count(DISTINCT id), count(*) FILTER (WHERE running) \
         FROM r WHERE ($5 = '' OR repo ILIKE $6) AND (NOT $7 OR running) \
         GROUP BY repo ORDER BY count(DISTINCT id) DESC, repo LIMIT $8"
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(group)
    .bind(runtime)
    .bind(q.q.trim())
    .bind(escape_like(q.q.trim()))
    .bind(q.running)
    .bind(LIMIT + 1)
    .fetch_all(&st.pool)
    .await?;
    let truncated = rows.len() as i64 > LIMIT;
    rows.truncate(LIMIT as usize);
    Ok(render(&ImagesPage {
        nav: Nav::new(&s, "images"),
        runtimes: runtime_options(runtime),
        groups: group_options(&st, &s, &q.group, true).await?,
        rows: rows
            .into_iter()
            .map(|(repo, tags, tag_count, hosts, running)| ImageRow {
                url: format!("/containers/image?repo={}", enc(&repo)),
                more_tags: tag_count - tags.len() as i64,
                tags: tags.iter().map(|t| tag_label(t)).collect(),
                repo: if repo.is_empty() {
                    "（未知）".into()
                } else {
                    repo
                },
                hosts,
                running,
            })
            .collect(),
        q: q.q,
        running_only: q.running,
        truncated,
    }))
}

#[derive(Deserialize)]
pub struct DetailQuery {
    #[serde(default)]
    repo: String,
    #[serde(default)]
    sort: String,
}

/// 明細的欄位（排序白名單）
const DETAIL_COLS: [Column; 6] = [
    Column::new("host", "主機", "r.hostname"),
    Column::new("name", "容器", "r.name"),
    Column::new("tag", "版本標籤", "r.tag"),
    Column::new("runtime", "執行環境", "r.runtime"),
    Column::new("state", "狀態", "r.running"),
    Column::new("started", "啟動時間", "r.started").desc_first(),
];

pub struct DetailRow {
    pub device: Uuid,
    pub hostname: String,
    pub name: String,
    pub pod: String,
    pub tag: String,
    pub runtime: &'static str,
    pub state: &'static str,
    pub state_tone: &'static str,
    pub started: String,
}

#[derive(Template)]
#[template(path = "image_detail.html")]
struct DetailPage {
    nav: Nav,
    repo: String,
    headers: Vec<sort::Header>,
    rows: Vec<DetailRow>,
    hosts: usize,
    truncated: bool,
}

type DetailDbRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<time::OffsetDateTime>,
);

pub async fn detail(
    State(st): State<AppState>,
    AdminSession(s): AdminSession,
    Query(q): Query<DetailQuery>,
) -> Result<Response, AppError> {
    let sort = Sort::parse(&q.sort, &DETAIL_COLS, ("host", false));
    let mut rows: Vec<DetailDbRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "{ROWS} \
         SELECT r.id, r.hostname, r.name, r.pod, r.tag, r.runtime, r.state, r.started \
         FROM r WHERE r.repo = $5 ORDER BY {}, r.hostname, r.name LIMIT $6",
        sort.order_by(&DETAIL_COLS)
    )))
    .bind(s.all_devices())
    .bind(&s.groups)
    .bind(None::<i64>)
    .bind("")
    .bind(&q.repo)
    .bind(DETAIL_LIMIT + 1)
    .fetch_all(&st.pool)
    .await?;
    let truncated = rows.len() as i64 > DETAIL_LIMIT;
    rows.truncate(DETAIL_LIMIT as usize);
    let hosts = rows
        .iter()
        .map(|r| r.0)
        .collect::<std::collections::HashSet<_>>()
        .len();
    let repo = q.repo.clone();
    Ok(render(&DetailPage {
        nav: Nav::new(&s, "images"),
        headers: sort::headers(&DETAIL_COLS, sort, |p| {
            format!("/containers/image?repo={}&sort={p}", enc(&repo))
        }),
        rows: rows
            .into_iter()
            .map(
                |(device, hostname, name, pod, tag, runtime, state, started)| {
                    let (state, state_tone) =
                        super::containers::state_label(state.as_deref().unwrap_or(""));
                    DetailRow {
                        device,
                        hostname,
                        name: name.unwrap_or_default(),
                        pod: pod.unwrap_or_default(),
                        tag: tag_label(&tag),
                        runtime: super::containers::runtime_label(runtime.as_deref().unwrap_or("")),
                        state,
                        state_tone,
                        started: fmt_time(&st, started),
                    }
                },
            )
            .collect(),
        hosts,
        repo: q.repo,
        truncated,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_and_labels() {
        assert_eq!(runtime_filter("containerd"), "containerd");
        assert_eq!(runtime_filter("lxc"), "lxc");
        assert_eq!(runtime_filter("x' OR 1=1"), "");
        assert_eq!(tag_label(""), "—");
        assert_eq!(tag_label("1.27"), "1.27");
        assert!(
            runtime_options("incus")
                .iter()
                .any(|o| o.selected && o.value == "incus")
        );
    }
}
