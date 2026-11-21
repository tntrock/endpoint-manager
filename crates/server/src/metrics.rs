//! Prometheus 格式的監控指標（`/metrics`，需要 `EM_METRICS_TOKEN`）。
//!
//! 只輸出統計數字，不含主機名稱、帳號等個別資料。文字格式自己輸出，不另外引入依賴。

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::AppState;

/// 權杖最短長度（`EM_METRICS_TOKEN`）
pub const MIN_TOKEN_LEN: usize = 32;
/// 資料庫指標的快取時間
const DB_CACHE: Duration = Duration::from_secs(15);
/// 處理時間 histogram 的上界（秒）
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];
/// 估計列數的資料表（固定清單）
const TABLES: [&str; 7] = [
    "audit_log",
    "command_runs",
    "command_targets",
    "inventory_changes",
    "violation_events",
    "device_software",
    "deployment_status",
];

#[derive(Default, Clone)]
struct RouteStats {
    /// 1xx..5xx
    codes: [u64; 5],
    /// 每個上界各自的計數（輸出時再累計）
    buckets: [u64; BUCKETS.len()],
    sum: f64,
    count: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RetentionKind {
    Commands,
    Audit,
}

impl RetentionKind {
    fn label(self) -> &'static str {
        match self {
            RetentionKind::Commands => "commands",
            RetentionKind::Audit => "audit",
        }
    }
}

#[derive(Default)]
pub struct Metrics {
    /// 權杖的 SHA-256；None 表示關閉 `/metrics`
    token_hash: Option<[u8; 32]>,
    http: Mutex<BTreeMap<(&'static str, String), RouteStats>>,
    retention_commands: AtomicU64,
    retention_audit: AtomicU64,
    /// 0 表示還沒成功過
    retention_last_success: AtomicI64,
    db_cache: tokio::sync::Mutex<Option<(Instant, String)>>,
}

impl Metrics {
    pub fn new(token: Option<&str>) -> Self {
        Self {
            token_hash: token.map(|t| Sha256::digest(t.as_bytes()).into()),
            ..Self::default()
        }
    }

    pub fn enabled(&self) -> bool {
        self.token_hash.is_some()
    }

    /// 沒開啟：404；缺少或錯誤的權杖：401。
    pub fn authorize(&self, headers: &HeaderMap) -> Result<(), StatusCode> {
        let Some(want) = &self.token_hash else {
            return Err(StatusCode::NOT_FOUND);
        };
        let got = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(StatusCode::UNAUTHORIZED)?;
        // 比對雜湊：長度固定，比較時間與權杖內容無關
        let got: [u8; 32] = Sha256::digest(got.trim().as_bytes()).into();
        if &got == want {
            Ok(())
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }

    pub fn observe(&self, listener: &'static str, route: &str, status: u16, secs: f64) {
        let mut http = self.http.lock().expect("metrics lock");
        let s = http.entry((listener, route.to_string())).or_default();
        let class = usize::from(status / 100).clamp(1, 5) - 1;
        s.codes[class] += 1;
        if let Some(i) = BUCKETS.iter().position(|b| secs <= *b) {
            s.buckets[i] += 1;
        }
        s.sum += secs;
        s.count += 1;
    }

    pub fn retention_deleted(&self, kind: RetentionKind, n: u64) {
        let c = match kind {
            RetentionKind::Commands => &self.retention_commands,
            RetentionKind::Audit => &self.retention_audit,
        };
        c.fetch_add(n, Ordering::Relaxed);
    }

    pub fn retention_succeeded(&self, at: time::OffsetDateTime) {
        self.retention_last_success
            .store(at.unix_timestamp(), Ordering::Relaxed);
    }

    /// 程序內的指標
    fn render_process(&self, out: &mut String, heartbeat_buffered: usize, pool: &PgPool) {
        gauge(
            out,
            "em_build_info",
            "Build information",
            &[(&[("version", env!("CARGO_PKG_VERSION"))], 1.0)],
        );

        let http = self.http.lock().expect("metrics lock").clone();
        header_line(
            out,
            "em_http_requests_total",
            "HTTP requests by listener, route template and status class",
            "counter",
        );
        for ((listener, route), s) in &http {
            for (i, n) in s.codes.iter().enumerate() {
                if *n > 0 {
                    let code = format!("{}xx", i + 1);
                    sample(
                        out,
                        "em_http_requests_total",
                        &[("listener", listener), ("route", route), ("code", &code)],
                        *n as f64,
                    );
                }
            }
        }
        header_line(
            out,
            "em_http_request_duration_seconds",
            "Time to produce a response",
            "histogram",
        );
        for ((listener, route), s) in &http {
            let mut cum = 0;
            for (b, n) in BUCKETS.iter().zip(s.buckets) {
                cum += n;
                let le = b.to_string();
                sample(
                    out,
                    "em_http_request_duration_seconds_bucket",
                    &[("listener", listener), ("route", route), ("le", &le)],
                    cum as f64,
                );
            }
            let labels = [("listener", *listener), ("route", route.as_str())];
            sample(
                out,
                "em_http_request_duration_seconds_bucket",
                &[labels[0], labels[1], ("le", "+Inf")],
                s.count as f64,
            );
            sample(out, "em_http_request_duration_seconds_sum", &labels, s.sum);
            sample(
                out,
                "em_http_request_duration_seconds_count",
                &labels,
                s.count as f64,
            );
        }

        gauge(
            out,
            "em_heartbeat_buffered",
            "Check-ins not yet written to the database",
            &[(&[], heartbeat_buffered as f64)],
        );
        let size = pool.size() as f64;
        let idle = pool.num_idle() as f64;
        gauge(
            out,
            "em_db_pool_connections",
            "Database pool connections",
            &[
                (&[("state", "idle")], idle),
                (&[("state", "used")], (size - idle).max(0.0)),
            ],
        );

        header_line(
            out,
            "em_retention_deleted_total",
            "Rows deleted by the retention job",
            "counter",
        );
        for kind in [RetentionKind::Commands, RetentionKind::Audit] {
            let n = match kind {
                RetentionKind::Commands => &self.retention_commands,
                RetentionKind::Audit => &self.retention_audit,
            };
            sample(
                out,
                "em_retention_deleted_total",
                &[("kind", kind.label())],
                n.load(Ordering::Relaxed) as f64,
            );
        }
        gauge(
            out,
            "em_retention_last_success_timestamp_seconds",
            "Unix time of the last successful retention run (0 = never)",
            &[(
                &[],
                self.retention_last_success.load(Ordering::Relaxed) as f64,
            )],
        );
    }

    /// 資料庫指標，快取 `DB_CACHE`；查詢失敗時回 None（不快取失敗）
    async fn db_section(&self, pool: &PgPool) -> Option<String> {
        let mut cache = self.db_cache.lock().await;
        if let Some((at, text)) = cache.as_ref()
            && at.elapsed() < DB_CACHE
        {
            return Some(text.clone());
        }
        match render_db(pool).await {
            Ok(text) => {
                *cache = Some((Instant::now(), text.clone()));
                Some(text)
            }
            Err(e) => {
                tracing::warn!(error = %e, "metrics database query failed");
                None
            }
        }
    }
}

/// 收集時的資料庫查詢
async fn render_db(pool: &PgPool) -> Result<String, sqlx::Error> {
    let mut out = String::new();
    let settings = crate::db::load_settings(pool).await?;
    let cutoff = time::OffsetDateTime::now_utc()
        - time::Duration::seconds(3 * i64::from(settings.checkin_interval_secs));

    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT os_family, status, count(*) FROM devices GROUP BY 1, 2 ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await?;
    labeled_gauge(
        &mut out,
        "em_devices",
        "Devices by OS family and status",
        rows.iter().map(|(os, st, n)| {
            (
                vec![("os_family", os.as_str()), ("status", st.as_str())],
                *n,
            )
        }),
    );

    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT os_family, count(*) FROM devices \
         WHERE status = 'active' AND last_seen_at >= $1 GROUP BY 1 ORDER BY 1",
    )
    .bind(cutoff)
    .fetch_all(pool)
    .await?;
    // 沒有在線裝置時也輸出 0，告警規則才有值可比
    let online = |os: &str| rows.iter().find(|(o, _)| o == os).map_or(0, |r| r.1);
    labeled_gauge(
        &mut out,
        "em_devices_online",
        "Active devices that checked in within three check-in intervals",
        ["windows", "linux"]
            .into_iter()
            .map(|os| (vec![("os_family", os)], online(os))),
    );

    let violating: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT v.device_id) FROM device_violations v \
         JOIN devices d ON d.id = v.device_id \
         WHERE d.status = 'active' AND v.status = 'violating'",
    )
    .fetch_one(pool)
    .await?;
    labeled_gauge(
        &mut out,
        "em_devices_violating",
        "Active devices with at least one compliance violation",
        [(vec![], violating)],
    );

    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, count(*) FROM command_targets \
         WHERE status IN ('pending', 'sent') GROUP BY 1",
    )
    .fetch_all(pool)
    .await?;
    let open = |s: &str| rows.iter().find(|(o, _)| o == s).map_or(0, |r| r.1);
    labeled_gauge(
        &mut out,
        "em_command_targets_open",
        "Remote command targets not finished yet",
        ["pending", "sent"]
            .into_iter()
            .map(|s| (vec![("status", s)], open(s))),
    );

    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT stage, count(*) FROM deployments GROUP BY 1 ORDER BY 1")
            .fetch_all(pool)
            .await?;
    labeled_gauge(
        &mut out,
        "em_deployments",
        "Deployments by stage",
        rows.iter().map(|(s, n)| (vec![("stage", s.as_str())], *n)),
    );

    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT status, count(*) FROM caches GROUP BY 1 ORDER BY 1")
            .fetch_all(pool)
            .await?;
    labeled_gauge(
        &mut out,
        "em_caches",
        "Branch caches by status",
        rows.iter().map(|(s, n)| (vec![("status", s.as_str())], *n)),
    );
    let stale: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM caches WHERE status = 'active' \
         AND (last_seen IS NULL OR last_seen < now() - interval '5 minutes')",
    )
    .fetch_one(pool)
    .await?;
    labeled_gauge(
        &mut out,
        "em_caches_stale",
        "Active caches that have not checked in for 5 minutes",
        [(vec![], stale)],
    );

    // 分割表（inventory_changes）加總各分割區；從未 ANALYZE 的表 reltuples 為 -1
    let rows: Vec<(String, f64)> = sqlx::query_as(
        "SELECT p.relname::text, sum(GREATEST(c.reltuples, 0))::float8 \
         FROM pg_class p \
         LEFT JOIN pg_inherits i ON i.inhparent = p.oid \
         JOIN pg_class c ON c.oid = COALESCE(i.inhrelid, p.oid) \
         WHERE p.relname = ANY($1) AND p.relkind IN ('r', 'p') AND pg_table_is_visible(p.oid) \
         GROUP BY 1 ORDER BY 1",
    )
    .bind(TABLES.as_slice())
    .fetch_all(pool)
    .await?;
    header_line(
        &mut out,
        "em_table_rows_estimate",
        "Estimated rows of the largest tables (planner statistics)",
        "gauge",
    );
    for (t, n) in &rows {
        sample(&mut out, "em_table_rows_estimate", &[("table", t)], *n);
    }

    let size: i64 = sqlx::query_scalar("SELECT pg_database_size(current_database())")
        .fetch_one(pool)
        .await?;
    labeled_gauge(
        &mut out,
        "em_database_size_bytes",
        "Size of the database",
        [(vec![], size)],
    );
    Ok(out)
}

pub async fn handler(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(code) = st.metrics.authorize(&headers) {
        return code.into_response();
    }
    let mut out = String::new();
    let db = st.metrics.db_section(&st.pool).await;
    gauge(
        &mut out,
        "em_metrics_db_up",
        "Whether the database queries for this scrape succeeded",
        &[(&[], if db.is_some() { 1.0 } else { 0.0 })],
    );
    if let Some(db) = db {
        out.push_str(&db);
    }
    st.metrics
        .render_process(&mut out, st.heartbeat.len(), &st.pool);
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
        .into_response()
}

/// 計數與計時的中介層（`route_layer`：只有對到路由的請求才有 `MatchedPath`）
pub async fn track(
    State((metrics, listener)): State<(Arc<Metrics>, &'static str)>,
    req: Request,
    next: Next,
) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string());
    let start = Instant::now();
    let res = next.run(req).await;
    if let Some(route) = route {
        metrics.observe(
            listener,
            &route,
            res.status().as_u16(),
            start.elapsed().as_secs_f64(),
        );
    }
    res
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn header_line(out: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

fn sample(out: &mut String, name: &str, labels: &[(&str, &str)], v: f64) {
    out.push_str(name);
    if !labels.is_empty() {
        out.push('{');
        for (i, (k, val)) in labels.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            let _ = write!(out, "{k}=\"{}\"", escape(val));
        }
        out.push('}');
    }
    let _ = writeln!(out, " {v}");
}

fn gauge(out: &mut String, name: &str, help: &str, samples: &[(&[(&str, &str)], f64)]) {
    header_line(out, name, help, "gauge");
    for (labels, v) in samples {
        sample(out, name, labels, *v);
    }
}

fn labeled_gauge<'a>(
    out: &mut String,
    name: &str,
    help: &str,
    samples: impl IntoIterator<Item = (Vec<(&'a str, &'a str)>, i64)>,
) {
    header_line(out, name, help, "gauge");
    for (labels, v) in samples {
        sample(out, name, &labels, v as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn bearer(t: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {t}")).unwrap(),
        );
        h
    }

    #[test]
    fn authorize() {
        let off = Metrics::new(None);
        assert_eq!(off.authorize(&bearer("x")), Err(StatusCode::NOT_FOUND));
        let m = Metrics::new(Some("a-very-long-metrics-token-0123456789"));
        assert!(
            m.authorize(&bearer("a-very-long-metrics-token-0123456789"))
                .is_ok()
        );
        assert_eq!(m.authorize(&bearer("wrong")), Err(StatusCode::UNAUTHORIZED));
        assert_eq!(
            m.authorize(&HeaderMap::new()),
            Err(StatusCode::UNAUTHORIZED)
        );
        let mut basic = HeaderMap::new();
        basic.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic eDp5"),
        );
        assert_eq!(m.authorize(&basic), Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn label_escaping() {
        let mut out = String::new();
        sample(&mut out, "m", &[("a", "x\"y\\z\nw")], 2.0);
        assert_eq!(out, "m{a=\"x\\\"y\\\\z\\nw\"} 2\n");
        let mut out = String::new();
        sample(&mut out, "m", &[], 0.5);
        assert_eq!(out, "m 0.5\n");
    }

    #[tokio::test]
    async fn histogram_is_cumulative() {
        let m = Metrics::new(Some("t"));
        m.observe("agent", "/v1/checkin", 200, 0.003);
        m.observe("agent", "/v1/checkin", 200, 0.2);
        m.observe("agent", "/v1/checkin", 503, 30.0);
        let mut out = String::new();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/none")
            .unwrap();
        m.render_process(&mut out, 4, &pool);
        let has = |line: &str| assert!(out.lines().any(|l| l == line), "missing {line}\n{out}");
        has(r#"em_http_requests_total{listener="agent",route="/v1/checkin",code="2xx"} 2"#);
        has(r#"em_http_requests_total{listener="agent",route="/v1/checkin",code="5xx"} 1"#);
        has(
            r#"em_http_request_duration_seconds_bucket{listener="agent",route="/v1/checkin",le="0.005"} 1"#,
        );
        has(
            r#"em_http_request_duration_seconds_bucket{listener="agent",route="/v1/checkin",le="0.1"} 1"#,
        );
        has(
            r#"em_http_request_duration_seconds_bucket{listener="agent",route="/v1/checkin",le="0.25"} 2"#,
        );
        has(
            r#"em_http_request_duration_seconds_bucket{listener="agent",route="/v1/checkin",le="10"} 2"#,
        );
        has(
            r#"em_http_request_duration_seconds_bucket{listener="agent",route="/v1/checkin",le="+Inf"} 3"#,
        );
        has(r#"em_http_request_duration_seconds_count{listener="agent",route="/v1/checkin"} 3"#);
        has("em_heartbeat_buffered 4");
        has(r#"em_retention_deleted_total{kind="commands"} 0"#);
        has(&format!(
            r#"em_build_info{{version="{}"}} 1"#,
            env!("CARGO_PKG_VERSION")
        ));
    }
}
