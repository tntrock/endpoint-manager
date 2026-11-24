//! 竄改偵測的「發現」（竄改偵測規格 §2）：事件序號缺口、日誌重建（§6），
//! Agent 被停止、強制結束、停用與作業系統紀錄被清除（§4.4），網路端交叉比對（§5）。
//!
//! 各層偵測到的結果都存進 `device_findings`，後台用同一套方式顯示與確認。

use protocol::{
    AgentEvent, AgentStarted, AgentStopping, OsLogCleared, OsServiceStopped, ServiceConfigChange,
    start_type, stop_reason,
};
use serde_json::{Value, json};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

/// 事件序號不連續，Agent 沒有說明原因
pub const JOURNAL_GAP: &str = "journal_gap";
/// 30 天內事件日誌重建多次
pub const JOURNAL_REBUILT: &str = "journal_rebuilt";

/// Agent 服務被停止（有人停止，不是關機或升級）
pub const AGENT_STOPPED: &str = "agent_stopped";
/// Agent 被強制結束或非正常結束
pub const AGENT_KILLED: &str = "agent_killed";
/// Agent 服務被改成停用或手動
pub const AGENT_DISABLED: &str = "agent_disabled";
/// 作業系統紀錄被清除
pub const LOG_CLEARED: &str = "log_cleared";

/// Agent 啟動與停止相關的事件種類（「完整性」分頁列出）
pub const LIFECYCLE_KINDS: [&str; 5] = [
    AgentEvent::AGENT_STARTED,
    AgentEvent::AGENT_STOPPING,
    AgentEvent::AGENT_SERVICE_CONFIG,
    AgentEvent::OS_SERVICE_STOPPED,
    AgentEvent::OS_LOG_CLEARED,
];

/// 同一次強制結束可能同時有「沒有正常結束標記」與作業系統紀錄：這段時間內只記一筆
pub const KILL_DEDUP: time::Duration = time::Duration::minutes(10);

/// 30 天內重建幾次（第一份日誌不算）就標示
pub const REBUILD_THRESHOLD: i64 = 3;

/// 種類的顯示名稱
pub fn label(kind: &str) -> &str {
    match kind {
        JOURNAL_GAP => "事件序號不連續",
        JOURNAL_REBUILT => "事件日誌一再重建",
        "agent_stopped" => "Agent 服務被停止",
        "agent_killed" => "Agent 被強制結束",
        "agent_disabled" => "Agent 服務被停用",
        "log_cleared" => "系統紀錄被清除",
        "silent_on_network" => "Agent 沒報到但電腦在網路上",
        "ip_conflict" => "IP 被其他設備使用",
        "mac_duplicate" => "MAC 同時出現在兩個埠",
        other => other,
    }
}

/// 可能的正常原因（裝置頁與說明顯示）
pub fn hint(kind: &str) -> &'static str {
    match kind {
        JOURNAL_GAP => {
            "有人刪除了本機事件日誌裡的事件。舊版 Agent 寫到一半斷電時略過壞掉的紀錄，也會出現這種缺口"
        }
        JOURNAL_REBUILT => "本機事件日誌被刪除或損毀後會重建。重新安裝 Agent 也會",
        AGENT_STOPPED => "IT 人員維護時可能會停止服務。升級、關機與重新開機不會出現這項",
        AGENT_KILLED => "Agent 當機也會出現這項。斷電與重新開機不算",
        AGENT_DISABLED => "除非 IT 刻意設定，Agent 服務應該是自動啟動",
        LOG_CLEARED => "清除紀錄常被用來掩蓋其他操作。確認是誰、為什麼清除",
        "silent_on_network" => {
            "Agent 可能被停掉或移除了。電腦睡眠時有些網卡仍會送少量封包（例如 Windows 的新式待命），也會出現這項"
        }
        "ip_conflict" => {
            "有人設定了相同的靜態 IP，或 Agent 回報的 IP 不實。路由器的 ARP 表還沒更新時也可能短暫出現"
        }
        "mac_duplicate" => {
            "可能有其他設備複製了這台電腦的 MAC（例如想通過以 MAC 認證的網路）。筆電換位置時舊的埠只會短暫重疊"
        }
        _ => "",
    }
}

fn num(detail: &Value, key: &str) -> i64 {
    detail.get(key).and_then(Value::as_i64).unwrap_or(0)
}

/// 一筆發現的說明
pub fn describe(kind: &str, detail: &Value) -> String {
    match kind {
        JOURNAL_GAP => {
            let (from, to) = (num(detail, "from_seq"), num(detail, "to_seq"));
            let range = if from == to {
                format!("序號 {from}")
            } else {
                format!("序號 {from}–{to}")
            };
            format!(
                "缺 {} 筆（{range}），Agent 沒有說明原因",
                num(detail, "unexplained")
            )
        }
        JOURNAL_REBUILT => format!("30 天內重建 {} 次", num(detail, "count")),
        AGENT_STOPPED => "有人停止了 Agent 服務".into(),
        AGENT_KILLED => match detail.get("event_id").and_then(Value::as_i64) {
            Some(id) => format!("作業系統紀錄 {id}：Agent 服務意外終止{}", by(detail)),
            None if str_of(detail, "source") == "journald" => {
                format!("systemd 紀錄：{}", str_of(detail, "message"))
            }
            None => "上次沒有正常結束，期間也沒有重新開機".into(),
        },
        AGENT_DISABLED => format!(
            "啟動類型改成「{}」{}",
            start_type_label(str_of(detail, "to")),
            match detail.get("from").and_then(Value::as_str) {
                Some(f) => format!("（原本「{}」）", start_type_label(f)),
                None => String::new(),
            }
        ),
        LOG_CLEARED => format!(
            "{}紀錄被清除{}",
            log_label(str_of(detail, "log")),
            by(detail)
        ),
        "silent_on_network" => format!(
            "Agent 沒有報到，但 {} 的 {} 一直看得到這台電腦（{}）",
            str_of(detail, "net_device"),
            str_of(detail, "port"),
            str_of(detail, "mac")
        ),
        "ip_conflict" => format!(
            "這台回報的 IP {}，在 {} 的 ARP 表對到別的 MAC {}",
            str_of(detail, "ip"),
            str_of(detail, "net_device"),
            str_of(detail, "mac")
        ),
        "mac_duplicate" => {
            let ports: Vec<&str> = detail
                .get("ports")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect())
                .unwrap_or_default();
            format!(
                "MAC {} 同時出現在 {} 的 {}",
                str_of(detail, "mac"),
                str_of(detail, "net_device"),
                ports.join("、")
            )
        }
        _ => String::new(),
    }
}

fn str_of<'a>(detail: &'a Value, key: &str) -> &'a str {
    detail.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// 「（使用者 X）」，沒有使用者時是空字串
fn by(detail: &Value) -> String {
    match detail.get("user").and_then(Value::as_str) {
        Some(u) if !u.is_empty() => format!("（使用者 {u}）"),
        _ => String::new(),
    }
}

fn start_type_label(t: &str) -> &str {
    match t {
        start_type::AUTO => "自動",
        start_type::MANUAL => "手動",
        start_type::DISABLED => "停用",
        other => other,
    }
}

fn log_label(log: &str) -> &str {
    match log {
        "Security" => "安全性",
        "System" => "系統",
        "Application" => "應用程式",
        "Setup" => "安裝",
        other => other,
    }
}

fn stop_reason_label(r: &str) -> &str {
    match r {
        stop_reason::SERVICE_STOP => "有人停止服務",
        stop_reason::SHUTDOWN => "關機或重新開機",
        stop_reason::UPGRADE => "安裝程式（升級、修復或移除）",
        stop_reason::RECONFIGURE => "重新設定",
        stop_reason::CERTIFICATE => "伺服器拒絕憑證",
        other => other,
    }
}

/// Agent 啟動與停止相關事件的說明（「完整性」分頁、時間軸）
pub fn lifecycle_text(kind: &str, data: &Value) -> Option<String> {
    Some(match kind {
        AgentEvent::AGENT_STARTED => {
            let s: AgentStarted = serde_json::from_value(data.clone()).ok()?;
            if s.clean {
                format!("Agent 啟動（版本 {}）", s.version)
            } else {
                format!("Agent 啟動（版本 {}），上次沒有正常結束", s.version)
            }
        }
        AgentEvent::AGENT_STOPPING => {
            let s: AgentStopping = serde_json::from_value(data.clone()).ok()?;
            format!("Agent 停止：{}", stop_reason_label(&s.reason))
        }
        AgentEvent::AGENT_SERVICE_CONFIG => {
            let c: ServiceConfigChange = serde_json::from_value(data.clone()).ok()?;
            match c.from {
                Some(f) => format!(
                    "Agent 服務啟動類型：{} → {}",
                    start_type_label(&f),
                    start_type_label(&c.to)
                ),
                None => format!("Agent 服務啟動類型：{}", start_type_label(&c.to)),
            }
        }
        AgentEvent::OS_SERVICE_STOPPED => {
            let s: OsServiceStopped = serde_json::from_value(data.clone()).ok()?;
            let what = if s.killed { "意外終止" } else { "停止" };
            let id = s.event_id.map(|i| format!(" {i}")).unwrap_or_default();
            let user = s
                .user
                .map(|u| format!("（使用者 {u}）"))
                .unwrap_or_default();
            format!("作業系統紀錄{id}：Agent 服務{what}{user}")
        }
        AgentEvent::OS_LOG_CLEARED => {
            let c: OsLogCleared = serde_json::from_value(data.clone()).ok()?;
            let user = c
                .user
                .map(|u| format!("（使用者 {u}）"))
                .unwrap_or_default();
            format!("{}紀錄被清除{user}", log_label(&c.log))
        }
        _ => return None,
    })
}

/// 值得放進時間軸的啟動與停止事件：正常的啟動、關機、升級不放，免得每次開機都多兩筆
pub fn lifecycle_notable(kind: &str, data: &Value) -> bool {
    match kind {
        AgentEvent::AGENT_STARTED => data.get("clean").and_then(Value::as_bool) == Some(false),
        AgentEvent::AGENT_STOPPING => str_of(data, "reason") == stop_reason::SERVICE_STOP,
        AgentEvent::AGENT_SERVICE_CONFIG
        | AgentEvent::OS_SERVICE_STOPPED
        | AgentEvent::OS_LOG_CLEARED => true,
        _ => false,
    }
}

/// 一筆事件判定出的發現
#[derive(Debug, PartialEq)]
pub struct Judged {
    pub kind: &'static str,
    pub severity: &'static str,
    pub started_at: OffsetDateTime,
    pub detail: Value,
}

/// 依 Agent 的啟動與停止事件判定發現（規格 §4.4）。`at` 是事件時間
pub fn judge(kind: &str, data: &Value, at: OffsetDateTime) -> Option<Judged> {
    match kind {
        AgentEvent::AGENT_STOPPING => {
            let s: AgentStopping = serde_json::from_value(data.clone()).ok()?;
            (s.reason == stop_reason::SERVICE_STOP).then(|| Judged {
                kind: AGENT_STOPPED,
                severity: "medium",
                started_at: at,
                detail: json!({"reason": s.reason}),
            })
        }
        AgentEvent::AGENT_STARTED => {
            let s: AgentStarted = serde_json::from_value(data.clone()).ok()?;
            if s.clean {
                return None;
            }
            // 開機時間晚於最後活著的時間：中間重開機或斷電，不算被強制結束
            if let (Some(boot), Some(alive)) = (s.boot_time, s.last_alive)
                && boot > alive
            {
                return None;
            }
            Some(Judged {
                kind: AGENT_KILLED,
                severity: "high",
                started_at: s.last_alive.unwrap_or(at).min(at),
                detail: json!({"source": "marker", "restarted_at": protocol::timefmt::format_rfc3339(at).ok()}),
            })
        }
        AgentEvent::OS_SERVICE_STOPPED => {
            let s: OsServiceStopped = serde_json::from_value(data.clone()).ok()?;
            s.killed.then(|| Judged {
                kind: AGENT_KILLED,
                severity: "high",
                started_at: s.at.min(at),
                detail: json!({"source": s.source, "event_id": s.event_id,
                               "user": s.user, "message": s.message}),
            })
        }
        AgentEvent::AGENT_SERVICE_CONFIG => {
            let c: ServiceConfigChange = serde_json::from_value(data.clone()).ok()?;
            (c.to != start_type::AUTO).then(|| Judged {
                kind: AGENT_DISABLED,
                severity: "high",
                started_at: at,
                detail: json!({"from": c.from, "to": c.to}),
            })
        }
        AgentEvent::OS_LOG_CLEARED => {
            let c: OsLogCleared = serde_json::from_value(data.clone()).ok()?;
            Some(Judged {
                kind: LOG_CLEARED,
                severity: "high",
                started_at: c.at.min(at),
                detail: json!({"log": c.log, "event_id": c.event_id, "user": c.user}),
            })
        }
        _ => None,
    }
}

/// 把新存下的事件判定成發現存起來。同一次強制結束只記一筆（見 [`KILL_DEDUP`]）
pub async fn record_lifecycle(
    conn: &mut PgConnection,
    device_id: Uuid,
    events: &[(OffsetDateTime, &str, &Value)],
) -> Result<(), sqlx::Error> {
    for (at, kind, data) in events {
        let Some(j) = judge(kind, data, *at) else {
            continue;
        };
        if j.kind == AGENT_KILLED {
            let dup: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM device_findings WHERE device_id = $1 AND kind = $2                    AND started_at BETWEEN $3 - $4 AND $3 + $4)",
            )
            .bind(device_id)
            .bind(AGENT_KILLED)
            .bind(j.started_at)
            .bind(KILL_DEDUP)
            .fetch_one(&mut *conn)
            .await?;
            if dup {
                continue;
            }
        }
        insert(
            conn,
            device_id,
            j.kind,
            j.severity,
            "agent",
            j.started_at,
            Some(j.started_at),
            j.detail,
        )
        .await?;
    }
    Ok(())
}

/// 序號檢查的結果
#[derive(Debug, Default, PartialEq)]
pub struct Track {
    /// 新的最大序號
    pub last_seq: i64,
    /// 新發現的缺口（含兩端）
    pub gaps: Vec<(i64, i64)>,
    /// 補上之前缺口的序號
    pub fills: Vec<i64>,
    /// 這批 `journal.dropped` 說明的筆數
    pub explained: i64,
}

/// 依序號檢查這次新存下的事件（重送的已經排除）。`inserted` 是 (序號, journal.dropped 的筆數)
pub fn track(last_seq: i64, inserted: &[(i64, Option<i64>)]) -> Track {
    let mut sorted: Vec<&(i64, Option<i64>)> = inserted.iter().collect();
    sorted.sort_by_key(|(seq, _)| *seq);
    let mut t = Track {
        last_seq,
        ..Track::default()
    };
    for (seq, dropped) in sorted {
        t.explained += dropped.unwrap_or(0).max(0);
        if *seq <= t.last_seq {
            t.fills.push(*seq);
            continue;
        }
        if *seq > t.last_seq + 1 {
            t.gaps.push((t.last_seq + 1, seq - 1));
        }
        t.last_seq = *seq;
    }
    t
}

/// 鎖住這份日誌的追蹤紀錄，回傳 (已收到的最大序號, 還沒抵銷的說明筆數, 是否第一次看到)。
/// 要在存事件之前呼叫：第一次看到時，從資料庫裡已有的事件接續。
pub async fn journal_begin(
    conn: &mut PgConnection,
    device_id: Uuid,
    journal_id: Uuid,
) -> Result<(i64, i64, bool), sqlx::Error> {
    let lock = "SELECT last_seq, credit FROM device_journals \
                WHERE device_id = $1 AND journal_id = $2 FOR UPDATE";
    if let Some(row) = sqlx::query_as::<_, (i64, i64)>(lock)
        .bind(device_id)
        .bind(journal_id)
        .fetch_optional(&mut *conn)
        .await?
    {
        return Ok((row.0, row.1, false));
    }
    // 重新註冊後沿用同一份日誌：從原本那台的序號接續，不算缺口
    let inserted = sqlx::query(
        "INSERT INTO device_journals (device_id, journal_id, last_seq) \
         SELECT $1, $2, coalesce( \
             (SELECT max(last_seq) FROM device_journals WHERE journal_id = $2 AND device_id <> $1), \
             (SELECT max(seq) FROM device_events WHERE device_id = $1 AND journal_id = $2), 0) \
         ON CONFLICT DO NOTHING",
    )
    .bind(device_id)
    .bind(journal_id)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    let (last, credit): (i64, i64) = sqlx::query_as(lock)
        .bind(device_id)
        .bind(journal_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok((last, credit, inserted))
}

/// 存完事件後更新序號、記下缺口、用 `journal.dropped` 抵銷；新日誌時檢查是否一再重建
pub async fn journal_finish(
    conn: &mut PgConnection,
    device_id: Uuid,
    journal_id: Uuid,
    begin: (i64, i64, bool),
    inserted: &[(i64, Option<i64>)],
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let (last_seq, credit, new) = begin;
    let t = track(last_seq, inserted);
    for (from, to) in &t.gaps {
        let n = to - from + 1;
        insert(
            conn,
            device_id,
            JOURNAL_GAP,
            "medium",
            "server",
            now,
            Some(now),
            json!({"journal_id": journal_id, "from_seq": from, "to_seq": to,
                   "missing": n, "unexplained": n}),
        )
        .await?;
    }
    let gaps: Vec<(i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT id, (detail->>'from_seq')::bigint, (detail->>'to_seq')::bigint, \
                (detail->>'unexplained')::bigint \
         FROM device_findings WHERE device_id = $1 AND kind = $2 \
           AND detail->>'journal_id' = $3 AND (detail->>'unexplained')::bigint > 0 \
         ORDER BY id FOR UPDATE",
    )
    .bind(device_id)
    .bind(JOURNAL_GAP)
    .bind(journal_id.to_string())
    .fetch_all(&mut *conn)
    .await?;
    let mut remaining: Vec<(i64, i64)> = gaps
        .iter()
        .map(|(id, from, to, left)| {
            let filled = t
                .fills
                .iter()
                .filter(|s| (*from..=*to).contains(*s))
                .count() as i64;
            (*id, (left - filled).max(0))
        })
        .collect();
    // 說明可能晚幾批才到：從最舊的缺口開始抵銷
    let mut pool = credit + t.explained;
    for (_, left) in remaining.iter_mut() {
        let take = pool.min(*left);
        *left -= take;
        pool -= take;
    }
    for ((id, left), (_, _, _, before)) in remaining.iter().zip(&gaps) {
        if *left == 0 {
            sqlx::query("DELETE FROM device_findings WHERE id = $1")
                .bind(id)
                .execute(&mut *conn)
                .await?;
        } else if left != before {
            sqlx::query(
                "UPDATE device_findings SET detail = jsonb_set(detail, '{unexplained}', to_jsonb($2::bigint)) \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(left)
            .execute(&mut *conn)
            .await?;
        }
    }
    sqlx::query(
        "UPDATE device_journals SET last_seq = $3, credit = $4 WHERE device_id = $1 AND journal_id = $2",
    )
    .bind(device_id)
    .bind(journal_id)
    .bind(t.last_seq)
    .bind(pool)
    .execute(&mut *conn)
    .await?;
    if new {
        rebuilt(conn, device_id, now).await?;
    }
    Ok(())
}

/// 30 天內出現 [`REBUILD_THRESHOLD`] 份以上新日誌（這台的第一份不算）：標示一次，30 天內不重複
async fn rebuilt(
    conn: &mut PgConnection,
    device_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), sqlx::Error> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM device_journals j WHERE j.device_id = $1 \
           AND j.first_seen_at > $2 - interval '30 days' \
           AND j.first_seen_at > (SELECT min(first_seen_at) FROM device_journals WHERE device_id = $1)",
    )
    .bind(device_id)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    if n < REBUILD_THRESHOLD {
        return Ok(());
    }
    let recent: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM device_findings WHERE device_id = $1 AND kind = $2 \
                        AND started_at > $3 - interval '30 days')",
    )
    .bind(device_id)
    .bind(JOURNAL_REBUILT)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    if !recent {
        insert(
            conn,
            device_id,
            JOURNAL_REBUILT,
            "medium",
            "server",
            now,
            Some(now),
            json!({"count": n}),
        )
        .await?;
    }
    Ok(())
}

/// 新增一筆發現
#[allow(clippy::too_many_arguments)]
pub async fn insert(
    conn: &mut PgConnection,
    device_id: Uuid,
    kind: &str,
    severity: &str,
    source: &str,
    started_at: OffsetDateTime,
    ended_at: Option<OffsetDateTime>,
    detail: Value,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "INSERT INTO device_findings (device_id, kind, severity, source, started_at, ended_at, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(device_id)
    .bind(kind)
    .bind(severity)
    .bind(source)
    .bind(started_at)
    .bind(ended_at)
    .bind(detail)
    .fetch_one(conn)
    .await
}

/// 網路端交叉比對：這台網路設備上連續成立 `streak` 次以上的，開一筆持續中的發現
/// （已經有持續中的就更新細節，開始時間不變）
pub async fn insert_or_refresh_network(
    conn: &mut PgConnection,
    net_device_id: i64,
    kind: &str,
    severity: &str,
    streak: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO device_findings (device_id, kind, severity, source, started_at, detail) \
         SELECT DISTINCT ON (s.device_id) s.device_id, s.kind, $3, 'network', s.first_at, s.detail \
         FROM net_crosscheck_streaks s \
         WHERE s.net_device_id = $1 AND s.kind = $2 AND s.streak >= $4 \
         ORDER BY s.device_id, s.first_at \
         ON CONFLICT (device_id, kind) WHERE ended_at IS NULL \
         DO UPDATE SET detail = EXCLUDED.detail",
    )
    .bind(net_device_id)
    .bind(kind)
    .bind(severity)
    .bind(streak)
    .execute(conn)
    .await?;
    Ok(())
}

/// 網路端交叉比對：任何網路設備上都不再成立（最近 30 分鐘沒有連續紀錄）的持續中發現結束
pub async fn close_network(conn: &mut PgConnection, kind: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_findings f SET ended_at = now() \
         WHERE f.kind = $1 AND f.ended_at IS NULL AND f.source = 'network' \
           AND NOT EXISTS (SELECT 1 FROM net_crosscheck_streaks s \
                           WHERE s.device_id = f.device_id AND s.kind = f.kind \
                             AND s.last_at > now() - interval '30 minutes')",
    )
    .bind(kind)
    .execute(conn)
    .await?;
    Ok(())
}

/// 確認一筆發現（看過、沒問題）：寫入稽核記錄。已確認過或不存在回 false
pub async fn acknowledge(
    conn: &mut PgConnection,
    device_id: Uuid,
    id: i64,
    actor: &str,
    note: &str,
) -> Result<bool, sqlx::Error> {
    let kind: Option<String> = sqlx::query_scalar(
        "UPDATE device_findings SET acknowledged_at = now(), acknowledged_by = $3, ack_note = $4 \
         WHERE id = $1 AND device_id = $2 AND acknowledged_at IS NULL RETURNING kind",
    )
    .bind(id)
    .bind(device_id)
    .bind(actor)
    .bind(note)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(kind) = kind else {
        return Ok(false);
    };
    crate::audit::record(
        conn,
        actor,
        "finding_ack",
        Some(&device_id.to_string()),
        json!({"finding": id, "kind": kind, "note": note}),
    )
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn lifecycle_judgements() {
        let at = datetime!(2026-11-24 10:00 UTC);
        let t = |s: &str| json!(s);
        // 停止原因
        let j = judge("agent.stopping", &json!({"reason": "service_stop"}), at).unwrap();
        assert_eq!(
            (j.kind, j.severity, j.started_at),
            (AGENT_STOPPED, "medium", at)
        );
        for r in ["shutdown", "upgrade", "reconfigure", "certificate"] {
            assert_eq!(judge("agent.stopping", &json!({"reason": r}), at), None);
        }
        // 非正常結束與重新開機
        let started = |clean: bool, alive: Option<&str>, boot: Option<&str>| {
            judge(
                "agent.started",
                &json!({"version": "1", "clean": clean, "last_alive": alive.map(t),
                        "boot_time": boot.map(t)}),
                at,
            )
        };
        assert_eq!(started(true, Some("2026-11-24T09:00:00Z"), None), None);
        assert_eq!(
            started(
                false,
                Some("2026-11-24T09:00:00Z"),
                Some("2026-11-24T09:30:00Z")
            ),
            None,
            "中間重開機"
        );
        let j = started(
            false,
            Some("2026-11-24T09:00:00Z"),
            Some("2026-11-20T00:00:00Z"),
        )
        .unwrap();
        assert_eq!(j.kind, AGENT_KILLED);
        assert_eq!(j.started_at, datetime!(2026-11-24 09:00 UTC));
        // 沒有開機時間也算；沒有最後活著的時間用事件時間
        assert_eq!(started(false, None, None).unwrap().started_at, at);
        // 時鐘錯亂（最後活著的時間比啟動還晚）：不晚於事件時間
        let j = started(false, Some("2026-11-25T00:00:00Z"), None).unwrap();
        assert_eq!(j.started_at, at);
        // 作業系統紀錄
        let os = |killed: bool| {
            judge(
                "os.service_stopped",
                &json!({"at": "2026-11-24T09:59:00Z", "source": "eventlog",
                        "event_id": 7034, "killed": killed}),
                at,
            )
        };
        assert_eq!(os(false), None);
        let j = os(true).unwrap();
        assert_eq!(j.detail["event_id"], 7034);
        assert_eq!(j.started_at, datetime!(2026-11-24 09:59 UTC));
        // 啟動類型
        let cfg = |to: &str| {
            judge(
                "agent.service_config",
                &json!({"from": "auto", "to": to}),
                at,
            )
        };
        assert_eq!(cfg("auto"), None);
        assert_eq!(cfg("manual").unwrap().kind, AGENT_DISABLED);
        assert_eq!(cfg("disabled").unwrap().severity, "high");
        // 紀錄被清除
        let j = judge(
            "os.log_cleared",
            &json!({"at": "2026-11-24T09:00:00Z", "log": "System", "event_id": 104}),
            at,
        )
        .unwrap();
        assert_eq!(j.kind, LOG_CLEARED);
        assert_eq!(describe(LOG_CLEARED, &j.detail), "系統紀錄被清除");
        // 資料壞掉、不相關的種類
        assert_eq!(judge("agent.started", &json!({"x": 1}), at), None);
        assert_eq!(judge("net.up", &json!({}), at), None);
    }

    #[test]
    fn lifecycle_texts() {
        let text = |k: &str, d: Value| lifecycle_text(k, &d).unwrap();
        assert_eq!(
            text("agent.started", json!({"version": "1.2", "clean": true})),
            "Agent 啟動（版本 1.2）"
        );
        assert_eq!(
            text("agent.stopping", json!({"reason": "reconfigure"})),
            "Agent 停止：重新設定"
        );
        assert_eq!(
            text("agent.stopping", json!({"reason": "certificate"})),
            "Agent 停止：伺服器拒絕憑證"
        );
        assert_eq!(
            text("agent.service_config", json!({"to": "manual"})),
            "Agent 服務啟動類型：手動"
        );
        assert_eq!(
            text(
                "os.service_stopped",
                json!({"at": "2026-11-24T09:00:00Z", "source": "journald",
                "killed": true, "user": "root"})
            ),
            "作業系統紀錄：Agent 服務意外終止（使用者 root）"
        );
        assert_eq!(
            text(
                "os.log_cleared",
                json!({"at": "2026-11-24T09:00:00Z", "log": "Setup",
                "event_id": 104})
            ),
            "安裝紀錄被清除"
        );
        assert_eq!(lifecycle_text("net.up", &json!({})), None);
        assert_eq!(lifecycle_text("agent.stopping", &json!({})), None);
        assert!(!lifecycle_notable("agent.started", &json!({"clean": true})));
        assert!(lifecycle_notable("agent.started", &json!({"clean": false})));
        assert!(lifecycle_notable("os.log_cleared", &json!({})));
        assert!(!lifecycle_notable("net.up", &json!({})));
        assert_eq!(
            describe(AGENT_DISABLED, &json!({"to": "manual", "from": null})),
            "啟動類型改成「手動」"
        );
        assert_eq!(
            describe(LOG_CLEARED, &json!({"log": "Other", "user": "x"})),
            "Other紀錄被清除（使用者 x）"
        );
        for k in [AGENT_STOPPED, AGENT_KILLED, AGENT_DISABLED, LOG_CLEARED] {
            assert!(!hint(k).is_empty());
        }
    }

    #[test]
    fn gaps_fills_and_explanations() {
        // 連續
        let t = track(0, &[(1, None), (2, None), (3, None)]);
        assert_eq!(t.last_seq, 3);
        assert!(t.gaps.is_empty() && t.fills.is_empty());
        // 跳號，順序亂掉也一樣；journal.dropped 的筆數累計
        let t = track(3, &[(9, Some(2)), (4, None), (7, None)]);
        assert_eq!(t.gaps, vec![(5, 6), (8, 8)]);
        assert_eq!(t.last_seq, 9);
        assert_eq!(t.explained, 2);
        // 補上之前的缺口
        let t = track(9, &[(5, None), (10, None)]);
        assert_eq!(t.fills, vec![5]);
        assert!(t.gaps.is_empty());
        assert_eq!(t.last_seq, 10);
        // 負數筆數不算
        assert_eq!(track(0, &[(1, Some(-5))]).explained, 0);
    }

    #[test]
    fn descriptions() {
        let d = json!({"from_seq": 5, "to_seq": 7, "unexplained": 2});
        assert_eq!(
            describe(JOURNAL_GAP, &d),
            "缺 2 筆（序號 5–7），Agent 沒有說明原因"
        );
        let d = json!({"from_seq": 5, "to_seq": 5, "unexplained": 1});
        assert!(describe(JOURNAL_GAP, &d).contains("（序號 5）"));
        assert_eq!(
            describe(JOURNAL_REBUILT, &json!({"count": 3})),
            "30 天內重建 3 次"
        );
        assert_eq!(label("x"), "x");
        for k in [
            "agent_stopped",
            "agent_killed",
            "agent_disabled",
            "log_cleared",
            "silent_on_network",
            "ip_conflict",
            "mac_duplicate",
        ] {
            assert_ne!(label(k), k);
        }
        assert_eq!(describe("x", &json!({})), "");
        assert!(!hint(JOURNAL_GAP).is_empty() && hint("x").is_empty());
    }
}
