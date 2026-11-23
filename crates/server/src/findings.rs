//! 竄改偵測的「發現」（竄改偵測規格 §2）與事件序號缺口、日誌重建（§6）。
//!
//! 各層偵測到的結果都存進 `device_findings`，後台用同一套方式顯示與確認。

use serde_json::{Value, json};
use sqlx::PgConnection;
use time::OffsetDateTime;
use uuid::Uuid;

/// 事件序號不連續，Agent 沒有說明原因
pub const JOURNAL_GAP: &str = "journal_gap";
/// 30 天內事件日誌重建多次
pub const JOURNAL_REBUILT: &str = "journal_rebuilt";

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
        _ => String::new(),
    }
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
        assert_eq!(describe("x", &json!({})), "");
        assert!(!hint(JOURNAL_GAP).is_empty() && hint("x").is_empty());
    }
}
