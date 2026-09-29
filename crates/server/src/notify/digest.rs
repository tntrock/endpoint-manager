//! 通知內容：彙整、Webhook JSON 與簽章。全部是純函式。

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::compliance::evaluate::summarize;
use crate::compliance::rules::Severity;

pub const MAX_WEBHOOK_ITEMS: usize = 500;

#[derive(Debug, Clone, PartialEq)]
pub struct EventInfo {
    pub id: i64,
    pub device_id: Uuid,
    pub hostname: String,
    pub rule_name: String,
    pub severity: Severity,
    pub from_status: String,
    pub to_status: String,
    pub detail: Value,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Digest {
    /// 最多 MAX_WEBHOOK_ITEMS 筆（呼叫端讀取時已限制）
    pub new: Vec<EventInfo>,
    pub resolved: Vec<EventInfo>,
    pub total_new: i64,
    pub total_resolved: i64,
    /// 因積壓過多而略過的事件數
    pub dropped: i64,
}

impl Digest {
    pub fn is_empty(&self) -> bool {
        self.total_new == 0 && self.total_resolved == 0 && self.dropped == 0
    }
}

fn item(e: &EventInfo) -> Value {
    json!({
        "rule": e.rule_name,
        "severity": e.severity.as_str(),
        "device_id": e.device_id,
        "hostname": e.hostname,
        "from": e.from_status,
        "to": e.to_status,
        "summary": summarize(&e.detail),
        "detail": e.detail,
    })
}

pub fn webhook_body(d: &Digest, generated_at: DateTime<Utc>) -> Value {
    let new: Vec<Value> = d.new.iter().take(MAX_WEBHOOK_ITEMS).map(item).collect();
    let room = MAX_WEBHOOK_ITEMS - new.len();
    let resolved: Vec<Value> = d.resolved.iter().take(room).map(item).collect();
    let truncated = ((new.len() + resolved.len()) as i64) < d.total_new + d.total_resolved;
    json!({
        "generated_at": generated_at,
        "total_new": d.total_new,
        "total_resolved": d.total_resolved,
        "dropped": d.dropped,
        "truncated": truncated,
        "new": new,
        "resolved": resolved,
    })
}

/// HMAC-SHA256(secret, "{timestamp}.{body}")，接收端以 X-EM-Timestamp 防止舊請求被重送。
pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

/// 「送出測試通知」用的示範內容。
pub fn test_digest() -> Digest {
    let e = EventInfo {
        id: 0,
        device_id: Uuid::nil(),
        hostname: "TEST-PC".into(),
        rule_name: "測試通知".into(),
        severity: Severity::Low,
        from_status: "none".into(),
        to_status: "violating".into(),
        detail: json!({"kb": "KB0000000"}),
    };
    Digest {
        new: vec![e],
        resolved: vec![],
        total_new: 1,
        total_resolved: 0,
        dropped: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(id: i64, rule: &str, host: &str, from: &str, to: &str) -> EventInfo {
        EventInfo {
            id,
            device_id: Uuid::nil(),
            hostname: host.into(),
            rule_name: rule.into(),
            severity: Severity::High,
            from_status: from.into(),
            to_status: to.into(),
            detail: json!({"kb": "KB5031455"}),
        }
    }

    fn digest(n_new: usize) -> Digest {
        Digest {
            new: (0..n_new)
                .map(|i| {
                    let rule = if i % 2 == 0 { "規則A" } else { "規則B" };
                    ev(i as i64, rule, &format!("PC{i:03}"), "none", "violating")
                })
                .collect(),
            resolved: vec![ev(9999, "規則A", "PC-OK", "violating", "none")],
            total_new: n_new as i64,
            total_resolved: 1,
            dropped: 0,
        }
    }

    #[test]
    fn webhook_body_truncates_at_500() {
        let v = webhook_body(&digest(600), DateTime::UNIX_EPOCH);
        assert_eq!(
            v["new"].as_array().unwrap().len() + v["resolved"].as_array().unwrap().len(),
            MAX_WEBHOOK_ITEMS
        );
        assert_eq!(v["truncated"], true);
        assert_eq!(v["total_new"], 600);
        assert_eq!(v["new"][0]["summary"], "缺少 KB5031455");
        assert_eq!(v["new"][0]["severity"], "high");
        let small = webhook_body(&digest(2), DateTime::UNIX_EPOCH);
        assert_eq!(small["truncated"], false);
        assert_eq!(small["resolved"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn signature_is_hmac_sha256_over_timestamp_and_body() {
        // 以外部工具算出的固定值，獨立驗證 HMAC 實作：
        // printf '1700000000.{}' | openssl dgst -sha256 -hmac secret
        assert_eq!(
            signature("secret", 1_700_000_000, b"{}"),
            "sha256=b8569b78799ff9e3cbff0fc2d63a33a2b57f3282abd07c37ae5e8e7d79a5f163"
        );
        assert_ne!(signature("secret", 1, b"{}"), signature("secret", 2, b"{}"));
    }
}
