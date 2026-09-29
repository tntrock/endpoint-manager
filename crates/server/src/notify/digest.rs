//! 通知內容：彙整、Email 文字、Webhook JSON 與簽章。全部是純函式。

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use uuid::Uuid;

use crate::compliance::evaluate::summarize;
use crate::compliance::rules::Severity;

pub const MAX_WEBHOOK_ITEMS: usize = 500;
pub const EMAIL_PER_RULE: usize = 20;

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

type RuleGroup<'a> = (&'a str, Severity, Vec<&'a EventInfo>);

/// 依規則分組：嚴重度高的在前，同嚴重度台數多的在前。
fn by_rule(events: &[EventInfo]) -> Vec<RuleGroup<'_>> {
    let mut groups: Vec<RuleGroup<'_>> = vec![];
    for e in events {
        match groups.iter_mut().find(|g| g.0 == e.rule_name) {
            Some(g) => g.2.push(e),
            None => groups.push((&e.rule_name, e.severity, vec![e])),
        }
    }
    groups.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then(b.2.len().cmp(&a.2.len()))
            .then(a.0.cmp(b.0))
    });
    groups
}

fn section(out: &mut String, title: &str, verb: &str, events: &[EventInfo]) {
    if events.is_empty() {
        return;
    }
    out.push_str(&format!("\n== {title} ==\n"));
    for (rule, sev, list) in by_rule(events) {
        out.push_str(&format!(
            "\n{rule}（{}）：{verb} {} 台\n",
            sev.label(),
            list.len()
        ));
        for e in list.iter().take(EMAIL_PER_RULE) {
            out.push_str(&format!("  - {}：{}\n", e.hostname, summarize(&e.detail)));
        }
        if list.len() > EMAIL_PER_RULE {
            out.push_str(&format!("  …另有 {} 台\n", list.len() - EMAIL_PER_RULE));
        }
    }
}

pub fn email_text(d: &Digest, web_url: &str) -> (String, String) {
    let subject = format!(
        "[Endpoint Manager] 合規：新增 {} 筆違規、解除 {} 筆",
        d.total_new, d.total_resolved
    );
    let mut body = String::from("Endpoint Manager 合規通知\n");
    if (d.new.len() as i64) < d.total_new || (d.resolved.len() as i64) < d.total_resolved {
        body.push_str(&format!(
            "\n（本次共新增 {} 筆、解除 {} 筆，以下只列出部分）\n",
            d.total_new, d.total_resolved
        ));
    }
    section(&mut body, "新增違規", "新增", &d.new);
    section(&mut body, "已解除", "解除", &d.resolved);
    if d.dropped > 0 {
        body.push_str(&format!(
            "\n注意：有 {} 筆事件因積壓過多而略過。\n",
            d.dropped
        ));
    }
    if !web_url.is_empty() {
        body.push_str(&format!("\n查看：{web_url}/compliance\n"));
    }
    (subject, body)
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
    fn email_groups_by_rule_and_caps() {
        let (subject, body) = email_text(&digest(60), "https://em.example.com");
        assert_eq!(
            subject,
            "[Endpoint Manager] 合規：新增 60 筆違規、解除 1 筆"
        );
        assert!(body.contains("規則A（高）：新增 30 台"), "{body}");
        assert_eq!(
            body.matches("PC0").count(),
            2 * EMAIL_PER_RULE,
            "每條規則最多列 20 台"
        );
        assert!(body.contains("另有 10 台"));
        assert!(body.contains("PC-OK"));
        assert!(body.contains("https://em.example.com/compliance"));
        let (_, body) = email_text(&digest(1), "");
        assert!(!body.contains("http"), "沒有網址就不附連結");
    }

    #[test]
    fn email_mentions_dropped() {
        let mut d = digest(1);
        d.dropped = 1234;
        assert!(email_text(&d, "").1.contains("1234 筆事件因積壓過多而略過"));
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
