//! 實際送出 Webhook（reqwest）。

use std::time::Duration;

use super::digest::signature;

pub const TIMEOUT: Duration = Duration::from_secs(10);

/// 系統信任的根憑證（企業內部 CA 通常已裝在伺服器上）加上額外指定的根憑證。
pub fn webhook_client(extra_roots: &[reqwest::Certificate]) -> anyhow::Result<reqwest::Client> {
    let native = rustls_native_certs::load_native_certs();
    for e in &native.errors {
        tracing::warn!(error = %e, "loading a system root certificate failed");
    }
    let mut roots: Vec<reqwest::Certificate> = native
        .certs
        .iter()
        .filter_map(|c| reqwest::Certificate::from_der(c.as_ref()).ok())
        .collect();
    roots.extend(extra_roots.iter().cloned());
    Ok(reqwest::Client::builder()
        .tls_certs_only(roots)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(TIMEOUT)
        .build()?)
}

/// 非 2xx（含重新導向）視為失敗。錯誤訊息不含網址（可能帶權杖）與密鑰。
pub async fn send_webhook(
    client: &reqwest::Client,
    url: &str,
    secret: Option<&str>,
    body: &serde_json::Value,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
    let mut req = client.post(url).header("content-type", "application/json");
    if let Some(secret) = secret {
        let ts = chrono::Utc::now().timestamp();
        req = req
            .header("x-em-timestamp", ts.to_string())
            .header("x-em-signature", signature(secret, ts, &bytes));
    }
    let res = req
        .body(bytes)
        .send()
        .await
        .map_err(|e| format!("Webhook 連線失敗：{}", describe(e.without_url())))?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("Webhook 回應 {}", res.status().as_u16()))
    }
}

/// 錯誤本身加上底層原因（拒絕連線、DNS、TLS、逾時）；網址已先移除，原因裡沒有網址或密鑰。
fn describe(e: reqwest::Error) -> String {
    let mut causes = vec![];
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        causes.push(s.to_string());
        src = s.source();
    }
    join_causes(e.to_string(), causes)
}

/// 把底層原因接在錯誤後面；已出現在前面文字裡的原因不再重複
fn join_causes(top: String, causes: Vec<String>) -> String {
    let mut kept: Vec<String> = vec![];
    for c in causes {
        if c.is_empty() || top.contains(&c) || kept.iter().any(|k| k.contains(&c)) {
            continue;
        }
        kept.push(c);
    }
    if kept.is_empty() {
        top
    } else {
        format!("{top}（{}）", kept.join("："))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causes_are_not_repeated() {
        let s = join_causes(
            "error sending request（connection refused）".into(),
            vec![
                "connection refused".into(),
                "tcp connect error".into(),
                "tcp connect error".into(),
                "os error 10061".into(),
            ],
        );
        assert_eq!(s.matches("connection refused").count(), 1, "{s}");
        assert_eq!(s.matches("tcp connect error").count(), 1, "{s}");
        assert!(s.contains("os error 10061"), "{s}");
        assert_eq!(join_causes("x".into(), vec![]), "x");
    }
}
