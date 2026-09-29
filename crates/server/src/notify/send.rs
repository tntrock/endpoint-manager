//! 實際送出：Webhook（reqwest）與 Email（lettre）。

use std::time::Duration;

use lettre::message::{Mailbox, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use super::digest::signature;
use super::{EmailSettings, TlsMode};

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
        .map_err(|e| format!("Webhook 連線失敗：{}", e.without_url()))?;
    if res.status().is_success() {
        Ok(())
    } else {
        Err(format!("Webhook 回應 {}", res.status().as_u16()))
    }
}

pub fn email_message(e: &EmailSettings, subject: &str, body: &str) -> anyhow::Result<Message> {
    let mut b = Message::builder()
        .from(e.from.parse::<Mailbox>()?)
        .subject(subject);
    for to in &e.to {
        b = b.to(to.parse::<Mailbox>()?);
    }
    Ok(b.header(ContentType::TEXT_PLAIN).body(body.to_string())?)
}

pub async fn send_email_with<T: AsyncTransport + Sync>(t: &T, msg: Message) -> Result<(), String>
where
    T::Error: std::fmt::Display,
{
    t.send(msg)
        .await
        .map(|_| ())
        .map_err(|e| format!("寄信失敗：{e}"))
}

pub async fn send_email(
    e: &EmailSettings,
    password: Option<&str>,
    msg: Message,
) -> Result<(), String> {
    let builder = match e.tls {
        TlsMode::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&e.host),
        TlsMode::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&e.host),
    }
    .map_err(|err| format!("SMTP 設定錯誤：{err}"))?
    .port(e.port)
    .timeout(Some(TIMEOUT));
    let builder = if e.username.is_empty() {
        builder
    } else {
        builder.credentials(Credentials::new(
            e.username.clone(),
            password.unwrap_or_default().to_string(),
        ))
    };
    send_email_with(&builder.build(), msg).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::{EmailSettings, TlsMode};

    #[tokio::test]
    async fn email_message_and_stub_send() {
        let e = EmailSettings {
            host: "smtp.example.com".into(),
            port: 587,
            tls: TlsMode::StartTls,
            username: String::new(),
            from: "em@example.com".into(),
            to: vec!["a@example.com".into(), "b@example.com".into()],
        };
        let msg = email_message(&e, "主旨", "內文").unwrap();
        let raw = String::from_utf8(msg.formatted()).unwrap();
        assert!(raw.contains("To: a@example.com, b@example.com"), "{raw}");
        assert!(raw.contains("Content-Type: text/plain; charset=utf-8"));
        send_email_with(
            &lettre::transport::stub::AsyncStubTransport::new_ok(),
            msg.clone(),
        )
        .await
        .unwrap();
        let err = send_email_with(
            &lettre::transport::stub::AsyncStubTransport::new_error(),
            msg,
        )
        .await
        .unwrap_err();
        assert!(!err.is_empty());
    }
}
