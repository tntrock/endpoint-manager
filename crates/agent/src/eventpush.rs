//! 事件立即上傳（竄改偵測規格 §3）：日誌有新事件就在 1 秒後送到 `POST /v1/events`，
//! 不等下一次報到。送到之後本機怎麼改都沒用，竄改的時間窗只剩幾秒。
//!
//! 報到仍然附帶沒確認的事件，當作備援；兩邊都送到時伺服器不重複計算。

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::{EventsAck, EventsUpload, MAX_EVENTS_PER_CHECKIN};
use tokio::sync::{Notify, watch};

use crate::client::{ClientError, ServerClient};
use crate::journal::Journal;

/// 等一下再送：同時發生的事件（例如一次拔掉兩張網卡）合成一批
pub const SETTLE: Duration = Duration::from_secs(1);
/// 失敗後第一次重試的等待，之後加倍
pub const RETRY_MIN: Duration = Duration::from_secs(5);
/// 重試等待的上限（報到也會補送，不用等太久）
pub const RETRY_MAX: Duration = Duration::from_secs(300);

/// 送到哪裡：伺服器在報到回應宣告支援後才有值
#[derive(Clone, Debug, PartialEq)]
pub struct Target {
    pub url: String,
    pub root_pem: String,
    pub identity_pem: Option<String>,
}

pub type SharedTarget = Arc<Mutex<Option<Target>>>;

/// 一次送出的結果
#[derive(Debug, PartialEq)]
pub enum Sent {
    /// 送完了（或沒有要送的）
    Done,
    /// 還有下一批
    More,
    /// 現在不能送（伺服器不支援、憑證或資料被拒）：交給報到處理
    Skip,
    /// 暫時失敗，稍後重試
    Retry(Option<Duration>),
}

fn lock(j: &Mutex<Journal>) -> std::sync::MutexGuard<'_, Journal> {
    j.lock().unwrap_or_else(|p| p.into_inner())
}

/// 送出最舊的一批。`send` 回傳 None 表示現在沒有目標（伺服器不支援）
pub async fn send_once<F, Fut>(journal: &Mutex<Journal>, send: &F) -> Sent
where
    F: Fn(EventsUpload) -> Fut,
    Fut: Future<Output = Option<Result<EventsAck, ClientError>>>,
{
    let up = {
        let j = lock(journal);
        EventsUpload {
            journal_id: j.id(),
            events: j.pending(MAX_EVENTS_PER_CHECKIN),
        }
    };
    if up.events.is_empty() {
        return Sent::Done;
    }
    let full = up.events.len() == MAX_EVENTS_PER_CHECKIN;
    match send(up).await {
        None => Sent::Skip,
        Some(Ok(ack)) => {
            let mut j = lock(journal);
            if let Some(seq) = ack.events_ack
                && let Err(e) = j.ack(seq)
            {
                tracing::warn!(error = %e, "cannot update event journal");
            }
            if full && !j.is_empty() {
                Sent::More
            } else {
                Sent::Done
            }
        }
        Some(Err(ClientError::Retry(after))) => Sent::Retry(after),
        Some(Err(e)) => {
            tracing::warn!(error = %e, "event push rejected; events will go with the next checkin");
            Sent::Skip
        }
    }
}

/// 有新事件（`notify`）就送；失敗時退避重試。收到停止訊號時結束
pub async fn run_with<F, Fut>(
    journal: Arc<Mutex<Journal>>,
    notify: Arc<Notify>,
    mut shutdown: watch::Receiver<bool>,
    send: F,
) where
    F: Fn(EventsUpload) -> Fut,
    Fut: Future<Output = Option<Result<EventsAck, ClientError>>>,
{
    let mut retry = RETRY_MIN;
    loop {
        tokio::select! {
            _ = notify.notified() => {}
            _ = shutdown.changed() => return,
        }
        tokio::select! {
            _ = tokio::time::sleep(SETTLE) => {}
            _ = shutdown.changed() => return,
        }
        loop {
            match send_once(&journal, &send).await {
                Sent::More => {
                    retry = RETRY_MIN;
                    continue;
                }
                Sent::Done | Sent::Skip => {
                    retry = RETRY_MIN;
                    break;
                }
                Sent::Retry(after) => {
                    let wait = after.unwrap_or(retry).min(RETRY_MAX);
                    retry = (retry * 2).min(RETRY_MAX);
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {}
                        _ = shutdown.changed() => return,
                    }
                }
            }
        }
    }
}

/// 實際送到伺服器（目標由報到迴圈更新）
pub async fn run(
    journal: Arc<Mutex<Journal>>,
    target: SharedTarget,
    shutdown: watch::Receiver<bool>,
) {
    let notify = lock(&journal).notifier();
    run_with(journal, notify, shutdown, move |up| {
        let t = target.lock().unwrap_or_else(|p| p.into_inner()).clone();
        async move {
            let t = t?;
            let client = match ServerClient::new(&t.url, &t.root_pem, t.identity_pem) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "cannot build client for event push");
                    return None;
                }
            };
            Some(client.push_events(&up).await)
        }
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn journal(n: usize) -> (tempfile::TempDir, Arc<Mutex<Journal>>) {
        let dir = tempfile::tempdir().unwrap();
        let mut j = Journal::open(dir.path());
        for _ in 0..n {
            j.append("t", serde_json::json!({}), time::OffsetDateTime::now_utc())
                .unwrap();
        }
        (dir, Arc::new(Mutex::new(j)))
    }

    fn ack_all(up: EventsUpload) -> Option<Result<EventsAck, ClientError>> {
        Some(Ok(EventsAck {
            events_ack: up.events.last().map(|e| e.seq),
        }))
    }

    #[tokio::test]
    async fn sends_in_batches_until_empty() {
        let (_d, j) = journal(MAX_EVENTS_PER_CHECKIN + 3);
        let send = |up: EventsUpload| async move { ack_all(up) };
        assert_eq!(send_once(&j, &send).await, Sent::More);
        assert_eq!(lock(&j).len(), 3);
        assert_eq!(send_once(&j, &send).await, Sent::Done);
        assert!(lock(&j).is_empty());
        assert_eq!(send_once(&j, &send).await, Sent::Done);
    }

    #[tokio::test]
    async fn keeps_events_when_not_sent() {
        let (_d, j) = journal(2);
        let none = |_: EventsUpload| async { None };
        assert_eq!(send_once(&j, &none).await, Sent::Skip);
        let busy =
            |_: EventsUpload| async { Some(Err(ClientError::Retry(Some(Duration::from_secs(7))))) };
        assert_eq!(
            send_once(&j, &busy).await,
            Sent::Retry(Some(Duration::from_secs(7)))
        );
        let bad = |_: EventsUpload| async { Some(Err(ClientError::Rejected(400, "x".into()))) };
        assert_eq!(send_once(&j, &bad).await, Sent::Skip);
        assert_eq!(lock(&j).len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn new_events_are_sent_after_settling_and_retried() {
        let (_d, j) = journal(0);
        let notify = lock(&j).notifier();
        let calls = Arc::new(AtomicUsize::new(0));
        let (stop, shutdown) = watch::channel(false);
        let c = calls.clone();
        let task = tokio::spawn(run_with(j.clone(), notify, shutdown, move |up| {
            let n = c.fetch_add(1, Ordering::SeqCst);
            async move {
                // 第一次暫時失敗，之後成功
                if n == 0 {
                    Some(Err(ClientError::Retry(None)))
                } else {
                    ack_all(up)
                }
            }
        }));
        tokio::task::yield_now().await;
        lock(&j)
            .append("a", serde_json::json!({}), time::OffsetDateTime::now_utc())
            .unwrap();
        lock(&j)
            .append("b", serde_json::json!({}), time::OffsetDateTime::now_utc())
            .unwrap();
        // 合併期間還沒送
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // 1 秒後送出（失敗），5 秒後重試成功，兩筆一起
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(lock(&j).is_empty());
        stop.send(true).unwrap();
        task.await.unwrap();
    }
}
