//! 監看網卡變化，寫進本機事件日誌（網路規格 §4.1）。
//!
//! Linux 每 15 秒讀一次；Windows 由位址變更通知喚醒，另外每 5 分鐘讀一次補漏。
//! 喚醒後等幾秒再讀：網卡啟用時位址與閘道會分幾次出現。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::{AgentEvent, InventoryPayload, NetInterface, NetworkInfo, Section};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use crate::collector::Collector;
use crate::journal::Journal;

/// 喚醒後等多久再讀
pub const SETTLE: Duration = Duration::from_secs(3);

fn down(i: &NetInterface) -> Value {
    json!({ "name": i.name, "kind": i.kind })
}

fn full(i: &NetInterface) -> Value {
    serde_json::to_value(i).expect("interface serializes")
}

/// 比較前後兩份網卡清單，產生事件（依網卡名稱排序，結果穩定）
pub fn diff(old: &NetworkInfo, new: &NetworkInfo) -> Vec<(&'static str, Value)> {
    let before: BTreeMap<&str, &NetInterface> = old
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();
    let after: BTreeMap<&str, &NetInterface> = new
        .interfaces
        .iter()
        .map(|i| (i.name.as_str(), i))
        .collect();
    let mut out = Vec::new();
    for (name, n) in &after {
        match before.get(name) {
            None if n.up => out.push((AgentEvent::NET_UP, full(n))),
            None => {}
            Some(o) if !o.up && n.up => out.push((AgentEvent::NET_UP, full(n))),
            Some(o) if o.up && !n.up => out.push((AgentEvent::NET_DOWN, down(n))),
            Some(o) if o.up && n.up && o != n => out.push((AgentEvent::NET_CHANGED, full(n))),
            Some(_) => {}
        }
    }
    for (name, o) in &before {
        if o.up && !after.contains_key(name) {
            out.push((AgentEvent::NET_DOWN, down(o)));
        }
    }
    out
}

fn record(journal: &Mutex<Journal>, kind: &str, data: Value) {
    let mut j = journal.lock().unwrap_or_else(|p| p.into_inner());
    if let Err(e) = j.append(kind, data, time::OffsetDateTime::now_utc()) {
        tracing::warn!(error = %e, "cannot write event journal");
    }
}

async fn read<C: Collector>(c: &Arc<C>) -> Option<NetworkInfo> {
    let c = c.clone();
    match tokio::task::spawn_blocking(move || c.collect(Section::Network)).await {
        Ok(Ok(InventoryPayload::Network(mut n))) => {
            // 跟送給伺服器的一樣先清理，事件與區段的內容才一致
            let mut p = InventoryPayload::Network(n.clone());
            crate::sanitize::sanitize(&mut p);
            if let InventoryPayload::Network(clean) = p {
                n = clean;
            }
            Some(n)
        }
        _ => None,
    }
}

/// 一開始記下完整清單（伺服器以它為重播起點），之後有變化就記事件並觸發 network 區段
pub async fn run<C: Collector>(
    collector: Arc<C>,
    journal: Arc<Mutex<Journal>>,
    triggers: mpsc::Sender<Section>,
    mut wake: mpsc::Receiver<()>,
    poll: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut prev: Option<NetworkInfo> = None;
    loop {
        if let Some(now) = read(&collector).await {
            match &prev {
                None => record(
                    &journal,
                    AgentEvent::NET_SNAPSHOT,
                    serde_json::to_value(&now).expect("network serializes"),
                ),
                Some(p) => {
                    let events = diff(p, &now);
                    for (kind, data) in &events {
                        record(&journal, kind, data.clone());
                    }
                    if !events.is_empty() {
                        // 讓報到提早，事件與新的網卡清單盡快送出；通道滿了就算了
                        let _ = triggers.try_send(Section::Network);
                    }
                }
            }
            prev = Some(now);
        }
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            Some(()) = wake.recv() => {
                tokio::select! {
                    _ = tokio::time::sleep(SETTLE) => {}
                    _ = shutdown.changed() => return,
                }
                // 這段時間內的其他通知一起處理
                while wake.try_recv().is_ok() {}
            }
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nic(name: &str, up: bool, addr: &str) -> NetInterface {
        NetInterface {
            name: name.into(),
            description: None,
            kind: "ethernet".into(),
            up,
            mac: None,
            addresses: vec![addr.into()],
            gateways: vec![],
            dns: vec![],
            ssid: None,
        }
    }

    fn info(v: Vec<NetInterface>) -> NetworkInfo {
        NetworkInfo { interfaces: v }
    }

    #[test]
    fn diff_kinds() {
        let old = info(vec![
            nic("a", true, "10.0.0.1/24"),
            nic("b", true, "10.0.1.1/24"),
            nic("c", false, ""),
            nic("gone", true, "10.0.2.1/24"),
            nic("quiet", false, ""),
        ]);
        let new = info(vec![
            nic("a", true, "10.0.0.9/24"),
            nic("b", false, "10.0.1.1/24"),
            nic("c", true, "10.0.3.1/24"),
            nic("new", true, "192.168.43.5/24"),
            nic("new-down", false, ""),
            nic("quiet", false, "x"),
        ]);
        let ev: Vec<(&str, String)> = diff(&old, &new)
            .into_iter()
            .map(|(k, v)| (k, v["name"].as_str().unwrap().to_string()))
            .collect();
        assert_eq!(
            ev,
            [
                ("net.changed", "a".to_string()),
                ("net.down", "b".into()),
                ("net.up", "c".into()),
                ("net.up", "new".into()),
                ("net.down", "gone".into()),
            ]
        );
        let d = diff(&old, &new);
        // 停用的事件只帶名稱與種類
        assert_eq!(d[1].1, json!({"name": "b", "kind": "ethernet"}));
        assert_eq!(d[0].1["addresses"][0], "10.0.0.9/24");
        assert!(diff(&new, &new).is_empty());
    }

    /// 依序回傳預先準備的網卡清單；用完後一直回傳最後一份
    struct Seq(Mutex<Vec<NetworkInfo>>);

    impl Collector for Seq {
        fn identity(&self) -> anyhow::Result<crate::collector::Identity> {
            anyhow::bail!("unused")
        }
        fn heartbeat(&self) -> anyhow::Result<crate::collector::Heartbeat> {
            anyhow::bail!("unused")
        }
        fn collect(&self, s: Section) -> anyhow::Result<InventoryPayload> {
            assert_eq!(s, Section::Network);
            let mut v = self.0.lock().unwrap();
            let n = if v.len() > 1 {
                v.remove(0)
            } else {
                v[0].clone()
            };
            Ok(InventoryPayload::Network(n))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_then_events_and_trigger() {
        let dir = tempfile::tempdir().unwrap();
        let journal = Arc::new(Mutex::new(Journal::open(dir.path())));
        let c = Arc::new(Seq(Mutex::new(vec![
            info(vec![nic("eth", true, "10.0.0.1/24")]),
            info(vec![
                nic("eth", true, "10.0.0.1/24"),
                nic("usb0", true, "192.168.8.2/24"),
            ]),
            info(vec![nic("eth", true, "10.0.0.1/24")]),
        ])));
        let (tx, mut rx) = mpsc::channel(4);
        let (wake_tx, wake_rx) = mpsc::channel(4);
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run(
            c,
            journal.clone(),
            tx,
            wake_rx,
            Duration::from_secs(15),
            stop_rx,
        ));
        // 第一次：快照；15 秒後：usb0 出現
        tokio::time::sleep(Duration::from_secs(16)).await;
        assert_eq!(rx.recv().await, Some(Section::Network));
        // 喚醒：等 SETTLE 後再讀，usb0 消失
        wake_tx.send(()).await.unwrap();
        wake_tx.send(()).await.unwrap();
        tokio::time::sleep(SETTLE + Duration::from_secs(1)).await;
        assert_eq!(rx.recv().await, Some(Section::Network));
        stop_tx.send(true).unwrap();
        task.await.unwrap();
        let kinds: Vec<String> = journal
            .lock()
            .unwrap()
            .pending(10)
            .into_iter()
            .map(|e| e.kind)
            .collect();
        assert_eq!(kinds, ["net.snapshot", "net.up", "net.down"]);
    }
}
