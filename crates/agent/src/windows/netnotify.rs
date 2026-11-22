//! IPv4 位址表有變化時喚醒網卡監看（NotifyAddrChange 的同步模式）。
//! 網卡插拔、連上或斷開 Wi-Fi 都會改變位址表；只改路由的情況由定時讀取補上。

use tokio::sync::mpsc;
use windows_sys::Win32::NetworkManagement::IpHelper::NotifyAddrChange;

pub fn watch_addresses(wake: mpsc::Sender<()>) {
    std::thread::spawn(move || {
        loop {
            // 兩個參數都是 NULL：呼叫會一直等到位址表改變才返回
            let rc = unsafe { NotifyAddrChange(std::ptr::null_mut(), std::ptr::null()) };
            if rc != 0 {
                tracing::warn!(code = rc, "NotifyAddrChange failed; relying on polling");
                return;
            }
            // 通道滿了表示監看還沒處理完上一批，略過即可；接收端結束就停止
            if let Err(mpsc::error::TrySendError::Closed(_)) = wake.try_send(()) {
                return;
            }
        }
    });
}
