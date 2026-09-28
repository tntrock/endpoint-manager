//! 把 tracing 輸出寫到「事件檢視器 → Windows 記錄 → 應用程式」。
//! 事件來源由 MSI 註冊（計畫 4）；未註冊時事件仍會寫入，只是檢視器顯示「找不到描述」。

use std::io::Write;

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;
use windows_sys::Win32::System::EventLog::{
    EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, RegisterEventSourceW,
    ReportEventW,
};

pub const SOURCE: &str = "EndpointManagerAgent";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// 事件來源 handle（以 usize 保存，才能跨執行緒共用）。
pub struct EventLog(usize);

impl EventLog {
    pub fn open() -> std::io::Result<Self> {
        let src = wide(SOURCE);
        let h = unsafe { RegisterEventSourceW(std::ptr::null(), src.as_ptr()) };
        if h.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(h as usize))
        }
    }

    pub fn report(&self, ty: u16, msg: &str) {
        let w = wide(msg);
        let strings = [w.as_ptr()];
        unsafe {
            ReportEventW(
                self.0 as _,
                ty,
                0,
                1,
                std::ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                std::ptr::null(),
            );
        }
    }
}

pub struct EventLine<'a> {
    log: &'a EventLog,
    ty: u16,
    buf: Vec<u8>,
}

impl Write for EventLine<'_> {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for EventLine<'_> {
    fn drop(&mut self) {
        if !self.buf.is_empty() {
            self.log
                .report(self.ty, String::from_utf8_lossy(&self.buf).trim_end());
        }
    }
}

impl<'a> MakeWriter<'a> for EventLog {
    type Writer = EventLine<'a>;

    fn make_writer(&'a self) -> EventLine<'a> {
        EventLine {
            log: self,
            ty: EVENTLOG_INFORMATION_TYPE,
            buf: Vec::new(),
        }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> EventLine<'a> {
        let ty = match *meta.level() {
            Level::ERROR => EVENTLOG_ERROR_TYPE,
            Level::WARN => EVENTLOG_WARNING_TYPE,
            _ => EVENTLOG_INFORMATION_TYPE,
        };
        EventLine {
            log: self,
            ty,
            buf: Vec::new(),
        }
    }
}
