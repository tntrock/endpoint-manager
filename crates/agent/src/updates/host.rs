//! WU 原則登錄檔的讀寫與待重開機偵測；測試用記憶體版本。

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use protocol::update::PolicyData;

pub trait WuHost: Send + Sync + 'static {
    /// 值不存在（或機碼不存在）→ None
    fn read(&self, name: &str) -> std::io::Result<Option<PolicyData>>;
    fn write(&self, name: &str, data: &PolicyData) -> std::io::Result<()>;
    /// 值不存在也算成功
    fn delete(&self, name: &str) -> std::io::Result<()>;
    fn reboot_pending(&self) -> bool;
}

/// 測試用：記憶體中的登錄檔
#[derive(Default)]
pub struct MemoryHost {
    pub values: Mutex<BTreeMap<String, PolicyData>>,
    pub reboot: AtomicBool,
    pub fail_writes: AtomicBool,
}

impl WuHost for MemoryHost {
    fn read(&self, name: &str) -> std::io::Result<Option<PolicyData>> {
        Ok(self.values.lock().expect("lock").get(name).cloned())
    }

    fn write(&self, name: &str, data: &PolicyData) -> std::io::Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        self.values
            .lock()
            .expect("lock")
            .insert(name.to_string(), data.clone());
        Ok(())
    }

    fn delete(&self, name: &str) -> std::io::Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }
        self.values.lock().expect("lock").remove(name);
        Ok(())
    }

    fn reboot_pending(&self) -> bool {
        self.reboot.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_host() {
        let h = MemoryHost::default();
        assert_eq!(h.read("A").unwrap(), None);
        h.write("A", &PolicyData::Dword(3)).unwrap();
        assert_eq!(h.read("A").unwrap(), Some(PolicyData::Dword(3)));
        h.delete("A").unwrap();
        h.delete("A").unwrap();
        assert_eq!(h.read("A").unwrap(), None);
        h.fail_writes.store(true, Ordering::SeqCst);
        assert!(h.write("A", &PolicyData::Dword(1)).is_err());
        assert!(!h.reboot_pending());
    }
}
