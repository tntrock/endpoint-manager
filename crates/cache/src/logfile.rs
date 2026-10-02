//! 服務模式的記錄檔：`<資料目錄>/cache.log`，啟動時超過 10 MB 就改名為 cache.log.1。

use std::path::Path;

const MAX_BYTES: u64 = 10 * 1024 * 1024;

pub fn open(dir: &Path) -> std::io::Result<std::fs::File> {
    let path = dir.join("cache.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_BYTES) {
        std::fs::rename(&path, dir.join("cache.log.1"))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_large_log() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("cache.log"),
            vec![b'x'; MAX_BYTES as usize + 1],
        )
        .unwrap();
        drop(open(dir.path()).unwrap());
        assert!(dir.path().join("cache.log.1").exists());
        assert_eq!(
            std::fs::metadata(dir.path().join("cache.log"))
                .unwrap()
                .len(),
            0
        );
    }
}
