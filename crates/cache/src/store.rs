//! 本機套件檔：以 sha256 命名放在儲存目錄；存取時間記在資料目錄的 access.json。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;

use crate::config::write_atomic;

/// 不在清單上的套件保留多久
pub const RETENTION: Duration = Duration::from_secs(7 * 24 * 3600);
const ACCESS_FILE: &str = "access.json";

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

use protocol::is_sha256;

pub struct Store {
    dir: PathBuf,
    access_path: PathBuf,
    access: Mutex<HashMap<String, u64>>,
    in_use: Mutex<HashMap<String, usize>>,
}

/// 傳送期間持有，避免檔案被清除
pub struct InUse {
    store: Arc<Store>,
    sha256: String,
}

impl Drop for InUse {
    fn drop(&mut self) {
        let mut m = self.store.in_use.lock().expect("in_use lock");
        if let Some(n) = m.get_mut(&self.sha256) {
            *n -= 1;
            if *n == 0 {
                m.remove(&self.sha256);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileInfo {
    pub sha256: String,
    pub size: u64,
    pub last_access: u64,
    pub listed: bool,
    pub in_use: bool,
}

/// 要刪哪些檔案：
/// 1. 不在清單上、最後存取超過 retention 秒的。
/// 2. 之後仍超過上限：先刪不在清單上的、再刪清單上的，各自從最久沒用的開始。
///
/// 傳送中的檔案一律不刪（可能因此暫時超過上限）。
pub fn eviction_plan(files: &[FileInfo], disk_limit: u64, now: u64, retention: u64) -> Vec<String> {
    let mut remove: Vec<String> = vec![];
    let mut keep: Vec<&FileInfo> = vec![];
    for f in files {
        if !f.listed && !f.in_use && now.saturating_sub(f.last_access) > retention {
            remove.push(f.sha256.clone());
        } else {
            keep.push(f);
        }
    }
    let mut total: u64 = keep.iter().map(|f| f.size).sum();
    keep.sort_by_key(|f| (f.listed, f.last_access));
    for f in keep {
        if total <= disk_limit {
            break;
        }
        if f.in_use {
            continue;
        }
        total -= f.size;
        remove.push(f.sha256.clone());
    }
    remove
}

impl Store {
    /// 建立儲存目錄、刪除上次留下的暫存檔（*.part）、載入存取時間
    pub fn open(storage: &Path, state_dir: &Path) -> anyhow::Result<Store> {
        std::fs::create_dir_all(storage)
            .with_context(|| format!("creating {}", storage.display()))?;
        for entry in std::fs::read_dir(storage)? {
            let path = entry?.path();
            if path.extension().is_some_and(|x| x == "part") {
                let _ = std::fs::remove_file(&path);
            }
        }
        let access_path = state_dir.join(ACCESS_FILE);
        let access = match std::fs::read(&access_path) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "access.json unreadable; starting fresh");
                HashMap::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Store {
            dir: storage.to_path_buf(),
            access_path,
            access: Mutex::new(access),
            in_use: Mutex::new(HashMap::new()),
        })
    }

    pub fn path(&self, sha256: &str) -> PathBuf {
        self.dir.join(sha256)
    }

    /// 檔案存在且大小相符
    pub fn has(&self, sha256: &str, size: u64) -> bool {
        is_sha256(sha256)
            && std::fs::metadata(self.path(sha256)).is_ok_and(|m| m.is_file() && m.len() == size)
    }

    pub fn touch(&self, sha256: &str) {
        self.access
            .lock()
            .expect("access lock")
            .insert(sha256.to_string(), now_secs());
    }

    pub fn last_access(&self, sha256: &str) -> Option<u64> {
        self.access
            .lock()
            .expect("access lock")
            .get(sha256)
            .copied()
    }

    pub fn use_file(self: &Arc<Self>, sha256: &str) -> InUse {
        *self
            .in_use
            .lock()
            .expect("in_use lock")
            .entry(sha256.to_string())
            .or_default() += 1;
        InUse {
            store: self.clone(),
            sha256: sha256.to_string(),
        }
    }

    pub fn save_access(&self) -> anyhow::Result<()> {
        let json = serde_json::to_vec(&*self.access.lock().expect("access lock"))?;
        write_atomic(&self.access_path, &json)?;
        Ok(())
    }

    /// 儲存目錄中完整的套件檔：(sha256, 大小, 修改時間)
    fn files(&self) -> anyhow::Result<Vec<(String, u64, u64)>> {
        let mut out = vec![];
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let meta = entry.metadata()?;
            if !is_sha256(&name) || !meta.is_file() {
                continue;
            }
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push((name, meta.len(), mtime));
        }
        Ok(out)
    }

    pub fn used_bytes(&self) -> u64 {
        self.files()
            .map(|f| f.iter().map(|(_, size, _)| size).sum())
            .unwrap_or(0)
    }

    /// 依 eviction_plan 刪檔，回傳刪掉的 sha256
    pub fn evict(
        &self,
        listed: &HashSet<String>,
        disk_limit: u64,
        now: u64,
    ) -> anyhow::Result<Vec<String>> {
        let files = self.files()?;
        let infos: Vec<FileInfo> = {
            let access = self.access.lock().expect("access lock");
            let in_use = self.in_use.lock().expect("in_use lock");
            files
                .into_iter()
                .map(|(sha256, size, mtime)| FileInfo {
                    last_access: access.get(&sha256).copied().unwrap_or(mtime),
                    listed: listed.contains(&sha256),
                    in_use: in_use.contains_key(&sha256),
                    sha256,
                    size,
                })
                .collect()
        };
        let plan = eviction_plan(&infos, disk_limit, now, RETENTION.as_secs());
        let mut removed = vec![];
        for sha in plan {
            match std::fs::remove_file(self.path(&sha)) {
                Ok(()) => {
                    tracing::info!(sha256 = %sha, "package evicted");
                    self.access.lock().expect("access lock").remove(&sha);
                    removed.push(sha);
                }
                Err(e) => tracing::warn!(sha256 = %sha, error = %e, "evicting package failed"),
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;
    const NOW: u64 = 100 * DAY;

    fn f(name: &str, days_ago: u64, listed: bool, in_use: bool) -> FileInfo {
        FileInfo {
            sha256: name.into(),
            size: 1,
            last_access: NOW - days_ago * DAY,
            listed,
            in_use,
        }
    }

    fn plan(files: &[FileInfo], limit: u64) -> Vec<String> {
        let mut p = eviction_plan(files, limit, NOW, RETENTION.as_secs());
        p.sort();
        p
    }

    #[test]
    fn expired_unlisted_files_are_removed() {
        let files = [
            f("old", 8, false, false),
            f("recent", 6, false, false),
            f("listed_old", 8, true, false),
            f("busy_old", 8, false, true),
        ];
        assert_eq!(plan(&files, 100), vec!["old"]);
    }

    #[test]
    fn over_limit_unlisted_first_then_oldest() {
        let files = [
            f("a", 3, false, false),
            f("b", 1, false, false),
            f("c", 5, true, false),
            f("d", 1, true, false),
        ];
        assert_eq!(plan(&files, 2), vec!["a", "b"]);
        assert_eq!(plan(&files, 1), vec!["a", "b", "c"]);
        assert_eq!(plan(&files, 0), vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn files_in_use_are_never_removed() {
        let files = [f("a", 3, false, true), f("b", 1, true, true)];
        assert!(plan(&files, 0).is_empty());
    }

    fn sha(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn open_cleans_partials_and_keeps_access_times() {
        let dir = tempfile::tempdir().unwrap();
        let storage = dir.path().join("packages");
        std::fs::create_dir_all(&storage).unwrap();
        std::fs::write(storage.join(format!("{}.part", sha('a'))), b"half").unwrap();
        std::fs::write(storage.join(sha('b')), b"done").unwrap();
        let s = Arc::new(Store::open(&storage, dir.path()).unwrap());
        assert!(!storage.join(format!("{}.part", sha('a'))).exists());
        assert!(s.has(&sha('b'), 4));
        assert!(!s.has(&sha('b'), 5), "大小不符");
        assert_eq!(s.used_bytes(), 4);
        s.touch(&sha('b'));
        s.save_access().unwrap();
        let t = s.last_access(&sha('b')).unwrap();
        let s2 = Store::open(&storage, dir.path()).unwrap();
        assert_eq!(s2.last_access(&sha('b')), Some(t));
    }

    #[test]
    fn evict_deletes_files_and_respects_in_use() {
        let dir = tempfile::tempdir().unwrap();
        let storage = dir.path().join("packages");
        let s = Arc::new(Store::open(&storage, dir.path()).unwrap());
        for c in ['a', 'b'] {
            std::fs::write(s.path(&sha(c)), b"12345").unwrap();
            s.touch(&sha(c));
        }
        let busy = s.use_file(&sha('a'));
        let removed = s.evict(&HashSet::new(), 0, now_secs()).unwrap();
        assert_eq!(removed, vec![sha('b')]);
        assert!(s.path(&sha('a')).exists());
        drop(busy);
        let removed = s.evict(&HashSet::new(), 0, now_secs()).unwrap();
        assert_eq!(removed, vec![sha('a')]);
        assert_eq!(s.used_bytes(), 0);
    }

    #[test]
    fn rejects_non_hex_names() {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::open(&dir.path().join("p"), dir.path()).unwrap();
        assert!(!s.has("../config.json", 0));
    }
}
