//! 套件檔案：以 SHA-256 命名存在套件目錄，同內容只存一份。

use std::path::{Path, PathBuf};

use anyhow::Context;
use axum::body::Bytes;
use futures_util::{Stream, StreamExt};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub use protocol::deploy::MAX_PACKAGE_BYTES;

#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub sha256: String,
    pub size: u64,
}

pub fn file_path(dir: &Path, sha256: &str) -> PathBuf {
    dir.join(sha256)
}

const TEMP_PREFIX: &str = ".upload-";

/// 檔案超過上限（網頁回 413）
#[derive(Debug)]
pub struct TooLarge;

impl std::fmt::Display for TooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "檔案超過上限 2 GiB")
    }
}

impl std::error::Error for TooLarge {}

/// 暫存檔守衛：上傳失敗、被取消（連線中斷時 future 被 drop）或改名失敗時都會刪檔
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// 啟動時清掉上次中斷留下的暫存檔（例如伺服器在上傳中被關閉）
pub async fn cleanup_temp(dir: &Path) {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return;
    };
    while let Ok(Some(e)) = entries.next_entry().await {
        if e.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            let _ = tokio::fs::remove_file(e.path()).await;
        }
    }
}

/// 串流寫入暫存檔並邊寫邊算雜湊，完成後改名為雜湊。
pub async fn save<S, E>(dir: &Path, body: S) -> anyhow::Result<Stored>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    save_limited(dir, body, MAX_PACKAGE_BYTES).await
}

pub async fn save_limited<S, E>(dir: &Path, mut body: S, max: u64) -> anyhow::Result<Stored>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("建立套件目錄 {}", dir.display()))?;
    let mut tmp = TempFile {
        path: dir.join(format!("{TEMP_PREFIX}{}", uuid::Uuid::new_v4())),
        keep: false,
    };
    let st = {
        let mut f = tokio::fs::File::create(&tmp.path).await?;
        let mut hasher = Sha256::new();
        let mut size: u64 = 0;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| anyhow::anyhow!("上傳中斷：{e}"))?;
            size += chunk.len() as u64;
            if size > max {
                return Err(TooLarge.into());
            }
            hasher.update(&chunk);
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        f.sync_all().await?;
        Stored {
            sha256: hex::encode(hasher.finalize()),
            size,
        }
    };
    let dest = file_path(dir, &st.sha256);
    // 已有同內容的檔案：守衛會刪掉暫存檔
    if !tokio::fs::try_exists(&dest).await.unwrap_or(false) {
        tokio::fs::rename(&tmp.path, &dest).await?;
        tmp.keep = true;
    }
    Ok(st)
}

#[derive(Debug, Clone, PartialEq)]
pub struct MsiInfo {
    pub name: String,
    pub version: String,
    pub product_code: String,
    pub manufacturer: String,
}

/// 讀 MSI 的 Property 表；不是 MSI 或沒有 ProductCode 時回 None。
pub fn msi_info(path: &Path) -> Option<MsiInfo> {
    let mut pkg = msi::open(path).ok()?;
    let rows = pkg.select_rows(msi::Select::table("Property")).ok()?;
    let mut get = std::collections::HashMap::new();
    for row in rows {
        if let (Some(k), Some(v)) = (row[0].as_str(), row[1].as_str()) {
            get.insert(k.to_string(), v.to_string());
        }
    }
    let field = |k: &str| get.get(k).cloned().unwrap_or_default();
    let product_code = field("ProductCode");
    if product_code.is_empty() {
        return None;
    }
    Some(MsiInfo {
        name: field("ProductName"),
        version: field("ProductVersion"),
        product_code,
        manufacturer: field("Manufacturer"),
    })
}
