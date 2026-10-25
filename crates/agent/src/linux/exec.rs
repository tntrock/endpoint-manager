//! 執行外部指令：完整路徑、逾時 kill、非 0 結束碼回錯誤。

use anyhow::{anyhow, bail};
use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// 每個外部指令的逾時
pub const CMD_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct NotFound(String);

impl std::fmt::Display for NotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "找不到指令：{}", self.0)
    }
}

impl std::error::Error for NotFound {}

/// 錯誤是否為「這台機器沒有這個指令」
pub fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<NotFound>().is_some()
}

/// 搜尋順序：/usr/bin、/bin、/usr/sbin、/sbin（都是 root 擁有；RHEL 的 `ip` 在 /usr/sbin）。
const SEARCH_DIRS: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

fn resolve(program: &str) -> Option<PathBuf> {
    resolve_in(&SEARCH_DIRS, program)
}

fn resolve_in(dirs: &[&str], program: &str) -> Option<PathBuf> {
    if program.contains('/') {
        return PathBuf::from(program).exists().then(|| program.into());
    }
    dirs.iter()
        .map(|d| PathBuf::from(d).join(program))
        .find(|p| p.exists())
}

/// 執行指令並回傳 stdout；非 0 結束碼或逾時都回 Err。
pub fn run_capture(program: &str, args: &[&str], timeout: Duration) -> anyhow::Result<String> {
    let path = resolve(program).ok_or_else(|| anyhow::Error::new(NotFound(program.into())))?;
    let mut child = Command::new(&path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow!("無法執行 {program}：{e}"))?;
    // 另開執行緒讀管線，避免輸出塞滿造成死鎖
    let mut out = child.stdout.take().expect("stdout piped");
    let mut err = child.stderr.take().expect("stderr piped");
    let t_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let t_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{program} 逾時（{} 秒）", timeout.as_secs());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stdout = t_out.join().unwrap_or_default();
    let stderr = t_err.join().unwrap_or_default();
    if !status.success() {
        let msg: String = String::from_utf8_lossy(&stderr).chars().take(200).collect();
        bail!(
            "{program} 結束碼 {}：{}",
            status.code().unwrap_or(-1),
            msg.trim()
        );
    }
    Ok(String::from_utf8_lossy(&stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_falls_back_to_sbin_in_order() {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (pa, pb) = (a.path().to_str().unwrap(), b.path().to_str().unwrap());
        std::fs::write(b.path().join("ip"), "").unwrap();
        assert_eq!(resolve_in(&[pa, pb], "ip"), Some(b.path().join("ip")));
        std::fs::write(a.path().join("ip"), "").unwrap();
        assert_eq!(resolve_in(&[pa, pb], "ip"), Some(a.path().join("ip")));
        assert_eq!(SEARCH_DIRS[2..], ["/usr/sbin", "/sbin"]);
    }

    #[test]
    fn captures_and_reports_errors() {
        assert_eq!(
            run_capture("echo", &["hi"], CMD_TIMEOUT).unwrap().trim(),
            "hi"
        );
        assert!(run_capture("false", &[], CMD_TIMEOUT).is_err());
        let e = run_capture("no-such-cmd-xyz", &[], CMD_TIMEOUT).unwrap_err();
        assert!(is_not_found(&e));
        let e = run_capture("sleep", &["5"], Duration::from_millis(100)).unwrap_err();
        assert!(!is_not_found(&e) && e.to_string().contains("逾時"));
    }
}
