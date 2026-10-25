//! 遠端指令在 Linux 上的實際動作：重新收集、shutdown、sh 腳本。

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use protocol::Section;
use protocol::command::ScriptLanguage;
use tokio::sync::mpsc;

use crate::commands::logic::shutdown_message;
use crate::commands::worker::CommandHost;
use crate::deploy::logic::Cmd;
use crate::deploy::worker::{RunOutput, run_process};

const ENV_ARGS: &str =
    "-i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 HOME=/root";

pub struct LinuxHost {
    /// 報到迴圈的收集觸發
    pub triggers: mpsc::Sender<Section>,
}

impl CommandHost for LinuxHost {
    fn language(&self) -> ScriptLanguage {
        ScriptLanguage::Sh
    }

    /// 只由固定文字與數字組成，可放心交給 `sh -c`
    fn shutdown_args(&self, reboot: bool, delay_minutes: u32) -> String {
        let delay = delay_minutes.min(60);
        let when = if delay == 0 {
            "now".to_string()
        } else {
            format!("+{delay}")
        };
        format!(
            "{} {when} \"{}\"",
            if reboot { "-r" } else { "-h" },
            shutdown_message(reboot, delay)
        )
    }

    fn shutdown_label(&self) -> &'static str {
        "shutdown"
    }

    async fn collect_all(&self) {
        for s in Section::LINUX {
            if self.triggers.send(s).await.is_err() {
                return;
            }
        }
    }

    fn apply_now(&self) {}

    async fn shutdown(&self, args: &str) -> std::io::Result<()> {
        // 參數含帶引號的訊息，不能走 run_process 的空白切割，交給 sh 解析
        let child = tokio::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("/sbin/shutdown {args}"))
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .output();
        let out = tokio::time::timeout(Duration::from_secs(60), child)
            .await
            .map_err(|_| std::io::Error::other("shutdown 逾時"))??;
        if out.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "{}: {}{}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )))
        }
    }

    /// 乾淨環境執行；有 shebang 就直接執行檔案，否則交給 /bin/sh。
    async fn run_script(&self, path: &Path, timeout: Duration) -> std::io::Result<RunOutput> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        let mut head = [0u8; 2];
        let shebang = std::fs::File::open(path)
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
            .is_ok()
            && &head == b"#!";
        let p = path.display();
        let cmd = Cmd {
            program: "/usr/bin/env".into(),
            args: if shebang {
                format!("{ENV_ARGS} {p}")
            } else {
                format!("{ENV_ARGS} /bin/sh {p}")
            },
        };
        run_process(&cmd, timeout, true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deploy::worker::RunResult;

    fn host() -> LinuxHost {
        LinuxHost {
            triggers: mpsc::channel(1).0,
        }
    }

    #[test]
    fn shutdown_args_linux() {
        let h = host();
        assert_eq!(
            h.shutdown_args(true, 0),
            r#"-r now "IT 部門即將重新開機。""#
        );
        assert_eq!(
            h.shutdown_args(false, 5),
            r#"-h +5 "IT 部門排定在 5 分鐘後關機，請儲存您的工作。""#
        );
        assert_eq!(h.shutdown_label(), "shutdown");
        assert_eq!(h.language(), ScriptLanguage::Sh);
    }

    #[tokio::test]
    async fn script_runs_with_clean_env() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("1.sh");
        std::fs::write(&p, "echo \"$FOO|$PATH\"; exit 4\n").unwrap();
        // SAFETY: 只有這個測試設定 FOO。
        unsafe { std::env::set_var("FOO", "x") };
        let out = host()
            .run_script(&p, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(out.result, RunResult::Exited(4));
        assert_eq!(
            out.output.trim(),
            "|/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        );
    }

    #[tokio::test]
    async fn shebang_script_uses_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("2.sh");
        std::fs::write(&p, "#!/bin/sh\necho $0\n").unwrap();
        let out = host()
            .run_script(&p, Duration::from_secs(20))
            .await
            .unwrap();
        assert_eq!(out.result, RunResult::Exited(0));
        assert_eq!(out.output.trim(), p.display().to_string());
    }
}
