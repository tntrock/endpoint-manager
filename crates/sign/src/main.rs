use std::io::BufRead;
use std::path::PathBuf;

use anyhow::{Context, bail};
use endpoint_sign::{KeyFile, check_file, describe, generate, load_request, sign, verify};

const USAGE: &str = "usage:
  endpoint-sign keygen <key.json>                              產生金鑰（密語從 stdin 讀兩次）
  endpoint-sign pubkey <key.json>                              印出公鑰
  endpoint-sign sign <key.json> <request.json> [--file <安裝檔>]  簽章（密語從 stdin 讀）
  endpoint-sign verify <公鑰> <request.json> <簽章>             檢查簽章";

fn read_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    let mut s = String::new();
    std::io::stdin().lock().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let arg = |i: usize| args.get(i).map(PathBuf::from).context(USAGE);
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let path = arg(1)?;
            let pw = read_line("密語（至少 12 字元）：")?;
            if read_line("再輸入一次：")? != pw {
                bail!("兩次輸入的密語不同");
            }
            let kf = generate(&pw)?;
            kf.save_new(&path)?;
            eprintln!(
                "已建立 {}。請把它存在離線媒體，並記住密語：遺失任一個都無法再簽章。",
                path.display()
            );
            println!("公鑰：{}", kf.public_key);
            println!("金鑰 ID：{}", kf.key_id);
            Ok(())
        }
        Some("pubkey") => {
            let kf = KeyFile::load(&arg(1)?)?;
            println!("{}", kf.public_key);
            Ok(())
        }
        Some("sign") => {
            let kf = KeyFile::load(&arg(1)?)?;
            let req = load_request(&arg(2)?)?;
            eprintln!("── 要簽章的內容 ──\n{}", describe(&req));
            if let Some(content) = &req.content {
                eprintln!("── 腳本全文（SHA-256 已由本工具重新計算確認）──\n{content}\n── 結束 ──");
            }
            match args.iter().position(|a| a == "--file") {
                Some(i) => {
                    let file = args.get(i + 1).map(PathBuf::from).context(USAGE)?;
                    check_file(&req, &file)?;
                    eprintln!("安裝檔 {} 與請求相符。", file.display());
                }
                None if req.content.is_none() => eprintln!(
                    "注意：沒有用 --file 比對安裝檔，等於相信伺服器上的檔案。建議指定從原廠取得的安裝檔。"
                ),
                None => {}
            }
            let pair = kf.unlock(&read_line(&format!(
                "確認無誤後輸入金鑰 {} 的密語：",
                kf.key_id
            ))?)?;
            println!("{}", sign(&pair, &req));
            Ok(())
        }
        Some("verify") => {
            let key = args.get(1).context(USAGE)?;
            let req = load_request(&arg(2)?)?;
            let sig = args.get(3).context(USAGE)?;
            let id = verify(key, &req, sig)?;
            println!("簽章有效（金鑰 {id}）");
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}
