use std::time::Duration;

use anyhow::{Context, bail};
use loadsim::{Device, Report, Target};

const USAGE: &str = "usage:
  loadsim enroll    --server URL --root root.pem --token TOKEN --count N [--concurrency 50] --out devices.json
  loadsim heartbeat --server URL --root root.pem --devices devices.json [--rate 500] [--secs 60] [--max-p99-ms 200]
  loadsim upload    --server URL --root root.pem --devices devices.json [--items 150] [--concurrency 100] [--max-secs 600]";

fn arg(args: &[String], name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    args.get(i + 1).cloned()
}

fn num<T: std::str::FromStr>(args: &[String], name: &str, default: T) -> anyhow::Result<T> {
    match arg(args, name) {
        Some(v) => v
            .parse()
            .map_err(|_| anyhow::anyhow!("{name}: invalid number")),
        None => Ok(default),
    }
}

fn need(args: &[String], name: &str) -> anyhow::Result<String> {
    arg(args, name).with_context(|| format!("{name} is required\n{USAGE}"))
}

fn print(r: &Report) {
    println!(
        "ok {} errors {} | p50 {:?} p99 {:?} max {:?} | elapsed {:?} ({:.0}/s)",
        r.ok,
        r.errors,
        r.p50,
        r.p99,
        r.max,
        r.elapsed,
        r.ok as f64 / r.elapsed.as_secs_f64()
    );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("crypto provider already installed"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().cloned() else {
        bail!("{USAGE}")
    };
    let t = Target {
        server: need(&args, "--server")?,
        root_pem: std::fs::read_to_string(need(&args, "--root")?).context("reading --root")?,
    };
    let load = || -> anyhow::Result<Vec<Device>> {
        Ok(serde_json::from_slice(&std::fs::read(need(
            &args,
            "--devices",
        )?)?)?)
    };
    match cmd.as_str() {
        "enroll" => {
            let count = num(&args, "--count", 0usize)?;
            let devices = loadsim::enroll(
                &t,
                &need(&args, "--token")?,
                count,
                num(&args, "--concurrency", 50)?,
            )
            .await?;
            std::fs::write(need(&args, "--out")?, serde_json::to_vec(&devices)?)?;
            println!("enrolled {}", devices.len());
        }
        "heartbeat" => {
            let r = loadsim::heartbeat(
                &t,
                &load()?,
                num(&args, "--rate", 500)?,
                Duration::from_secs(num(&args, "--secs", 60)?),
            )
            .await;
            print(&r);
            let max = Duration::from_millis(num(&args, "--max-p99-ms", 200)?);
            if r.errors > 0 || r.p99 > max {
                bail!(
                    "FAIL: errors {} / p99 {:?} (limit {max:?})",
                    r.errors,
                    r.p99
                );
            }
        }
        "upload" => {
            let (r, unverified) = loadsim::upload(
                &t,
                &load()?,
                num(&args, "--items", 150)?,
                num(&args, "--concurrency", 100)?,
            )
            .await;
            print(&r);
            println!("unverified {unverified}");
            let max = Duration::from_secs(num(&args, "--max-secs", 600)?);
            if r.errors > 0 || unverified > 0 || r.elapsed > max {
                bail!(
                    "FAIL: errors {} / unverified {unverified} / elapsed {:?}",
                    r.errors,
                    r.elapsed
                );
            }
        }
        _ => bail!("{USAGE}"),
    }
    Ok(())
}
