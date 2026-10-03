//! 據點管理（平台管理員）：名稱、網段、快取無法使用時是否改向中央、頻寬與磁碟上限。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, bail, ensure};
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use crate::audit;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_LIMIT: i32 = 100_000;
const MAX_CIDRS: usize = 100;

#[derive(Debug, Clone)]
pub struct SiteInput {
    pub name: String,
    pub cidrs: Vec<String>,
    pub fallback_to_central: bool,
    pub bandwidth_limit_mbps: Option<i32>,
    pub disk_limit_gb: i32,
}

/// 正規化網段（主機位元清零，例如 10.1.2.3/16 → 10.1.0.0/16）；格式錯誤回 Err
pub fn parse_cidr(s: &str) -> anyhow::Result<(IpAddr, u8)> {
    let s = s.trim();
    let (ip, len) = s
        .split_once('/')
        .with_context(|| format!("網段「{s}」要寫成 位址/前綴長度"))?;
    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("網段「{s}」的位址無效"))?;
    let len: u8 = len
        .parse()
        .with_context(|| format!("網段「{s}」的前綴長度無效"))?;
    Ok(match ip {
        IpAddr::V4(v4) => {
            ensure!(len <= 32, "網段「{s}」的前綴長度超過 32");
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            (IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask)), len)
        }
        IpAddr::V6(v6) => {
            ensure!(len <= 128, "網段「{s}」的前綴長度超過 128");
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            (IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask)), len)
        }
    })
}

pub fn cidr_string(c: &(IpAddr, u8)) -> String {
    format!("{}/{}", c.0, c.1)
}

pub fn cidr_contains(c: &(IpAddr, u8), ip: &IpAddr) -> bool {
    match (c.0, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(c.1)).unwrap_or(0);
            u32::from(*ip) & mask == u32::from(net)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(c.1)).unwrap_or(0);
            u128::from(*ip) & mask == u128::from(net)
        }
        _ => false,
    }
}

struct Valid {
    name: String,
    cidrs: Vec<String>,
}

fn validate(i: &SiteInput) -> anyhow::Result<Valid> {
    let name = i.name.trim().to_string();
    ensure!(
        !name.is_empty() && name.chars().count() <= MAX_NAME_LEN,
        "據點名稱必填，最多 {MAX_NAME_LEN} 字"
    );
    ensure!(
        !name.chars().any(char::is_control),
        "據點名稱不能包含控制字元"
    );
    ensure!(
        (1..=MAX_LIMIT).contains(&i.disk_limit_gb),
        "磁碟上限要在 1–{MAX_LIMIT} GB"
    );
    if let Some(b) = i.bandwidth_limit_mbps {
        ensure!(
            (1..=MAX_LIMIT).contains(&b),
            "頻寬上限要在 1–{MAX_LIMIT} Mbps"
        );
    }
    let mut cidrs = vec![];
    for c in &i.cidrs {
        let s = cidr_string(&parse_cidr(c)?);
        if !cidrs.contains(&s) {
            cidrs.push(s);
        }
    }
    ensure!(!cidrs.is_empty(), "至少要有一個網段");
    ensure!(cidrs.len() <= MAX_CIDRS, "網段最多 {MAX_CIDRS} 個");
    Ok(Valid { name, cidrs })
}

async fn bump(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE branch_state SET generation = generation + 1")
        .execute(conn)
        .await?;
    Ok(())
}

/// 網段已屬於其他據點時回錯誤（寫出是哪個據點）。
/// 先鎖住 sites 表：同時新增相同網段的兩個交易依序檢查（據點異動很少，鎖整張表沒關係）。
async fn check_cidrs(conn: &mut PgConnection, id: i64, cidrs: &[String]) -> anyhow::Result<()> {
    sqlx::query("LOCK TABLE sites IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await?;
    let taken: Option<(String, String)> = sqlx::query_as(
        "SELECT c::text, s.name FROM sites s, UNNEST(s.cidrs) c \
         WHERE s.id <> $1 AND c = ANY($2::cidr[]) ORDER BY s.name LIMIT 1",
    )
    .bind(id)
    .bind(cidrs)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some((cidr, site)) = taken {
        bail!("網段 {cidr} 已屬於據點「{site}」");
    }
    Ok(())
}

fn name_taken(e: sqlx::Error) -> anyhow::Error {
    match &e {
        sqlx::Error::Database(d) if d.is_unique_violation() => anyhow::anyhow!("據點名稱已存在"),
        _ => e.into(),
    }
}

fn detail(id: i64, i: &SiteInput, v: &Valid) -> serde_json::Value {
    json!({
        "id": id,
        "cidrs": v.cidrs,
        "fallback_to_central": i.fallback_to_central,
        "bandwidth_limit_mbps": i.bandwidth_limit_mbps,
        "disk_limit_gb": i.disk_limit_gb,
    })
}

pub async fn create_site(pool: &PgPool, i: &SiteInput, actor: &str) -> anyhow::Result<i64> {
    let v = validate(i)?;
    let mut tx = pool.begin().await?;
    check_cidrs(&mut tx, 0, &v.cidrs).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO sites (name, cidrs, fallback_to_central, bandwidth_limit_mbps, disk_limit_gb) \
         VALUES ($1, $2::cidr[], $3, $4, $5) RETURNING id",
    )
    .bind(&v.name)
    .bind(&v.cidrs)
    .bind(i.fallback_to_central)
    .bind(i.bandwidth_limit_mbps)
    .bind(i.disk_limit_gb)
    .fetch_one(&mut *tx)
    .await
    .map_err(name_taken)?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "site_create",
        Some(&v.name),
        detail(id, i, &v),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

pub async fn update_site(pool: &PgPool, id: i64, i: &SiteInput, actor: &str) -> anyhow::Result<()> {
    let v = validate(i)?;
    let mut tx = pool.begin().await?;
    check_cidrs(&mut tx, id, &v.cidrs).await?;
    let n = sqlx::query(
        "UPDATE sites SET name = $2, cidrs = $3::cidr[], fallback_to_central = $4, \
         bandwidth_limit_mbps = $5, disk_limit_gb = $6, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(&v.name)
    .bind(&v.cidrs)
    .bind(i.fallback_to_central)
    .bind(i.bandwidth_limit_mbps)
    .bind(i.disk_limit_gb)
    .execute(&mut *tx)
    .await
    .map_err(name_taken)?
    .rows_affected();
    ensure!(n == 1, "據點不存在");
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "site_update",
        Some(&v.name),
        detail(id, i, &v),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn delete_site(pool: &PgPool, id: i64, actor: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    let name: Option<String> = sqlx::query_scalar("DELETE FROM sites WHERE id = $1 RETURNING name")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    let name = name.ok_or_else(|| {
        anyhow::Error::from(crate::commands::CmdError::NotFound("據點不存在".into()))
    })?;
    bump(&mut tx).await?;
    audit::record(
        &mut tx,
        actor,
        "site_delete",
        Some(&name),
        json!({ "id": id }),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_parsing() {
        assert_eq!(
            parse_cidr("10.1.2.3/16").unwrap(),
            ("10.1.0.0".parse().unwrap(), 16)
        );
        assert_eq!(
            parse_cidr(" fd12:3456::1/32 ").unwrap(),
            ("fd12:3456::".parse().unwrap(), 32)
        );
        assert_eq!(
            cidr_string(&parse_cidr("10.1.2.3/16").unwrap()),
            "10.1.0.0/16"
        );
        for bad in ["10.1.0.0/33", "abc", "10.1.0.0", "10.1.0.0/x", "::/129", ""] {
            assert!(parse_cidr(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn contains() {
        let c = parse_cidr("10.1.0.0/16").unwrap();
        assert!(cidr_contains(&c, &"10.1.255.1".parse().unwrap()));
        assert!(!cidr_contains(&c, &"10.2.0.1".parse().unwrap()));
        assert!(!cidr_contains(&c, &"::1".parse().unwrap()), "不同位址族");
        let all = parse_cidr("0.0.0.0/0").unwrap();
        assert!(cidr_contains(&all, &"8.8.8.8".parse().unwrap()));
    }
}
