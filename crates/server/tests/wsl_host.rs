//! WSL 對應到所在的 Windows 主機：主機名稱相同，且網路上看得出是同一台

mod common;

use common::TestServer;
use sqlx::PgPool;
use uuid::Uuid;

async fn set(s: &TestServer, id: Uuid, hostname: &str, linux: bool, ips: &[&str], os: &str) {
    sqlx::query(
        "UPDATE devices SET hostname = $2, os_family = $3, runs_in = $4, runs_in_detail = $5, \
         ips = $6::text[]::inet[], os_caption = $7, last_seen_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(hostname)
    .bind(if linux { "linux" } else { "windows" })
    .bind(if linux { "wsl" } else { "host" })
    .bind(if linux { "2" } else { "none" })
    .bind(ips.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .bind(os)
    .execute(&s.pool)
    .await
    .unwrap();
}

async fn network(s: &TestServer, id: Uuid, addr: &str, gw: &[&str]) {
    sqlx::query(
        "INSERT INTO device_network (device_id, data) VALUES ($1, $2) \
         ON CONFLICT (device_id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind(id)
    .bind(serde_json::json!({"interfaces": [
        {"name": "eth0", "kind": "ethernet", "up": true,
         "addresses": [addr], "gateways": gw, "dns": []},
        // 格式不對的資料只是對不到，不能讓查詢失敗
        {"name": "x", "kind": "other", "up": true, "gateways": "nope"}
    ]}))
    .execute(&s.pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn wsl_maps_to_windows_host(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(5).await;
    let win = s.enroll_ok(&tok, None, None).await.device_id;
    let other = s.enroll_ok(&tok, None, None).await.device_id;
    let wsl = s.enroll_ok(&tok, None, None).await.device_id;
    let mirrored = s.enroll_ok(&tok, None, None).await.device_id;
    let stranger = s.enroll_ok(&tok, None, None).await.device_id;
    let c = s.admin_client().await;

    set(&s, win, "PC-01", false, &["10.0.0.5"], "Windows 11").await;
    // 同名但網路對不上的另一台 Windows（例如重灌前的舊紀錄）
    set(&s, other, "pc-01", false, &["10.9.0.5"], "Windows 10").await;
    // NAT 模式：閘道是 Windows 的 vEthernet (WSL) 位址
    set(
        &s,
        wsl,
        "pc-01",
        true,
        &["172.20.5.9"],
        "Ubuntu 24.04.1 LTS",
    )
    .await;
    network(&s, wsl, "172.20.5.9/20", &["172.20.0.1"]).await;
    // Windows 報到時的 IP 清單沒有 vEthernet (WSL)，只有網路資料裡有
    network(&s, win, "172.20.0.1/20", &[]).await;
    // 鏡像模式：位址與 Windows 相同
    set(
        &s,
        mirrored,
        "PC-01.corp.example.com",
        true,
        &["10.0.0.5"],
        "Debian GNU/Linux 12",
    )
    .await;
    // 名稱不同：網路對得上也不配對
    set(&s, stranger, "PC-02", true, &["10.0.0.5"], "Alpine").await;

    let page = |id: Uuid| {
        let (s, c) = (&s, &c);
        async move { s.page(c, &format!("/devices/{id}")).await.1 }
    };
    let html = page(wsl).await;
    assert!(
        html.contains(&format!(
            "執行於 <a href=\"/devices/{win}\">PC-01</a></span>"
        )),
        "{html}"
    );
    let html = page(mirrored).await;
    assert!(html.contains(&format!(
        "執行於 <a href=\"/devices/{win}\">PC-01</a></span>"
    )));
    assert!(!page(stranger).await.contains("執行於"));

    let html = page(win).await;
    assert!(
        html.contains(&format!(
            "WSL：<a href=\"/devices/{mirrored}\">Debian GNU/Linux 12</a>、<a href=\"/devices/{wsl}\">Ubuntu 24.04.1 LTS</a>"
        )),
        "{html}"
    );
    assert!(!page(other).await.contains("WSL：<a"));

    // Windows 除役後不再配對
    sqlx::query("UPDATE devices SET status = 'retired' WHERE id = $1")
        .bind(win)
        .execute(&s.pool)
        .await
        .unwrap();
    assert!(!page(wsl).await.contains("執行於"));
}
