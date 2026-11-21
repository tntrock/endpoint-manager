#!/usr/bin/env bash
# 建置映像 → 建立 CA → 啟動 → 檢查兩個監聽埠 → docker stop 應以 0 結束。
set -euo pipefail
cd "$(dirname "$0")"
export EM_DB_PASSWORD=smoke-test-password
export EM_METRICS_TOKEN=smoke-metrics-token-0123456789abcdef
docker compose build
mkdir -p pki agent
sudo chown 65532:65532 pki
docker run --rm -v "$PWD/pki:/pki" endpoint-manager-server ca-init /pki localhost
docker compose up -d
for _ in $(seq 60); do
  curl -skf --max-time 5 https://localhost:8443/healthz && break
  sleep 2
done
curl -skf --max-time 5 https://localhost:8443/healthz
test "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://localhost/login)" = 200
metrics=$(curl -skf --max-time 5 -H "Authorization: Bearer $EM_METRICS_TOKEN" https://localhost/metrics)
grep -qx "em_metrics_db_up 1" <<<"$metrics"
test "$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' https://localhost/metrics)" = 401
docker compose stop server
id=$(docker compose ps -aq server)
test "$(docker inspect -f '{{.State.ExitCode}}' "$id")" = 0
docker compose logs server | grep -q "shutting down"
docker compose down -v
sudo rm -rf pki agent
echo "smoke ok"
