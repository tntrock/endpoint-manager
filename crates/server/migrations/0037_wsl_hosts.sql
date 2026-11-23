-- WSL 對應到所在的 Windows 主機（待辦第 2 項）。WSL 沒有自己的 BIOS UUID，
-- 改用兩個條件同時成立才配對，避免對錯：
--   1. 主機名稱相同（WSL 預設沿用 Windows 的電腦名稱；忽略大小寫與網域）
--   2. 網路上看得出是同一台：
--      - NAT 模式（WSL2 預設）：WSL 的預設閘道是那台 Windows 的位址之一
--        （vEthernet (WSL) 網卡。Windows 報到時的 IP 清單不含它，要看網路資料）
--      - 鏡像模式與 WSL1：WSL 與 Windows 共用網路，位址有重疊
-- 同名的 Windows 不只一台時，取最近回報的那台。
-- jsonb 一律先確認是陣列、位址用文字比對不轉型：格式不對的資料只是對不到，不會讓查詢失敗。

-- 裝置的全部位址（不含網路遮罩）：報到時的 IP 清單，加上網路資料裡每張網卡的位址
CREATE FUNCTION device_addrs(d UUID) RETURNS SETOF TEXT
LANGUAGE sql STABLE AS $$
    SELECT host(x) FROM devices, unnest(ips) x WHERE id = d
    UNION
    SELECT split_part(a, '/', 1)
    FROM device_network n
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(n.data -> 'interfaces') = 'array'
             THEN n.data -> 'interfaces' ELSE '[]'::jsonb END) i
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(i -> 'addresses') = 'array'
             THEN i -> 'addresses' ELSE '[]'::jsonb END) a
    WHERE n.device_id = d
$$;

-- 裝置網卡上的預設閘道
CREATE FUNCTION device_gateways(d UUID) RETURNS SETOF TEXT
LANGUAGE sql STABLE AS $$
    SELECT g
    FROM device_network n
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(n.data -> 'interfaces') = 'array'
             THEN n.data -> 'interfaces' ELSE '[]'::jsonb END) i
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE WHEN jsonb_typeof(i -> 'gateways') = 'array'
             THEN i -> 'gateways' ELSE '[]'::jsonb END) g
    WHERE n.device_id = d
$$;

CREATE VIEW wsl_hosts AS
SELECT DISTINCT ON (w.id) w.id AS wsl_id, h.id AS host_id
FROM devices w
JOIN devices h
  ON h.os_family = 'windows'
 AND h.status <> 'retired'
 AND h.id <> w.id
 AND lower(split_part(h.hostname, '.', 1)) = lower(split_part(w.hostname, '.', 1))
WHERE w.runs_in = 'wsl'
  AND w.status <> 'retired'
  AND EXISTS (
    SELECT 1 FROM device_addrs(h.id) a
    WHERE a IN (SELECT device_gateways(w.id))
       OR a IN (SELECT device_addrs(w.id))
  )
ORDER BY w.id, h.last_seen_at DESC NULLS LAST;
