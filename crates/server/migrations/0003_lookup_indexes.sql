-- 核准重新註冊時以 reenroll_of 找原裝置
CREATE INDEX devices_reenroll_of_idx ON devices (reenroll_of) WHERE reenroll_of IS NOT NULL;

-- 軟體搜尋是 name ILIKE '%...%'，一般 B-tree 用不上，改用 trigram
-- 已有大量資料時建索引會延長這次升級的啟動時間（伺服器在 migration 完成前不提供服務）
CREATE EXTENSION IF NOT EXISTS pg_trgm;
SET LOCAL maintenance_work_mem = '512MB';
CREATE INDEX device_software_name_trgm_idx ON device_software USING gin (name gin_trgm_ops);
