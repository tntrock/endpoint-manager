-- 核准重新註冊時以 reenroll_of 找原裝置
CREATE INDEX devices_reenroll_of_idx ON devices (reenroll_of) WHERE reenroll_of IS NOT NULL;

-- 軟體搜尋是 name ILIKE '%...%'，一般 B-tree 用不上，改用 trigram
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX device_software_name_trgm_idx ON device_software USING gin (name gin_trgm_ops);
