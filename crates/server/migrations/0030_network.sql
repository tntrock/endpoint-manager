-- 每張網卡（network 區段）
CREATE TABLE device_network (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 報到時回報的全部位址（last_ip 仍是主要位址），搜尋任何一個都找得到
ALTER TABLE devices ADD COLUMN ips INET[] NOT NULL DEFAULT '{}';
CREATE INDEX devices_ips_idx ON devices USING GIN (ips);
