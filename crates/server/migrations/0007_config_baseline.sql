-- 第三期：組態基準（安全設定、登錄檔值）
CREATE TABLE device_security (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    firewall   JSONB NOT NULL,
    bitlocker  JSONB NOT NULL,
    defender   JSONB NOT NULL,
    password   JSONB NOT NULL,
    admins     JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_registry (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    path      TEXT NOT NULL,
    name      TEXT NOT NULL,
    state     TEXT NOT NULL CHECK (state IN ('present', 'absent', 'denied')),
    kind      TEXT NOT NULL,
    data      TEXT NOT NULL,
    PRIMARY KEY (device_id, path, name)
);
CREATE INDEX device_registry_value_idx ON device_registry (path, name);

INSERT INTO settings (key, value) VALUES
    ('security_interval_secs', '3600'),
    ('registry_interval_secs', '3600'),
    ('registry_max_values', '1000');
