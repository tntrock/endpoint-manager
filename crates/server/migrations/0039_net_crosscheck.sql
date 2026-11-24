-- 竄改偵測第三期（規格 §5）：網路端交叉比對要「連續幾次查詢都成立」才標示。
-- 每台網路設備每次查詢 MAC 表、ARP 表後更新：這次還成立的加一，不成立的刪掉。
CREATE TABLE net_crosscheck_streaks (
    net_device_id BIGINT NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- silent_on_network、mac_duplicate 是 MAC；ip_conflict 是 IP
    key           TEXT NOT NULL,
    streak        INT NOT NULL DEFAULT 1,
    first_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    detail        JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (net_device_id, kind, device_id, key)
);
CREATE INDEX net_crosscheck_streaks_device_idx ON net_crosscheck_streaks (device_id, kind);
