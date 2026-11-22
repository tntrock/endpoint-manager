-- Agent 本機暫存後上傳的事件（網路規格 §4）。(device_id, journal_id, seq) 唯一：重送的直接略過
CREATE TABLE device_events (
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    journal_id  UUID NOT NULL,
    seq         BIGINT NOT NULL,
    -- 端點時間；比收到時間晚超過 5 分鐘時改用收到時間
    at          TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    kind        TEXT NOT NULL,
    data        JSONB NOT NULL,
    PRIMARY KEY (device_id, journal_id, seq)
);
CREATE INDEX device_events_device_at_idx ON device_events (device_id, at DESC);
CREATE INDEX device_events_received_idx ON device_events (received_at);

-- 依事件重播得到的網卡狀態（多重連線期間的判斷依據）
CREATE TABLE device_net_state (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    interfaces JSONB NOT NULL DEFAULT '[]',
    -- 事件有缺漏（journal.dropped）：下一段期間標記為可能不完整
    gap        BOOLEAN NOT NULL DEFAULT false
);

-- 多重連線的期間；ended_at 為 NULL 表示還在持續
CREATE TABLE device_dual_homed_periods (
    id          BIGSERIAL PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    started_at  TIMESTAMPTZ NOT NULL,
    ended_at    TIMESTAMPTZ,
    detail      TEXT NOT NULL,
    interfaces  TEXT[] NOT NULL DEFAULT '{}',
    incomplete  BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX device_dual_homed_periods_device_idx
    ON device_dual_homed_periods (device_id, started_at DESC);
CREATE UNIQUE INDEX device_dual_homed_periods_open_idx
    ON device_dual_homed_periods (device_id) WHERE ended_at IS NULL;
