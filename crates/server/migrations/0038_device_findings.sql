-- 偵測本機資料竄改（竄改偵測規格 §2、§6）：各層偵測到的結果統一存成「發現」
CREATE TABLE device_findings (
    id              BIGSERIAL PRIMARY KEY,
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('high', 'medium')),
    source          TEXT NOT NULL CHECK (source IN ('agent', 'network', 'server')),
    started_at      TIMESTAMPTZ NOT NULL,
    -- 持續型的發現何時結束；一次性的與 started_at 相同；空的表示還在持續
    ended_at        TIMESTAMPTZ,
    detail          JSONB NOT NULL DEFAULT '{}',
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    ack_note        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX device_findings_device_idx ON device_findings (device_id, started_at DESC);
CREATE INDEX device_findings_open_idx ON device_findings (device_id) WHERE acknowledged_at IS NULL;
CREATE INDEX device_findings_created_idx ON device_findings (created_at);
-- 同一台、同一種類，持續中的只有一筆
CREATE UNIQUE INDEX device_findings_ongoing_idx ON device_findings (device_id, kind)
    WHERE ended_at IS NULL;

-- 每份事件日誌收到的最大序號，以及還沒抵銷完的 journal.dropped 筆數
CREATE TABLE device_journals (
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    journal_id    UUID NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seq      BIGINT NOT NULL,
    credit        BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, journal_id)
);
CREATE INDEX device_journals_journal_idx ON device_journals (journal_id);

-- 已經收過事件的日誌從現有的最大序號接續；之前的事件不回頭檢查
INSERT INTO device_journals (device_id, journal_id, first_seen_at, last_seq)
SELECT device_id, journal_id, min(received_at), max(seq)
FROM device_events GROUP BY device_id, journal_id;
