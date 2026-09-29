-- 通知：每個管道記錄已送到哪個 violation_events.id
CREATE TABLE notify_channels (
    channel         TEXT PRIMARY KEY CHECK (channel IN ('email', 'webhook')),
    last_event_id   BIGINT NOT NULL DEFAULT 0,
    last_sent_at    TIMESTAMPTZ,
    last_ok_at      TIMESTAMPTZ,
    next_attempt_at TIMESTAMPTZ,
    failures        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    dropped         BIGINT NOT NULL DEFAULT 0
);
INSERT INTO notify_channels (channel) VALUES ('email'), ('webhook');

INSERT INTO settings (key, value) VALUES
    ('notify_min_severity', '"medium"'),
    ('notify_interval_minutes', '10'),
    ('notify_email', 'null'),
    ('notify_webhook_url', 'null');
