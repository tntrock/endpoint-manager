CREATE TABLE device_groups (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO device_groups (name)
    SELECT DISTINCT group_label FROM enroll_tokens WHERE coalesce(group_label, '') <> '';

ALTER TABLE enroll_tokens ADD COLUMN group_id BIGINT REFERENCES device_groups(id);
UPDATE enroll_tokens t SET group_id = g.id FROM device_groups g WHERE g.name = t.group_label;
ALTER TABLE enroll_tokens DROP COLUMN group_label;

ALTER TABLE devices ADD COLUMN group_id BIGINT REFERENCES device_groups(id);
UPDATE devices d SET group_id = t.group_id FROM enroll_tokens t WHERE t.id = d.enroll_token_id;
CREATE INDEX devices_group_idx ON devices (group_id);

ALTER TABLE devices DROP CONSTRAINT devices_status_check;
ALTER TABLE devices ADD CONSTRAINT devices_status_check
    CHECK (status IN ('active', 'retired', 'duplicate_suspect', 'pending_approval'));
ALTER TABLE devices ADD COLUMN reenroll_of UUID REFERENCES devices(id) ON DELETE SET NULL;

CREATE TABLE admins (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('platform_admin', 'group_admin', 'viewer')),
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    disabled_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE admin_groups (
    admin_id BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (admin_id, group_id)
);

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id   BIGINT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_admin_idx ON sessions (admin_id);

CREATE TABLE audit_log (
    id     BIGSERIAL PRIMARY KEY,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail JSONB NOT NULL DEFAULT '{}',
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
