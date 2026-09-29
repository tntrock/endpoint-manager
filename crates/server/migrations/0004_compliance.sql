-- 第二期：軟體與修補合規
ALTER TABLE devices ADD COLUMN os_ubr INTEGER;

CREATE TABLE compliance_rules (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL CHECK (kind IN ('forbidden_software', 'required_software',
                                              'software_allowlist', 'os_build', 'required_kb')),
    severity    TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    params      JSONB NOT NULL,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- group_id 不 cascade：被引用的群組不能刪除（groups::delete 檢查）
CREATE TABLE compliance_rule_groups (
    rule_id  BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    group_id BIGINT NOT NULL REFERENCES device_groups(id),
    mode     TEXT NOT NULL CHECK (mode IN ('include', 'exclude')),
    PRIMARY KEY (rule_id, group_id)
);
CREATE INDEX compliance_rule_groups_group_idx ON compliance_rule_groups (group_id);

CREATE TABLE compliance_exemptions (
    id         BIGSERIAL PRIMARY KEY,
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id    BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    reason     TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (device_id, rule_id)
);
CREATE INDEX compliance_exemptions_expires_idx ON compliance_exemptions (expires_at);

CREATE TABLE device_violations (
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id    BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    status     TEXT NOT NULL CHECK (status IN ('violating', 'unknown', 'exempt')),
    detail     JSONB NOT NULL,
    since      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, rule_id)
);
CREATE INDEX device_violations_rule_idx ON device_violations (rule_id, status);

-- 歷程；規則刪除後保留名稱與嚴重度快照。from_status / to_status 的 'none' 表示無結果
CREATE TABLE violation_events (
    id          BIGSERIAL PRIMARY KEY,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    rule_id     BIGINT REFERENCES compliance_rules(id) ON DELETE SET NULL,
    rule_name   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    from_status TEXT NOT NULL,
    to_status   TEXT NOT NULL,
    detail      JSONB NOT NULL,
    at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX violation_events_device_idx ON violation_events (device_id, at);
CREATE INDEX violation_events_at_idx ON violation_events (at);

CREATE TABLE compliance_daily (
    day       DATE NOT NULL,
    rule_id   BIGINT NOT NULL REFERENCES compliance_rules(id) ON DELETE CASCADE,
    violating INTEGER NOT NULL,
    unknown   INTEGER NOT NULL,
    exempt    INTEGER NOT NULL,
    PRIMARY KEY (day, rule_id)
);

-- 單列：generation 在規則變更時 +1；背景工作重算到 done_generation 追上為止
CREATE TABLE compliance_state (
    id              BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    generation      BIGINT NOT NULL DEFAULT 0,
    done_generation BIGINT NOT NULL DEFAULT 0,
    run_generation  BIGINT NOT NULL DEFAULT 0,
    cursor          UUID,
    started_at      TIMESTAMPTZ
);
INSERT INTO compliance_state DEFAULT VALUES;

INSERT INTO settings (key, value) VALUES ('violation_history_days', '365');
