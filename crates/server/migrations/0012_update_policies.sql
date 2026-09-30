-- 第五期：Windows Update 原則
CREATE TABLE update_policies (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    revision    INT NOT NULL DEFAULT 1,
    settings    JSONB NOT NULL DEFAULT '{}',
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 一台裝置只屬一個群組：一個群組最多屬於一個原則，裝置就最多對應一個原則
CREATE TABLE update_policy_groups (
    group_id   BIGINT PRIMARY KEY REFERENCES device_groups(id) ON DELETE RESTRICT,
    policy_id  BIGINT NOT NULL REFERENCES update_policies(id) ON DELETE CASCADE
);
CREATE INDEX update_policy_groups_policy_idx ON update_policy_groups (policy_id);

-- Agent 回報的套用狀態；policy_id 不設外鍵：原則刪除後，裝置下次回報前仍保留
CREATE TABLE update_policy_status (
    device_id            UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    policy_id            BIGINT,
    revision             INT,
    state                TEXT NOT NULL CHECK (state IN ('unmanaged', 'applied', 'conflict', 'error')),
    detail               TEXT NOT NULL DEFAULT '',
    reboot_pending       BOOLEAN NOT NULL,
    reboot_pending_since TIMESTAMPTZ,
    last_patch_date      DATE,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX update_policy_status_policy_idx ON update_policy_status (policy_id, state);

CREATE TABLE update_state (generation BIGINT NOT NULL);
INSERT INTO update_state VALUES (0);
