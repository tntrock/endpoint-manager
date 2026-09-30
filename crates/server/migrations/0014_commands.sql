-- 第六期：遠端指令（腳本、指令、每台的執行狀態）
CREATE TABLE scripts (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    description      TEXT NOT NULL DEFAULT '',
    content          TEXT NOT NULL,
    sha256           TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    timeout_minutes  INT NOT NULL CHECK (timeout_minutes BETWEEN 1 AND 120),
    status           TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'disabled')),
    created_by       TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- 最後修改內容（或逾時）的人：雙人核准時不能核准自己的修改
    updated_by       TEXT NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by      TEXT,
    approved_at      TIMESTAMPTZ
);

-- 一次操作；腳本內容在建立時複製，之後修改腳本不影響已下的指令
CREATE TABLE command_runs (
    id                     BIGSERIAL PRIMARY KEY,
    action                 TEXT NOT NULL CHECK (action IN ('collect', 'apply', 'reboot', 'shutdown', 'script')),
    delay_minutes          INT CHECK (delay_minutes BETWEEN 0 AND 60),
    script_id              BIGINT REFERENCES scripts(id) ON DELETE RESTRICT,
    script_sha256          TEXT,
    script_content         TEXT,
    script_timeout_minutes INT,
    target_label           TEXT NOT NULL,
    created_by             TEXT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at             TIMESTAMPTZ NOT NULL,
    canceled_at            TIMESTAMPTZ,
    canceled_by            TEXT,
    CHECK ((action = 'script') = (script_id IS NOT NULL))
);
CREATE INDEX command_runs_created_idx ON command_runs (created_at DESC);

CREATE TABLE command_targets (
    id           BIGSERIAL PRIMARY KEY,
    run_id       BIGINT NOT NULL REFERENCES command_runs(id) ON DELETE CASCADE,
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'sent', 'succeeded', 'failed', 'expired', 'canceled')),
    exit_code    INT,
    output       TEXT NOT NULL DEFAULT '',
    sent_at      TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    UNIQUE (run_id, device_id)
);
-- 報到時查這台未完成的指令：部分索引，沒有指令的裝置幾乎零成本
CREATE INDEX command_targets_open_idx ON command_targets (device_id, id)
    WHERE status IN ('pending', 'sent');
CREATE INDEX command_targets_run_idx ON command_targets (run_id, status);

INSERT INTO settings (key, value) VALUES ('scripts_require_second_approver', 'true')
ON CONFLICT (key) DO NOTHING;
