-- 第四期：軟體派送（套件、派送、每台狀態）

CREATE TABLE packages (
    id                 BIGSERIAL PRIMARY KEY,
    name               TEXT NOT NULL,
    version            TEXT NOT NULL DEFAULT '',
    kind               TEXT NOT NULL CHECK (kind IN ('msi', 'exe')),
    file_name          TEXT NOT NULL,
    size               BIGINT NOT NULL CHECK (size >= 0),
    sha256             TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    msi_product_code   TEXT,
    install_args       TEXT NOT NULL DEFAULT '',
    uninstall_args     TEXT NOT NULL DEFAULT '',
    success_codes      INTEGER[] NOT NULL DEFAULT '{}',
    detect_name        TEXT NOT NULL,
    detect_publisher   TEXT,
    detect_min_version TEXT,
    created_by         TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX packages_sha256_idx ON packages (sha256);

CREATE TABLE deployments (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    package_id      BIGINT NOT NULL REFERENCES packages(id) ON DELETE RESTRICT,
    action          TEXT NOT NULL CHECK (action IN ('install', 'uninstall')),
    stage           TEXT NOT NULL CHECK (stage IN ('pilot', 'all', 'paused', 'stopped')),
    paused_from     TEXT CHECK (paused_from IN ('pilot', 'all')),
    pilot_group_id  BIGINT REFERENCES device_groups(id),
    max_failure_pct INTEGER NOT NULL CHECK (max_failure_pct BETWEEN 1 AND 100),
    min_samples     INTEGER NOT NULL CHECK (min_samples BETWEEN 1 AND 10000),
    revision        INTEGER NOT NULL DEFAULT 1,
    created_by      TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX deployments_package_idx ON deployments (package_id);
CREATE INDEX deployments_pilot_idx ON deployments (pilot_group_id);

CREATE TABLE deployment_groups (
    deployment_id BIGINT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    group_id      BIGINT NOT NULL REFERENCES device_groups(id),
    mode          TEXT NOT NULL CHECK (mode IN ('include', 'exclude')),
    PRIMARY KEY (deployment_id, group_id)
);
CREATE INDEX deployment_groups_group_idx ON deployment_groups (group_id);

CREATE TABLE deployment_status (
    deployment_id BIGINT NOT NULL REFERENCES deployments(id) ON DELETE CASCADE,
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status        TEXT NOT NULL
                  CHECK (status IN ('compliant', 'succeeded', 'reboot_required', 'failed')),
    exit_code     INTEGER,
    message       TEXT NOT NULL DEFAULT '',
    attempts      INTEGER NOT NULL DEFAULT 0,
    revision      INTEGER NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (deployment_id, device_id)
);
CREATE INDEX deployment_status_device_idx ON deployment_status (device_id);
CREATE INDEX deployment_status_status_idx ON deployment_status (deployment_id, status);

-- 任何派送或套件異動都加一，報到端的快取依它判斷是否過期
CREATE TABLE deploy_state (
    id         BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    generation BIGINT NOT NULL DEFAULT 0
);
INSERT INTO deploy_state DEFAULT VALUES;
