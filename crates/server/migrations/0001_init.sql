CREATE TABLE enroll_tokens (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    group_label TEXT,
    expires_at  TIMESTAMPTZ,
    max_uses    INTEGER NOT NULL CHECK (max_uses > 0),
    used_count  INTEGER NOT NULL DEFAULT 0,
    revoked_at  TIMESTAMPTZ,
    created_by  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id               UUID PRIMARY KEY,
    hostname         TEXT NOT NULL,
    domain           TEXT,
    is_domain_joined BOOLEAN NOT NULL DEFAULT false,
    smbios_uuid      TEXT,
    bios_serial      TEXT,
    management_type  TEXT NOT NULL DEFAULT 'agent'
                     CHECK (management_type IN ('agent', 'legacy_import')),
    status           TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active', 'retired', 'duplicate_suspect')),
    last_seen_at     TIMESTAMPTZ,
    last_ip          TEXT,
    logged_on_user   TEXT,
    boot_time        TIMESTAMPTZ,
    agent_version    TEXT,
    os_caption       TEXT,
    os_build         TEXT,
    section_errors   JSONB NOT NULL DEFAULT '{}',
    enrolled_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    enroll_token_id  BIGINT REFERENCES enroll_tokens(id)
);
CREATE INDEX devices_smbios_uuid_idx ON devices (smbios_uuid);
CREATE INDEX devices_hostname_idx ON devices (hostname);

CREATE TABLE device_certs (
    serial      TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    device_id   UUID NOT NULL REFERENCES devices(id),
    not_after   TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX device_certs_device_idx ON device_certs (device_id);

CREATE TABLE device_hardware (
    device_id    UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    manufacturer TEXT,
    model        TEXT,
    cpu          TEXT,
    ram_mb       BIGINT NOT NULL,
    disks        JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE device_software (
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT,
    publisher    TEXT,
    install_date TEXT,
    arch         TEXT NOT NULL
);
CREATE INDEX device_software_device_idx ON device_software (device_id);
CREATE INDEX device_software_name_idx ON device_software (name);

CREATE TABLE device_patches (
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kb           TEXT NOT NULL,
    installed_on TEXT
);
CREATE INDEX device_patches_device_idx ON device_patches (device_id);
CREATE INDEX device_patches_kb_idx ON device_patches (kb);

CREATE TABLE device_services (
    device_id    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    display_name TEXT,
    start_mode   TEXT NOT NULL,
    state        TEXT NOT NULL,
    binary_path  TEXT
);
CREATE INDEX device_services_device_idx ON device_services (device_id);

CREATE TABLE inventory_sections (
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    section    TEXT NOT NULL,
    hash       TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, section)
);

CREATE TABLE inventory_changes (
    id          BIGSERIAL,
    device_id   UUID NOT NULL,
    section     TEXT NOT NULL,
    change      TEXT NOT NULL CHECK (change IN ('added', 'removed', 'updated')),
    item_key    TEXT NOT NULL,
    old_value   TEXT,
    new_value   TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, detected_at)
) PARTITION BY RANGE (detected_at);
CREATE INDEX inventory_changes_device_idx ON inventory_changes (device_id, detected_at);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);
INSERT INTO settings (key, value) VALUES
    ('checkin_interval_secs', '60'),
    ('software_interval_secs', '3600'),
    ('patches_interval_secs', '3600'),
    ('services_interval_secs', '3600'),
    ('hardware_interval_secs', '86400');
