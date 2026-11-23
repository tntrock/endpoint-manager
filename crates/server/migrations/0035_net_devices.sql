-- 網路設備（SNMP，由據點的快取主機查詢）

-- SNMP 帳密：內容以 EM_SECRET_KEY_FILE 的金鑰加密（ChaCha20-Poly1305，nonce 放在前 12 位元組）
CREATE TABLE snmp_credentials (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    version     TEXT NOT NULL CHECK (version IN ('v2c', 'v3')),
    -- v3 的使用者名稱（不是機密，清單上顯示）
    username    TEXT,
    secret_enc  BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE net_devices (
    id                   BIGSERIAL PRIMARY KEY,
    -- 刪除據點前要先刪除它的網路設備（避免設定悄悄消失）
    site_id              BIGINT NOT NULL REFERENCES sites(id),
    name                 TEXT NOT NULL,
    address              TEXT NOT NULL,
    port                 INT NOT NULL DEFAULT 161 CHECK (port BETWEEN 1 AND 65535),
    credential_id        BIGINT NOT NULL REFERENCES snmp_credentials(id),
    enabled              BOOLEAN NOT NULL DEFAULT true,
    cisco_vlan           TEXT NOT NULL DEFAULT 'auto' CHECK (cisco_vlan IN ('auto', 'on', 'off')),
    -- 管理員新增或修改後要立即查詢一次；快取上傳結果後清掉
    poll_requested       BOOLEAN NOT NULL DEFAULT true,
    sys_name             TEXT,
    sys_descr            TEXT,
    sys_location         TEXT,
    sys_contact          TEXT,
    sys_object_id        TEXT,
    uptime_secs          BIGINT,
    model                TEXT,
    serial               TEXT,
    firmware             TEXT,
    last_polled_at       TIMESTAMPTZ,
    last_ok_at           TIMESTAMPTZ,
    last_error           TEXT,
    consecutive_failures INT NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (site_id, address, port)
);
CREATE INDEX net_devices_credential_idx ON net_devices (credential_id);

CREATE TABLE net_interfaces (
    device_id      BIGINT NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    if_index       BIGINT NOT NULL,
    name           TEXT NOT NULL,
    alias          TEXT NOT NULL DEFAULT '',
    if_type        INT NOT NULL,
    admin_up       BOOLEAN NOT NULL,
    oper_up        BOOLEAN NOT NULL,
    speed_mbps     BIGINT,
    mac            TEXT,
    pvid           INT,
    last_change_at TIMESTAMPTZ,
    -- 自動判斷（auto_*）或管理員指定；第二期用來判斷 MAC 位址表上的設備接在哪裡
    role           TEXT NOT NULL DEFAULT 'auto_edge'
                   CHECK (role IN ('auto_edge', 'auto_uplink', 'edge', 'uplink')),
    lldp           JSONB NOT NULL DEFAULT '[]',
    PRIMARY KEY (device_id, if_index)
);

INSERT INTO settings (key, value) VALUES
    ('snmp_system_interval_secs', '900'),
    ('snmp_table_interval_secs', '300')
ON CONFLICT (key) DO NOTHING;
