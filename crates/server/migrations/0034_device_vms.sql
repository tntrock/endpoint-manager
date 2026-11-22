-- 虛擬化主機上的虛擬機（vms 區段）
CREATE TABLE device_vms (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 每台虛擬機一列，用 BIOS UUID 對到已註冊的裝置（上傳 vms 區段時整批重寫）
CREATE TABLE vm_guests (
    host_id      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    platform     TEXT NOT NULL,
    vm_id        TEXT NOT NULL,
    name         TEXT NOT NULL,
    state        TEXT NOT NULL,
    -- 小寫；另一個是前三段位元組反轉的寫法（有些平台客體讀到的順序相反）
    bios_uuid    TEXT,
    bios_uuid_swapped TEXT,
    PRIMARY KEY (host_id, platform, vm_id)
);
CREATE INDEX vm_guests_uuid_idx ON vm_guests (bios_uuid);
CREATE INDEX vm_guests_uuid_swapped_idx ON vm_guests (bios_uuid_swapped);
CREATE INDEX devices_smbios_uuid_lower_idx ON devices (lower(smbios_uuid));
