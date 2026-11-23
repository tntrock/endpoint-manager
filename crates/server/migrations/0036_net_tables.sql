-- 網路設備第二期：MAC 位址表、ARP 表、電腦的網路位置、未管理設備

-- 電腦網卡的 MAC（小寫、冒號分隔），由 device_network 觸發器同步，方便用 MAC 對到電腦
CREATE TABLE device_macs (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac       TEXT NOT NULL,
    PRIMARY KEY (device_id, mac)
);
CREATE INDEX device_macs_mac_idx ON device_macs (mac);

CREATE FUNCTION sync_device_macs() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM device_macs WHERE device_id = NEW.device_id;
    INSERT INTO device_macs (device_id, mac)
    SELECT DISTINCT NEW.device_id, lower(i->>'mac')
    FROM jsonb_array_elements(
             CASE WHEN jsonb_typeof(NEW.data->'interfaces') = 'array'
                  THEN NEW.data->'interfaces' ELSE '[]'::jsonb END) i
    WHERE i->>'mac' ~* '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$';
    RETURN NEW;
END $$;

CREATE TRIGGER device_network_macs AFTER INSERT OR UPDATE OF data ON device_network
    FOR EACH ROW EXECUTE FUNCTION sync_device_macs();

INSERT INTO device_macs (device_id, mac)
SELECT DISTINCT n.device_id, lower(i->>'mac')
FROM device_network n,
     jsonb_array_elements(CASE WHEN jsonb_typeof(n.data->'interfaces') = 'array'
                               THEN n.data->'interfaces' ELSE '[]'::jsonb END) i
WHERE i->>'mac' ~* '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$'
ON CONFLICT DO NOTHING;

-- 這個埠上目前學到幾個 MAC（MAC 表那一輪更新）
ALTER TABLE net_interfaces ADD COLUMN mac_count INT NOT NULL DEFAULT 0;

-- 上行埠：管理員指定，或依 LLDP 自動判斷，或同時有 10 個以上 MAC（接了下游交換器或 AP）
CREATE FUNCTION net_port_is_uplink(role TEXT, mac_count INT) RETURNS BOOLEAN
    LANGUAGE sql IMMUTABLE AS $$
    SELECT role IN ('uplink', 'auto_uplink') OR (role = 'auto_edge' AND mac_count >= 10)
$$;

-- MAC 位址表：最後一次看到超過 30 天就刪除
CREATE TABLE net_mac_sightings (
    device_id  BIGINT NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    if_index   BIGINT NOT NULL,
    mac        TEXT NOT NULL,
    -- 0 表示不知道 VLAN
    vlan       INT NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, if_index, mac, vlan)
);
CREATE INDEX net_mac_sightings_mac_idx ON net_mac_sightings (mac);
CREATE INDEX net_mac_sightings_seen_idx ON net_mac_sightings (last_seen);

CREATE TABLE net_arp (
    device_id  BIGINT NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    ip         INET NOT NULL,
    mac        TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, ip, mac)
);
CREATE INDEX net_arp_mac_idx ON net_arp (mac);
CREATE INDEX net_arp_seen_idx ON net_arp (last_seen);

-- 電腦接在哪個埠：換位置時結束舊的一段、開新的一段；保留 365 天
CREATE TABLE endpoint_locations (
    id            BIGSERIAL PRIMARY KEY,
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac           TEXT NOT NULL,
    net_device_id BIGINT REFERENCES net_devices(id) ON DELETE SET NULL,
    -- 網路設備刪除後仍能顯示歷史
    net_device_name TEXT NOT NULL,
    port_name     TEXT NOT NULL,
    if_index      BIGINT NOT NULL,
    vlan          INT NOT NULL DEFAULT 0,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at      TIMESTAMPTZ
);
CREATE UNIQUE INDEX endpoint_locations_open_idx ON endpoint_locations (device_id, mac)
    WHERE ended_at IS NULL;
CREATE INDEX endpoint_locations_device_idx ON endpoint_locations (device_id, started_at DESC);

-- 標記為「已知」的未管理設備：單一 MAC、廠商前綴（6 個十六進位字元），或某個埠（net_device_id:if_index）
CREATE TABLE net_known_macs (
    id         BIGSERIAL PRIMARY KEY,
    match      TEXT NOT NULL CHECK (match IN ('mac', 'oui', 'port')),
    value      TEXT NOT NULL,
    note       TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (match, value)
);
