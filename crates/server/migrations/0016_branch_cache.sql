-- 第七期：分點快取
CREATE TABLE sites (
    id                   BIGSERIAL PRIMARY KEY,
    name                 TEXT NOT NULL UNIQUE,
    cidrs                CIDR[] NOT NULL CHECK (cardinality(cidrs) > 0),
    fallback_to_central  BOOLEAN NOT NULL DEFAULT true,
    bandwidth_limit_mbps INT CHECK (bandwidth_limit_mbps > 0),
    disk_limit_gb        INT NOT NULL DEFAULT 100 CHECK (disk_limit_gb > 0),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE caches (
    id               BIGSERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    site_id          BIGINT UNIQUE REFERENCES sites(id) ON DELETE SET NULL,
    url              TEXT NOT NULL,
    dns_names        TEXT[] NOT NULL,
    csr_pem          TEXT NOT NULL,
    poll_secret_hash TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled', 'rejected')),
    last_seen        TIMESTAMPTZ,
    version          TEXT,
    disk_used_bytes  BIGINT,
    enroll_token_id  BIGINT REFERENCES enroll_tokens(id),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE cache_certs (
    serial       TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL UNIQUE,
    cache_id     BIGINT NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
    not_after    TIMESTAMPTZ NOT NULL,
    pem          TEXT NOT NULL,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE cache_packages (
    cache_id    BIGINT NOT NULL REFERENCES caches(id) ON DELETE CASCADE,
    package_id  BIGINT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    size        BIGINT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (cache_id, package_id)
);
ALTER TABLE enroll_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'device'
    CHECK (kind IN ('device', 'cache'));
ALTER TABLE deployment_status ADD COLUMN source TEXT CHECK (source IN ('cache', 'central'));
CREATE TABLE branch_state (generation BIGINT NOT NULL);
INSERT INTO branch_state VALUES (0);
