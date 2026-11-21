-- 主機上的容器（containers 區段，Linux Agent）
CREATE TABLE device_containers (
    device_id  UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    data       JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
