-- 裝置頁「遠端指令」分頁依裝置查最近的指令；刪除裝置時的 ON DELETE CASCADE 也需要這個索引
CREATE INDEX command_targets_device_idx ON command_targets (device_id, id DESC);
