-- 違規清單依開始時間排序分頁
CREATE INDEX device_violations_since_idx ON device_violations (since DESC, device_id, rule_id);
