-- 登錄檔值查詢頁以不分大小寫比對路徑與名稱
CREATE INDEX device_registry_upper_idx ON device_registry (upper(path), upper(name));
