-- 已拒絕的快取不占用名稱：重新註冊同名的快取時不必先刪除舊紀錄
ALTER TABLE caches DROP CONSTRAINT caches_name_key;
CREATE UNIQUE INDEX caches_name_active ON caches (name) WHERE status <> 'rejected';
