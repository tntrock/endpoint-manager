-- 負載測試用：據點 10.0.0.0/8（loadsim 回報 10.0.0.1）、1 個套件、1 個派送（全部裝置）、一把快取註冊金鑰。
-- 先用 `loadsim make-package --out pkg.bin` 取得 sha256 與大小，把檔案以 sha256 為檔名複製到伺服器的套件目錄，再執行：
--   psql -v sha=<sha256> -v size=<位元組> -v token=<自訂的快取金鑰明碼> -f tools/loadsim/cache_setup.sql
-- 接著用這把金鑰執行 `endpoint-cache enroll`，再以 cache_approve.sql 核准。
\set ON_ERROR_STOP on
INSERT INTO sites (name, cidrs, fallback_to_central) VALUES ('loadsim', ARRAY['10.0.0.0/8']::cidr[], true);
INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by)
VALUES ('Loadsim Cache Package', '1.0', 'exe', 'loadsim.exe', :size, :'sha', '/S', 'Loadsim Cache Package*', 'loadsim');
INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by)
SELECT 'load cache deploy', (SELECT max(id) FROM packages), 'install', 'all', 100, 10000, 'loadsim';
INSERT INTO enroll_tokens (name, token_hash, max_uses, created_by, kind)
VALUES ('loadsim cache', encode(sha256(convert_to(:'token', 'UTF8')), 'hex'), 1, 'loadsim', 'cache');
UPDATE deploy_state SET generation = generation + 1;
UPDATE branch_state SET generation = generation + 1;
