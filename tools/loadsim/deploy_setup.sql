-- 負載測試用：1 個套件、10 個派送（全部裝置）。
-- 先用 `loadsim make-package --out pkg.bin` 取得 sha256 與大小，把檔案以 sha256 為檔名複製到伺服器的套件目錄，再執行：
--   psql -v sha=<sha256> -v size=<位元組> -f tools/loadsim/deploy_setup.sql
\set ON_ERROR_STOP on
INSERT INTO packages (name, version, kind, file_name, size, sha256, install_args, detect_name, created_by)
VALUES ('Loadsim Package', '1.0', 'exe', 'loadsim.exe', :size, :'sha', '/S', 'Loadsim Package*', 'loadsim');
INSERT INTO deployments (name, package_id, action, stage, max_failure_pct, min_samples, created_by)
SELECT 'load deploy ' || i, (SELECT max(id) FROM packages), 'install', 'all', 100, 10000, 'loadsim'
FROM generate_series(1, 10) i;
UPDATE deploy_state SET generation = generation + 1;
