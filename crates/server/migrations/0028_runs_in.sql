-- Agent 的執行環境（basic 區段）：host／container／wsl 與細節（虛擬化平台、容器種類、WSL 版本）
ALTER TABLE devices ADD COLUMN runs_in text, ADD COLUMN runs_in_detail text;
