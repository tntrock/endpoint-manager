# 計畫 11：組態基準效能改善

**Goal:** 達成規格 §1.1：三萬台 × 1,000 個登錄檔值時，全量重算 < 5 分鐘、上傳觸發的單台評估 p99 < 20ms。

**Spec:** `docs/superpowers/specs/2026-09-29-config-baseline-design.md` §1.1。設計已於 2026-09-29 經使用者同意（見 PR 說明）。

## Global Constraints
- 只改伺服器，不改 Agent，不加 migration，不加相依套件。
- 使用者可見文字用繁體中文。
- 負載測試未達標時照實記錄，不調整目標。

## Review Focus
1. 平行重算時，同一台裝置不能被兩個工作同時寫入（advisory lock），游標與 generation 語意不變；單台失敗不中斷。
2. 「未知」的進出不寫歷程，但「未知 → 違規」「違規 → 未知」仍要寫；刪除規則時也一樣。
3. 登錄檔差異寫入：值相同時不產生寫入；刪掉的值要刪除；同一批內重複的 (path, name) 不能讓寫入失敗。

### Task 1：平行重算
- `worker.rs`：同一批內以 `EM_RECOMPUTE_CONCURRENCY`（預設 8，範圍 1–32）台同時處理。
- 測試：既有重算測試全過；新增多台（> 並行數）重算結果正確的測試。

### Task 2：「未知」不寫歷程
- `store.rs::apply`：from/to 都屬於 {none, unknown} 的轉換不寫事件。
- `admin.rs` 刪除規則：unknown 的列不寫「→ none」事件。
- 測試：規則上線、資料未收集 → 有 unknown 結果但沒有事件；之後上傳造成違規 → 有「unknown → violating」事件；刪除規則 → 沒有 unknown 的事件。

### Task 3：登錄檔差異寫入
- `inventory.rs::write_payload` Registry：刪除不在新清單的值；以 `ON CONFLICT DO UPDATE ... WHERE IS DISTINCT FROM` 只更新變動的值；輸入先依 (path, name) 去重。
- 測試：相同內容再上傳時各列 `xmin` 不變；改一個值只有那列改變；少掉的值被刪除；重複鍵不失敗。

### Task 4：負載測試與文件
- 依 `docs/loadtest.md` 重跑組態部分，另量「資料不變時再上傳」。更新結果表格與 README 容量說明。
