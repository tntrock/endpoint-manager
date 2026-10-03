# 管理網頁改版

日期：2026-10-03

## 1. 目標與範圍

使用者要求：「這個介面實在有點簡陋，請做到至少能拿下某個網頁設計比賽獎項的程度」，範圍選「全面重新設計」。

使用者確認的方向：

- 視覺：**B 監控中心風**。深色為預設、等寬數字、青綠色點綴、資訊密度高。另有淺色主題，採「冷灰」配色（不用純白）。
- 技術：**做法 A**。頁面仍由伺服器產生（askama），搭配自製設計系統（CSS）、少量 JavaScript、伺服器產生的 SVG 圖表。不加前端框架，也不加建置工具。
- 主要使用情境（四項都要照顧）：查某台電腦、監看整體合規與風險、派送與更新、主管報告。
- 這是內部工具：未登入前不放產品說明。

設計稿（已核准，作為實作的視覺依據）：

- `2026-10-03-ui-redesign/dashboard-mockup.html`：儀表板（第二期內容，第一期取其外殼、配色與元件樣式）
- `2026-10-03-ui-redesign/components-mockup.html`：元件樣張；深色與「淺色 1 冷灰」為定案，「淺色 2 暖灰」不採用
- `2026-10-03-ui-redesign/mobile-mockup.html`：手機版面。登入頁改為精簡版（見 §3.7），稿上左半邊的標語與數字不採用

### 1.1 分期

| 期別 | 內容 |
|---|---|
| **第一期（本文件詳述）** | 設計系統、外殼（側邊欄、頂端列、搜尋、主題切換）、所有頁面套用新元件、登入頁、手機版面 |
| 第二期 | 儀表板改版（趨勢圖、需要處理清單、各據點狀態、違規最多的規則）與可列印的主管報告 |
| 第三期 | 裝置體驗：搜尋結果、裝置頁重新編排（狀態摘要、問題清單、時間軸） |
| 第四期 | 作業頁面：合規、派送、更新、遠端指令的表格排序、篩選與批次操作 |

第二～四期各自另寫規格。

### 1.2 限制

- CSP 維持現狀：`default-src 'self'`。不能用 inline script、inline style 屬性、外部字型或 CDN；所有資源由伺服器內嵌提供（`include_str!`）。
- 不新增 Rust 或前端依賴。
- 字型只用 Windows 內建：`"Segoe UI", "Microsoft JhengHei UI", "Microsoft JhengHei", system-ui, sans-serif`；數字用 `"Cascadia Mono", Consolas, ui-monospace, monospace`。
- 網址、表單欄位名稱、htmx 端點都不變；功能與權限行為不變。
- 沒有 JavaScript 時頁面仍可正常使用。JavaScript 只負責加分功能。

## 2. 設計系統（`static/app.css` 重寫）

### 2.1 色彩變數

主題以 `<html data-theme="dark|light">` 切換。沒有設定時，依 `prefers-color-scheme` 決定，預設為深色。

| 變數 | 深色 | 淺色（冷灰） | 用途 |
|---|---|---|---|
| `--bg` | `#070b12` | `#dfe4eb` | 頁面底色 |
| `--panel` | `#0e1623` | `#eef1f5` | 卡片、表格 |
| `--panel2` | `#111c2c` | `#eef1f5` | 卡片漸層上緣 |
| `--line` | `#1b2738` | `#cfd6e0` | 分隔線 |
| `--line2` | `#243349` | `#bfc8d4` | 輸入框、按鈕框線 |
| `--text` | `#dbe5f3` | `#172131` | 內文 |
| `--muted` | `#7d8ba1` | `#4f5c70` | 次要文字 |
| `--faint` | `#4d5b70` | `#7e8a9c` | 提示、ID |
| `--accent` | `#3fd0c9` | `#0e9f98` | 主色（按鈕、選取、焦點框） |
| `--accent-ink` | `#04221f` | `#ffffff` | 主色按鈕上的字 |
| `--ok` | `#46c97a` | `#1e8e4f` | 正常、在線、合規 |
| `--warn` | `#f2b24c` | `#b26b00` | 警告、待核准、中風險 |
| `--bad` | `#f0646b` | `#d03a43` | 錯誤、違規、高風險、危險動作 |
| `--info` | `#8f8cf7` | `#5753d9` | 資訊、進行中、低風險 |
| `--ok-bg` | `rgba(70,201,122,.12)` | `#d6ecdf` | 標籤底色（`--warn-bg`／`--bad-bg`／`--info-bg`／`--accent-bg` 同理，值見元件樣張） |
| `--row` | `#0b121c` | `#e6eaf0` | 表頭底色 |
| `--input` | `#0a111b` | `#f6f8fa` | 輸入框底色 |

深色頁面背景另加兩個淡光暈：右上角青色、左下角紫色，各為 `radial-gradient`，透明度 0.07～0.08。淺色主題不加。

文字對比：兩個主題中，`--text`、`--muted` 與底色的對比都要達到 WCAG AA（一般文字 4.5:1）。`--faint` 只用在非必要資訊（ID、提示文字）。

### 2.2 尺寸

- 字級：內文 14px；頁面標題 22px；區塊標題 14px 粗體；表頭 11.5px，字距 0.06em；小字 12px。
- 圓角：卡片與表格 12px，按鈕與輸入框 9px，標籤 20px（膠囊形）。
- 間距：以 4px 為單位。頁面左右邊距 28px，卡片內距 16px，卡片之間 14px。

### 2.3 元件（class 名稱）

| 元件 | class | 說明 |
|---|---|---|
| 頁首 | `.page-head`（內含 `.crumb`、`h1`、`.sub`、`.actions`） | 每頁頂端：路徑、標題、副標，右側為操作按鈕 |
| 卡片 | `.card`；數字卡 `.card.kpi`（`.kpi-label`、`.kpi-value`） | 數字用 `.num` |
| 按鈕 | `button`／`.btn`；`.btn.primary`、`.btn.danger`、`.btn.ghost`、`.btn.sm` | 現有的 `button.danger` 改為 `.btn.danger` |
| 狀態標籤 | `.tag.ok`／`.warn`／`.bad`／`.info`／`.off` | 圓點加文字；取代現在的 `.badge` |
| 嚴重度 | `.sev.high`／`.medium`／`.low` | 沿用現有 class 名稱，改樣式 |
| 表格 | `table`（預設就是新樣式）、`td.num` 靠右 | 圓角外框、表頭底色、滑過整列反白 |
| 表單 | `.field`（`label`、輸入、`.help`）、`.field.error` | 欄位錯誤時框線變紅，原因寫在下方 |
| 分頁籤 | `.tabs`（`a`，目前所在的加 `.on` 與 `aria-current="page"`）、`.tabs .count` | 用於合併的頁面（§3.3） |
| 提示框 | `.notice`（預設警告）、`.notice.error`、`.notice.ok` | 取代現在的 `.notice` |
| 空狀態 | `.empty`（圖示、說明、建議動作） | 清單沒有資料時 |
| 分頁 | `.pager` | 上一頁、範圍、下一頁 |
| 等寬數字 | `.num` | `font-variant-numeric: tabular-nums` |
| 次要文字 | `.muted`、`.faint` | 沿用 `.muted` |
| 程式碼 | `.code`（`textarea`、`pre`） | 等寬字。取代 `script_form.html` 現有的 `style="font-family: monospace"`，那個屬性目前其實被 CSP 擋掉了 |

### 2.4 圖示

`static/icons.svg` 是一份 SVG sprite，每個圖示是一個 `<symbol id="i-…">`，範本以 `<svg class="icon"><use href="/static/icons.svg#i-…"></use></svg>` 引用。線條 1.4px，`stroke="currentColor"`。

需要的圖示：總覽、裝置、軟體、登錄檔、合規、更新、派送、指令、腳本、據點、金鑰、群組、帳號、通知、稽核、搜尋、主題（太陽／月亮）、選單、登出、使用者。

### 2.5 動態效果

- 換頁：`@view-transition { navigation: auto; }`，主要內容區淡入淡出 150ms，側邊欄不動（`view-transition-name`）。
- 在線燈號有脈動動畫。
- 滑過、按下、焦點都有 120ms 的過場。
- `prefers-reduced-motion: reduce` 時，以上全部關閉。

## 3. 外殼（`templates/base.html`）

### 3.1 版面

- 桌面（寬度 ≥ 900px）：左側欄固定寬 232px、與視窗等高、不隨頁面捲動；右側上方為頂端列（`position: sticky`，半透明加模糊背景），下方為主要內容。
- 手機與窄視窗（< 900px）：側邊欄隱藏；頂端列左側出現選單鈕，按下後側邊欄從左邊滑出，其餘畫面加上暗色遮罩。
- 主要內容最大寬度 1440px。

### 3.2 側邊欄

最上方是標誌（青紫漸層的圓角方塊）、「Endpoint」，下面一行小字是版本。

| 分組 | 項目 | 連結 | 顯示條件 |
|---|---|---|---|
| — | 總覽 | `/` | 所有人 |
| 資產 | 裝置 | `/devices` | 所有人 |
| 資產 | 軟體 | `/software` | 所有人 |
| 資產 | 登錄檔 | `/registry` | 所有人 |
| 安全與合規 | 合規 | `/compliance` | 所有人 |
| 安全與合規 | Windows Update | `/updates` | 所有人 |
| 作業 | 派送 | `/deployments` | 所有人 |
| 作業 | 遠端指令 | `/commands` | 所有人 |
| 作業 | 腳本 | `/scripts` | 平台管理員 |
| 設定 | 註冊金鑰 | `/tokens` | `nav.manage` |
| 設定 | 據點與快取 | `/sites` | 平台管理員 |
| 設定 | 群組 | `/groups` | 平台管理員 |
| 設定 | 帳號 | `/accounts` | 平台管理員 |
| 設定 | 通知 | `/compliance/notify` | 平台管理員 |
| 設定 | 稽核記錄 | `/audit` | 平台管理員 |

- 分組內沒有任何可見項目時，整個分組（含標題）不顯示。
- 目前所在的項目加上 `.on` 與 `aria-current="page"`。判斷方式：每個頁面的 `Nav` 帶一個 `section`（例如 `"devices"`、`"compliance"`），由各頁 handler 設定；子頁面沿用上層的 section，例如 `/devices/{id}` 的 section 是 `devices`。
- 「裝置」旁顯示裝置數，「合規」旁顯示有違規的裝置數（> 0 時以紅色顯示）。數字的載入方式見 §3.5。

### 3.3 合併頁面的分頁籤

以下頁面在 `.page-head` 下方顯示分頁籤，彼此切換。網址不變。

- 合規：總覽 `/compliance`、違規 `/compliance/violations`、規則 `/compliance/rules`、範本 `/compliance/rules/templates`（範本只對平台管理員顯示，與現在相同）
- Windows Update：原則 `/updates`、組建與重開機 `/updates/overview`
- 派送：派送 `/deployments`、套件 `/packages`
- 據點與快取：據點 `/sites`、快取 `/caches`

### 3.4 頂端列

左到右依序是：

1. 選單鈕（只在窄視窗顯示）。
2. 搜尋框：`<form action="/devices" method="get"><input name="q" placeholder="搜尋主機名稱、使用者或 IP…">`，右側提示 `Ctrl K`。
3. 在線狀態：綠點加「N 台在線」。
4. 主題切換鈕。
5. 使用者：顯示名稱與角色，下拉選單裡有「變更密碼」（`/password`）與「登出」（POST `/logout`，帶 CSRF）。

下拉選單用 `<details>` 實作，不需要 JavaScript。

### 3.5 狀態數字（`GET /ui/status`）

- 新端點，回傳一段 HTML 片段，裡面是頂端列的在線數，以及側邊欄的裝置數、違規裝置數，以 htmx `hx-swap-oob` 更新各自的位置。
- `base.html` 用 `hx-get="/ui/status" hx-trigger="load, every 60s"` 載入。這樣不必修改每個頁面的 handler，頁面本身也不會因此變慢。
- 數字依登入者的範圍計算，和裝置清單、合規總覽的範圍相同：群組管理員只算自己的群組。
- 未登入時回 401，htmx 不更新畫面。沒有 JavaScript 時，數字位置顯示「—」。

### 3.6 `static/app.js`

只做三件事：

1. 按 `Ctrl+K`（macOS 為 `⌘K`）或 `/` 時聚焦搜尋框；正在輸入文字時不攔截 `/`。
2. 主題切換：點擊後在 `dark` 與 `light` 間切換，寫入 `localStorage['em-theme']`，並設定 `<html data-theme>`。
   - 為了避免載入時先閃一下錯的主題，`base.html` 的 `<head>` 先同步載入極小的 `static/theme.js`，在畫面出現前套用主題。CSP 不允許 inline script，所以要放成獨立檔案。
3. 手機選單：開關側邊欄、按 Esc 關閉、點遮罩關閉。

現有的 `htmx.min.js`、`upload.js` 保留。

### 3.7 登入頁

- 深色背景，有淡網格與光暈。中間是登入框：標誌、「Endpoint Manager」、帳號、密碼、登入鈕。
- 錯誤訊息用 `.notice.error`。下方一行小字：「連續失敗多次會暫時鎖定帳號。」
- 不放產品說明、標語或任何統計數字。
- 登入頁不載入側邊欄與頂端列，也不呼叫 `/ui/status`。

## 4. 頁面套用

所有範本改用 §2.3 的元件：

- 每頁以 `.page-head` 開頭，取代現在的 `<h1>` 與分散的按鈕。
- 主要的建立或操作按鈕放進 `.actions`。
- 數字欄加 `.num`。
- 狀態一律改用 `.tag`；嚴重度沿用 `.sev`。
- 原本以 `<p>` 排列的操作表單，改放在 `.actions` 或表格的操作欄。
- 清單沒有資料時顯示 `.empty`，不再是空表格。
- 內容區塊用 `.card` 包起來。表格不需要外包卡片，表格本身就有外框。
- 儀表板只把現有內容（狀態卡片、待核准清單）換成新元件；新圖表留給第二期。

需要調整 handler 的地方只有兩處：

- `Nav` 增加 `section` 欄位（§3.2）。
- 合併頁面的分頁籤需要知道目前是哪一頁，由範本依 `section` 與頁面自身決定，不新增後端資料。

## 5. 無障礙

- 對比符合 WCAG AA（§2.1）。
- 所有可操作的元素有清楚的焦點框：`:focus-visible` 時顯示 2px 主色外框，外推 2px。
- 狀態不只靠顏色：`.tag` 有文字，`.sev` 有文字（高／中／低）。
- 側邊欄是 `<nav aria-label="主要">`；目前所在項目用 `aria-current="page"`。
- 手機選單鈕有 `aria-expanded`、`aria-controls`。
- 主題切換鈕有 `aria-label`，文字隨目前狀態改變（「切換為淺色」／「切換為深色」）。
- 頁面最前面有「跳到主要內容」連結，只在鍵盤焦點時顯示。

## 6. 測試

- **範本斷言：** 現有測試中比對 HTML 片段的斷言，凡受改版影響的都要更新。更新後仍須驗證原本的意圖，例如範圍、權限、數字，不能只改成比較寬鬆的比對。
- **新增測試：**
  - 外殼：登入後的頁面都有側邊欄與頂端列；登入頁沒有。
  - 導覽權限：平台管理員看得到「設定」分組的全部項目。群組管理員只看到「註冊金鑰」（若可管理）。檢視者看不到「設定」分組。
  - 目前所在項目：`/devices/{id}` 頁面中，「裝置」有 `aria-current="page"`。
  - `/ui/status`：
    - 數字依範圍計算，例如群組管理員只算自己的群組。
    - 未登入回 401。
    - 回應包含 `hx-swap-oob`。
  - 靜態檔：`/static/icons.svg`（`image/svg+xml`）、`/static/app.js`、`/static/theme.js`（`text/javascript`）回 200 與正確的 Content-Type。
  - CSP：所有範本中不得出現 `style="`、`<script>`（沒有 `src` 的）或 `on…=` 事件屬性。以測試掃描 `templates/` 目錄。
- **外觀檢查（人工加截圖）：**
  - 用測試環境（`em_demo`）與瀏覽器工具截圖，頁面為儀表板、裝置清單、裝置頁、合規總覽、派送詳情、登入頁、手機版面，各截深色與淺色。
  - 截圖附在 PR 說明中。

## 7. 不做

- 第二～四期的內容（§1.1）。
- 自訂字型檔（字型一律用系統內建）。
- 使用者自訂主題色。
- 修改既有功能的行為或權限。
