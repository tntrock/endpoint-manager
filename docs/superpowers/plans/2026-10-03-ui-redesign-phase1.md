# 管理網頁改版第一期（設計系統與外殼）實作計畫

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal：** 用新的設計系統、側邊欄與頂端列外殼、精簡登入頁重做管理網頁的外觀。網址、表單欄位、權限與功能都不變。

**Architecture：**
- 頁面仍由 askama 在伺服器端產生。
- `static/app.css` 整份重寫成設計系統，以 `data-theme` 切換深色與淺色。
- `base.html` 改成側邊欄加頂端列的外殼，導覽連結與分頁籤用 `_macros.html` 的 askama macro 產生。
- 狀態數字由新端點 `GET /ui/status` 回傳 htmx out-of-band 片段。
- 加分功能（搜尋快捷鍵、主題、手機選單、送出前確認）放在 `static/app.js`；`static/theme.js` 在畫面出現前套用主題。

**Tech Stack：** Rust、axum 0.8、askama 0.16、htmx 2.0.11、純 CSS 與 SVG。不新增任何依賴。

**Spec：** `docs/superpowers/specs/2026-10-03-ui-redesign-design.md`；設計稿在同名資料夾 `2026-10-03-ui-redesign/`。

## Global Constraints

- CSP 維持 `default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`：不能有 inline script、`style="` 屬性、`on…=` 事件屬性、外部字型或 CDN。
- 不新增 Rust 或前端依賴。靜態檔一律用 `include_str!` 內嵌。
- 字型：`"Segoe UI", "Microsoft JhengHei UI", "Microsoft JhengHei", system-ui, sans-serif`；數字用 `"Cascadia Mono", Consolas, ui-monospace, monospace`。
- 網址、表單欄位名稱、htmx 端點、功能與權限行為都不變。
- 沒有 JavaScript 時頁面仍可正常使用，JS 只負責加分功能。
- 對比符合 WCAG AA（一般文字 4.5:1）；`--faint` 只用在非必要資訊。
- 範本寫法：
  - 所有給使用者看的文字都用繁體中文（台灣用語）。
  - 程式註解的密度與語氣比照現有程式碼。

## 與規格的差異（計畫審閱時請確認）

1. **淺色主題的語意色與主色加深。** 規格裡的淺色值放在對應的標籤底色上，對比只有 2.9～4.3，達不到規格 §5 的 AA。依實測改為下表，其餘淺色變數不變。

   | 變數 | 規格值 | 改為 | 改後對比 |
   |---|---|---|---|
   | `--ok` | `#1e8e4f` | `#17703f` | 在 `--ok-bg` 上 4.94 |
   | `--warn` | `#b26b00` | `#8a5300` | 在 `--warn-bg` 上 5.12 |
   | `--bad` | `#d03a43` | `#b02a33` | 在 `--bad-bg` 上 4.88 |
   | `--info` | `#5753d9` | `#4a46c4` | 在 `--info-bg` 上 5.28 |
   | `--accent` | `#0e9f98` | `#0a6b66` | 在 `--panel` 上 5.6；白字在主色上 6.35 |

   深色主題的值都已達標，不改。
2. **`app.js` 多做第四件事：送出前確認。** 現有 8 處 `onsubmit="return confirm(…)"`／`onclick` 一直被 CSP 擋掉，所以確認視窗從來沒有出現過。規格 §6 的 CSP 掃描測試也不允許這種屬性。改成 `data-confirm="訊息"`，由 `app.js` 攔截 submit。群組指令表單另用 `data-confirm-skip="collect apply"`，保留原本「重新收集、立即套用不必確認」的意圖。沒有 JS 時不確認，與目前的實際行為相同。
3. **`.field` 用 `<label class="field">` 包住輸入框**，不另外加 `for` 與 `id`。原本的 `<p><label>名稱 <input></label></p>` 只要換掉外層，關聯也不會斷。
4. **表格裡的紅字數字沿用 `<span class="error">`。** `.error` 在新樣式裡就是 `--bad` 色，現有測試不用改。

## Review Focus

1. **群組管理員的狀態數字。** `/ui/status` 的裝置數、違規數、在線數都只算自己的群組，和儀表板、合規總覽一致。由 Task 4 的 `ui_status_counts_by_scope` 釘住。
2. **沒有 JS 的窄視窗。** 側邊欄要排在內容上方，仍然可以導覽；不能被藏起來而無法使用。由 Task 3 的 CSS 規則 `.js .sidebar` 處理（沒有 `.js` 時不隱藏），Task 10 人工驗證。
3. **htmx 載入的片段裡的確認表單。** 例如裝置頁「指令」分頁的重新開機。`app.js` 在 document 上監聽 submit，所以動態插入的表單也會確認。Task 10 人工驗證。
4. **淺色主題的標籤、連結、主色按鈕對比。** 由 Task 2 的色值處理，Task 10 用瀏覽器實測抽查。
5. **CSRF 取值位置改變。** 頂端列的登出表單現在是頁面上第一個 `csrf` 欄位，值與頁面其他表單相同。現有測試的 `csrf_from` 取第一個，Task 3 跑完整個 `web` 測試確認不受影響。

---

## 檔案結構

| 檔案 | 動作 | 負責 |
|---|---|---|
| `crates/server/static/app.css` | 重寫 | 色彩變數、外殼、元件、響應式、動態 |
| `crates/server/static/app.js` | 新增 | 搜尋快捷鍵、主題切換、手機選單、送出前確認 |
| `crates/server/static/theme.js` | 新增 | 在畫面出現前套用主題、標記 `.js` |
| `crates/server/static/icons.svg` | 新增 | SVG sprite |
| `crates/server/src/web/mod.rs` | 修改 | 新靜態檔路由、`/ui/status` 路由、範本 CSP 掃描測試 |
| `crates/server/src/web/auth.rs` | 修改 | `Nav` 加 `section`、`version`；`Nav::new` 取代 `From<&Session>` |
| `crates/server/src/web/dashboard.rs` | 修改 | 抽出 `device_counts`；新增 `status` handler |
| `crates/server/src/web/compliance.rs` | 修改 | 抽出 `devices_violating` |
| `crates/server/src/web/devices.rs`、`accounts.rs` | 修改 | 狀態 class 改成 `.tag` 的 ok／warn／bad／off |
| 其他 `src/web/*.rs` | 修改 | `Nav::from(&s)` 改為 `Nav::new(&s, "<section>")` |
| `crates/server/templates/base.html` | 重寫 | 外殼 |
| `crates/server/templates/_macros.html` | 新增 | 導覽連結、分頁籤、空狀態 |
| `crates/server/templates/*.html` | 修改 | 套用元件 |
| `crates/server/tests/web.rs` 與其他 `tests/*_web.rs` | 修改 | 新測試與受影響的斷言 |

測試指令都要有 `DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres`（Docker `em-postgres`）。以下寫 `$DB` 代表這個前綴。

---

### Task 1：靜態資源與 CSP 清理

**Files：**
- Create：`crates/server/static/app.js`、`crates/server/static/theme.js`、`crates/server/static/icons.svg`
- Modify：`crates/server/src/web/mod.rs`（路由與測試）
- Modify：`templates/caches.html`、`commands.html`、`commands_tab.html`、`command_detail.html`、`script_detail.html`、`sites.html`、`update_detail.html`（inline 事件改成 `data-confirm`），`script_form.html`（`style=` 改為 `class="code"`）
- Test：`crates/server/tests/web.rs::static_assets_served`、`src/web/mod.rs::tests::templates_have_no_inline_code`

**Interfaces：**
- Produces：
  - `/static/app.js`、`/static/theme.js`（`text/javascript; charset=utf-8`）與 `/static/icons.svg`（`image/svg+xml`）。
  - icons.svg 的 symbol id 為 `i-overview i-devices i-software i-registry i-compliance i-updates i-deploy i-command i-script i-site i-key i-group i-account i-notify i-audit i-search i-sun i-moon i-menu i-logout i-user i-empty`。
  - 表單屬性 `data-confirm`、`data-confirm-skip`。
  - CSS 用的 `.js` class 由 theme.js 加在 `<html>` 上。

- [ ] **Step 1：寫失敗的測試**

`src/web/mod.rs` 的 `mod tests` 加：

```rust
    /// CSP 不允許 inline style、inline script 與事件屬性：寫了也不會生效
    #[test]
    fn templates_have_no_inline_code() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let html = std::fs::read_to_string(&path).unwrap().to_lowercase();
            let name = path.display();
            assert!(!html.contains("style=") && !html.contains("<style"), "{name}: inline style");
            for (i, _) in html.match_indices("<script") {
                let tag = html[i..].split('>').next().unwrap();
                assert!(tag.contains(" src="), "{name}: inline script");
            }
            for (i, _) in html.match_indices(" on") {
                let rest = &html[i + 1..];
                let attr: String = rest.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
                assert!(
                    !(attr.len() > 2 && rest[attr.len()..].starts_with('=')),
                    "{name}: 事件屬性 {attr}"
                );
            }
        }
    }
```

`tests/web.rs` 的 `static_assets_served` 最後加：

```rust
    for (path, ty) in [
        ("/static/app.js", "text/javascript"),
        ("/static/theme.js", "text/javascript"),
        ("/static/icons.svg", "image/svg+xml"),
    ] {
        let r = c.get(s.web_url(path)).send().await.unwrap();
        assert_eq!(r.status(), 200, "{path}");
        assert!(r.headers()["content-type"].to_str().unwrap().starts_with(ty), "{path}");
    }
```

- [ ] **Step 2：確認失敗**

執行：`cd crates/server && $DB cargo test -p endpoint-server --lib templates_have_no_inline_code`
預期：FAIL，訊息指出 `inline style`（`script_form.html`）或某個事件屬性。

執行：`$DB cargo test -p endpoint-server --test web static_assets_served`
預期：FAIL，`/static/app.js` 回 404。

- [ ] **Step 3：新增 `static/theme.js`**

```js
// 在畫面出現前套用主題，避免閃一下錯的顏色（CSP 不允許 inline script，所以是獨立檔案）
(function (root) {
  root.classList.add('js');
  try {
    var t = localStorage.getItem('em-theme');
    if (t === 'light' || t === 'dark') root.dataset.theme = t;
  } catch (e) {}
})(document.documentElement);
```

- [ ] **Step 4：新增 `static/app.js`**

```js
// 外殼的加分功能：搜尋快捷鍵、主題切換、手機選單、送出前確認。沒有 JS 時頁面照常可用
(function () {
  var root = document.documentElement;

  function theme() {
    return root.dataset.theme ||
      (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  }

  function paintThemeButton(btn) {
    var light = theme() === 'light';
    btn.setAttribute('aria-label', light ? '切換為深色' : '切換為淺色');
    btn.querySelector('use').setAttribute('href', '/static/icons.svg#' + (light ? 'i-moon' : 'i-sun'));
  }

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.querySelector('.theme-btn');
    if (btn) {
      btn.hidden = false;
      paintThemeButton(btn);
      btn.addEventListener('click', function () {
        var next = theme() === 'light' ? 'dark' : 'light';
        root.dataset.theme = next;
        try { localStorage.setItem('em-theme', next); } catch (e) {}
        paintThemeButton(btn);
      });
    }

    var menu = document.querySelector('.menu-btn');
    function setMenu(open) {
      document.body.classList.toggle('menu-open', open);
      if (menu) menu.setAttribute('aria-expanded', String(open));
    }
    if (menu) {
      menu.addEventListener('click', function () {
        setMenu(!document.body.classList.contains('menu-open'));
      });
    }
    var scrim = document.querySelector('.scrim');
    if (scrim) scrim.addEventListener('click', function () { setMenu(false); });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { setMenu(false); return; }
      var q = document.getElementById('q');
      if (!q) return;
      var t = e.target;
      var typing = t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName);
      if (((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') || (e.key === '/' && !typing)) {
        e.preventDefault();
        q.focus();
        q.select();
      }
    });
  });

  // 危險動作送出前確認（CSP 不允許 inline onsubmit）；監聽 document，htmx 載入的表單也適用
  document.addEventListener('submit', function (e) {
    var f = e.target;
    var msg = f.dataset.confirm;
    if (!msg) return;
    var action = f.elements.action;
    var skip = (f.dataset.confirmSkip || '').split(' ');
    if (action && skip.indexOf(action.value) >= 0) return;
    if (!confirm(msg)) e.preventDefault();
  });
})();
```

- [ ] **Step 5：新增 `static/icons.svg`**

```xml
<svg xmlns="http://www.w3.org/2000/svg">
<symbol id="i-overview" viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></symbol>
<symbol id="i-devices" viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></symbol>
<symbol id="i-software" viewBox="0 0 24 24"><path d="M12 3 20 7.5v9L12 21l-8-4.5v-9z"/><path d="m4 7.5 8 4.5 8-4.5M12 12v9"/></symbol>
<symbol id="i-registry" viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></symbol>
<symbol id="i-compliance" viewBox="0 0 24 24"><path d="M12 3 4 6v6c0 5 3.4 8.3 8 9 4.6-.7 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/></symbol>
<symbol id="i-updates" viewBox="0 0 24 24"><path d="M20 11a8 8 0 0 0-14.9-3.9L4 9M4 4v5h5M4 13a8 8 0 0 0 14.9 3.9L20 15M20 20v-5h-5"/></symbol>
<symbol id="i-deploy" viewBox="0 0 24 24"><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4"/></symbol>
<symbol id="i-command" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/></symbol>
<symbol id="i-script" viewBox="0 0 24 24"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6M10 13l-2 2 2 2M14 13l2 2-2 2"/></symbol>
<symbol id="i-site" viewBox="0 0 24 24"><path d="M12 21s-7-6.1-7-11a7 7 0 0 1 14 0c0 4.9-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></symbol>
<symbol id="i-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 9.2-9.2M16 7l3 3M14 9l2 2"/></symbol>
<symbol id="i-group" viewBox="0 0 24 24"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6"/></symbol>
<symbol id="i-account" viewBox="0 0 24 24"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.5"/><path d="M5.5 17a3.5 3.5 0 0 1 7 0M15 10h3M15 14h3"/></symbol>
<symbol id="i-notify" viewBox="0 0 24 24"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9M10.3 21a1.9 1.9 0 0 0 3.4 0"/></symbol>
<symbol id="i-audit" viewBox="0 0 24 24"><rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1M9 10h6M9 14h6M9 18h3"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></symbol>
<symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></symbol>
<symbol id="i-moon" viewBox="0 0 24 24"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></symbol>
<symbol id="i-menu" viewBox="0 0 24 24"><path d="M4 6h16M4 12h16M4 18h16"/></symbol>
<symbol id="i-logout" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/></symbol>
<symbol id="i-user" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/></symbol>
<symbol id="i-empty" viewBox="0 0 24 24"><path d="M3 13h5l1.5 3h5L16 13h5"/><path d="M5.5 5h13L21 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-6z"/></symbol>
</svg>
```

- [ ] **Step 6：在 `web_router` 加路由**

放在 `/static/app.css` 那一段旁邊，寫法沿用現有的 closure：

```rust
        .route(
            "/static/app.js",
            get(|| async {
                asset(
                    include_str!("../../static/app.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/static/theme.js",
            get(|| async {
                asset(
                    include_str!("../../static/theme.js"),
                    "text/javascript; charset=utf-8",
                )
            }),
        )
        .route(
            "/static/icons.svg",
            get(|| async { asset(include_str!("../../static/icons.svg"), "image/svg+xml") }),
        )
```

- [ ] **Step 7：把 inline 事件換成 `data-confirm`**

每處只改屬性，確認訊息照抄原文：

| 檔案 | 原本 | 改成 |
|---|---|---|
| `caches.html` | `<form … onsubmit="return confirm('刪除快取？之後要重新註冊才能使用。')">` | `<form … data-confirm="刪除快取？之後要重新註冊才能使用。">` |
| `command_detail.html` | `onsubmit="return confirm('取消後還沒執行的裝置不會再執行；已在執行的無法中止。確定取消？')"` | `data-confirm="取消後還沒執行的裝置不會再執行；已在執行的無法中止。確定取消？"` |
| `commands_tab.html`（3 處） | `onsubmit="return confirm('…')"` | `data-confirm="…"`（三段訊息照抄） |
| `script_detail.html` | `onsubmit="return confirm('確定刪除這個腳本？')"` | `data-confirm="確定刪除這個腳本？"` |
| `sites.html` | `onsubmit="return confirm('刪除據點？這個據點的端點會改向中央下載。')"` | `data-confirm="刪除據點？這個據點的端點會改向中央下載。"` |
| `update_detail.html` | `onsubmit="return confirm('刪除後，這些群組的電腦會移除 Agent 寫入的 Windows Update 設定。確定刪除？')"` | `data-confirm="刪除後，這些群組的電腦會移除 Agent 寫入的 Windows Update 設定。確定刪除？"` |
| `commands.html` | `<form method="post" action="/commands">`，以及按鈕上的 `<button onclick="…">送出</button>` | `<form method="post" action="/commands" data-confirm="確定要對整個群組執行？" data-confirm-skip="collect apply">` 與 `<button>送出</button>` |
| `script_form.html` | `<textarea … style="font-family: monospace" required>` | `<textarea … class="code" required>` |

- [ ] **Step 8：確認通過**

執行：`$DB cargo test -p endpoint-server --lib templates_have_no_inline_code`
預期：PASS。

執行：`$DB cargo test -p endpoint-server --test web static_assets_served`
預期：PASS。

- [ ] **Step 9：Commit**

```bash
git add crates/server/static crates/server/src/web/mod.rs crates/server/templates crates/server/tests/web.rs
git commit -m "feat(web): 新增 app.js、theme.js、圖示，危險動作改用 data-confirm（原 inline 事件被 CSP 擋掉）"
```

---

### Task 2：設計系統（`static/app.css` 重寫）

**Files：**
- Modify：`crates/server/static/app.css`（整份取代）
- Test：`crates/server/tests/web.rs::static_assets_served`

**Interfaces：**
- Produces（後續範本使用的 class）：
  - 外殼：`.app` `.sidebar` `.brand` `.logo` `.nav-group` `.icon` `.count(.hot)` `.topbar` `.search` `.live` `.dot` `.user` `.avatar` `.menu` `.icon-btn` `.menu-btn` `.theme-btn` `.scrim` `.skip`
  - 頁首與卡片：`.page-head` `.crumb` `.sub` `.actions` `.card` `.cards` `.kpi` `.kpi-label` `.kpi-value`
  - 按鈕：`.btn(.primary/.danger/.ghost/.sm)`
  - 標籤：`.tag(.ok/.warn/.bad/.info/.off)` `.sev(.high/.medium/.low)`
  - 表單：`.field` `.help` `.field.error` `.row` `.checks` `form.filters`
  - 分頁與提示：`.tabs(.on)` `.chips` `.notice(.error/.ok)` `.empty` `.pager`
  - 文字：`.num` `.muted` `.faint` `.error` `.ok` `.code`
  - 登入頁：`.login` `.login-box` `.foot`

- [ ] **Step 1：寫失敗的測試**

`static_assets_served` 原本只檢查 app.css 的 content-type，在那之後加上：

```rust
    let css = c.get(s.web_url("/static/app.css")).send().await.unwrap().text().await.unwrap();
    // 兩個主題、系統偏好、減少動態都要有
    for needle in [
        r#":root[data-theme="light"]"#,
        "prefers-color-scheme: light",
        "prefers-reduced-motion: reduce",
        "@view-transition",
    ] {
        assert!(css.contains(needle), "app.css 缺少 {needle}");
    }
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test web static_assets_served`
預期：FAIL，`app.css 缺少 :root[data-theme="light"]`。

- [ ] **Step 3：整份取代 `static/app.css`**

```css
/* 設計系統。深色為預設；淺色由 <html data-theme> 或系統偏好決定（theme.js 先套用使用者的選擇） */
:root {
  color-scheme: dark;
  --bg: #070b12; --panel: #0e1623; --panel2: #111c2c; --line: #1b2738; --line2: #243349;
  --text: #dbe5f3; --muted: #7d8ba1; --faint: #4d5b70;
  --accent: #3fd0c9; --accent-ink: #04221f;
  --ok: #46c97a; --warn: #f2b24c; --bad: #f0646b; --info: #8f8cf7;
  --ok-bg: rgba(70,201,122,.12); --warn-bg: rgba(242,178,76,.12); --bad-bg: rgba(240,100,107,.13);
  --info-bg: rgba(143,140,247,.13); --accent-bg: rgba(63,208,201,.12);
  --row: #0b121c; --input: #0a111b; --side: #090e17; --top: rgba(7,11,18,.72);
  --glow: radial-gradient(1200px 600px at 80% -10%, rgba(63,208,201,.08), transparent 60%),
          radial-gradient(900px 500px at -10% 110%, rgba(143,140,247,.07), transparent 60%);
  --shadow: 0 12px 30px -10px rgba(0,0,0,.6);
  --sans: "Segoe UI", "Microsoft JhengHei UI", "Microsoft JhengHei", system-ui, sans-serif;
  --mono: "Cascadia Mono", Consolas, ui-monospace, monospace;
}
/* 淺色（冷灰）：語意色與主色比規格稍深，讓標籤與連結達到 AA */
:root[data-theme="light"] {
  color-scheme: light;
  --bg: #dfe4eb; --panel: #eef1f5; --panel2: #eef1f5; --line: #cfd6e0; --line2: #bfc8d4;
  --text: #172131; --muted: #4f5c70; --faint: #7e8a9c;
  --accent: #0a6b66; --accent-ink: #ffffff;
  --ok: #17703f; --warn: #8a5300; --bad: #b02a33; --info: #4a46c4;
  --ok-bg: #d6ecdf; --warn-bg: #f3e6cb; --bad-bg: #f2d9dc; --info-bg: #dedcf5; --accent-bg: #d3ebea;
  --row: #e6eaf0; --input: #f6f8fa; --side: #e7ebf0; --top: rgba(223,228,235,.82);
  --glow: none; --shadow: 0 12px 30px -12px rgba(23,33,49,.25);
}
@media (prefers-color-scheme: light) {
  :root:not([data-theme="dark"]) {
    color-scheme: light;
    --bg: #dfe4eb; --panel: #eef1f5; --panel2: #eef1f5; --line: #cfd6e0; --line2: #bfc8d4;
    --text: #172131; --muted: #4f5c70; --faint: #7e8a9c;
    --accent: #0a6b66; --accent-ink: #ffffff;
    --ok: #17703f; --warn: #8a5300; --bad: #b02a33; --info: #4a46c4;
    --ok-bg: #d6ecdf; --warn-bg: #f3e6cb; --bad-bg: #f2d9dc; --info-bg: #dedcf5; --accent-bg: #d3ebea;
    --row: #e6eaf0; --input: #f6f8fa; --side: #e7ebf0; --top: rgba(223,228,235,.82);
    --glow: none; --shadow: 0 12px 30px -12px rgba(23,33,49,.25);
  }
}

/* 基本 */
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; min-height: 100vh; background: var(--glow), var(--bg); background-attachment: fixed;
  color: var(--text); font: 14px/1.5 var(--sans); -webkit-font-smoothing: antialiased; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
h1 { font-size: 22px; margin: 0; font-weight: 650; letter-spacing: .01em; }
h2 { font-size: 14px; margin: 24px 0 10px; font-weight: 650; }
h3 { font-size: 13px; margin: 18px 0 8px; color: var(--muted); letter-spacing: .04em; }
p { margin: 0 0 12px; }
.num { font-family: var(--mono); font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); }
.faint { color: var(--faint); }
.error { color: var(--bad); }
.ok { color: var(--ok); }
code, pre, .code { font-family: var(--mono); font-size: 12.5px; }
pre { background: var(--input); border: 1px solid var(--line); border-radius: 9px; padding: 10px 12px;
  margin: 0 0 14px; overflow: auto; white-space: pre-wrap; word-break: break-all; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.skip { position: absolute; left: -999px; top: 8px; z-index: 30; padding: 6px 12px; border-radius: 9px;
  background: var(--accent); color: var(--accent-ink); }
.skip:focus { left: 8px; }
.icon { width: 16px; height: 16px; flex: none; fill: none; stroke: currentColor; stroke-width: 1.4;
  stroke-linecap: round; stroke-linejoin: round; }

/* 外殼 */
.app { display: grid; grid-template-columns: 232px minmax(0, 1fr); min-height: 100vh; }
.sidebar { position: sticky; top: 0; height: 100vh; overflow-y: auto; padding: 18px 14px;
  background: var(--side); border-right: 1px solid var(--line); view-transition-name: sidebar; }
.brand { display: flex; align-items: center; gap: 10px; padding: 4px 8px 12px; color: var(--text); }
.brand:hover { text-decoration: none; }
.brand b { font-size: 15px; letter-spacing: .02em; }
.brand small { display: block; color: var(--faint); font-size: 11px; font-family: var(--mono); }
.logo { width: 30px; height: 30px; flex: none; border-radius: 9px; display: grid; place-items: center;
  background: conic-gradient(from 210deg, #3fd0c9, #8f8cf7, #3fd0c9); box-shadow: 0 0 24px rgba(63,208,201,.35); }
.logo::after { content: ""; width: 12px; height: 12px; border-radius: 3px; background: var(--bg); transform: rotate(45deg); }
.nav-group { color: var(--faint); font-size: 11px; letter-spacing: .12em; margin: 16px 10px 6px; }
.sidebar nav a { position: relative; display: flex; align-items: center; gap: 10px; padding: 7px 10px;
  border-radius: 8px; color: var(--muted); font-size: 13.5px; transition: background .12s, color .12s; }
.sidebar nav a:hover { background: var(--accent-bg); color: var(--text); text-decoration: none; }
.sidebar nav a.on { background: linear-gradient(90deg, var(--accent-bg), transparent); color: var(--text); font-weight: 600; }
.sidebar nav a.on::before { content: ""; position: absolute; left: -14px; top: 8px; bottom: 8px; width: 3px;
  border-radius: 0 3px 3px 0; background: var(--accent); box-shadow: 0 0 10px var(--accent); }
.count { margin-left: auto; padding: 0 6px; border-radius: 10px; font-size: 11px; background: var(--row); color: var(--muted); }
.count.hot { background: var(--bad-bg); color: var(--bad); }
.shell { min-width: 0; }
.topbar { position: sticky; top: 0; z-index: 5; display: flex; align-items: center; gap: 14px; padding: 12px 28px;
  border-bottom: 1px solid var(--line); background: var(--top); backdrop-filter: blur(10px); }
.search { flex: 1; max-width: 520px; display: flex; align-items: center; gap: 8px; padding: 0 10px;
  background: var(--panel); border: 1px solid var(--line2); border-radius: 10px; color: var(--faint); }
.search:focus-within { outline: 2px solid var(--accent); outline-offset: 1px; }
.search input { flex: 1; min-width: 0; border: 0; background: transparent; padding: 8px 0; outline: none; }
kbd { font: 11px var(--mono); color: var(--muted); border: 1px solid var(--line2); border-bottom-width: 2px;
  border-radius: 5px; padding: 1px 6px; }
.live { display: flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; white-space: nowrap; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); animation: pulse 2s infinite; }
@keyframes pulse {
  0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--ok) 60%, transparent); }
  70%, 100% { box-shadow: 0 0 0 8px transparent; }
}
.icon-btn { display: inline-grid; place-items: center; width: 34px; height: 34px; padding: 0; }
.menu-btn { display: none; }
.user { position: relative; margin-left: auto; }
.user summary { display: flex; align-items: center; gap: 8px; padding: 4px 8px; border-radius: 9px;
  cursor: pointer; list-style: none; }
.user summary::-webkit-details-marker { display: none; }
.user summary:hover { background: var(--accent-bg); }
.avatar { width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center;
  background: linear-gradient(135deg, #2b5876, #4e4376); color: #fff; font-size: 12px; font-weight: 700; }
.user .menu { position: absolute; right: 0; top: calc(100% + 6px); z-index: 10; min-width: 180px; padding: 6px;
  background: var(--panel); border: 1px solid var(--line2); border-radius: 10px; box-shadow: var(--shadow); }
.user .menu a, .user .menu button { display: flex; width: 100%; gap: 8px; padding: 7px 10px; border: 0;
  border-radius: 7px; background: none; color: var(--text); font-size: 13px; text-align: left; }
.user .menu a:hover, .user .menu button:hover { background: var(--accent-bg); text-decoration: none; }
.user .menu form { margin: 0; }
main { max-width: 1440px; padding: 24px 28px 48px; view-transition-name: main; }
.scrim { display: none; }

/* 頁首、卡片 */
.page-head { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px; flex-wrap: wrap; margin-bottom: 18px; }
.crumb { font-size: 12px; color: var(--muted); margin-bottom: 4px; }
.crumb a { color: var(--muted); }
.sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; }
.page-head .actions { margin: 0; }
.actions form, form.inline { display: inline-flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 0; }
.card { position: relative; background: linear-gradient(180deg, var(--panel2), var(--panel));
  border: 1px solid var(--line); border-radius: 12px; padding: 16px; margin-bottom: 14px; }
.card > h2:first-child, .card > h3:first-child { margin-top: 0; }
.card > :last-child { margin-bottom: 0; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-bottom: 14px; }
.cards .card { margin: 0; }
.kpi-label { color: var(--muted); font-size: 12px; letter-spacing: .06em; }
.kpi-value { font-size: 30px; font-weight: 600; line-height: 1.15; margin-top: 4px; }
.kpi-value small { font-size: 14px; color: var(--muted); font-weight: 400; }

/* 按鈕 */
button, .btn { display: inline-flex; align-items: center; gap: 6px; padding: 7px 13px; border-radius: 9px;
  border: 1px solid var(--line2); background: var(--panel); color: var(--text); font: inherit; font-size: 13px;
  line-height: 1.4; cursor: pointer; text-decoration: none; transition: background .12s, border-color .12s, transform .12s; }
button:hover, .btn:hover { border-color: var(--accent); text-decoration: none; }
button:active, .btn:active { transform: translateY(1px); }
button:disabled { opacity: .5; cursor: not-allowed; }
.btn.primary { background: var(--accent); border-color: transparent; color: var(--accent-ink); font-weight: 600; }
.btn.primary:hover { border-color: transparent; filter: brightness(1.08); }
.btn.danger { color: var(--bad); border-color: color-mix(in srgb, var(--bad) 40%, transparent); }
.btn.danger:hover { background: var(--bad-bg); border-color: var(--bad); }
.btn.ghost { background: transparent; border-color: transparent; color: var(--muted); }
.btn.sm { padding: 4px 9px; font-size: 12px; border-radius: 7px; }

/* 狀態標籤、嚴重度 */
.tag { display: inline-flex; align-items: center; gap: 5px; padding: 1px 9px 1px 7px; border-radius: 20px;
  font-size: 12px; font-weight: 500; white-space: nowrap;
  background: color-mix(in srgb, var(--muted) 14%, transparent); color: var(--muted); }
.tag::before { content: ""; width: 6px; height: 6px; border-radius: 50%; background: currentColor; }
.tag.ok { background: var(--ok-bg); color: var(--ok); }
.tag.warn { background: var(--warn-bg); color: var(--warn); }
.tag.bad { background: var(--bad-bg); color: var(--bad); }
.tag.info { background: var(--info-bg); color: var(--info); }
.sev { padding: 1px 7px; border-radius: 5px; font-size: 11px; font-weight: 700; letter-spacing: .04em; white-space: nowrap; }
.sev.high { background: var(--bad-bg); color: var(--bad); }
.sev.medium { background: var(--warn-bg); color: var(--warn); }
.sev.low { background: var(--info-bg); color: var(--info); }

/* 表格 */
table { width: 100%; margin: 0 0 16px; border-collapse: separate; border-spacing: 0; overflow: hidden;
  background: var(--panel); border: 1px solid var(--line); border-radius: 12px; font-size: 13px; }
th { padding: 9px 12px; text-align: left; vertical-align: top; font-size: 11.5px; font-weight: 600;
  letter-spacing: .06em; color: var(--muted); background: var(--row); border-bottom: 1px solid var(--line); }
td { padding: 9px 12px; vertical-align: top; border-bottom: 1px solid var(--line); }
tr:last-child > td, tr:last-child > th { border-bottom: 0; }
tr:hover > td { background: color-mix(in srgb, var(--accent) 5%, transparent); }
td.num, th.num { text-align: right; }
td .faint { display: block; font-size: 11px; font-family: var(--mono); }

/* 表單 */
input, select, textarea { max-width: 100%; padding: 7px 11px; border: 1px solid var(--line2); border-radius: 9px;
  background: var(--input); color: var(--text); font: inherit; }
input[type=checkbox], input[type=radio] { padding: 0; accent-color: var(--accent); }
input[type=file] { padding: 5px; }
input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.field { display: grid; gap: 5px; margin: 0 0 12px; font-size: 12.5px; color: var(--muted); }
.field input, .field select, .field textarea { font-size: 14px; }
.field textarea { width: 100%; }
.help { display: block; font-size: 12px; color: var(--muted); }
.field.error input, .field.error select, .field.error textarea { border-color: var(--bad); }
.field.error .help { color: var(--bad); }
.row { display: flex; flex-wrap: wrap; gap: 4px 14px; align-items: flex-end; }
.checks { display: flex; flex-wrap: wrap; gap: 6px 16px; margin: 0 0 12px; }
.checks label { display: inline-flex; align-items: center; gap: 6px; font-size: 13px; }
fieldset { margin: 0 0 14px; padding: 12px 16px 4px; border: 1px solid var(--line); border-radius: 12px; background: var(--panel); }
legend { padding: 0 6px; color: var(--muted); font-size: 12.5px; font-weight: 600; }
form.filters { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 14px; }
progress { width: 12em; vertical-align: middle; accent-color: var(--accent); }

/* 分頁籤、篩選、提示、空狀態、分頁 */
.tabs { display: flex; gap: 2px; margin: 0 0 16px; overflow-x: auto; border-bottom: 1px solid var(--line); }
.tabs a, .tabs button { margin-bottom: -1px; padding: 8px 14px; border: 0; border-bottom: 2px solid transparent;
  border-radius: 0; background: none; color: var(--muted); font-size: 13px; white-space: nowrap; }
.tabs a:hover, .tabs button:hover { color: var(--text); border-bottom-color: var(--line2); text-decoration: none; }
.tabs .on { color: var(--text); border-bottom-color: var(--accent); font-weight: 600; }
.tabs .count { margin-left: 6px; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 0 0 12px; }
.chips a, .chips strong { padding: 3px 10px; border: 1px solid var(--line2); border-radius: 20px; font-size: 12.5px; color: var(--muted); }
.chips a:hover { color: var(--text); text-decoration: none; }
.chips strong { background: var(--accent-bg); border-color: var(--accent); color: var(--text); font-weight: 600; }
.notice { margin: 0 0 14px; padding: 10px 14px; border: 1px solid color-mix(in srgb, var(--warn) 35%, transparent);
  border-radius: 10px; background: var(--warn-bg); word-break: break-word; }
.notice.error { border-color: color-mix(in srgb, var(--bad) 35%, transparent); background: var(--bad-bg); }
.notice.ok { border-color: color-mix(in srgb, var(--ok) 35%, transparent); background: var(--ok-bg); }
.notice p { margin: 0 0 6px; }
.notice p:last-child { margin: 0; }
.empty { margin: 0 0 14px; padding: 28px; border: 1px dashed var(--line2); border-radius: 12px; text-align: center; color: var(--muted); }
.empty .icon { display: block; width: 32px; height: 32px; margin: 0 auto 8px; color: var(--faint); }
.pager { display: flex; gap: 8px; align-items: center; margin: 0 0 14px; font-size: 12.5px; color: var(--muted); }

/* 登入頁 */
.login { display: grid; place-items: center; padding: 24px;
  background-image: var(--glow), linear-gradient(color-mix(in srgb, var(--accent) 6%, transparent) 1px, transparent 1px),
    linear-gradient(90deg, color-mix(in srgb, var(--accent) 6%, transparent) 1px, transparent 1px);
  background-size: auto, auto, 32px 32px, 32px 32px; }
.login-box { width: 100%; max-width: 360px; padding: 32px 28px; background: var(--panel);
  border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow); }
.login-box .brand { flex-direction: column; padding: 0 0 22px; text-align: center; }
.login-box .logo { width: 40px; height: 40px; border-radius: 11px; }
.login-box .logo::after { width: 15px; height: 15px; background: var(--panel); }
.login-box .field input { width: 100%; }
.login-box .btn.primary { width: 100%; justify-content: center; padding: 9px; margin-top: 6px; }
.foot { margin: 16px 0 0; font-size: 12px; color: var(--muted); text-align: center; }

/* 窄視窗：有 JS 時側邊欄變抽屜；沒有 JS 時排在內容上方 */
@media (max-width: 899px) {
  .app { grid-template-columns: minmax(0, 1fr); }
  .sidebar { position: static; height: auto; }
  .js .sidebar { position: fixed; inset: 0 auto 0 0; z-index: 20; width: 260px; height: 100vh;
    transform: translateX(-100%); transition: transform .2s; }
  .js .menu-open .sidebar { transform: none; }
  .js .menu-open .scrim { display: block; position: fixed; inset: 0; z-index: 15; background: rgba(3,6,10,.6); }
  .js .menu-btn { display: inline-grid; }
  .topbar { gap: 10px; padding: 10px 14px; }
  .live, kbd, .user-name { display: none; }
  main { padding: 16px 14px 40px; }
  table { display: block; overflow-x: auto; }
}

/* 換頁淡入淡出；減少動態時全部關閉 */
@view-transition { navigation: auto; }
::view-transition-old(main), ::view-transition-new(main) { animation-duration: 150ms; }
@media (prefers-reduced-motion: reduce) {
  @view-transition { navigation: none; }
  *, *::before, *::after { animation: none !important; transition: none !important; }
}
```

- [ ] **Step 4：確認通過**

執行：`$DB cargo test -p endpoint-server --test web static_assets_served`
預期：PASS。

- [ ] **Step 5：Commit**

```bash
git add crates/server/static/app.css crates/server/tests/web.rs
git commit -m "feat(web): 重寫 app.css 為設計系統（深色／冷灰淺色、元件、響應式）"
```

---

### Task 3：`Nav.section` 與外殼

**Files：**
- Modify：`crates/server/src/web/auth.rs:302-337`（`Nav`）
- Modify：所有呼叫 `Nav::from(&s)` 的 `src/web/*.rs`（共 48 處）
- Create：`crates/server/templates/_macros.html`
- Modify：`crates/server/templates/base.html`（整份取代）
- Test：`crates/server/tests/web.rs`（新增 `shell_and_nav_by_role`、`current_section_is_marked`）

**Interfaces：**
- Consumes：Task 1 的 `/static/app.js`、`/static/theme.js`、`/static/icons.svg` 與 symbol id；Task 2 的外殼 class。
- Produces：
  - `pub fn Nav::new(s: &Session, section: &'static str) -> Nav`。
  - `Nav` 欄位 `section: &'static str` 與 `version: &'static str`。
  - `_macros.html` 的 macro：
    - `link(cur, sec, href, icon, label, count_id)`
    - `tab(href, label, active)`
    - `empty(msg, hint)`
  - 元素 id：`#main`、`#sidebar`、`#q`、`#st-online`、`#st-devices`、`#st-violating`。

各模組的 section 值：

| 模組 | section |
|---|---|
| `dashboard.rs` | `"overview"` |
| `devices.rs` | `"devices"` |
| `software.rs` | `"software"` |
| `registry.rs` | `"registry"` |
| `compliance.rs`、`rules.rs` | `"compliance"` |
| `notify.rs` | `"notify"` |
| `updates.rs` | `"updates"` |
| `deployments.rs`、`packages.rs` | `"deployments"` |
| `commands.rs` | `"commands"` |
| `scripts.rs` | `"scripts"` |
| `tokens.rs` | `"tokens"` |
| `sites.rs`、`caches.rs` | `"sites"` |
| `groups.rs` | `"groups"` |
| `accounts.rs` | `"accounts"` |
| `audit.rs` | `"audit"` |
| `password.rs` | `"password"`（側邊欄沒有對應項目，不會標示） |

- [ ] **Step 1：寫失敗的測試**（`tests/web.rs`）

```rust
#[sqlx::test(migrations = false)]
async fn shell_and_nav_by_role(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let (_, login) = s.page(&s.web_client(), "/login").await;
    assert!(!login.contains(r#"class="sidebar""#) && !login.contains("/ui/status"));

    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/").await;
    assert!(html.contains(r#"<aside class="sidebar""#) && html.contains(r#"class="topbar""#));
    assert!(html.contains(r#"hx-get="/ui/status""#) && html.contains(r#"action="/devices""#));
    let settings = [
        "/scripts", "/tokens", "/sites", "/groups", "/accounts", "/compliance/notify", "/audit",
    ];
    for href in settings {
        assert!(html.contains(&format!(r#"href="{href}""#)), "平台管理員要看到 {href}");
    }
    assert!(html.contains(">設定<"));

    let g = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, html) = s.page(&g, "/").await;
    assert!(html.contains(r#"href="/tokens""#) && html.contains(">設定<"));
    for href in settings.iter().filter(|h| **h != "/tokens") {
        assert!(!html.contains(&format!(r#"href="{href}""#)), "群組管理員不應看到 {href}");
    }

    let v = s.login_as("vera", Role::Viewer, &["台北總部"]).await;
    let (_, html) = s.page(&v, "/").await;
    assert!(!html.contains(">設定<") && !html.contains(r#"href="/tokens""#));
}

#[sqlx::test(migrations = false)]
async fn current_section_is_marked(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    let a = s.enroll_ok(&tok, None, None).await;
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, &format!("/devices/{}", a.device_id)).await;
    assert!(
        html.contains(r#"<a href="/devices" class="on" aria-current="page">"#),
        "{html}"
    );
    assert_eq!(html.matches(r#"aria-current="page""#).count(), 1);
}
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test web shell_and_nav_by_role current_section_is_marked`
預期：兩個都 FAIL，原因是找不到 `class="sidebar"`／`class="on"`。

- [ ] **Step 3：修改 `Nav`**（`auth.rs`）

把 `pub struct Nav`、`impl Nav`、`impl From<&Session> for Nav` 換成：

```rust
/// 版面共用資訊。`section` 決定側邊欄標示哪一項（子頁面沿用上層的值）
pub struct Nav {
    pub logged_in: bool,
    pub user: String,
    pub role: &'static str,
    pub csrf: String,
    pub platform: bool,
    pub manage: bool,
    pub section: &'static str,
    pub version: &'static str,
}

impl Nav {
    pub fn new(s: &Session, section: &'static str) -> Nav {
        Nav {
            logged_in: true,
            user: s.username.clone(),
            role: s.role.label(),
            csrf: s.csrf.clone(),
            platform: s.all_devices(),
            manage: s.can_manage(),
            section,
            version: env!("CARGO_PKG_VERSION"),
        }
    }

    pub fn anonymous() -> Nav {
        Nav {
            logged_in: false,
            user: String::new(),
            role: "",
            csrf: String::new(),
            platform: false,
            manage: false,
            section: "",
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}
```

- [ ] **Step 4：替換呼叫處**

依上表，每個模組逐一把 `Nav::from(&s)`／`Nav::from(s)` 換成 `Nav::new(&s, "<section>")` 或 `Nav::new(s, "<section>")`，例如：

```bash
sed -i 's/Nav::from(&s)/Nav::new(\&s, "devices")/; s/Nav::from(s)/Nav::new(s, "devices")/' crates/server/src/web/devices.rs
```

其他模組照同樣寫法執行，section 換成表中的值。

執行：`cargo build -p endpoint-server 2>&1 | grep -E "^error" | head`
預期：沒有輸出。`From` 已經刪除，漏改的呼叫處會編譯失敗。

- [ ] **Step 5：新增 `templates/_macros.html`**

```html
{% macro link(cur, sec, href, icon, label, count_id) %}
<a href="{{ href }}"{% if cur == sec %} class="on" aria-current="page"{% endif %}><svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-{{ icon }}"></use></svg>{{ label }}{% if count_id != "" %}<span class="count num" id="{{ count_id }}">—</span>{% endif %}</a>
{% endmacro %}

{% macro tab(href, label, active) %}
<a href="{{ href }}"{% if active %} class="on" aria-current="page"{% endif %}>{{ label }}</a>
{% endmacro %}

{% macro empty(msg, hint) %}
<div class="empty"><svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-empty"></use></svg><div>{{ msg }}</div>{% if hint != "" %}<div class="faint">{{ hint }}</div>{% endif %}</div>
{% endmacro %}
```

- [ ] **Step 6：整份取代 `templates/base.html`**

```html
{% import "_macros.html" as m %}
<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="htmx-config" content='{"includeIndicatorStyles": false}'>
<title>Endpoint Manager</title>
<script src="/static/theme.js"></script>
<link rel="stylesheet" href="/static/app.css">
<script src="/static/htmx.min.js" defer></script>
<script src="/static/app.js" defer></script>
</head>
<body{% if !nav.logged_in %} class="login"{% endif %}>
{% if nav.logged_in %}
<a class="skip" href="#main">跳到主要內容</a>
<div class="app">
<aside class="sidebar" id="sidebar">
  <a class="brand" href="/"><span class="logo"></span><span><b>Endpoint</b><small>v{{ nav.version }}</small></span></a>
  <nav aria-label="主要">
    {% call m::link(nav.section, "overview", "/", "overview", "總覽", "") %}
    <div class="nav-group">資產</div>
    {% call m::link(nav.section, "devices", "/devices", "devices", "裝置", "st-devices") %}
    {% call m::link(nav.section, "software", "/software", "software", "軟體", "") %}
    {% call m::link(nav.section, "registry", "/registry", "registry", "登錄檔", "") %}
    <div class="nav-group">安全與合規</div>
    {% call m::link(nav.section, "compliance", "/compliance", "compliance", "合規", "st-violating") %}
    {% call m::link(nav.section, "updates", "/updates", "updates", "Windows Update", "") %}
    <div class="nav-group">作業</div>
    {% call m::link(nav.section, "deployments", "/deployments", "deploy", "派送", "") %}
    {% call m::link(nav.section, "commands", "/commands", "command", "遠端指令", "") %}
    {% if nav.platform %}{% call m::link(nav.section, "scripts", "/scripts", "script", "腳本", "") %}{% endif %}
    {% if nav.manage %}
    <div class="nav-group">設定</div>
    {% call m::link(nav.section, "tokens", "/tokens", "key", "註冊金鑰", "") %}
    {% if nav.platform %}
    {% call m::link(nav.section, "sites", "/sites", "site", "據點與快取", "") %}
    {% call m::link(nav.section, "groups", "/groups", "group", "群組", "") %}
    {% call m::link(nav.section, "accounts", "/accounts", "account", "帳號", "") %}
    {% call m::link(nav.section, "notify", "/compliance/notify", "notify", "通知", "") %}
    {% call m::link(nav.section, "audit", "/audit", "audit", "稽核記錄", "") %}
    {% endif %}
    {% endif %}
  </nav>
</aside>
<div class="shell">
<header class="topbar">
  <button class="icon-btn menu-btn" type="button" aria-controls="sidebar" aria-expanded="false" aria-label="開啟選單"><svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-menu"></use></svg></button>
  <form class="search" role="search" method="get" action="/devices">
    <svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-search"></use></svg>
    <input id="q" name="q" type="search" placeholder="搜尋主機名稱、使用者或 IP…" aria-label="搜尋裝置">
    <kbd>Ctrl K</kbd>
  </form>
  <span class="live"><span class="dot" aria-hidden="true"></span><span id="st-online">—</span></span>
  <button class="icon-btn theme-btn" type="button" hidden aria-label="切換主題"><svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-sun"></use></svg></button>
  <details class="user">
    <summary><span class="avatar" aria-hidden="true">{{ nav.user.chars().next().unwrap_or('?') }}</span><span class="user-name">{{ nav.user }} <span class="muted">{{ nav.role }}</span></span></summary>
    <div class="menu">
      <a href="/password"><svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-user"></use></svg>變更密碼</a>
      <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button><svg class="icon" aria-hidden="true"><use href="/static/icons.svg#i-logout"></use></svg>登出</button></form>
    </div>
  </details>
</header>
<main id="main">
{% endif %}
{% block content %}{% endblock %}
{% if nav.logged_in %}
</main>
</div>
</div>
<div class="scrim"></div>
<div hx-get="/ui/status" hx-trigger="load, every 60s" hx-swap="none"></div>
{% endif %}
</body>
</html>
```

Askama 0.16 的 macro 呼叫語法若不同，例如 import 名稱或 `{% call %}` 的寫法，照編譯錯誤調整，並在 ledger 記一筆 Ruling。

- [ ] **Step 7：確認通過**

執行：`$DB cargo test -p endpoint-server --test web shell_and_nav_by_role current_section_is_marked nav_depends_on_role`
預期：PASS。

執行：`$DB cargo test -p endpoint-server --test web`
預期：除了下面三個以外全部 PASS（`/ui/status` 還沒做，不影響其他頁面）：
- `login_logout_roundtrip_and_security_headers`：斷言「儀表板」，Task 6 改。
- `group_admin_sees_only_own_group`：斷言 `裝置總數<b>`，Task 6 改。
- `dashboard_counts_and_device_list`：斷言「裝置總數」，這個字串應該仍然存在。

如果還有其他失敗，在這一步找出原因。

- [ ] **Step 8：Commit**

```bash
git add crates/server/src/web crates/server/templates/_macros.html crates/server/templates/base.html crates/server/tests/web.rs
git commit -m "feat(web): 側邊欄與頂端列外殼，Nav 帶目前所在區段"
```

---

### Task 4：狀態數字端點 `GET /ui/status`

**Files：**
- Modify：`crates/server/src/web/dashboard.rs`（抽出 `device_counts`，新增 `status`）
- Modify：`crates/server/src/web/compliance.rs:288-296`（抽出 `devices_violating`）
- Modify：`crates/server/src/web/mod.rs`（路由）
- Test：`crates/server/tests/web.rs::ui_status_counts_by_scope`

**Interfaces：**
- Consumes：Task 3 的 `#st-online`、`#st-devices`、`#st-violating`，以及 `.count num` 與 `.hot` class。
- Produces：
  - `pub(super) async fn device_counts(st: &AppState, s: &Session) -> Result<(i64, i64, i64), sqlx::Error>`，回傳（總數, 在線, 疑似重複）。
  - `pub(super) async fn devices_violating(pool: &PgPool, s: &Session) -> Result<i64, sqlx::Error>`。
  - `pub async fn status(State<AppState>, Result<AdminSession, Response>) -> Response`。

- [ ] **Step 1：寫失敗的測試**

```rust
#[sqlx::test(migrations = false)]
async fn ui_status_counts_by_scope(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tp = s.create_group_token("台北總部", 1).await;
    let kh = s.create_group_token("高雄廠", 1).await;
    s.enroll_ok(&tp, None, None).await;
    s.enroll_ok(&kh, None, None).await;
    sqlx::query("UPDATE devices SET last_seen_at = now()").execute(&s.pool).await.unwrap();
    let rule: i64 = sqlx::query_scalar(
        "INSERT INTO compliance_rules (name, kind, severity, params, created_by) \
         VALUES ('r', 'forbidden_software', 'high', '{\"name\":\"x\"}'::jsonb, 't') RETURNING id",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO device_violations (device_id, rule_id, status, detail) \
         SELECT id, $1, 'violating', '{}'::jsonb FROM devices",
    )
    .bind(rule)
    .execute(&s.pool)
    .await
    .unwrap();

    let r = s.web_client().get(s.web_url("/ui/status")).send().await.unwrap();
    assert_eq!(r.status(), 401, "未登入不能取得數字");

    let admin = s.admin_client().await;
    let (st, body) = s.page(&admin, "/ui/status").await;
    assert_eq!(st, 200);
    assert!(body.contains(r#"<span id="st-online" hx-swap-oob="true">2 台在線</span>"#), "{body}");
    assert!(body.contains(r#"id="st-devices" hx-swap-oob="true">2<"#), "{body}");
    assert!(body.contains(r#"class="count num hot" id="st-violating" hx-swap-oob="true">2<"#), "{body}");

    let g = s.login_as("gary", Role::GroupAdmin, &["台北總部"]).await;
    let (_, body) = s.page(&g, "/ui/status").await;
    assert!(body.contains(">1 台在線<"), "群組管理員只算自己的群組：{body}");
    assert!(body.contains(r#"id="st-devices" hx-swap-oob="true">1<"#), "{body}");
    assert!(body.contains(r#"id="st-violating" hx-swap-oob="true">1<"#), "{body}");
}
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test web ui_status_counts_by_scope`
預期：FAIL，未登入時回 404，不是 401（路由不存在）。

- [ ] **Step 3：實作**

在 `compliance.rs` 把 `overview` 開頭的查詢抽出來，`overview` 改為呼叫它：

```rust
/// 範圍內有違規的裝置數（合規總覽與側邊欄共用）
pub(super) async fn devices_violating(pool: &PgPool, s: &Session) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(DISTINCT v.device_id) FROM device_violations v \
         JOIN devices d ON d.id = v.device_id \
         WHERE v.status = 'violating' AND ($1::bool OR d.group_id = ANY($2::bigint[]))",
    )
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_one(pool)
    .await
}
```

`overview` 裡原本的查詢改成：

```rust
    let devices_violating = devices_violating(&st.pool, &s).await?;
```

如果 `PgPool`、`Session` 還沒 import，就補上。

在 `dashboard.rs` 把 `build` 開頭的統計抽出來：

```rust
/// 範圍內的（總數, 在線, 疑似重複）；不含已除役與待核准
pub(super) async fn device_counts(st: &AppState, s: &Session) -> Result<(i64, i64, i64), sqlx::Error> {
    let cutoff = online_cutoff(st).await?;
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status NOT IN ('retired', 'pending_approval')), \
                count(*) FILTER (WHERE status NOT IN ('retired', 'pending_approval') \
                                   AND last_seen_at > $1), \
                count(*) FILTER (WHERE status = 'duplicate_suspect') \
         FROM devices d WHERE ($2::bool OR d.group_id = ANY($3::bigint[]))",
    )
    .bind(cutoff)
    .bind(s.all_devices())
    .bind(&s.groups)
    .fetch_one(&st.pool)
    .await
}

/// 外殼的狀態數字：htmx out-of-band 片段，每 60 秒更新。未登入回 401（htmx 不更新畫面）
pub async fn status(
    State(st): State<AppState>,
    session: Result<AdminSession, Response>,
) -> Response {
    let Ok(AdminSession(s)) = session else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let counts = async {
        let (total, online, _) = device_counts(&st, &s).await?;
        let violating = super::compliance::devices_violating(&st.pool, &s).await?;
        Ok::<_, sqlx::Error>((total, online, violating))
    };
    match counts.await {
        Ok((total, online, violating)) => Html(format!(
            r#"<span id="st-online" hx-swap-oob="true">{online} 台在線</span><span class="count num" id="st-devices" hx-swap-oob="true">{total}</span><span class="count num{hot}" id="st-violating" hx-swap-oob="true">{violating}</span>"#,
            hot = if violating > 0 { " hot" } else { "" },
        ))
        .into_response(),
        Err(e) => AppError::from(e).into_response(),
    }
}
```

`build` 的統計改為：

```rust
    let (total, online, duplicate) = device_counts(st, s).await?;
```

需要補的 import 有 `axum::http::StatusCode` 與 `axum::response::Html`。`online_cutoff` 回傳 `sqlx::Error` 以外的錯誤型別時，`device_counts` 的回傳型別改成 `AppError`，並記一筆 Ruling。

`mod.rs` 的路由加 `.route("/ui/status", get(dashboard::status))`。

- [ ] **Step 4：確認通過**

執行：`$DB cargo test -p endpoint-server --test web ui_status_counts_by_scope dashboard_counts_and_device_list`
預期：PASS。

執行：`$DB cargo test -p endpoint-server --test compliance_web`
預期：PASS（總覽的違規數沒有改變）。

- [ ] **Step 5：Commit**

```bash
git add crates/server/src/web crates/server/tests/web.rs
git commit -m "feat(web): /ui/status 以 htmx out-of-band 更新在線數、裝置數與違規數"
```

---

### Task 5：登入頁

**Files：**
- Modify：`crates/server/templates/login.html`
- Test：`crates/server/tests/web.rs`（`pages_require_login` 加斷言；`wrong_password_and_locked_show_generic_error` 不用改）

**Interfaces：**
- Consumes：Task 2 的 `.login-box`、`.brand`、`.logo`、`.field`、`.btn.primary`、`.notice.error`、`.foot`；Task 3 `base.html` 未登入時的 `class="login"`。

- [ ] **Step 1：寫失敗的測試**

`pages_require_login` 的最後加：

```rust
    assert!(html.contains(r#"class="login-box""#) && html.contains("連續失敗多次會暫時鎖定帳號"));
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test web pages_require_login`
預期：FAIL。

- [ ] **Step 3：整份取代 `login.html`**

```html
{% extends "base.html" %}
{% block content %}
<main class="login-box" id="main">
  <div class="brand"><span class="logo"></span><b>Endpoint Manager</b></div>
  {% if let Some(e) = error %}<div class="notice error" role="alert">{{ e }}</div>{% endif %}
  <form method="post" action="/login">
    <label class="field">帳號 <input name="username" autocomplete="username" required autofocus></label>
    <label class="field">密碼 <input name="password" type="password" autocomplete="current-password" required></label>
    <button class="btn primary">登入</button>
  </form>
  <p class="foot">連續失敗多次會暫時鎖定帳號。</p>
</main>
{% endblock %}
```

- [ ] **Step 4：確認通過**

執行：`$DB cargo test -p endpoint-server --test web pages_require_login wrong_password_and_locked_show_generic_error`
預期：PASS。

- [ ] **Step 5：Commit**

```bash
git add crates/server/templates/login.html crates/server/tests/web.rs
git commit -m "feat(web): 精簡登入頁"
```

---

## 頁面套用的共同規則（Task 6–9 都適用）

每個 `{% extends "base.html" %}` 的範本照以下規則改：

1. **頁首。** 開頭的 `<h1>…</h1>` 與「← 返回」連結，換成：

   ```html
   <div class="page-head">
     <div><div class="crumb"><a href="/上層">上層名稱</a> ／ 本頁</div><h1>標題</h1><div class="sub">副標（可省略）</div></div>
     <div class="actions">主要操作（可省略）</div>
   </div>
   ```

   第一層頁面（側邊欄直接連到的）不需要 `.crumb`。原本的「← xxx」連結改成 crumb 裡的上層連結。

2. **主要操作。** 「建立」「新增」「上傳」類連結改成 `<a class="btn primary" href="…">＋ 建立派送</a>`；其他頁首連結用 `<a class="btn" href="…">`。

3. **按鈕。**
   - `<button class="danger">` 改成 `<button class="btn danger">`。
   - 表單的送出鈕（儲存、建立、修改）改成 `<button class="btn primary">`。
   - 表格內的小按鈕加 `.sm`。

4. **錯誤與訊息。**
   - `<p class="error">…</p>` 改成 `<div class="notice error">…</div>`。
   - `<p class="notice">` 改成 `<div class="notice">`。
   - `<p class="ok">` 改成 `<div class="notice ok">`。
   - 行內的 `<span class="error">`、`<td class="error">` 保留。

5. **表單欄位。**
   - `<p><label>名稱 <input …></label></p>` 改成 `<label class="field">名稱 <input …></label>`。
   - 同一行的多個欄位用 `<div class="row">…</div>` 包起來。
   - 說明文字 `<span class="muted">…</span>` 放進 label 時改成 `<span class="help">…</span>`。
   - 一串 checkbox 或 radio 用 `<div class="checks">…</div>` 包起來。
   - 搜尋與篩選的 GET 表單加 `class="filters"`。

6. **數字欄。** 計數、台數、大小、天數的 `<th>` 與 `<td>` 加 `class="num"`。

7. **空清單。**
   - 原本「表格之後 `{% if rows.is_empty() %}<p class="muted">還沒有…</p>{% endif %}`」改成：

     ```html
     {% if rows.is_empty() %}{% call m::empty("還沒有…", "建議動作") %}{% else %}<table>…</table>{% endif %}
     ```

   - 範本開頭要加 `{% import "_macros.html" as m %}`，放在 `{% extends %}` 之後。

8. **狀態篩選連結。** `<p>{% for f in filters %}…<strong>…</strong>…{% endfor %}</p>` 改成 `<nav class="chips" aria-label="篩選">…</nav>`，內容不變。

9. **分頁連結。** 原本的 `<p>{% if let Some(u) = prev %}…` 與 `<div class="pager">` 統一成：

   ```html
   <div class="pager">{% if let Some(u) = prev %}<a class="btn sm" href="{{ u }}">← 上一頁</a>{% endif %}{% if let Some(u) = next %}<a class="btn sm" href="{{ u }}">下一頁 →</a>{% endif %}</div>
   ```

   用 `page`／`has_next` 的頁面保留原本的變數，也改成 `.btn.sm`，「第 N 頁」放在中間的 `<span class="num">`。

10. **鍵值表。** 詳情頁的 `<table><tr><th>欄位</th><td>值</td></tr>` 保留表格結構。測試有比對 `<th>據點（依最後回報的 IP）</th><td>—</td>` 這類片段，不要在 `<th>`／`<td>` 上加 class。

11. **不能改的東西。**
    - 所有 `name=`、`action=`、`method=`、`hx-*` 屬性、隱藏欄位，以及 `{% if %}` 權限條件，一律照抄。
    - 測試用來切段或比對的文字也照抄，例如 `<h2>裝置</h2>`、`<code class="sha">`、`共 N 台`、`失敗：1`。

每個 task 結束前都跑：

```bash
$DB cargo test -p endpoint-server --lib templates_have_no_inline_code
```

---

### Task 6：頁面套用：總覽與資產

**Files：**
- Modify：
  - `templates/dashboard.html`、`devices.html`、`device.html`
  - `templates/software.html`、`registry.html`、`registry_devices.html`
  - 片段：`templates/table.html`、`security_tab.html`
- Modify：`src/web/devices.rs:26-34`（`status_label` 的 class）
- Test：
  - `tests/web.rs`：`login_logout_roundtrip_and_security_headers`、`group_admin_sees_only_own_group`、新增 `device_status_uses_tag`
  - `tests/followups.rs:189`
  - `tests/config_web.rs:121,131`

**Interfaces：**
- Consumes：Task 3 的 `m::empty`；Task 2 的 class。
- Produces：`status_label` 回傳 `("ok"|"warn"|"bad"|"off", label)`。

- [ ] **Step 1：更新與新增測試**

```rust
// tests/web.rs login_logout_roundtrip_and_security_headers
assert!(html.contains("<h1>總覽</h1>") && html.contains("平台管理員"));
// tests/web.rs group_admin_sees_only_own_group
assert!(
    html.contains(r#"裝置總數</div><div class="kpi-value num">1</div>"#),
    "儀表板只算自己群組：{html}"
);
// tests/followups.rs:189
assert!(html.contains(r#"裝置總數</div><div class="kpi-value num">1</div>"#), "{html}");
// tests/config_web.rs:121 與 131（登錄檔查詢結果的台數欄改為 .num）
html.contains(r#"<td class="num">1</td>"#) && html.contains(r#"<td class="num">0</td>"#)
!html.contains(r#"<td class="num">0</td>"#) && html.contains("共 1 台")
```

註：config_web 第 121、131 行的 `<td>1</td>`／`<td>0</td>` 依實際比對的欄位判斷：
- 如果比對的是 `registry.html` 的「台數」欄，就照上面改。
- 如果不是，就保留原斷言。

新增：

```rust
#[sqlx::test(migrations = false)]
async fn device_status_uses_tag(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let tok = s.create_token(1).await;
    s.enroll_ok(&tok, None, None).await;
    sqlx::query("UPDATE devices SET last_seen_at = now()").execute(&s.pool).await.unwrap();
    let c = s.admin_client().await;
    let (_, html) = s.page(&c, "/devices").await;
    assert!(html.contains(r#"<span class="tag ok">在線</span>"#), "{html}");
}
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test web device_status_uses_tag group_admin_sees_only_own_group login_logout_roundtrip_and_security_headers`
預期：三個都 FAIL。

- [ ] **Step 3：`status_label` 改成標籤 class**

```rust
pub fn status_label(status: &str, online: bool) -> (&'static str, &'static str) {
    match status {
        "retired" => ("bad", "已除役"),
        "pending_approval" => ("warn", "待核准"),
        "duplicate_suspect" => ("warn", "疑似重複"),
        _ if online => ("ok", "在線"),
        _ => ("off", "離線"),
    }
}
```

- [ ] **Step 4：改範本**

`dashboard.html` 整份取代：

```html
{% extends "base.html" %}
{% import "_macros.html" as m %}
{% block content %}
<div class="page-head"><div><h1>總覽</h1><div class="sub">管理範圍內的裝置狀態</div></div></div>
{% if let Some(r) = approve_result %}<div class="notice ok">已核准 {{ r.0 }} 台{% if r.1 > 0 %}，略過 {{ r.1 }} 台（原因記錄在伺服器日誌）{% endif %}。</div>{% endif %}
<div class="cards">
  <div class="card kpi"><div class="kpi-label">裝置總數</div><div class="kpi-value num">{{ total }}</div></div>
  <div class="card kpi"><div class="kpi-label">在線</div><div class="kpi-value num ok">{{ online }}</div></div>
  <div class="card kpi"><div class="kpi-label">離線</div><div class="kpi-value num">{{ total - online }}</div></div>
  <div class="card kpi"><div class="kpi-label">疑似重複</div><div class="kpi-value num{% if duplicate > 0 %} error{% endif %}">{{ duplicate }}</div></div>
  <div class="card kpi"><div class="kpi-label">待核准</div><div class="kpi-value num">{{ pending.len() }}</div></div>
</div>
{% if !pending.is_empty() %}
<div class="card">
<h2>待核准的重新註冊</h2>
<p class="muted">硬體識別與既有裝置相同（通常是重灌）。核准後新憑證會接手原裝置的記錄；若不是預期的重灌，請拒絕。</p>
{% if nav.manage %}
<form class="actions" method="post" action="/devices/approve-all">
  <input type="hidden" name="csrf" value="{{ nav.csrf }}">
  {% for p in pending %}<input type="hidden" name="ids" value="{{ p.id }}">{% endfor %}
  <label class="checks"><input type="checkbox" name="confirm" value="1" required> 我已確認這些都是預期的重灌</label>
  <button class="btn primary">全部核准（{{ pending.len() }}）</button>
</form>
{% endif %}
<table>
  <tr><th>新註冊</th><th>原裝置</th><th>群組</th><th>註冊時間</th><th></th></tr>
  {% for p in pending %}
  <tr>
    <td><a href="/devices/{{ p.id }}">{{ p.hostname }}</a></td>
    <td><a href="/devices/{{ p.old_id }}">{{ p.old_hostname }}</a></td>
    <td>{{ p.group }}</td>
    <td class="num">{{ p.enrolled_at }}</td>
    <td>{% if nav.manage %}<div class="actions">
      <form method="post" action="/devices/{{ p.id }}/approve"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button class="btn sm">核准</button></form>
      <form method="post" action="/devices/{{ p.id }}/reject"><input type="hidden" name="csrf" value="{{ nav.csrf }}"><button class="btn sm danger">拒絕</button></form>
    </div>{% endif %}</td>
  </tr>
  {% endfor %}
</table>
</div>
{% endif %}
{% endblock %}
```

`devices.html` 整份取代：

```html
{% extends "base.html" %}
{% import "_macros.html" as m %}
{% block content %}
<div class="page-head"><div><h1>裝置</h1>{% if !software.is_empty() %}<div class="sub">安裝了「{{ software }} {{ version }}」</div>{% endif %}</div></div>
<form class="filters" method="get" action="/devices">
  <input name="q" value="{{ q }}" placeholder="電腦名稱／使用者／IP" aria-label="搜尋">
  <select name="status" aria-label="狀態">
    {% for o in statuses %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}
  </select>
  <select name="group" aria-label="群組">
    {% for o in groups %}<option value="{{ o.value }}" {% if o.selected %}selected{% endif %}>{{ o.label }}</option>{% endfor %}
  </select>
  {% if !software.is_empty() %}
  <input type="hidden" name="software" value="{{ software }}">
  <input type="hidden" name="version" value="{{ version }}">
  {% endif %}
  <button class="btn primary">搜尋</button>
</form>
{% if rows.is_empty() %}{% call m::empty("沒有符合條件的裝置", "調整搜尋條件，或到「註冊金鑰」建立安裝參數") %}{% else %}
<table>
  <tr><th>電腦名稱</th><th>群組</th><th>網域</th><th>作業系統</th><th>使用者</th><th>IP</th><th>最後報到</th><th>狀態</th></tr>
  {% for d in rows %}
  <tr>
    <td><a href="/devices/{{ d.id }}">{{ d.hostname }}</a></td>
    <td>{{ d.group }}</td><td>{{ d.domain }}</td><td>{{ d.os }}</td><td>{{ d.user }}</td><td class="num">{{ d.ip }}</td>
    <td class="num">{{ d.last_seen }}</td>
    <td><span class="tag {{ d.badge }}">{{ d.badge_label }}</span></td>
  </tr>
  {% endfor %}
</table>
{% endif %}
<div class="pager">
  {% if page > 0 %}<a class="btn sm" href="{{ prev_url }}">← 上一頁</a>{% endif %}
  <span class="num">第 {{ page + 1 }} 頁</span>
  {% if has_next %}<a class="btn sm" href="{{ next_url }}">下一頁 →</a>{% endif %}
</div>
{% endblock %}
```

`device.html`：
- 頁首：

  ```html
  <div class="page-head"><div><div class="crumb"><a href="/devices">裝置</a> ／ {{ d.hostname }}</div><h1>{{ d.hostname }} <span class="tag {{ d.badge }}">{{ d.badge_label }}</span></h1></div><div class="actions">…</div></div>
  ```

  把「移到群組」與「除役」兩個表單移進 `.actions`：
  - 移到群組的 select 加 `aria-label="移到群組"`，按鈕改成 `class="btn"`。
  - 除役按鈕改成 `class="btn danger"`，文字改為「除役」。
  - 原本括號內的說明改成 `data-confirm="除役會撤銷憑證，Agent 將停止報到。確定除役？"`，加在除役表單上。
- 基本資料表格不改。
- 收集錯誤：外層包 `<div class="card">`，保留裡面的 `<h2>` 與 table。
- 分頁籤：`<div class="tabs">` 改成 `<nav class="tabs" aria-label="裝置資料">`，裡面的 `<button>` 保持原樣，`.tabs button` 已有樣式。

`software.html`、`registry.html`：
- 換成 `.page-head`。
- 搜尋表單加 `class="filters"`，按鈕改成 `.btn.primary`。
- 數字欄加 `.num`。
- `registry.html` 的錯誤訊息改成 `.notice.error`。

`registry_devices.html`：
- 換成 `.page-head`，crumb 為「登錄檔 ／ 裝置清單」，連到原本的「回到查詢」網址。

片段 `table.html`、`security_tab.html`：不用改。

- [ ] **Step 5：確認通過**

```bash
$DB cargo test -p endpoint-server --test web --test followups --test config_web --test branch_web
$DB cargo test -p endpoint-server --lib
```

預期：全部 PASS。

- [ ] **Step 6：Commit**

```bash
git add crates/server/templates crates/server/src/web/devices.rs crates/server/tests
git commit -m "feat(web): 總覽、裝置、軟體與登錄檔頁套用新元件"
```

---

### Task 7：頁面套用：合規

**Files：**
- Modify：
  - `templates/_macros.html`（加 `compliance_tabs`）
  - `templates/compliance.html`、`violations.html`、`rules.html`、`rule_templates.html`、`rule_form.html`、`notify.html`
  - 片段：`templates/compliance_tab.html`
- Test：`tests/compliance_web.rs`（新增 `compliance_tabs_mark_current`）

**Interfaces：**
- Consumes：Task 3 的 `m::tab`、`m::empty`。
- Produces：`m::compliance_tabs(on: &str, platform: bool)`，`on` 的值為 `"overview" | "violations" | "rules" | "templates"`。

- [ ] **Step 1：寫失敗的測試**

```rust
#[sqlx::test(migrations = false)]
async fn compliance_tabs_mark_current(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/compliance/rules").await;
    assert!(html.contains(r#"<a href="/compliance" class="on" aria-current="page">"#), "側邊欄：{html}");
    assert!(html.contains(r#"<a href="/compliance/rules" class="on" aria-current="page">規則</a>"#), "分頁籤：{html}");
    assert!(html.contains(r#"href="/compliance/rules/templates""#));
    let v = s.login_as("vera", Role::Viewer, &["台北"]).await;
    let (_, html) = s.page(&v, "/compliance/violations").await;
    assert!(html.contains(r#"class="on" aria-current="page">違規</a>"#), "{html}");
    assert!(!html.contains(r#"href="/compliance/rules/templates""#), "範本只給平台管理員");
}
```

如果檔案還沒有 `use endpoint_server::web::auth::Role;`，就補上。`login_as` 的群組名稱用這個檔案其他測試用的名稱。

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test compliance_web compliance_tabs_mark_current`
預期：FAIL。

- [ ] **Step 3：加 macro**（`_macros.html`）

```html
{% macro compliance_tabs(on, platform) %}
<nav class="tabs" aria-label="合規">
  <a href="/compliance"{% if on == "overview" %} class="on" aria-current="page"{% endif %}>總覽</a>
  <a href="/compliance/violations"{% if on == "violations" %} class="on" aria-current="page"{% endif %}>違規</a>
  <a href="/compliance/rules"{% if on == "rules" %} class="on" aria-current="page"{% endif %}>規則</a>
  {% if platform %}<a href="/compliance/rules/templates"{% if on == "templates" %} class="on" aria-current="page"{% endif %}>範本</a>{% endif %}
</nav>
{% endmacro %}
```

`<a href="/compliance"…>` 在側邊欄也會出現：
- 側邊欄的連結含 `<svg`，所以 `<a href="/compliance" class="on" aria-current="page">` 會同時比對到側邊欄與分頁籤。
- 測試第一個斷言只確認有出現，這是預期行為。

- [ ] **Step 4：改範本**

`compliance.html`：
- 頁首 `<div class="page-head"><div><h1>合規</h1></div><div class="actions"><a class="btn" href="/compliance/violations.csv">匯出違規 CSV</a></div></div>`，接著 `{% call m::compliance_tabs("overview", nav.platform) %}`。
- 原本 `<p><a href="/compliance/rules">規則</a> · …</p>` 刪除，由分頁籤取代。
- KPI 改成 `.card.kpi`：違規裝置的 `.kpi-value` 在數字 > 0 時加 `error`。
- 進度提示改成 `<div class="notice">`。
- 規則表的三個數字欄加 `.num`。
- 「通知」區塊外包 `.card`，`<h2>` 裡的「設定」連結改成 `<a class="btn sm" href="/compliance/notify">設定</a>`。
- 趨勢表外包 `.card`。

`violations.html`：
- 頁首 `<h1>合規</h1>` 加 `{% call m::compliance_tabs("violations", nav.platform) %}`，刪除「← 合規總覽」。
- 篩選表單加 `class="filters"`。
- 「匯出 CSV」改成 `<a class="btn" href="{{ csv_url }}">`。
- 空清單用 `m::empty("沒有符合條件的違規", "")`。
- 套用分頁規則。

`rules.html`：
- 頁首 `<h1>合規</h1>`，`.actions` 放兩個按鈕：
  - `<a class="btn" href="/compliance/rules/templates">從範本建立</a>`
  - 「新增規則」下拉：

    ```html
    <details class="user"><summary class="btn primary">＋ 新增規則</summary><div class="menu">{% for k in kinds %}<a href="/compliance/rules/new?kind={{ k.0 }}">{{ k.1 }}</a>{% endfor %}</div></details>
    ```

    重用 `.user .menu` 的下拉樣式。`.actions` 只在 `nav.platform` 時輸出。
- 接著 `{% call m::compliance_tabs("rules", nav.platform) %}`。
- 狀態欄改成 `<span class="tag ok">啟用</span>`／`<span class="tag off">停用</span>`。
- 三個數字欄加 `.num`。
- 空清單用 `m::empty("還沒有合規規則", "可以從範本快速建立")`。

`rule_templates.html`：
- 頁首 `<h1>合規</h1>` 加 `{% call m::compliance_tabs("templates", nav.platform) %}`。
- 訊息改成 `.notice.ok`，失敗改成 `.notice.error`。
- 每個分組的 `<h2>` 與表格外包 `.card`。
- 送出鈕改成 `.btn.primary`。

`rule_form.html`：
- 頁首 crumb 為「合規 ／ 規則 ／ 新增」或「編輯」，`<h1>` 沿用原文字。
- 套用共同規則 4、5：
  - 所有 `<p><label>` 改成 `<label class="field">`。
  - checkbox 與 radio 群組改成 `.checks`。
  - 說明的 `<p class="muted">` 保留。
- 儲存鈕改成 `.btn.primary`，預覽鈕改成 `.btn`。
- 刪除表單的按鈕改成 `.btn danger`。

`notify.html`：
- 頁首 `<h1>通知設定</h1>`，crumb 為「設定 ／ 通知」。
- 欄位改成 `.field`，儲存鈕改成 `.btn.primary`。

`compliance_tab.html`（裝置頁片段）：
- 三個 `<h3>` 保留。
- 狀態欄依值套 `.tag`：

  ```html
  {% if r.status == "違規" %}<span class="tag bad">{{ r.status }}</span>{% else %}<span class="tag off">{{ r.status }}</span>{% endif %}
  ```

  先看 `compliance.rs` 的 `status_label` 回傳哪些中文字，比對字串要照抄。
- 新增豁免表單加 `class="filters"`，撤銷按鈕改成 `.btn.sm.danger`。

- [ ] **Step 5：確認通過**

```bash
$DB cargo test -p endpoint-server --test compliance_web --test config_web --test web
$DB cargo test -p endpoint-server --lib
```

預期：全部 PASS。

- [ ] **Step 6：Commit**

```bash
git add crates/server/templates crates/server/tests/compliance_web.rs
git commit -m "feat(web): 合規頁面套用新元件與分頁籤"
```

---

### Task 8：頁面套用：作業（派送、更新、遠端指令、腳本）

**Files：**
- Modify：
  - `templates/_macros.html`（加 `deploy_tabs`、`updates_tabs`）
  - 派送：`deployments.html`、`deployment_detail.html`、`deployment_form.html`
  - 套件：`packages.html`、`package_form.html`、`package_upload.html`
  - 更新：`updates.html`、`update_detail.html`、`update_form.html`、`updates_overview.html`
  - 遠端指令：`commands.html`、`command_detail.html`
  - 腳本：`scripts.html`、`script_detail.html`、`script_form.html`
  - 片段：`deploy_tab.html`、`updates_tab.html`、`commands_tab.html`
- Test：
  - `tests/updates_web.rs:295-296`
  - `tests/deploy_web.rs:453`
  - 新增 `tests/deploy_web.rs::deploy_tabs_mark_current`

**Interfaces：**
- Consumes：`m::empty`。
- Produces：
  - `m::deploy_tabs(on)`，`on` 為 `"deployments" | "packages"`。
  - `m::updates_tabs(on)`，`on` 為 `"policies" | "overview"`。

- [ ] **Step 1：更新與新增測試**

```rust
// tests/updates_web.rs:295-296（組建、UBR、台數都改成 .num）
html.contains(r#"<td class="num">19045</td><td class="num">5000</td><td class="num">2</td>"#)
    && html.contains(r#"<td class="num">22631</td><td class="num">4000</td><td class="num">1</td>"#)
// tests/deploy_web.rs:453（主要失敗原因的台數欄改成 .num）
summary.contains(r#"<td>第二輪失敗</td><td class="num">1</td>"#) && !summary.contains("第一輪失敗")
```

新增：

```rust
#[sqlx::test(migrations = false)]
async fn deploy_tabs_mark_current(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/packages").await;
    assert!(html.contains(r#"<a href="/packages" class="on" aria-current="page">套件</a>"#), "{html}");
    assert!(html.contains(r#"<a href="/deployments" class="on" aria-current="page">"#), "側邊欄仍標示派送：{html}");
}
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test deploy_web --test updates_web`
預期：上面三個斷言 FAIL。

- [ ] **Step 3：加 macro**

```html
{% macro deploy_tabs(on) %}
<nav class="tabs" aria-label="派送">
  <a href="/deployments"{% if on == "deployments" %} class="on" aria-current="page"{% endif %}>派送</a>
  <a href="/packages"{% if on == "packages" %} class="on" aria-current="page"{% endif %}>套件</a>
</nav>
{% endmacro %}

{% macro updates_tabs(on) %}
<nav class="tabs" aria-label="Windows Update">
  <a href="/updates"{% if on == "policies" %} class="on" aria-current="page"{% endif %}>原則</a>
  <a href="/updates/overview"{% if on == "overview" %} class="on" aria-current="page"{% endif %}>組建與重開機</a>
</nav>
{% endmacro %}
```

- [ ] **Step 4：改範本**

`deployments.html`：
- `<h1>派送</h1>`，`.actions` 在 `nav.platform` 時放 `<a class="btn primary" href="/deployments/new">＋ 建立派送</a>`。
- 接著 `{% call m::deploy_tabs("deployments") %}`。
- 狀態欄依 `r.stage` 的中文值套 `.tag`。先讀 `deployments.rs` 確認 `stage` 欄位的字串：
  - 試點、全部 → `info`
  - 暫停 → `warn`
  - 停止 → `off`
- 六個數字欄加 `.num`，失敗欄保留 `<span class="error">`。
- 空清單用 `m::empty("還沒有派送", "上傳套件後就能建立第一個派送")`。

`deployment_detail.html`：
- crumb 為「派送 ／ {{ name }}」，`<h1>{{ name }}</h1>`。
- `.actions` 放原本 `<div class="actions">` 裡的所有表單：
  - 按鈕改成 `.btn`，危險的用 `.btn danger`。
  - 「擴大到全部」用 `.btn primary`。
- 鍵值表保留。
- 暫停提示用 `.notice`。
- 篩選列套用規則 8，分頁套用規則 9。
- 「主要失敗原因」與「裝置」各自外包 `.card`，`<h2>主要失敗原因</h2>` 與 `<h2>裝置</h2>` 原字照抄（測試以 `<h2>裝置</h2>` 切段）。
- 主要失敗原因的台數欄加 `.num`。

`deployment_form.html`、`package_form.html`、`update_form.html`、`script_form.html`：
- 套用共同規則 1、4、5。
- `fieldset` 保留。
- 送出鈕改成 `.btn.primary`，刪除改成 `.btn.danger`。
- `package_form.html` 的「還沒填靜默安裝參數」改成 `.notice.error`。

`packages.html`：
- `<h1>派送</h1>`，`.actions` 放 `<a class="btn primary" href="/packages/upload">＋ 上傳套件</a>`。
- 接著 `{% call m::deploy_tabs("packages") %}`。
- 大小、派送數欄加 `.num`。
- 空清單用 `m::empty("還沒有套件", "上傳 MSI 或 EXE 後建立派送")`。

`package_upload.html`：
- crumb 為「派送 ／ 套件 ／ 上傳」。
- 表單外包 `.card`，按鈕改成 `.btn.primary`。
- `<script src="/static/upload.js" defer></script>` 保留。

`updates.html`：
- `<h1>Windows Update</h1>`，`.actions` 在 `nav.platform` 時放 `<a class="btn primary" href="/updates/new">＋ 建立原則</a>`。
- 接著 `{% call m::updates_tabs("policies") %}`。
- 數字欄加 `.num`。
- 空清單用 `m::empty("還沒有更新原則", "沒有原則的群組，Agent 不會改動 Windows Update 設定")`。

`updates_overview.html`：
- `<h1>Windows Update</h1>` 加 `{% call m::updates_tabs("overview") %}`，刪除「← 更新原則」。
- 兩個區塊各自外包 `.card`。
- 組建、UBR、台數欄加 `.num`。

`update_detail.html`：
- crumb 為「Windows Update ／ {{ name }}」。
- `.actions` 改法同 deployment_detail。
- 篩選與分頁套用規則 8、9。

`commands.html`：
- `<h1>遠端指令</h1>`，`.actions` 在 `nav.platform` 時放 `<a class="btn" href="/scripts">腳本</a>`。
- 建立表單的 fieldset 欄位套用規則 5，送出鈕改成 `.btn.primary`。
- 數字欄加 `.num`。
- 空清單用 `m::empty("還沒有遠端指令", "")`。
- 套用分頁規則。

`command_detail.html`：
- crumb 為「遠端指令 ／ {{ run.action }}」。
- 取消表單放進 `.actions`。
- 篩選與分頁套用規則 8、9。

`scripts.html`：
- `<h1>腳本</h1>`，`.actions` 放 `<a class="btn primary" href="/scripts/new">＋ 建立腳本</a>`。
- 第二位核准設定表單外包 `.card`。
- 空清單用 `m::empty("還沒有腳本", "")`。

`script_detail.html`：
- crumb 為「腳本 ／ {{ name }}」。
- `<div class="actions">` 裡的按鈕套 `.btn`。
- `<code class="sha">` 照抄。

片段：
- `deploy_tab.html`：空狀態保留 `<p class="muted">`，片段不用 macro。
- `updates_tab.html`：不用改。
- `commands_tab.html`：
  - `.actions` 保留，按鈕改成 `.btn.sm`，重新開機與關機改成 `.btn.sm.danger`。
  - Task 1 加的 `data-confirm` 保留。

- [ ] **Step 5：確認通過**

```bash
$DB cargo test -p endpoint-server --test deploy_web --test updates_web --test commands_web --test branch_web --test web
$DB cargo test -p endpoint-server --lib
```

預期：全部 PASS。

- [ ] **Step 6：Commit**

```bash
git add crates/server/templates crates/server/tests
git commit -m "feat(web): 派送、更新、遠端指令與腳本頁套用新元件與分頁籤"
```

---

### Task 9：頁面套用：設定（金鑰、據點與快取、群組、帳號、稽核、密碼）

**Files：**
- Modify：
  - `templates/_macros.html`（加 `sites_tabs`）
  - `templates/tokens.html`、`sites.html`、`site_form.html`、`caches.html`
  - `templates/groups.html`、`accounts.html`、`account.html`、`audit.html`、`password.html`
- Modify：`src/web/accounts.rs:68-74`（`state_class`）
- Test：
  - `tests/branch_web.rs:210,515,622-623` 確認仍通過，必要時更新
  - 新增 `tests/branch_web.rs::sites_tabs_mark_current`

**Interfaces：**
- Produces：`m::sites_tabs(on)`，`on` 為 `"sites" | "caches"`。帳號的 `state_class` 改成 `"bad"|"warn"|"ok"`。

- [ ] **Step 1：寫失敗的測試**

```rust
#[sqlx::test(migrations = false)]
async fn sites_tabs_mark_current(pool: PgPool) {
    let s = TestServer::start(pool).await;
    let admin = s.admin_client().await;
    let (_, html) = s.page(&admin, "/caches").await;
    assert!(html.contains(r#"<a href="/caches" class="on" aria-current="page">快取</a>"#), "{html}");
    assert!(html.contains(r#"<a href="/sites" class="on" aria-current="page">"#), "側邊欄標示據點與快取：{html}");
}
```

- [ ] **Step 2：確認失敗**

執行：`$DB cargo test -p endpoint-server --test branch_web sites_tabs_mark_current`
預期：FAIL。

- [ ] **Step 3：加 macro 與改 `state_class`**

```html
{% macro sites_tabs(on) %}
<nav class="tabs" aria-label="據點與快取">
  <a href="/sites"{% if on == "sites" %} class="on" aria-current="page"{% endif %}>據點</a>
  <a href="/caches"{% if on == "caches" %} class="on" aria-current="page"{% endif %}>快取</a>
</nav>
{% endmacro %}
```

`accounts.rs`：

```rust
    let (state, state_class) = if disabled_at.is_some() {
        ("已停用", "bad")
    } else if locked {
        ("已鎖定", "warn")
    } else {
        ("啟用中", "ok")
    };
```

- [ ] **Step 4：改範本**

`tokens.html`：
- `<h1>註冊金鑰</h1>`。
- 新金鑰提示改成 `<div class="notice ok">`，裡面的 `<p>` 與 `<code id="new-token">` 保留。
- 建立表單的 fieldset 欄位套用規則 5：
  - 名稱、次數、群組、天數用 `.row`。
  - 伺服器網址那一段用 `.field`。
  - 「建立並下載安裝檔」用 `.btn`，「建立」用 `.btn.primary`。
- 已用／上限欄加 `.num`。
- 作廢按鈕改成 `.btn.sm.danger`，失效狀態改成 `<span class="tag off">{{ t.state }}</span>`。

`sites.html`：
- `<h1>據點與快取</h1>`，`.actions` 放 `<a class="btn primary" href="/sites/new">＋ 新增據點</a>`。
- 接著 `{% call m::sites_tabs("sites") %}`，刪除原本的「快取」連結。
- 說明段落保留。
- 編輯連結改成 `.btn.sm`，刪除改成 `.btn.sm.danger`，Task 1 的 `data-confirm` 保留。
- 裝置數已經是 `.num`。

`site_form.html`：
- crumb 為「據點與快取 ／ 新增」或「編輯」。
- 套用規則 4、5。

`caches.html`：
- `<h1>據點與快取</h1>` 加 `{% call m::sites_tabs("caches") %}`，刪除原本的「據點」連結。
- 新金鑰提示改成 `.notice.ok`。
- 狀態欄依 `c.status` 套 `.tag`，內容 `{{ c.status_label }}` 不變：
  - `active` → `ok`
  - `pending` → `warn`
  - `disabled` → `off`
  - 其他 → `bad`
- 表格操作欄的按鈕改成 `.btn.sm`，危險動作改成 `.btn.sm.danger`。
- `<td>{{ c.name }}</td>` 保持沒有 class（測試比對 `<td>台北快取</td>`）。
- 「快取註冊金鑰」`<h2>` 保留，fieldset 套用規則 5。

`groups.html`：
- `<h1>群組</h1>`。
- 建立表單改成 `<form class="filters" …>`，按鈕改成 `.btn.primary`。
- 數字欄加 `.num`，刪除鈕改成 `.btn.sm.danger`。

`accounts.html`：
- `<h1>帳號</h1>`。
- 建立表單套用規則 5，角色與群組用 `.checks`。
- 狀態欄改成 `<span class="tag {{ a.state_class }}">{{ a.state }}</span>`。

`account.html`：
- crumb 為「帳號 ／ {{ a.username }}」，`<h1>{{ a.username }} <span class="tag {{ a.state_class }}">{{ a.state }}</span></h1>`。
- 解除鎖定、啟用、停用按鈕放進頁首 `.actions`。
- 兩個 fieldset 套用規則 5。

`audit.html`：
- `<h1>稽核記錄</h1>`。
- 時間欄加 `.num`。
- 分頁套用規則 9（保留 `page`／`has_next`）。

`password.html`：
- `<h1>變更密碼</h1>`。
- 訊息改成 `.notice.ok`，錯誤改成 `.notice.error`。
- 表單外包 `.card`，欄位改成 `.field`，按鈕改成 `.btn.primary`。

- [ ] **Step 5：確認通過**

```bash
$DB cargo test -p endpoint-server --test branch_web --test web
$DB cargo test -p endpoint-server --lib
```

預期：全部 PASS。

- [ ] **Step 6：Commit**

```bash
git add crates/server/templates crates/server/src/web/accounts.rs crates/server/tests
git commit -m "feat(web): 設定類頁面套用新元件與分頁籤"
```

---

### Task 10：全面驗證與外觀檢查

**Files：** 無程式碼變更。只有檢查時發現問題才修，修正時要有對應的測試或截圖佐證。

- [ ] **Step 1：完整測試與靜態檢查**

```bash
cd /d/VSCode/endpoint-manager
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres cargo test --workspace -j 4 --no-fail-fast > "$CLAUDE_JOB_DIR/tmp/test.log" 2>&1; tail -40 "$CLAUDE_JOB_DIR/tmp/test.log"
```

預期：fmt 與 clippy 沒有輸出，測試全部 PASS。

- [ ] **Step 2：重建並重啟測試環境**

```bash
cargo build --release -p endpoint-server --bin endpoint-server
```

接著：
1. 先用 TaskStop 停掉 demo 伺服器背景工作（b9axs4u4r）。
2. 把 `target/release/endpoint-server.exe` 複製到 `D:\Claude\em-demo\`。
3. 用原本的指令在背景重啟：

   ```bash
   DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/em_demo EM_CA_DIR=pki EM_AGENT_LISTEN=127.0.0.1:28443 EM_WEB_LISTEN=127.0.0.1:9443 EM_PACKAGE_DIR=packages RUST_LOG=info ./endpoint-server.exe serve
   ```

4. 確認 https://localhost:9443/login 回 200。

- [ ] **Step 3：截圖與互動檢查**（瀏覽器工具，帳號 `demo` / `Demo-Test-2026!`）

- **截圖：**
  - 頁面：登入頁、總覽、裝置清單、裝置頁、合規總覽、派送詳情。
  - 每頁都要截深色與淺色兩種。
  - 另外截手機版面（寬 390px）：一張側邊欄收起、一張展開。
- **互動：**
  - `Ctrl+K` 與 `/` 會聚焦搜尋框；在輸入框中按 `/` 不會被攔截。
  - 主題切換後重新整理，選擇仍保留，而且載入時沒有閃爍。
  - `/ui/status` 載入後，側邊欄的數字從「—」變成實際數字。
  - 裝置頁的「指令」分頁按「重新開機」會跳出確認，按取消就不會送出。
  - 手機版按 Esc、點遮罩都能關閉選單。
- **無 JS 與減少動態：**
  - 停用 JavaScript 後，窄視窗的側邊欄排在內容上方，連結可以點。
  - 模擬 `prefers-reduced-motion: reduce` 時，燈號不再脈動。
- **對比：** 抽查淺色主題的 `.tag.ok`、連結、`.btn.primary`，計算出的對比要 ≥ 4.5。
- **主控台：** 沒有 CSP 錯誤。

截圖存到 `$CLAUDE_JOB_DIR/tmp/shots/`，PR 說明附上。

- [ ] **Step 4：Commit 檢查中的修正（若有）**

```bash
git commit -am "fix(web): 外觀檢查的修正"
```
