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
    // htmx 載入內容的分頁籤（裝置頁）：標示目前的分頁
    var tabTarget = document.getElementById('tab');
    document.querySelectorAll('.tabs button[hx-get]').forEach(function (b) {
      if (tabTarget && b.getAttribute('hx-get') === tabTarget.getAttribute('hx-get')) b.classList.add('on');
      b.addEventListener('click', function () {
        b.parentNode.querySelectorAll('button').forEach(function (o) { o.classList.toggle('on', o === b); });
      });
    });

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
