// 在畫面出現前套用主題，避免閃一下錯的顏色（CSP 不允許 inline script，所以是獨立檔案）
(function (root) {
  root.classList.add('js');
  try {
    var t = localStorage.getItem('em-theme');
    if (t === 'light' || t === 'dark') root.dataset.theme = t;
  } catch (e) {}
})(document.documentElement);
