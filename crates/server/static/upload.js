// 套件上傳：以 PUT 串流原始檔案（CSP 不允許 inline script，所以放在獨立檔案）
document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('upload-form');
  if (!form) return;
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var file = form.querySelector('input[type=file]').files[0];
    if (!file) return;
    var status = document.getElementById('upload-status');
    var button = form.querySelector('button');
    // 伺服器超過上限時會在收完檔案前關閉連線，瀏覽器只會看到「連線中斷」：先在這裡擋
    if (file.size > 2 * 1024 * 1024 * 1024) {
      status.textContent = '檔案超過 2 GiB 上限';
      return;
    }
    button.disabled = true;
    var xhr = new XMLHttpRequest();
    xhr.open('PUT', '/packages/upload');
    xhr.setRequestHeader('X-CSRF-Token', form.dataset.csrf);
    xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name));
    xhr.upload.onprogress = function (e) {
      if (e.lengthComputable) {
        status.textContent = '上傳中… ' + Math.floor((e.loaded * 100) / e.total) + '%';
      }
    };
    xhr.onload = function () {
      if (xhr.status === 201) {
        location.href = '/packages/' + JSON.parse(xhr.responseText).id;
      } else if (xhr.responseURL && xhr.responseURL.indexOf('/login') >= 0) {
        status.textContent = '登入已過期，請重新登入後再上傳';
        button.disabled = false;
      } else {
        status.textContent = '上傳失敗：' + xhr.responseText;
        button.disabled = false;
      }
    };
    xhr.onerror = function () {
      status.textContent = '上傳失敗：連線中斷';
      button.disabled = false;
    };
    xhr.send(file);
  });
});
