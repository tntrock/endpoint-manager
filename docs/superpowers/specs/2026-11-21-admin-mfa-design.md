# 管理網頁多因素驗證（MFA）第一版 設計

## 1. 目的

管理網頁現在只靠帳號密碼。平台管理員可以用 SYSTEM／root 在所有端點執行腳本，等於整個網域的最高權限，所以密碼外洩的代價很高。這一版加上第二道驗證。

### 1.1 範圍

- **TOTP**（RFC 6238）：驗證器 App（Google Authenticator、Microsoft Authenticator、1Password 等）產生的 6 位數字。
- 每個帳號自己設定；平台管理員可以要求所有帳號都必須設定。
- 復原碼、平台管理員重設別人的 MFA、伺服器指令列的緊急重設。

不在這一版：WebAuthn／通行金鑰（需要 JavaScript 與額外套件，留到下一版）、OIDC／SAML 單一登入、記住這台裝置。

### 1.2 成功標準

- 開啟 MFA 的帳號，只知道密碼無法取得工作階段。
- 同一個驗證碼不能用兩次（重放）。
- MFA 失敗跟密碼失敗共用鎖定次數，不能靠猜驗證碼繞過鎖定。
- 沒開「必須使用 MFA」時，現有帳號的登入流程完全不變。

## 2. TOTP 參數

- HMAC-SHA1、6 位數、30 秒一步，接受目前時間前後各一步（共 90 秒）。這是驗證器 App 的共同預設值；改其他參數，部分 App 會產生錯的碼。
- 金鑰 20 bytes，由作業系統亂數產生，以 Base32 顯示。
- 每個帳號記錄**最後使用的時間步**；步數小於或等於它的碼一律拒絕（防重放，也擋同一個碼在 90 秒內再用一次）。
- 金鑰以明文存在資料庫。（設計者決定：能讀資料庫的人已經能直接新增管理員或改密碼雜湊，加密金鑰不會多擋什麼，卻要多管一把金鑰。）

## 3. 登入流程

1. 帳號密碼正確，且帳號**已啟用 MFA**：不建立工作階段，改建立一個 **MFA 挑戰**（5 分鐘有效，存 SHA-256），以 cookie `em_mfa`（`Path=/login`、HttpOnly、Secure、SameSite=Strict）帶著，轉到 `/login/mfa`。
2. `/login/mfa` 輸入驗證碼或復原碼：
   - 正確：刪除挑戰，建立正常工作階段，稽核記錄 `login`（detail 記錄 `mfa: totp|recovery`）。
   - 錯誤：跟密碼錯誤一樣累計 `failed_logins`（到上限鎖定 15 分鐘），挑戰本身錯 5 次就作廢，要重新輸入密碼。稽核記錄 `login_failed`，reason `mfa`。
   - 帳號在這期間被鎖定、停用，或挑戰過期：一律失敗，回到登入頁。
   - 跟登入頁一樣受 IP 頻率限制。
3. 帳號密碼正確、帳號**沒有**啟用 MFA、而且系統設定**要求 MFA**：建立**只能設定 MFA 的工作階段**（`sessions.setup_only`）。這種工作階段打開任何頁面都會轉到 `/mfa`，只能完成設定或登出。設定完成後原工作階段直接升級成正常的。
4. 其他情況：跟現在一樣。

## 4. 設定頁 `/mfa`（所有角色）

- 側邊欄「變更密碼」旁加「兩步驟驗證」。
- **還沒啟用**：產生一把待確認的金鑰（存在 `admins.mfa_pending_secret`，重新整理頁面沿用同一把），顯示 QR code（伺服器產生 SVG，不用 JavaScript）、Base32 金鑰（手動輸入用）與輸入驗證碼的表單。驗證碼正確才啟用，並顯示 10 組復原碼。
- **已啟用**：顯示啟用時間、剩餘復原碼數量；可以「重新產生復原碼」或「停用 MFA」，兩者都要輸入目前的驗證碼。系統要求 MFA 時不能停用。
- **復原碼**：10 組，每組 `xxxx-xxxx`（小寫英數，去掉易混淆字元），只顯示一次。存 SHA-256（亂數夠長，不需要 Argon2）。每組只能用一次。重新產生會作廢舊的。
- 啟用、停用、重新產生復原碼後，刪除這個帳號**其他**的工作階段。

## 5. 管理

- 帳號列表加一欄「兩步驟驗證」：已啟用、未啟用。
- 帳號詳細頁：平台管理員可以「重設兩步驟驗證」（清除金鑰與復原碼，並登出該帳號所有工作階段）。不能對自己使用（自己請用 `/mfa`）。稽核記錄 `mfa_reset`。
- 帳號列表上方加一個設定：「所有帳號都必須使用兩步驟驗證」（設定鍵 `mfa_required`，預設關閉）。開啟時，**還沒設定的帳號**下次登入就會被要求設定；已登入的工作階段不受影響，直到過期。
- 伺服器指令列：`endpoint-server admin-reset-mfa <帳號>`，給所有平台管理員都無法登入時使用。

## 6. 稽核記錄

`mfa_enabled`、`mfa_disabled`、`mfa_recovery_regenerated`、`mfa_reset`（target 是被重設的帳號）、`mfa_required_changed`，以及 `login`／`login_failed` 的 detail。

## 7. 資料表

- `admins` 新增 `mfa_secret`、`mfa_pending_secret`、`mfa_enabled_at`、`mfa_last_step`。
- 新表 `admin_recovery_codes (admin_id, code_hash, used_at)`。
- 新表 `mfa_challenges (token_hash, admin_id, expires_at, failures)`；登入時順便清除過期的挑戰。
- `sessions` 新增 `setup_only BOOLEAN NOT NULL DEFAULT false`。
- `settings` 新增 `mfa_required = false`。

## 8. 測試

- 單元測試：RFC 6238 附錄 B 的 SHA-1 測試向量、Base32、前後一步的容許範圍、重放拒絕。
- 伺服器測試：MFA 登入成功與失敗、失敗累計鎖定、挑戰錯 5 次作廢、挑戰過期、重放、復原碼只能用一次、要求 MFA 時的設定流程與頁面導向、停用與重新產生需要驗證碼、平台管理員重設、指令列重設、未啟用 MFA 的帳號登入不變。
