# 管理網頁單一登入（OIDC）第一版 設計

## 1. 目的

讓管理者用公司的身分提供者（Microsoft Entra ID、Google Workspace、Keycloak、Okta 等支援 OpenID Connect 的系統）登入管理網頁：

- 員工離職時，在公司的身分系統停用帳號，就不能再登入管理網頁。
- 兩步驟驗證、密碼原則交給公司的身分系統統一管理。

### 1.1 範圍

- OpenID Connect 授權碼流程，搭配 PKCE（S256）、`state`、`nonce`。
- 只能登入**事先建立好**的管理帳號：角色與群組仍由平台管理員在「帳號」頁指定，不會自動建立帳號。
- 第一次單一登入時，帳號和身分提供者的使用者（`iss` + `sub`）綁定；之後只認綁定的使用者。
- 可以設定「密碼登入只限平台管理員」，讓其他帳號一定要走單一登入（平台管理員保留密碼登入作為緊急用）。

不在範圍：SAML、自動建立帳號、依身分提供者的群組指定角色、WebAuthn、單一登出。

### 1.2 成功標準

- 身分提供者的使用者只能登入綁定（或第一次綁定）的那一個帳號；已停用的帳號不能登入。
- 偽造或重放的回呼（`state` 不符、`nonce` 不符、過期、別的瀏覽器開始的流程）一律失敗。
- 沒設定單一登入時，行為與現在完全相同。

## 2. 設定

| 環境變數 | 說明 |
|---|---|
| `EM_OIDC_ISSUER` | 身分提供者的 Issuer（例如 `https://login.microsoftonline.com/<租戶 ID>/v2.0`）。設了才啟用 |
| `EM_OIDC_CLIENT_ID`、`EM_OIDC_CLIENT_SECRET` | 在身分提供者註冊的應用程式 |
| `EM_OIDC_REDIRECT_URL` | 回呼網址，固定路徑 `/login/oidc/callback`，例如 `https://em.example.com/login/oidc/callback`。要在身分提供者登記同一個網址 |
| `EM_OIDC_USERNAME_CLAIM` | 用哪個 claim 對應管理帳號名稱，預設 `email`（Entra ID 常用 `preferred_username`） |
| `EM_OIDC_LABEL` | 登入頁按鈕文字，預設「使用公司帳號登入」 |

- 設了 `EM_OIDC_ISSUER` 時，其他必填值缺少就拒絕啟動。
- Issuer 與各端點必須是 `https://`；只有本機（`localhost`、`127.0.0.1`、`[::1]`）允許 `http://`，供測試使用。
- 連線身分提供者使用系統信任的根憑證（與 Webhook 相同）。

## 3. 流程

1. 登入頁顯示單一登入按鈕 → `GET /login/oidc`。
2. 伺服器讀取（並快取 1 小時）`<issuer>/.well-known/openid-configuration`，檢查回傳的 `issuer` 與設定完全相同。
3. 產生隨機的 `state`、`nonce` 與 PKCE `code_verifier`，存進資料表 `oidc_logins`（10 分鐘有效），以隨機的識別碼放在 cookie `em_oidc`（`HttpOnly; Secure; SameSite=Lax; Path=/login/oidc`）。導向身分提供者，`scope=openid profile email`。
   - 這個 cookie 必須是 `Lax`：回呼是從身分提供者網站來的頂層 GET。
4. `GET /login/oidc/callback?code&state`：
   - 用 cookie 找到並**刪除**那一筆（只能用一次），沒找到、過期或 `state` 不符就失敗。這也防止「別人的瀏覽器開始、在你的瀏覽器完成」的登入 CSRF。
   - 以 `client_secret_basic` 向 token 端點交換授權碼（帶 `code_verifier`）。
   - 驗證 ID Token：`iss` 相同、`aud` 包含 Client ID（多個 `aud` 時 `azp` 必須是 Client ID）、`exp` 未過期（容許 60 秒誤差）、`nonce` 相同、有 `sub` 與帳號 claim；帳號 claim 是 `email` 而 `email_verified` 為 `false` 時拒絕。
   - **不驗證 ID Token 的簽章**：ID Token 是伺服器透過 TLS 直接從 token 端點取得，OpenID Connect Core 3.1.3.7 允許以 TLS 伺服器驗證取代簽章驗證，省下 JWKS 與多種演算法的處理。
5. 對應帳號（同一個交易）：
   - 有帳號綁定這個 `iss` + `sub`、而且沒停用 → 用它。
   - 否則找帳號名稱與 claim 相同（不分大小寫）、沒停用的帳號：還沒綁定就綁定（稽核 `oidc_linked`）；已綁定別的使用者就拒絕。
   - 都沒有 → 失敗，提示「沒有對應的管理帳號」。
   - 密碼錯誤造成的鎖定不影響單一登入（避免別人用猜密碼把你鎖在外面）。
6. 建立工作階段，稽核 `login`（細節 `method: oidc`）。回應一個 200 頁面再前往 `/`：工作階段 cookie 是 `SameSite=Strict`，直接從跨站的回呼重新導向，第一個請求不會帶 cookie。
   - 單一登入不再要求本系統的兩步驟驗證：由身分提供者負責。「所有帳號都必須使用兩步驟驗證」也不套用在單一登入。
7. 失敗時回登入頁並顯示原因，稽核 `login_failed`（`reason: oidc_*`）。和密碼登入共用每個 IP 的頻率限制。

## 4. 帳號頁

- 清單新增「單一登入」欄（已綁定／—）。
- 帳號詳細頁：已綁定時可「解除綁定」（平台管理員；稽核 `oidc_unlinked`）。用於員工改用新的公司帳號時。
- 設定「密碼登入」：所有帳號（預設）／只限平台管理員。只有設定了單一登入才顯示與生效。稽核 `setting_password_login`。
  - 生效時，非平台管理員輸入正確密碼也不能登入，提示「這個帳號只能用單一登入」；密碼錯誤時照舊顯示「帳號或密碼錯誤」。

## 5. 資料

Migration `0025_oidc.sql`：

- `admins.oidc_issuer`、`admins.oidc_subject`（唯一）。
- `oidc_logins(id_hash, state, nonce, code_verifier, expires_at)`。
- 設定 `password_login`：`all`／`platform`。

## 6. 測試

- 單元：ID Token 驗證（每個檢查各有失敗案例）、PKCE、授權網址、網址允許規則、設定解析。
- 整合（測試內建假的身分提供者）：完整登入並綁定、第二次以綁定登入、`state` 錯誤、cookie 遺失、重放回呼、`nonce` 不符、沒有對應帳號、已綁定別人、已停用、密碼登入限制、解除綁定、沒設定時 `/login/oidc` 回 404 且登入頁沒有按鈕。
