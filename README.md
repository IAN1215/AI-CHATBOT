# SaaS AI LINE Bot 客服系統平台

這是一個整合了 LINE Messaging API 的客服系統，包含管理後台和錯誤處理機制。

## 功能特點

- LINE Bot 自動回覆
- 客服人員管理介面
- 即時對話功能
- 完整的錯誤處理和日誌記錄
- 資料庫自動備份
- 安全性保護機制

## 系統需求

- Node.js 14.0 或以上
- SQLite3
- LINE Messaging API 帳號
- Google Cloud Vision API（用於圖片分析）

## 安裝步驟

1. 克隆專案：
   ```bash
   git clone [repository-url]
   cd kaichuan-line-bot
   ```

2. 安裝依賴：
   ```bash
   npm install
   ```

3. 設定環境變數：
   ```bash
   cp .env.example .env
   ```
   編輯 `.env` 文件，填入必要的設定：
   ```
   LINE_CHANNEL_ACCESS_TOKEN=your_line_channel_access_token
   LINE_CHANNEL_SECRET=your_line_channel_secret
   JWT_SECRET=your_jwt_secret
   ADMIN_USERNAME=admin
   ADMIN_PASSWORD=your_admin_password
   ADMIN_EMAIL=admin@example.com
   ```

4. 初始化資料庫：
   ```bash
   npm run init-admin
   ```

5. 啟動服務：
   ```bash
   npm start
   ```

## 開發模式

使用 nodemon 啟動開發模式：
```bash
npm run dev
```

## 資料庫備份

執行手動備份：
```bash
npm run backup
```

備份文件將保存在 `backups` 目錄下，預設保留最近 7 天的備份。

## 安全性考慮

- 使用 helmet 增強 HTTP 安全性
- 實現請求速率限制
- JWT 身份驗證
- 密碼加密存儲
- SQL 注入防護
- 完整的錯誤日誌

## API 端點

### 認證相關
- POST /api/login - 登入
- POST /api/change-password - 修改密碼

### 客服管理
- POST /api/staff - 創建客服帳號（需要管理員權限）
- GET /api/conversations - 獲取對話記錄
- GET /api/statistics - 獲取統計數據

## 錯誤處理

系統實現了完整的錯誤處理機制：
- 資料庫操作錯誤
- API 請求錯誤
- 認證錯誤
- 權限錯誤

所有錯誤都會被記錄到資料庫的 `error_logs` 表中。

## 監控和日誌

系統記錄以下資訊：
- 請求日誌（request_logs）
- 錯誤日誌（error_logs）
- 登入嘗試（login_attempts）

## 注意事項

1. 首次設置後請立即修改管理員密碼
2. 定期檢查錯誤日誌
3. 確保定期備份資料庫
4. 監控系統資源使用情況

## 授權

MIT License 
