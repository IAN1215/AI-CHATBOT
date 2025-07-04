const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { Client, middleware } = require('@line/bot-sdk');
const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { ImageAnnotatorClient } = require('@google-cloud/vision');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');
const { pipeline } = require('stream/promises');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

// 初始化 Express 應用
const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// 初始化 Vision 實體
const vision = new ImageAnnotatorClient({
    keyFilename: path.join(__dirname, 'credentials', 'google-vision-credentials.json')
});

// 確保上傳目錄存在
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
}

// 設置 multer
const upload = multer({ dest: 'uploads/' });

// 安全性中間件
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
        styleSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
        fontSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "data:"]
      },
    },
  })
);

// 請求速率限制
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        success: false,
        error: '請求次數過多，請稍後再試'
    }
});

// 登入請求限制
const loginLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        error: '登入失敗次數過多，請稍後再試'
    }
});

// 中間件設置
app.use(limiter);
app.use('/api/login', loginLimiter);
app.use('/webhook', express.raw({ type: '*/*' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/js', express.static(path.join(__dirname, 'public/js')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// JWT 身份驗證中間件
const authenticateJWT = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({
                success: false,
                error: '未提供認證令牌'
            });
        }

        const token = authHeader.split(' ')[1];
        jwt.verify(token, JWT_SECRET, (err, staff) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    error: '無效的認證令牌'
                });
            }

            req.staff = staff;
            next();
        });
    } catch (error) {
        next(error);
    }
};

// 權限檢查中間件
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.staff) {
            return res.status(401).json({
                success: false,
                error: '未經過身份驗證'
            });
        }

        if (!roles.includes(req.staff.role)) {
            return res.status(403).json({
                success: false,
                error: '沒有權限執行此操作'
            });
        }

        next();
    };
};

// LINE Bot 配置
const lineConfig = {
    channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN,
    channelSecret: process.env.LINE_CHANNEL_SECRET
};

// 創建 LINE client
const client = new Client(lineConfig);

// 用戶狀態管理
const userStates = {};
const userTimers = {};

// 資料庫連接
const dbPath = path.join(__dirname, 'database.db');
let db;

// 資料庫連接重試機制
const connectDatabase = (retries = 5) => {
    return new Promise((resolve, reject) => {
        const attemptConnection = (attemptsLeft) => {
            db = new sqlite3.Database(dbPath, (err) => {
                if (err) {
                    console.error(`❌ 資料庫連接失敗 (剩餘重試次數: ${attemptsLeft}):`, err);
                    if (attemptsLeft > 0) {
                        setTimeout(() => attemptConnection(attemptsLeft - 1), 2000);
                    } else {
                        reject(err);
                    }
                } else {
                    console.log('✅ 成功連接到資料庫');
                    console.log('✅ 資料庫載入位置：', dbPath);
                    resolve(db);
                }
            });
        };
        attemptConnection(retries);
    });
};

// GPT 回覆函數
async function getGPTResponse(userMessage, userId) {
    const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
    
    // 獲取最近的對話歷史
    const recentChats = await dbQuery(
        `SELECT message, response 
         FROM chat_history 
         WHERE userId = ? 
         ORDER BY created_at DESC 
         LIMIT 5`,
        [userId]
    );

    // 構建對話歷史
    const conversationHistory = recentChats
        .reverse()
        .map(chat => [
            { role: 'user', content: chat.message },
            { role: 'assistant', content: chat.response }
        ])
        .flat();

    const systemPrompt = `
    你是系統櫃工廠的 AI 客服「小逸」，風格自然、輕鬆、溫柔，像朋友一樣與客人對談。
    不要使用開場白。對話自然簡潔，有親切的 emoji。
    遇到客戶有高度與寬度時請幫忙進行估價。估價規則如下：
    
    1. 根據高度區間選擇公式：
    - 0~60cm: (寬/30)*2250
    - 60~89cm: (寬/30)*2550
    - 90~119cm: (寬/30)*2850
    - 120~240cm: (寬/30)*4500
    2. 四捨五入成整數，單位為元。
    3. 加一句提示：「這是基礎款式估價，實際報價會依照設計圖調整喔 😊」
    
    請用繁體中文。語氣自然，像朋友聊天，不用太制式。
    記住之前對話的內容，保持對話的連貫性。
    `;

    try {
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: 'gpt-3.5-turbo',
                messages: [
                    { role: 'system', content: systemPrompt },
                    ...conversationHistory,
                    { role: 'user', content: userMessage }
                ],
                temperature: 0.7
            },
            {
                headers: {
                    Authorization: `Bearer ${OPENAI_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const aiResponse = response.data.choices[0].message.content.trim();

        // 儲存對話記錄
        await dbQuery(
            `INSERT INTO chat_history (
                userId, message, response, created_at, 
                messageType, status
            ) VALUES (?, ?, ?, datetime('now'), 'text', 'normal')`,
            [userId, userMessage, aiResponse]
        );

        return aiResponse;
    } catch (error) {
        console.error('GPT API 錯誤:', error);
        return '抱歉，我現在無法正確處理您的請求，請稍後再試。';
    }
}

// 知識庫查詢
async function searchKnowledge(userMessage) {
    return new Promise((resolve, reject) => {
        db.get(
            `SELECT answer FROM knowledge WHERE question LIKE ?`,
            [`%${userMessage}%`],
            (err, row) => {
                if (err) reject(err);
                else resolve(row ? row.answer : null);
            }
        );
    });
}

// 建立快速回覆按鈕
function createQuickReply(mode) {
    return {
        items: [{
            type: 'action',
            action: {
                type: 'message',
                label: mode === 'gpt' ? '🙋‍♂️人工客服' : '😊 AI 客服',
                text: mode === 'gpt' ? '🙋‍♂️人工客服' : '😊 AI 客服'
            }
        }]
    };
}

// LINE Webhook 處理
app.post('/webhook', middleware(lineConfig), async (req, res) => {
    console.log('✅ 收到 LINE 訊息！');
    res.status(200).send('OK');

    const events = req.body.events;
    for (let event of events) {
        if (event.type !== 'message') continue;

        const userId = event.source.userId;
        const replyToken = event.replyToken;

        // 處理圖片訊息
        if (event.message.type === 'image') {
            console.log('📸 收到圖片訊息！');
            try {
                // 下載圖片
                const stream = await client.getMessageContent(event.message.id);
                const filePath = path.join(__dirname, 'uploads', `${event.message.id}.jpg`);
                const writable = fs.createWriteStream(filePath);

                // 使用 pipeline 處理串流
                await pipeline(stream, writable);

                // 當檔案寫入完成後進行辨識
                const imageBuffer = fs.readFileSync(filePath);
                
                try {
                    // 使用 Google Vision API 辨識圖片
                    const [result] = await vision.textDetection({
                        image: { content: imageBuffer }
                    });

                    // 同時取得物件偵測結果，用於空間分析
                    const [objectResult] = await vision.objectLocalization({
                        image: { content: imageBuffer }
                    });

                    const detections = result.textAnnotations;
                    const objects = objectResult.localizedObjectAnnotations;

                    // 分析空間和物件
                    let spaceAnalysis = '';
                    let hasWall = objects.some(obj => obj.name.toLowerCase().includes('wall'));
                    let hasWindow = objects.some(obj => obj.name.toLowerCase().includes('window'));
                    let hasDoor = objects.some(obj => obj.name.toLowerCase().includes('door'));
                    
                    // 根據偵測到的物件給出建議
                    let recommendation = '讓我為您分析這個空間：\n\n';
                    
                    if (hasWall) {
                        recommendation += '✨ 我看到這是一面牆，';
                        if (hasWindow) {
                            recommendation += '旁邊有窗戶，建議可以考慮在窗邊設計展示櫃或書櫃，讓採光更加充足。\n';
                        } else {
                            recommendation += '這是很好的系統櫃安裝位置。\n';
                        }
                    }

                    if (hasDoor) {
                        recommendation += '🚪 注意到這裡有門，建議預留適當的開門空間，可以考慮使用推拉門設計來節省空間。\n';
                    }

                    // 分析圖片中的尺寸資訊（如果有的話）
                    let dimensions = '';
                    if (detections.length > 0) {
                        const text = detections[0].description;
                        const numberPattern = /(\d+(?:\.\d+)?)\s*(公分|cm|公尺|m)?/gi;
                        const matches = [...text.matchAll(numberPattern)];
                        
                        if (matches.length > 0) {
                            dimensions = '\n📏 根據圖片中的尺寸資訊，我建議：\n';
                            // 轉換所有尺寸為公分
                            const measurements = matches.map(match => {
                                let value = parseFloat(match[1]);
                                if (match[2] && match[2].toLowerCase().includes('m')) {
                                    value *= 100; // 將公尺轉換為公分
                                }
                                return value;
                            });

                            // 根據尺寸給出建議
                            const maxSize = Math.max(...measurements);
                            if (maxSize > 180) {
                                dimensions += `- 這個空間寬度約 ${maxSize} 公分，適合打造整面收納牆\n`;
                                dimensions += `- 建議可以規劃：\n  ⭐ 衣櫃區（${Math.min(maxSize * 0.6, 180)} 公分）\n  ⭐ 展示收納區（${Math.min(maxSize * 0.4, 120)} 公分）\n`;
                            } else if (maxSize > 90) {
                                dimensions += `- 空間寬度約 ${maxSize} 公分，適合設計半身收納櫃\n`;
                                dimensions += '- 建議可以規劃：\n  ⭐ 上方展示層架\n  ⭐ 下方收納抽屜\n';
                            } else {
                                dimensions += `- 空間寬度約 ${maxSize} 公分，建議使用輕巧型收納櫃\n`;
                            }
                        }
                    }

                    // 組合完整回應訊息
                    let responseMessage = recommendation + dimensions + '\n💡 需要更詳細的專業空間規劃建議，歡迎預約我們的設計師為您服務！';

                    // 儲存辨識結果到資料庫
                    await dbQuery(
                        `INSERT INTO chat_history (
                            userId, message, response, messageType,
                            created_at, status
                        ) VALUES (?, ?, ?, 'image', datetime('now'), 'processed')`,
                        [
                            userId,
                            '傳送了一張空間照片',
                            responseMessage
                        ]
                    );

                    // 更新用戶狀態
                    await dbQuery(
                        `UPDATE user_states 
                         SET lastImageAnalysis = ?,
                             lastMessage = '傳送了一張空間照片',
                             lastTimestamp = datetime('now')
                         WHERE userId = ?`,
                        [responseMessage, userId]
                    );

                    // 回傳分析結果
                    await client.replyMessage(replyToken, {
                        type: 'text',
                        text: responseMessage
                    });

                } catch (error) {
                    console.error('❌ 圖片辨識錯誤：', error);
                    await client.pushMessage(userId, {
                        type: 'text',
                        text: '抱歉，圖片辨識過程發生錯誤，請稍後再試 😢'
                    });

                    // 記錄錯誤到資料庫
                    await logError({
                        error_type: 'IMAGE_RECOGNITION_ERROR',
                        error_message: error.message,
                        stack_trace: error.stack
                    });
                }

                // 清理暫存圖片
                fs.unlinkSync(filePath);

            } catch (error) {
                console.error('❌ 圖片處理錯誤：', error);
                await client.pushMessage(userId, {
                    type: 'text',
                    text: '抱歉，處理圖片時發生錯誤，請稍後再試 😢'
                });

                // 記錄錯誤到資料庫
                await logError({
                    error_type: 'IMAGE_PROCESSING_ERROR',
                    error_message: error.message,
                    stack_trace: error.stack
                });
            }
            continue;
        }

        // 處理文字訊息
        const userMessage = event.message.text;

        // 記錄用戶問題
        await dbQuery(
            `INSERT INTO user_questions (userId, question, created_at)
             VALUES (?, ?, datetime('now'))`,
            [userId, userMessage]
        );

        // 處理模式切換
        if (userMessage === '🙋‍♂️人工客服') {
            userStates[userId] = { mode: 'agent' };
            userTimers[userId] = setTimeout(async () => {
                userStates[userId] = { mode: 'gpt' };
                await client.pushMessage(userId, {
                    type: 'text',
                    text: '系統偵測您已離開人工客服，已自動切回 AI 小逸為您服務 😊'
                });
            }, 10 * 60 * 1000);

            await client.replyMessage(replyToken, {
                type: 'text',
                text: '已切換為人工客服，請稍等我們的客服人員 🧑‍💼',
                quickReply: createQuickReply('agent')
            });
            continue;
        }

        if (userMessage === '😊 AI 客服') {
            userStates[userId] = { mode: 'gpt' };
            if (userTimers[userId]) {
                clearTimeout(userTimers[userId]);
            }

            await client.replyMessage(replyToken, {
                type: 'text',
                text: '已切回 AI 客服，由我小逸繼續為您服務 😊',
                quickReply: createQuickReply('gpt')
            });
            continue;
        }

        // 如果是人工客服模式，不處理
        if (userStates[userId]?.mode === 'agent') {
            continue;
        }

        // 查詢知識庫
        const dbAnswer = await searchKnowledge(userMessage);
        if (dbAnswer) {
            await client.replyMessage(replyToken, {
                type: 'text',
                text: dbAnswer,
                quickReply: createQuickReply('gpt')
            });
            continue;
        }

        // 使用 GPT 回覆，傳入 userId 以獲取對話歷史
        const gptResponse = await getGPTResponse(userMessage, userId);
        await client.replyMessage(replyToken, {
            type: 'text',
            text: gptResponse,
            quickReply: createQuickReply('gpt')
        });

        // 更新用戶狀態
        if (!userStates[userId]) {
            userStates[userId] = {
                mode: 'gpt',
                firstMessage: userMessage,
                firstTimestamp: new Date().toISOString(),
                lastMessage: userMessage,
                lastTimestamp: new Date().toISOString()
            };
        } else {
            userStates[userId].lastMessage = userMessage;
            userStates[userId].lastTimestamp = new Date().toISOString();
        }
    }
});

// API 路由
app.get('/api/users', authenticateJWT, async (req, res) => {
    try {
        const users = Object.keys(userStates).map(userId => ({
            userId,
            ...userStates[userId]
        }));
        res.json(users);
    } catch (error) {
        next(error);
    }
});

app.get('/api/knowledge', authenticateJWT, async (req, res) => {
    try {
        const knowledge = await dbQuery('SELECT * FROM knowledge ORDER BY created_at DESC');
        res.json(knowledge);
    } catch (error) {
        console.error('Error fetching knowledge:', error);
        res.status(500).json({ error: 'Failed to fetch knowledge' });
    }
});

app.post('/api/knowledge', authenticateJWT, async (req, res) => {
    const { question, answer } = req.body;
    if (!question || !answer) {
        res.status(400).json({ error: 'Question and answer are required' });
        return;
    }

    try {
        const result = await dbQuery(
            'INSERT INTO knowledge (question, answer, created_at) VALUES (?, ?, datetime("now"))',
            [question, answer]
        );
        res.json({ id: result.lastID, question, answer });
    } catch (error) {
        console.error('Error adding knowledge:', error);
        res.status(500).json({ error: 'Failed to add knowledge' });
    }
});

app.delete('/api/knowledge/:id', authenticateJWT, async (req, res) => {
    const { id } = req.params;
    try {
        await dbQuery('DELETE FROM knowledge WHERE id = ?', [id]);
        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting knowledge:', error);
        res.status(500).json({ error: 'Failed to delete knowledge' });
    }
});

app.post('/api/switch', authenticateJWT, async (req, res) => {
    const { userId } = req.body;
    if (!userId) {
        res.status(400).json({ error: 'User ID is required' });
        return;
    }

    try {
        await dbQuery(
            'UPDATE users SET mode = CASE WHEN mode = "ai" THEN "human" ELSE "ai" END WHERE userId = ?',
            [userId]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Error switching mode:', error);
        res.status(500).json({ error: 'Failed to switch mode' });
    }
});

app.post('/upload-image', authenticateJWT, upload.single('photo'), async (req, res) => {
    try {
        const filePath = req.file.path;
        const imageBuffer = fs.readFileSync(filePath);

        const [result] = await vision.textDetection({
            image: { content: imageBuffer }
        });

        const detections = result.textAnnotations;
        fs.unlinkSync(filePath);

        if (detections.length > 0) {
            res.json({ success: true, text: detections[0].description });
        } else {
            res.json({ success: false, message: '沒有偵測到任何文字' });
        }
    } catch (error) {
        console.error('❌ 圖片辨識失敗：', error);
        res.status(500).json({ success: false, message: '辨識失敗' });
    }
});

// 統一的錯誤處理中間件
const errorHandler = (err, req, res, next) => {
    console.error('❌ 錯誤:', err);
    
    // 記錄錯誤到資料庫
    logError({
        error_type: err.name || 'UnknownError',
        error_message: err.message,
        stack_trace: err.stack
    }).catch(logErr => {
        console.error('❌ 錯誤日誌記錄失敗:', logErr);
    });

    // 根據錯誤類型返回適當的狀態碼和訊息
    const statusCode = err.statusCode || 500;
    res.status(statusCode).json({
        success: false,
        error: err.message || '系統錯誤，請稍後再試'
    });
};

// 錯誤日誌記錄函數
const logError = async ({ error_type, error_message, stack_trace }) => {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('資料庫未連接'));
            return;
        }

        db.run(
            `INSERT INTO error_logs (error_type, error_message, stack_trace)
             VALUES (?, ?, ?)`,
            [error_type, error_message, stack_trace],
            function(err) {
                if (err) reject(err);
                else resolve(this);
            }
        );
    });
};

// 資料庫查詢包裝函數
const dbQuery = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        if (!db) {
            reject(new Error('資料庫未連接'));
            return;
        }

        db.all(sql, params, (err, rows) => {
            if (err) {
                logError({
                    error_type: 'DATABASE_ERROR',
                    error_message: err.message,
                    stack_trace: err.stack
                }).catch(console.error);
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
};

// 請求驗證中間件
const validateRequest = (schema) => {
    return (req, res, next) => {
        const { error } = schema.validate(req.body);
        if (error) {
            return res.status(400).json({
                success: false,
                error: error.details[0].message
            });
        }
        next();
    };
};

// 初始化資料庫
async function initializeDatabase() {
    try {
        await connectDatabase();
        
        // 創建資料表的 SQL 語句
        const createTableQueries = [
            `CREATE TABLE IF NOT EXISTS error_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                error_type TEXT NOT NULL,
                error_message TEXT NOT NULL,
                stack_trace TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS staff_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'staff',
                name TEXT NOT NULL,
                email TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS user_questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userId TEXT NOT NULL,
                question TEXT NOT NULL,
                created_at TEXT NOT NULL,
                handled INTEGER DEFAULT 0
            )`,
            `CREATE TABLE IF NOT EXISTS user_states (
                userId TEXT PRIMARY KEY,
                mode TEXT DEFAULT 'gpt',
                firstMessage TEXT,
                firstTimestamp TEXT,
                lastMessage TEXT,
                lastTimestamp TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                lastImageAnalysis TEXT,
                preferredLanguage TEXT DEFAULT 'zh',
                tags TEXT,
                customerType TEXT,
                contactCount INTEGER DEFAULT 0,
                lastContactTime TEXT,
                displayName TEXT,
                current_staff TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS chat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                userId TEXT NOT NULL,
                message TEXT NOT NULL,
                response TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'normal',
                tags TEXT,
                messageType TEXT DEFAULT 'text',
                rating INTEGER,
                correct_answer TEXT,
                response_time TEXT,
                reminder_sent INTEGER DEFAULT 0,
                FOREIGN KEY (userId) REFERENCES user_states(userId)
            )`,
            `CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                line_token TEXT,
                discord_webhook TEXT,
                notify_on_user_switch INTEGER DEFAULT 0,
                notify_on_error INTEGER DEFAULT 1,
                enable_survey INTEGER DEFAULT 0,
                survey_questions TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS request_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                status INTEGER NOT NULL,
                duration INTEGER NOT NULL,
                ip TEXT NOT NULL,
                user_id TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                ip TEXT NOT NULL,
                success INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                question TEXT NOT NULL,
                answer TEXT NOT NULL
            )`,
            `CREATE TABLE IF NOT EXISTS line_channels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                channel_secret TEXT NOT NULL,
                channel_access_token TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS assistant_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT UNIQUE NOT NULL,
                assistant_name TEXT,
                llm TEXT,
                use_case TEXT,
                description TEXT,
                lang_mode TEXT,
                default_lang TEXT,
                dialog_mode TEXT,
                allow_handoff INTEGER,
                handoff_mode TEXT,
                handoff_timeout INTEGER,
                assistant_url TEXT,
                api_key TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )`
        ];

        // 依序執行創建表的操作
        for (const query of createTableQueries) {
            await dbQuery(query);
        }

        // 創建索引
        const createIndexQueries = [
            'CREATE INDEX IF NOT EXISTS idx_error_logs_created_at ON error_logs(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_chat_history_userid ON chat_history(userId)',
            'CREATE INDEX IF NOT EXISTS idx_chat_history_created_at ON chat_history(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_user_states_updated_at ON user_states(updated_at)',
            'CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_request_logs_user_id ON request_logs(user_id)',
            'CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username)',
            'CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip)',
            'CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at)',
            'CREATE INDEX IF NOT EXISTS idx_knowledge_question ON knowledge(question)'
        ];

        // 依序執行創建索引的操作
        for (const query of createIndexQueries) {
            await dbQuery(query);
        }

        // 初始化設定
        await dbQuery(`
            INSERT OR IGNORE INTO settings (id) VALUES (1)
        `);

        console.log('✅ 資料庫初始化完成');
    } catch (error) {
        console.error('❌ 資料庫初始化失敗:', error);
        process.exit(1);
    }
}

// 請求日誌中間件
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        const log = {
            method: req.method,
            path: req.path,
            status: res.statusCode,
            duration: duration,
            ip: req.ip,
            user: req.staff ? req.staff.username : 'anonymous',
            timestamp: new Date().toISOString()
        };

        // 記錄到資料庫
        if (db) {
            db.run(
                `INSERT INTO request_logs (
                    method, path, status, duration, ip, user_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    log.method,
                    log.path,
                    log.status,
                    log.duration,
                    log.ip,
                    log.user,
                    log.timestamp
                ],
                (err) => {
                    if (err) console.error('❌ 記錄請求日誌失敗:', err);
                }
            );
        }
    });
    next();
});

// 登入路由
app.post('/api/login', async (req, res, next) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                success: false,
                error: '請提供帳號和密碼'
            });
        }

        const users = await dbQuery(
            'SELECT * FROM staff_accounts WHERE username = ?',
            [username]
        );

        const user = users[0];
        if (!user) {
            return res.status(401).json({
                success: false,
                error: '帳號或密碼錯誤'
            });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                error: '帳號或密碼錯誤'
            });
        }

        const token = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role,
                name: user.name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            name: user.name,
            role: user.role
        });
    } catch (error) {
        next(error);
    }
});

// 創建客服帳號
app.post('/api/staff', authenticateJWT, checkRole(['admin']), async (req, res, next) => {
    try {
        const { username, password, name, email, role } = req.body;

        // 檢查必要欄位
        if (!username || !password || !name) {
            return res.status(400).json({
                success: false,
                error: '缺少必要欄位'
            });
        }

        // 檢查用戶名是否已存在
        const existingUsers = await dbQuery(
            'SELECT id FROM staff_accounts WHERE username = ?',
            [username]
        );

        if (existingUsers.length > 0) {
            return res.status(400).json({
                success: false,
                error: '帳號已存在'
            });
        }

        // 加密密碼
        const hashedPassword = await bcrypt.hash(password, 10);

        // 創建帳號
        await dbQuery(
            `INSERT INTO staff_accounts (username, password, name, email, role)
             VALUES (?, ?, ?, ?, ?)`,
            [username, hashedPassword, name, email, role || 'staff']
        );

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 修改密碼
app.post('/api/change-password', authenticateJWT, async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                error: '請提供當前密碼和新密碼'
            });
        }

        const users = await dbQuery(
            'SELECT * FROM staff_accounts WHERE id = ?',
            [req.staff.id]
        );

        const user = users[0];
        if (!user) {
            return res.status(404).json({
                success: false,
                error: '找不到用戶'
            });
        }

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        if (!validPassword) {
            return res.status(401).json({
                success: false,
                error: '當前密碼錯誤'
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await dbQuery(
            'UPDATE staff_accounts SET password = ? WHERE id = ?',
            [hashedPassword, req.staff.id]
        );

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 保護需要認證的路由
app.use('/api/conversations', authenticateJWT);
app.use('/api/statistics', authenticateJWT);
app.use('/api/users', authenticateJWT);
app.use('/api/settings', authenticateJWT);
app.use('/api/me', authenticateJWT);

// 靜態文件路由
app.get('/index.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/', (req, res) => {
    res.redirect('/index.html');
});

// 獲取統計數據
app.get('/api/statistics', authenticateJWT, async (req, res, next) => {
    try {
        const stats = {
            totalUsers: 0,
            todayChats: 0,
            pendingItems: 0,
            dailyStats: [],
            tagStats: [],
            responseTimeStats: [],
            handlingRatioStats: {}
        };

        // 獲取總用戶數
        const totalUsersResult = await dbQuery(
            'SELECT COUNT(DISTINCT userId) as count FROM user_states'
        );
        stats.totalUsers = totalUsersResult[0].count;

        // 獲取今日對話數
        const today = new Date().toISOString().split('T')[0];
        const todayChatsResult = await dbQuery(
            'SELECT COUNT(*) as count FROM chat_history WHERE DATE(created_at) = ?',
            [today]
        );
        stats.todayChats = todayChatsResult[0].count;

        // 獲取待處理事項數
        const pendingItemsResult = await dbQuery(
            'SELECT COUNT(*) as count FROM user_questions WHERE handled = 0'
        );
        stats.pendingItems = pendingItemsResult[0].count;

        // 獲取每日統計
        const dailyStats = await dbQuery(
            `SELECT DATE(created_at) as date, COUNT(*) as count 
             FROM chat_history 
             WHERE created_at >= date('now', '-7 days')
             GROUP BY DATE(created_at)
             ORDER BY date`
        );
        stats.dailyStats = dailyStats;

        // 獲取標籤統計
        const tagStats = await dbQuery(
            `SELECT tags, COUNT(*) as count 
             FROM chat_history 
             WHERE tags IS NOT NULL 
             GROUP BY tags`
        );
        stats.tagStats = tagStats;

        // 獲取回應時間統計
        const responseTimeStats = await dbQuery(
            `SELECT 
                CASE 
                    WHEN response_time < 1000 THEN '1秒內'
                    WHEN response_time < 5000 THEN '5秒內'
                    ELSE '5秒以上'
                END as range,
                COUNT(*) as count
             FROM chat_history
             WHERE response_time IS NOT NULL
             GROUP BY range`
        );
        stats.responseTimeStats = responseTimeStats;

        // 獲取處理比例
        const handlingRatioStats = await dbQuery(
            `SELECT 
                CASE 
                    WHEN messageType = 'text' THEN 'AI回覆'
                    ELSE '人工處理'
                END as type,
                COUNT(*) as count
             FROM chat_history
             GROUP BY type`
        );
        stats.handlingRatioStats = handlingRatioStats;

        res.json(stats);
    } catch (error) {
        next(error);
    }
});

// 獲取用戶列表
app.get('/api/users', authenticateJWT, async (req, res, next) => {
    try {
        const users = await dbQuery(`
            SELECT 
                user_states.*,
                (SELECT COUNT(*) FROM chat_history WHERE chat_history.userId = user_states.userId) as contactCount,
                (SELECT GROUP_CONCAT(DISTINCT tags) FROM chat_history WHERE chat_history.userId = user_states.userId AND tags IS NOT NULL) as allTags
            FROM user_states
        `);

        // 處理標籤
        const processedUsers = users.map(user => ({
            ...user,
            tags: user.allTags ? [...new Set(user.allTags.split(','))] : [],
            contactCount: user.contactCount || 0
        }));

        res.json(processedUsers);
    } catch (error) {
        next(error);
    }
});

// 獲取用戶詳情
app.get('/api/users/:userId', authenticateJWT, async (req, res, next) => {
    try {
        const { userId } = req.params;
        
        // 獲取用戶基本信息
        const users = await dbQuery(
            'SELECT * FROM user_states WHERE userId = ?',
            [userId]
        );

        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                error: '找不到用戶'
            });
        }

        const user = users[0];

        // 獲取最近對話
        const recentChats = await dbQuery(
            `SELECT * FROM chat_history 
             WHERE userId = ? 
             ORDER BY created_at DESC 
             LIMIT 10`,
            [userId]
        );

        // 獲取用戶標籤
        const tags = await dbQuery(
            `SELECT DISTINCT tags 
             FROM chat_history 
             WHERE userId = ? AND tags IS NOT NULL`,
            [userId]
        );

        const userTags = tags.reduce((acc, curr) => {
            if (curr.tags) {
                const tagArray = curr.tags.split(',');
                return [...new Set([...acc, ...tagArray])];
            }
            return acc;
        }, []);

        res.json({
            ...user,
            recentChats,
            tags: userTags
        });
    } catch (error) {
        next(error);
    }
});

// 獲取對話記錄
app.get('/api/conversations', authenticateJWT, async (req, res, next) => {
    try {
        const { startDate, endDate, userId } = req.query;
        let query = 'SELECT * FROM chat_history';
        const params = [];

        if (startDate || endDate || userId) {
            query += ' WHERE';
            const conditions = [];

            if (startDate) {
                conditions.push('DATE(created_at) >= ?');
                params.push(startDate);
            }

            if (endDate) {
                conditions.push('DATE(created_at) <= ?');
                params.push(endDate);
            }

            if (userId) {
                conditions.push('userId = ?');
                params.push(userId);
            }

            query += ' ' + conditions.join(' AND ');
        }

        query += ' ORDER BY created_at DESC LIMIT 100';

        const conversations = await dbQuery(query, params);
        
        // 獲取所有可用的標籤
        const tagsResult = await dbQuery(
            'SELECT DISTINCT tags FROM chat_history WHERE tags IS NOT NULL'
        );
        
        const availableTags = Array.from(new Set(
            tagsResult
                .map(row => JSON.parse(row.tags || '[]'))
                .flat()
        ));

        res.json({
            conversations,
            availableTags
        });
    } catch (error) {
        next(error);
    }
});

// 獲取系統設定
app.get('/api/settings', authenticateJWT, checkRole(['admin']), async (req, res, next) => {
    try {
        const settings = await dbQuery('SELECT * FROM settings');
        res.json(settings[0] || {});
    } catch (error) {
        next(error);
    }
});

// 更新系統設定
app.post('/api/settings', authenticateJWT, checkRole(['admin']), async (req, res, next) => {
    try {
        const { lineToken, discordWebhook, notifyOnUserSwitch, notifyOnError } = req.body;
        
        await dbQuery(
            `INSERT OR REPLACE INTO settings 
             (id, line_token, discord_webhook, notify_on_user_switch, notify_on_error)
             VALUES (1, ?, ?, ?, ?)`,
            [lineToken, discordWebhook, notifyOnUserSwitch, notifyOnError]
        );

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 獲取客服列表
app.get('/api/staff', authenticateJWT, checkRole(['admin']), async (req, res, next) => {
    try {
        const staff = await dbQuery(
            'SELECT id, username, name, email, role, created_at FROM staff_accounts'
        );
        res.json(staff);
    } catch (error) {
        next(error);
    }
});

// 交接用戶
app.post('/api/handover', authenticateJWT, async (req, res, next) => {
    try {
        const { userId, toStaff, note } = req.body;

        // 更新用戶狀態
        await dbQuery(
            `UPDATE user_states 
             SET current_staff = ?, 
                 mode = 'agent'
             WHERE userId = ?`,
            [toStaff, userId]
        );

        // 記錄交接日誌
        await dbQuery(
            `INSERT INTO chat_history (
                userId, message, response, messageType, 
                status, tags
            ) VALUES (?, ?, ?, 'system', 'handover', ?)`,
            [
                userId,
                `系統: 用戶已交接給 ${toStaff}`,
                note || '無備註',
                JSON.stringify(['交接紀錄'])
            ]
        );

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 更新用戶標籤
app.post('/api/users/:userId/tags', authenticateJWT, async (req, res, next) => {
    try {
        const { userId } = req.params;
        const { tags } = req.body;

        await dbQuery(
            `UPDATE user_states 
             SET tags = ?
             WHERE userId = ?`,
            [JSON.stringify(tags), userId]
        );

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 獲取未處理的訊息
app.get('/api/unhandled-messages', authenticateJWT, async (req, res, next) => {
    try {
        const result = await dbQuery(`
            SELECT * FROM user_questions
            WHERE handled = 0
            ORDER BY created_at DESC
            LIMIT 100
        `);
        res.json(result);
    } catch (error) {
        next(error);
    }
});

// 標記訊息為已處理
app.post('/api/messages/:id/handle', authenticateJWT, async (req, res, next) => {
    try {
        const { id } = req.params;

        await dbQuery(
            'UPDATE user_questions SET handled = 1 WHERE id = ?',
            [id]
        );

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 問卷設定
app.post('/api/settings/survey', authenticateJWT, checkRole(['admin']), async (req, res, next) => {
    try {
        const { enableSurvey, surveyQuestions } = req.body;
        await dbQuery(`
            UPDATE settings
            SET enable_survey = ?, survey_questions = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
        `, [
            enableSurvey ? 1 : 0,
            JSON.stringify(surveyQuestions || [])
        ]);
        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 新增用戶標籤
app.post('/api/users/:userId/tags', authenticateJWT, async (req, res, next) => {
    try {
        const { tag } = req.body;
        const { userId } = req.params;

        const userResult = await dbQuery('SELECT tags FROM user_states WHERE userId = ?', [userId]);
        let tags = [];

        if (userResult.length > 0 && userResult[0].tags) {
            tags = JSON.parse(userResult[0].tags);
        }

        if (!tags.includes(tag)) {
            tags.push(tag);
        }

        await dbQuery('UPDATE user_states SET tags = ? WHERE userId = ?', [JSON.stringify(tags), userId]);

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 新增對話標籤
app.post('/api/conversations/:id/tags', authenticateJWT, async (req, res, next) => {
    try {
        const { tag } = req.body;
        const { id } = req.params;

        const chatResult = await dbQuery('SELECT tags FROM chat_history WHERE id = ?', [id]);
        let tags = [];

        if (chatResult.length > 0 && chatResult[0].tags) {
            tags = JSON.parse(chatResult[0].tags);
        }

        if (!tags.includes(tag)) {
            tags.push(tag);
        }

        await dbQuery('UPDATE chat_history SET tags = ? WHERE id = ?', [JSON.stringify(tags), id]);

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 標記對話狀態
app.post('/api/conversations/:id/status', authenticateJWT, async (req, res, next) => {
    try {
        const { status } = req.body;
        const { id } = req.params;

        await dbQuery('UPDATE chat_history SET status = ? WHERE id = ?', [status, id]);

        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 刪除客服帳號
app.delete('/api/staff/:username', authenticateJWT, checkRole(['admin']), async (req, res, next) => {
    try {
        const { username } = req.params;

        if (username === req.staff.username) {
            return res.status(400).json({ error: '不能刪除自己' });
        }

        await dbQuery('DELETE FROM staff_accounts WHERE username = ?', [username]);
        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 提交評分
app.post('/api/rate-response', authenticateJWT, async (req, res, next) => {
    try {
        const { chatId, satisfied, correctAnswer } = req.body;
        await dbQuery(`
            UPDATE chat_history 
            SET rating = ?, correct_answer = ?
            WHERE id = ?
        `, [satisfied ? 1 : 0, correctAnswer || null, chatId]);
        res.json({ success: true });
    } catch (error) {
        next(error);
    }
});

// 註冊 API
app.post('/api/register', async (req, res, next) => {
    try {
        const { username, password, name, email } = req.body;
        if (!username || !password || !name) {
            return res.status(400).json({ success: false, error: '缺少必要欄位' });
        }
        // 檢查帳號是否已存在
        const users = await dbQuery('SELECT id FROM staff_accounts WHERE username = ?', [username]);
        if (users.length > 0) {
            return res.status(400).json({ success: false, error: '帳號已存在' });
        }
        // 產生 tenant_id
        const tenant_id = uuidv4();
        // 密碼加密
        const hashedPassword = await bcrypt.hash(password, 10);
        // 寫入資料庫
        await dbQuery(
            `INSERT INTO staff_accounts (tenant_id, username, password, name, email, role) VALUES (?, ?, ?, ?, ?, 'owner')`,
            [tenant_id, username, hashedPassword, name, email]
        );
        // 查詢新用戶
        const user = await dbQuery('SELECT * FROM staff_accounts WHERE username = ?', [username]);
        // 產生 JWT
        const token = jwt.sign({
            id: user[0].id,
            username: user[0].username,
            role: user[0].role,
            name: user[0].name,
            tenant_id: user[0].tenant_id
        }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ success: true, token, name: user[0].name, role: user[0].role });
    } catch (error) {
        next(error);
    }
});

// 錯誤處理中間件
app.use(errorHandler);

// 啟動伺服器
const port = process.env.PORT || 3000;
const startServer = async () => {
    try {
        await initializeDatabase();
        app.listen(port, () => {
            console.log(`🚀 LINE bot server is running on http://localhost:${port}`);
        });
    } catch (error) {
        console.error('❌ 伺服器啟動失敗:', error);
        process.exit(1);
    }
};

startServer();

// 優雅關閉
process.on('SIGTERM', () => {
    console.log('收到 SIGTERM 信號，準備關閉伺服器...');
    if (db) {
        db.close(() => {
            console.log('資料庫連接已關閉');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
});

// 新增 API：GET/POST /api/line-channel
app.get('/api/line-channel', authenticateJWT, async (req, res, next) => {
    try {
        const tenant_id = req.staff.tenant_id;
        const rows = await dbQuery('SELECT channel_id, channel_secret, channel_access_token FROM line_channels WHERE tenant_id = ?', [tenant_id]);
        if (rows.length === 0) return res.json({});
        res.json(rows[0]);
    } catch (error) { next(error); }
});
app.post('/api/line-channel', authenticateJWT, async (req, res, next) => {
    try {
        const tenant_id = req.staff.tenant_id;
        const { channel_id, channel_secret, channel_access_token } = req.body;
        if (!channel_id || !channel_secret || !channel_access_token) {
            return res.status(400).json({ error: '缺少必要欄位' });
        }
        // upsert
        await dbQuery(
            `INSERT INTO line_channels (tenant_id, channel_id, channel_secret, channel_access_token, created_at, updated_at)
             VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
             ON CONFLICT(tenant_id) DO UPDATE SET channel_id=excluded.channel_id, channel_secret=excluded.channel_secret, channel_access_token=excluded.channel_access_token, updated_at=datetime('now')`,
            [tenant_id, channel_id, channel_secret, channel_access_token]
        );
        res.json({ success: true });
    } catch (error) { next(error); }
});

// 新增 webhook 路由 /webhook/:tenant_id
app.post('/webhook/:tenant_id', async (req, res) => {
    const { tenant_id } = req.params;
    try {
        // 查詢該 tenant 的 LINE channel 設定
        const rows = await dbQuery('SELECT channel_id, channel_secret, channel_access_token FROM line_channels WHERE tenant_id = ?', [tenant_id]);
        if (rows.length === 0) {
            return res.status(404).send('LINE channel 設定不存在');
        }
        const lineConfig = {
            channelAccessToken: rows[0].channel_access_token,
            channelSecret: rows[0].channel_secret
        };
        const client = new Client(lineConfig);
        // 解析 LINE webhook 事件
        middleware(lineConfig)(req, res, async () => {
            const events = req.body.events;
            for (let event of events) {
                if (event.type !== 'message') continue;
                const userId = event.source.userId;
                const replyToken = event.replyToken;
                if (event.message.type === 'text') {
                    await client.replyMessage(replyToken, {
                        type: 'text',
                        text: '這是 ' + tenant_id + ' 的 AI 客服自動回覆：' + event.message.text
                    });
                }
                // 你可根據原本的訊息處理流程擴充
            }
        });
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).send('Internal error');
    }
});

// 新增 API：GET/POST /api/assistant-profile
app.get('/api/assistant-profile', authenticateJWT, async (req, res, next) => {
    try {
        const tenant_id = req.staff.tenant_id;
        const rows = await dbQuery('SELECT * FROM assistant_profiles WHERE tenant_id = ?', [tenant_id]);
        if (rows.length === 0) return res.json({});
        res.json(rows[0]);
    } catch (error) { next(error); }
});
app.post('/api/assistant-profile', authenticateJWT, async (req, res, next) => {
    try {
        const tenant_id = req.staff.tenant_id;
        const {
            assistant_name, llm, use_case, description,
            lang_mode, default_lang, dialog_mode,
            allow_handoff, handoff_mode, handoff_timeout,
            assistant_url, api_key
        } = req.body;
        // upsert
        await dbQuery(
            `INSERT INTO assistant_profiles (
                tenant_id, assistant_name, llm, use_case, description,
                lang_mode, default_lang, dialog_mode, allow_handoff, handoff_mode, handoff_timeout,
                assistant_url, api_key, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(tenant_id) DO UPDATE SET
                assistant_name=excluded.assistant_name,
                llm=excluded.llm,
                use_case=excluded.use_case,
                description=excluded.description,
                lang_mode=excluded.lang_mode,
                default_lang=excluded.default_lang,
                dialog_mode=excluded.dialog_mode,
                allow_handoff=excluded.allow_handoff,
                handoff_mode=excluded.handoff_mode,
                handoff_timeout=excluded.handoff_timeout,
                assistant_url=excluded.assistant_url,
                api_key=excluded.api_key,
                updated_at=datetime('now')
            `,
            [tenant_id, assistant_name, llm, use_case, description, lang_mode, default_lang, dialog_mode, allow_handoff, handoff_mode, handoff_timeout, assistant_url, api_key]
        );
        res.json({ success: true });
    } catch (error) { next(error); }
});

// ... 其他路由和功能的實現 ...
