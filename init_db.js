const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    // 用戶問題表
    db.run(`
        CREATE TABLE IF NOT EXISTS user_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            userId TEXT NOT NULL,
            question TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            handled INTEGER DEFAULT 0
        )
    `);

    // 知識庫表
    db.run(`
        CREATE TABLE IF NOT EXISTS knowledge (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // 用戶狀態表
    db.run(`
        CREATE TABLE IF NOT EXISTS user_states (
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
        )
    `);

    // 對話歷史表
    db.run(`
        CREATE TABLE IF NOT EXISTS chat_history (
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
            reminder_sent INTEGER DEFAULT 0
        )
    `);

    // 創建索引
    db.run('CREATE INDEX IF NOT EXISTS idx_user_questions_userid ON user_questions(userId)');
    db.run('CREATE INDEX IF NOT EXISTS idx_knowledge_question ON knowledge(question)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_history_userid ON chat_history(userId)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_history_created_at ON chat_history(created_at)');
});

db.close(() => {
    console.log('✅ 資料庫初始化完成');
});
