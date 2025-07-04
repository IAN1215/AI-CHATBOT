const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('database.db');

const adminUser = {
    username: 'admin',
    password: 'admin123',  // 這是初始密碼
    name: '系統管理員',
    email: 'admin@example.com',
    role: 'admin'
};

// 創建 staff_accounts 表（如果不存在）
db.run(`CREATE TABLE IF NOT EXISTS staff_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    name TEXT,
    email TEXT,
    role TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`, (err) => {
    if (err) {
        console.error('創建表格失敗:', err);
        return;
    }

    // 先刪除已存在的管理員帳號
    db.run('DELETE FROM staff_accounts WHERE username = ?', [adminUser.username], (err) => {
        if (err) {
            console.error('刪除舊帳號失敗:', err);
            db.close();
            return;
        }

        // 創建新的管理員帳號
        bcrypt.hash(adminUser.password, 10, (err, hashedPassword) => {
            if (err) {
                console.error('密碼加密失敗:', err);
                db.close();
                return;
            }

            // 確保密碼雜湊不為空
            if (!hashedPassword) {
                console.error('密碼雜湊為空');
                db.close();
                return;
            }

            db.run(
                'INSERT INTO staff_accounts (username, password, name, email, role) VALUES (?, ?, ?, ?, ?)',
                [adminUser.username, hashedPassword, adminUser.name, adminUser.email, adminUser.role],
                (err) => {
                    if (err) {
                        console.error('創建管理員帳號失敗:', err);
                    } else {
                        console.log('管理員帳號創建成功！');
                        console.log('帳號：admin');
                        console.log('密碼：admin123');
                    }
                    db.close();
                }
            );
        });
    });
}); 