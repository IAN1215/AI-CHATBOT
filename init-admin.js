const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();

const dbPath = path.join(__dirname, 'database.db');

async function initializeAdmin() {
    const db = new sqlite3.Database(dbPath, async (err) => {
        if (err) {
            console.error('❌ 資料庫連接失敗:', err);
            process.exit(1);
        }
        
        try {
            // 檢查是否已存在管理員帳號
            const adminExists = await new Promise((resolve, reject) => {
                db.get(
                    'SELECT id FROM staff_accounts WHERE role = ?',
                    ['admin'],
                    (err, row) => {
                        if (err) reject(err);
                        else resolve(row);
                    }
                );
            });

            if (adminExists) {
                console.log('ℹ️ 管理員帳號已存在，跳過初始化');
                db.close();
                return;
            }

            // 設定管理員帳號資料
            const adminData = {
                username: process.env.ADMIN_USERNAME || 'admin',
                password: process.env.ADMIN_PASSWORD || 'admin123',
                name: '系統管理員',
                email: process.env.ADMIN_EMAIL || 'admin@example.com',
                role: 'admin'
            };

            // 加密密碼
            const hashedPassword = await bcrypt.hash(adminData.password, 10);

            // 創建管理員帳號
            await new Promise((resolve, reject) => {
                db.run(
                    `INSERT INTO staff_accounts (username, password, name, email, role)
                     VALUES (?, ?, ?, ?, ?)`,
                    [
                        adminData.username,
                        hashedPassword,
                        adminData.name,
                        adminData.email,
                        adminData.role
                    ],
                    function(err) {
                        if (err) reject(err);
                        else resolve(this);
                    }
                );
            });

            console.log('✅ 管理員帳號創建成功');
            console.log(`帳號: ${adminData.username}`);
            console.log(`密碼: ${adminData.password}`);
            console.log('請儘快登入並修改密碼！');

        } catch (error) {
            console.error('❌ 創建管理員帳號失敗:', error);
        } finally {
            db.close();
        }
    });
}

initializeAdmin(); 