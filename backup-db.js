const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

// 配置
const dbPath = path.join(__dirname, 'database.db');
const backupDir = path.join(__dirname, 'backups');
const maxBackups = 7; // 保留最近7天的備份

// 確保備份目錄存在
if (!fs.existsSync(backupDir)) {
    fs.mkdirSync(backupDir);
}

async function backupDatabase() {
    const date = new Date();
    const timestamp = date.toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(backupDir, `backup-${timestamp}.db`);

    try {
        // 檢查源數據庫是否存在
        if (!fs.existsSync(dbPath)) {
            throw new Error('找不到源數據庫文件');
        }

        // 複製數據庫文件
        fs.copyFileSync(dbPath, backupPath);
        console.log(`✅ 數據庫備份成功: ${backupPath}`);

        // 清理舊備份
        const files = fs.readdirSync(backupDir)
            .filter(file => file.startsWith('backup-'))
            .map(file => ({
                name: file,
                path: path.join(backupDir, file),
                time: fs.statSync(path.join(backupDir, file)).mtime.getTime()
            }))
            .sort((a, b) => b.time - a.time);

        // 刪除超過保留天數的備份
        if (files.length > maxBackups) {
            files.slice(maxBackups).forEach(file => {
                fs.unlinkSync(file.path);
                console.log(`🗑️ 刪除舊備份: ${file.name}`);
            });
        }

        // 驗證備份
        const db = new sqlite3.Database(backupPath);
        await new Promise((resolve, reject) => {
            db.get('SELECT COUNT(*) as count FROM sqlite_master', (err, row) => {
                if (err) {
                    reject(new Error('備份驗證失敗'));
                } else {
                    console.log('✅ 備份驗證成功');
                    resolve();
                }
                db.close();
            });
        });

    } catch (error) {
        console.error('❌ 備份失敗:', error);
        process.exit(1);
    }
}

// 執行備份
backupDatabase(); 