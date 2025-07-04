const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const dbPath = path.join(__dirname, 'kaichuan.db');
const db = new sqlite3.Database(dbPath);

db.get("SELECT * FROM staff_accounts WHERE username = 'admin'", (err, row) => {
  if (err) {
    console.error("❌ 查詢錯誤：", err);
  } else if (!row) {
    console.log("❗ 查無 admin 帳號");
  } else {
    console.log("✅ 查詢成功，admin 帳號如下：");
    console.log(row);
  }
  db.close();
}); 