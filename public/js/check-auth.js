// 檢查是否已登入
const token = localStorage.getItem('token');
if (!token) {
    window.location.href = '/login.html';
} else {
    // 驗證 token 是否有效
    axios.get('/api/me', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    }).catch(() => {
        localStorage.removeItem('token');
        localStorage.removeItem('staffName');
        localStorage.removeItem('staffRole');
        window.location.href = '/login.html';
    });
} 