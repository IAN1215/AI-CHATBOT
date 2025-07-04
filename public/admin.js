// admin.js

// 獲取認證 token
function getAuthToken() {
    return localStorage.getItem('authToken');
}

// 檢查是否已登入
function isAuthenticated() {
    return !!getAuthToken();
}

// 重定向到登入頁面
function redirectToLogin() {
    window.location.href = '/login.html';
}

// 通用 API 請求函數
async function apiRequest(url, options = {}) {
    const token = getAuthToken();
    
    if (!token) {
        redirectToLogin();
        return;
    }
    
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
        }
    };
    
    try {
        const response = await fetch(url, { ...defaultOptions, ...options });
        
        if (response.status === 401) {
            // Token 無效，清除並重定向
            localStorage.removeItem('authToken');
            localStorage.removeItem('userInfo');
            redirectToLogin();
            return;
        }
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('API request failed:', error);
        showNotification('請求失敗，請稍後再試', 'error');
        throw error;
    }
}

function switchTab(tab) {
    // 隱藏所有頁面
    document.getElementById('userPage').classList.add('hidden');
    document.getElementById('knowledgePage').classList.add('hidden');
    document.getElementById('statsPage').classList.add('hidden');
    
    // 移除所有導航連結的 active 狀態
    document.querySelectorAll('.sidebar .nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    // 顯示選中的頁面
    if (tab === 'user') {
        document.getElementById('userPage').classList.remove('hidden');
        document.querySelector('.sidebar .nav-link:nth-child(1)').classList.add('active');
        updatePageTitle('用戶管理');
    } else if (tab === 'knowledge') {
        document.getElementById('knowledgePage').classList.remove('hidden');
        document.querySelector('.sidebar .nav-link:nth-child(2)').classList.add('active');
        updatePageTitle('知識庫管理');
    } else if (tab === 'stats') {
        document.getElementById('statsPage').classList.remove('hidden');
        document.querySelector('.sidebar .nav-link:nth-child(3)').classList.add('active');
        updatePageTitle('統計數據');
        loadStats();
    }
}

async function fetchUsers() {
    try {
        const users = await apiRequest('/api/users');
        displayUsers(users);
        updateUserStats(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        showNotification('載入用戶數據時發生錯誤', 'error');
    }
}

async function fetchKnowledge() {
    try {
        const knowledge = await apiRequest('/api/knowledge');
        displayKnowledge(knowledge);
    } catch (error) {
        console.error('Error fetching knowledge:', error);
        showNotification('載入知識庫數據時發生錯誤', 'error');
    }
}

function displayUsers(users) {
    const searchInput = document.getElementById('userSearch');
    const userList = document.getElementById('userList');

    function render(list) {
        userList.innerHTML = '';
        if (list.length === 0) {
            userList.innerHTML = `
                <div class="col-12 text-center py-5">
                    <i class="fas fa-users fa-3x text-muted mb-3"></i>
                    <p class="text-muted">沒有找到用戶</p>
                </div>
            `;
            return;
        }
        
        list.forEach(user => {
            const card = document.createElement('div');
            card.className = 'col-md-6 col-lg-4 mb-3';
            card.innerHTML = `
                <div class="user-card">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <div>
                            <h6 class="mb-1"><i class="fas fa-user me-2"></i>${user.userId}</h6>
                            <span class="badge bg-${user.mode === 'chat' ? 'success' : 'warning'}">${user.mode === 'chat' ? '聊天模式' : '知識庫模式'}</span>
                        </div>
                        <button class="btn btn-sm btn-outline-primary" onclick="switchMode('${user.userId}')">
                            <i class="fas fa-exchange-alt me-1"></i>切換
                        </button>
                    </div>
                    <div class="small text-muted">
                        <div><i class="fas fa-comment me-1"></i>最後訊息: ${user.lastMessage || '無'}</div>
                        <div><i class="fas fa-clock me-1"></i>時間: ${user.lastTimestamp || '無'}</div>
                    </div>
                </div>
            `;
            userList.appendChild(card);
        });
    }

    render(users);

    // 移除舊的事件監聽器
    const newSearchInput = searchInput.cloneNode(true);
    searchInput.parentNode.replaceChild(newSearchInput, searchInput);
    
    // 添加新的事件監聽器
    newSearchInput.addEventListener('input', () => {
        const keyword = newSearchInput.value.toLowerCase();
        const filtered = users.filter(user => 
            user.userId.toLowerCase().includes(keyword) ||
            user.mode.toLowerCase().includes(keyword)
        );
        render(filtered);
    });
}

function displayKnowledge(knowledge) {
    const searchInput = document.getElementById('knowledgeSearch');
    const knowledgeList = document.getElementById('knowledgeList');

    function render(list) {
        knowledgeList.innerHTML = '';
        if (list.length === 0) {
            knowledgeList.innerHTML = `
                <div class="text-center py-5">
                    <i class="fas fa-brain fa-3x text-muted mb-3"></i>
                    <p class="text-muted">沒有找到知識庫項目</p>
                </div>
            `;
            return;
        }
        
        list.forEach(item => {
            const card = document.createElement('div');
            card.className = 'knowledge-card';
            card.innerHTML = `
                <div class="d-flex justify-content-between align-items-start">
                    <div class="flex-grow-1">
                        <div class="mb-2">
                            <strong><i class="fas fa-question-circle me-2 text-primary"></i>問題:</strong>
                            <p class="mb-1">${item.question}</p>
                        </div>
                        <div>
                            <strong><i class="fas fa-comment me-2 text-success"></i>答案:</strong>
                            <p class="mb-0">${item.answer}</p>
                        </div>
                    </div>
                    <button class="btn btn-sm btn-outline-danger ms-3" onclick="deleteKnowledge(${item.id})">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            `;
            knowledgeList.appendChild(card);
        });
    }

    render(knowledge);

    // 移除舊的事件監聽器
    const newSearchInput = searchInput.cloneNode(true);
    searchInput.parentNode.replaceChild(newSearchInput, searchInput);
    
    // 添加新的事件監聽器
    newSearchInput.addEventListener('input', () => {
        const keyword = newSearchInput.value.toLowerCase();
        const filtered = knowledge.filter(item => 
            item.question.toLowerCase().includes(keyword) ||
            item.answer.toLowerCase().includes(keyword)
        );
        render(filtered);
    });
}

function updateUserStats(users) {
    const totalUsers = users.length;
    const activeUsers = users.filter(user => user.lastTimestamp).length;
    const todayMessages = users.filter(user => {
        if (!user.lastTimestamp) return false;
        const lastDate = new Date(user.lastTimestamp);
        const today = new Date();
        return lastDate.toDateString() === today.toDateString();
    }).length;
    
    document.getElementById('totalUsers').textContent = totalUsers;
    document.getElementById('activeUsers').textContent = activeUsers;
    document.getElementById('todayMessages').textContent = todayMessages;
    document.getElementById('avgResponse').textContent = '2.5s'; // 這裡可以從後端獲取實際數據
}

async function switchMode(userId) {
    try {
        await apiRequest('/api/switch', {
            method: 'POST',
            body: JSON.stringify({ userId })
        });
        
        showNotification('模式切換成功', 'success');
        fetchUsers();
    } catch (error) {
        console.error('Error switching mode:', error);
        showNotification('模式切換時發生錯誤', 'error');
    }
}

async function addKnowledge() {
    const question = document.getElementById('newQuestion').value.trim();
    const answer = document.getElementById('newAnswer').value.trim();
    
    if (!question || !answer) {
        showNotification('請輸入完整的問題和答案', 'warning');
        return;
    }

    try {
        await apiRequest('/api/knowledge', {
            method: 'POST',
            body: JSON.stringify({ question, answer })
        });

        document.getElementById('newQuestion').value = '';
        document.getElementById('newAnswer').value = '';
        fetchKnowledge();
        showNotification('知識新增成功', 'success');
    } catch (error) {
        console.error('Error adding knowledge:', error);
        showNotification('新增知識時發生錯誤', 'error');
    }
}

async function deleteKnowledge(id) {
    if (!confirm('確定要刪除這個知識項目嗎？')) return;
    
    try {
        await apiRequest(`/api/knowledge/${id}`, {
            method: 'DELETE'
        });
        
        fetchKnowledge();
        showNotification('知識刪除成功', 'success');
    } catch (error) {
        console.error('Error deleting knowledge:', error);
        showNotification('刪除知識時發生錯誤', 'error');
    }
}

function loadStats() {
    // 用戶活躍度圖表
    const userActivityCtx = document.getElementById('userActivityChart').getContext('2d');
    new Chart(userActivityCtx, {
        type: 'line',
        data: {
            labels: ['週一', '週二', '週三', '週四', '週五', '週六', '週日'],
            datasets: [{
                label: '活躍用戶',
                data: [12, 19, 15, 25, 22, 30, 28],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.1)',
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });

    // 訊息統計圖表
    const messageCtx = document.getElementById('messageChart').getContext('2d');
    new Chart(messageCtx, {
        type: 'doughnut',
        data: {
            labels: ['聊天模式', '知識庫模式'],
            datasets: [{
                data: [65, 35],
                backgroundColor: ['#667eea', '#764ba2'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

function showNotification(message, type = 'info') {
    // 創建通知元素
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // 自動移除通知
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

// 初始化
document.addEventListener('DOMContentLoaded', function() {
    if (isAuthenticated()) {
        fetchUsers();
        fetchKnowledge();
    }
});
  