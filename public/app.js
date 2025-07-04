// 設定 axios 攔截器
axios.interceptors.request.use(config => {
    const token = localStorage.getItem('token');
    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
});

axios.interceptors.response.use(
    response => response,
    error => {
        if (error.response && error.response.status === 401) {
            localStorage.removeItem('token');
            localStorage.removeItem('staffName');
            localStorage.removeItem('staffRole');
            window.location.href = '/login.html';
        }
        return Promise.reject(error);
    }
);

// 建立 Vue 應用程式
const { createApp } = Vue;

const app = createApp({
    data() {
        return {
            currentView: 'dashboard',
            staffName: localStorage.getItem('staffName'),
            staffRole: localStorage.getItem('staffRole'),
            isAdmin: localStorage.getItem('staffRole') === 'admin',
            stats: {
                totalUsers: 0,
                todayChats: 0,
                pendingItems: 0
            },
            users: [],
            userSearchQuery: '',
            selectedUser: null,
            handoverData: {
                toStaff: '',
                note: ''
            },
            staffList: [],
            chats: [],
            chatSearchQuery: '',
            chatSearchDate: '',
            chatSearchTag: '',
            availableTags: [],
            selectedChat: null,
            ratingData: {
                satisfied: null,
                correctAnswer: ''
            },
            settings: {
                lineToken: '',
                discordWebhook: '',
                notifyOnUserSwitch: false,
                notifyOnError: false,
                enableSurvey: false,
                surveyQuestions: []
            },
            newStaff: {
                username: '',
                password: '',
                name: '',
                email: '',
                role: 'staff'
            },
            knowledge: [],
            knowledgeSearchQuery: '',
            newKnowledge: {
                question: '',
                answer: ''
            },
            imageAnalysis: null,
            selectedImage: null,
            assistantProfile: {}
        };
    },
    computed: {
        filteredUsers() {
            return this.users.filter(user => 
                user.userId.toLowerCase().includes(this.userSearchQuery.toLowerCase()) ||
                (user.displayName && user.displayName.toLowerCase().includes(this.userSearchQuery.toLowerCase()))
            );
        },
        filteredChats() {
            return this.chats.filter(chat => {
                const matchesSearch = chat.message.toLowerCase().includes(this.chatSearchQuery.toLowerCase()) ||
                                    chat.response.toLowerCase().includes(this.chatSearchQuery.toLowerCase());
                const matchesDate = !this.chatSearchDate || chat.created_at.startsWith(this.chatSearchDate);
                const matchesTag = !this.chatSearchTag || chat.tags.includes(this.chatSearchTag);
                return matchesSearch && matchesDate && matchesTag;
            });
        },
        filteredKnowledge() {
            return this.knowledge.filter(item => 
                item.question.toLowerCase().includes(this.knowledgeSearchQuery.toLowerCase())
            );
        }
    },
    methods: {
        async logout() {
            localStorage.removeItem('token');
            localStorage.removeItem('staffName');
            localStorage.removeItem('staffRole');
            window.location.href = '/login.html';
        },
        async fetchStats() {
            try {
                const response = await axios.get('/api/statistics');
                this.stats = response.data;
            } catch (error) {
                console.error('Error fetching statistics:', error);
            }
        },
        async fetchUsers() {
            try {
                const response = await axios.get('/api/users');
                this.users = response.data;
            } catch (error) {
                console.error('Error fetching users:', error);
            }
        },
        async viewUserDetail(user) {
            try {
                const response = await axios.get(`/api/users/${user.userId}`);
                this.selectedUser = response.data;
                const modal = new bootstrap.Modal(document.getElementById('userDetailModal'));
                modal.show();
            } catch (error) {
                console.error('Error fetching user details:', error);
            }
        },
        async handoverUser(user) {
            this.handoverData = {
                toStaff: '',
                note: '',
                userId: user.userId
            };
            const modal = new bootstrap.Modal(document.getElementById('handoverModal'));
            modal.show();
        },
        async submitHandover() {
            try {
                await axios.post('/api/handover', this.handoverData);
                await this.fetchUsers();
                const modal = bootstrap.Modal.getInstance(document.getElementById('handoverModal'));
                modal.hide();
            } catch (error) {
                console.error('Error submitting handover:', error);
            }
        },
        async addUserTag() {
            const tag = prompt('請輸入標籤名稱:');
            if (tag) {
                try {
                    await axios.post(`/api/users/${this.selectedUser.userId}/tags`, { tag });
                    await this.viewUserDetail(this.selectedUser);
                } catch (error) {
                    console.error('Error adding tag:', error);
                }
            }
        },
        async fetchChats() {
            try {
                const response = await axios.get('/api/conversations');
                this.chats = response.data;
            } catch (error) {
                console.error('Error fetching chats:', error);
            }
        },
        async rateResponse(chat) {
            this.selectedChat = chat;
            this.ratingData = {
                satisfied: null,
                correctAnswer: ''
            };
            const modal = new bootstrap.Modal(document.getElementById('rateModal'));
            modal.show();
        },
        async submitRating() {
            try {
                await axios.post(`/api/conversations/${this.selectedChat.id}/rate`, this.ratingData);
                await this.fetchChats();
                const modal = bootstrap.Modal.getInstance(document.getElementById('rateModal'));
                modal.hide();
            } catch (error) {
                console.error('Error submitting rating:', error);
            }
        },
        async addChatTag(chat) {
            const tag = prompt('請輸入標籤名稱:');
            if (tag) {
                try {
                    await axios.post(`/api/conversations/${chat.id}/tags`, { tag });
                    await this.fetchChats();
                } catch (error) {
                    console.error('Error adding tag:', error);
                }
            }
        },
        async markStatus(chat, status) {
            try {
                await axios.post(`/api/conversations/${chat.id}/status`, { status });
                await this.fetchChats();
            } catch (error) {
                console.error('Error marking status:', error);
            }
        },
        async fetchSettings() {
            try {
                const response = await axios.get('/api/settings');
                this.settings = response.data;
            } catch (error) {
                console.error('Error fetching settings:', error);
            }
        },
        async saveSettings() {
            try {
                await axios.post('/api/settings', this.settings);
                alert('設定已儲存');
            } catch (error) {
                console.error('Error saving settings:', error);
            }
        },
        async saveSurveySettings() {
            try {
                await axios.post('/api/settings/survey', this.settings);
                alert('問卷設定已儲存');
            } catch (error) {
                console.error('Error saving survey settings:', error);
            }
        },
        addQuestion() {
            this.settings.surveyQuestions.push({ text: '' });
        },
        removeQuestion(index) {
            this.settings.surveyQuestions.splice(index, 1);
        },
        async fetchStaffList() {
            try {
                const response = await axios.get('/api/staff');
                this.staffList = response.data;
            } catch (error) {
                console.error('Error fetching staff list:', error);
            }
        },
        showCreateStaffModal() {
            this.newStaff = {
                username: '',
                password: '',
                name: '',
                email: '',
                role: 'staff'
            };
            const modal = new bootstrap.Modal(document.getElementById('createStaffModal'));
            modal.show();
        },
        async createStaff() {
            try {
                await axios.post('/api/staff', this.newStaff);
                await this.fetchStaffList();
                const modal = bootstrap.Modal.getInstance(document.getElementById('createStaffModal'));
                modal.hide();
            } catch (error) {
                console.error('Error creating staff:', error);
            }
        },
        async deleteStaff(staff) {
            if (confirm(`確定要刪除客服 ${staff.name} 嗎？`)) {
                try {
                    await axios.delete(`/api/staff/${staff.id}`);
                    await this.fetchStaffList();
                } catch (error) {
                    console.error('Error deleting staff:', error);
                }
            }
        },
        async fetchKnowledge() {
            try {
                const response = await axios.get('/api/knowledge');
                this.knowledge = response.data;
            } catch (error) {
                console.error('Error fetching knowledge:', error);
            }
        },
        async addKnowledge() {
            if (!this.newKnowledge.question.trim() || !this.newKnowledge.answer.trim()) {
                alert('請輸入完整的問題和答案');
                return;
            }

            try {
                await axios.post('/api/knowledge', this.newKnowledge);
                this.newKnowledge = { question: '', answer: '' };
                await this.fetchKnowledge();
                alert('✅ 新增成功');
            } catch (error) {
                console.error('Error adding knowledge:', error);
            }
        },
        async deleteKnowledge(id) {
            if (!confirm('確定要刪除嗎？')) return;
            
            try {
                await axios.delete(`/api/knowledge/${id}`);
                await this.fetchKnowledge();
                alert('✅ 刪除成功');
            } catch (error) {
                console.error('Error deleting knowledge:', error);
            }
        },
        async switchMode(userId) {
            try {
                await axios.post('/api/switch', { userId });
                await this.fetchUsers();
            } catch (error) {
                console.error('Error switching mode:', error);
            }
        },
        async analyzeImage(imageUrl) {
            try {
                const response = await axios.post('/api/vision/analyze', { imageUrl });
                this.imageAnalysis = response.data;
                this.selectedImage = imageUrl;
            } catch (error) {
                console.error('Error analyzing image:', error);
            }
        },
        async fetchAssistantProfile() {
            try {
                const response = await axios.get('/api/assistant-profile');
                this.assistantProfile = response.data || {};
            } catch (error) {
                console.error('Error fetching assistant profile:', error);
            }
        }
    },
    mounted() {
        // 檢查是否已登入
        const token = localStorage.getItem('token');
        if (!token) {
            window.location.href = '/login.html';
            return;
        }

        // 初始化數據
        this.fetchStats();
        this.fetchUsers();
        this.fetchChats();
        this.fetchSettings();
        this.fetchStaffList();
        this.fetchKnowledge();
        this.fetchAssistantProfile();

        // 設置定時更新
        setInterval(() => {
            this.fetchStats();
            this.fetchUsers();
            this.fetchChats();
        }, 30000); // 每30秒更新一次
    }
});

// 掛載應用程式
app.mount('#app');
  