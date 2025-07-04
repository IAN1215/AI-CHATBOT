async function fetchUsers() {
  const res = await fetch('/api/users');
  const users = await res.json();
  const tbody = document.getElementById('userTableBody');
  tbody.innerHTML = '';

  users.forEach(user => {
    const tr = document.createElement('tr');

    tr.innerHTML = `
      <td>${user.userId}</td>
      <td>${user.mode === 'gpt' ? 'AI 小逸' : '人工客服'}</td>
      <td>
        <button class="btn btn-sm ${user.mode === 'gpt' ? 'btn-warning' : 'btn-primary'}" onclick="toggleMode('${user.userId}')">
          切換為 ${user.mode === 'gpt' ? '人工客服' : 'AI 小逸'}
        </button>
      </td>
    `;

    tbody.appendChild(tr);
  });
}

async function toggleMode(userId) {
  await fetch('/api/switch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userId }),
  });

  fetchUsers();
}

fetchUsers();
