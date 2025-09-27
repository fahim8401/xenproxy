// IP Gateway Admin Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard functionality
    initializeDashboard();
    initializeUserDetail();
});

// Dashboard Functions
function initializeDashboard() {
    // User creation form
    const createUserForm = document.getElementById('createUserForm');
    if (createUserForm) {
        createUserForm.addEventListener('submit', handleCreateUser);
    }

    // Advanced config toggle
    const toggleAdvanced = document.getElementById('toggleAdvanced');
    if (toggleAdvanced) {
        toggleAdvanced.addEventListener('click', toggleAdvancedPanel);
    }

    // Save config button
    const saveConfigBtn = document.getElementById('saveConfigBtn');
    if (saveConfigBtn) {
        saveConfigBtn.addEventListener('click', handleSaveConfig);
    }

    // Delete user buttons
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('delete-user-btn')) {
            const userId = e.target.getAttribute('data-user-id');
            handleDeleteUser(userId);
        }
    });

    // Real-time status polling
    if (document.getElementById('userTableBody')) {
        startStatusPolling();
    }
}

function handleCreateUser(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const userData = {
        username: formData.get('username'),
        password: formData.get('password'),
        ip_address: formData.get('ip_address'),
        enable_ssh: document.getElementById('enable_ssh').checked,
        enable_socks5: document.getElementById('enable_socks5').checked,
        enable_http: document.getElementById('enable_http').checked,
        enable_pptp: document.getElementById('enable_pptp').checked
    };

    // Basic validation
    if (!userData.username || !userData.password || !userData.ip_address) {
        showToast('Please fill in all required fields', 'error');
        return;
    }

    const submitBtn = e.target.querySelector('button[type="submit"]');
    setLoading(submitBtn, true);

    fetch('/api/users', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(userData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
        } else {
            showToast('User created successfully!', 'success');
            e.target.reset();
            // Refresh the page to show new user
            setTimeout(() => location.reload(), 1000);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to create user', 'error');
    })
    .finally(() => {
        setLoading(submitBtn, false);
    });
}

function toggleAdvancedPanel() {
    const panel = document.getElementById('advancedPanel');
    const button = document.getElementById('toggleAdvanced');

    if (panel.classList.contains('hidden')) {
        panel.classList.remove('hidden');
        button.textContent = 'Hide Advanced Settings';
    } else {
        panel.classList.add('hidden');
        button.textContent = 'Show Advanced Settings';
    }
}

function handleSaveConfig() {
    const configData = {
        subnet_range: document.getElementById('subnet_range').value,
        network_interface: document.getElementById('network_interface').value,
        proxy_base_port: document.getElementById('proxy_base_port').value
    };

    const saveBtn = document.getElementById('saveConfigBtn');
    setLoading(saveBtn, true);

    fetch('/api/system/config', {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(configData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
        } else {
            showToast('Configuration saved successfully!', 'success');
            setTimeout(() => location.reload(), 1000);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to save configuration', 'error');
    })
    .finally(() => {
        setLoading(saveBtn, false);
    });
}

function handleDeleteUser(userId) {
    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        return;
    }

    fetch(`/api/users/${userId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
        } else {
            showToast('User deleted successfully!', 'success');
            // Remove user row from table
            const userRow = document.querySelector(`[data-user-id="${userId}"]`);
            if (userRow) {
                userRow.remove();
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to delete user', 'error');
    });
}

function startStatusPolling() {
    // Poll every 30 seconds
    setInterval(updateUserStatuses, 30000);
}

function updateUserStatuses() {
    const userRows = document.querySelectorAll('.user-row');

    userRows.forEach(row => {
        const userId = row.getAttribute('data-user-id');
        if (userId) {
            fetch(`/api/users/${userId}/status`)
                .then(response => response.json())
                .then(data => {
                    // Update status indicators if needed
                    // This could be enhanced to show real-time proxy status
                })
                .catch(error => console.error('Error updating status:', error));
        }
    });
}

// User Detail Functions
function initializeUserDetail() {
    // Protocol toggles
    const toggles = ['ssh', 'socks5', 'http', 'pptp'];
    toggles.forEach(protocol => {
        const toggle = document.getElementById(`toggle_${protocol}`);
        if (toggle) {
            toggle.addEventListener('change', () => handleProtocolToggle(protocol));
        }
    });

    // Test connection buttons
    document.addEventListener('click', function(e) {
        if (e.target.classList.contains('test-connection-btn')) {
            const protocol = e.target.getAttribute('data-protocol');
            testConnection(protocol);
        }
    });

    // Delete user button
    const deleteBtn = document.getElementById('deleteUserBtn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', handleDeleteUserDetail);
    }

    // Close test modal
    const closeModalBtn = document.getElementById('closeTestModal');
    if (closeModalBtn) {
        closeModalBtn.addEventListener('click', () => {
            document.getElementById('testModal').classList.add('hidden');
        });
    }

    // Real-time status polling for user detail
    if (document.getElementById('socks5-status')) {
        startUserStatusPolling();
    }
}

function handleProtocolToggle(protocol) {
    const toggle = document.getElementById(`toggle_${protocol}`);
    const userId = getUserIdFromUrl();

    const updateData = {};
    updateData[`enable_${protocol}`] = toggle.checked;

    fetch(`/api/users/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(updateData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
            // Revert toggle
            toggle.checked = !toggle.checked;
        } else {
            showToast(`${protocol.toUpperCase()} ${toggle.checked ? 'enabled' : 'disabled'}`, 'success');
            // Update status display
            updateProtocolStatus(protocol, toggle.checked);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast(`Failed to update ${protocol}`, 'error');
        // Revert toggle
        toggle.checked = !toggle.checked;
    });
}

function updateProtocolStatus(protocol, enabled) {
    if (protocol === 'socks5' || protocol === 'http') {
        const statusElement = document.getElementById(`${protocol}-status`);
        const textElement = document.getElementById(`${protocol}-status-text`);

        if (statusElement && textElement) {
            if (enabled) {
                statusElement.textContent = '⏳';
                textElement.textContent = 'Starting...';
                // Status will be updated by polling
            } else {
                statusElement.textContent = '🔴';
                textElement.textContent = 'Stopped';
            }
        }
    }
}

function testConnection(protocol) {
    const modal = document.getElementById('testModal');
    const title = document.getElementById('testModalTitle');
    const content = document.getElementById('testModalContent');

    title.textContent = `Testing ${protocol.toUpperCase()} Connection...`;
    content.innerHTML = `
        <div class="flex items-center">
            <div class="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
            Performing connection test...
        </div>
    `;
    modal.classList.remove('hidden');

    // Simulate connection test (replace with actual test logic)
    setTimeout(() => {
        const success = Math.random() > 0.3; // 70% success rate for demo
        if (success) {
            content.innerHTML = `
                <div class="text-green-600">
                    ✅ Connection test successful!<br>
                    <small class="text-gray-600">Response time: ${Math.floor(Math.random() * 100) + 50}ms</small>
                </div>
            `;
        } else {
            content.innerHTML = `
                <div class="text-red-600">
                    ❌ Connection test failed<br>
                    <small class="text-gray-600">Please check your configuration</small>
                </div>
            `;
        }
    }, 2000);
}

function handleDeleteUserDetail() {
    const userId = getUserIdFromUrl();

    if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        return;
    }

    const deleteBtn = document.getElementById('deleteUserBtn');
    setLoading(deleteBtn, true);

    fetch(`/api/users/${userId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
        } else {
            showToast('User deleted successfully!', 'success');
            setTimeout(() => window.location.href = '/dashboard', 1000);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to delete user', 'error');
    })
    .finally(() => {
        setLoading(deleteBtn, false);
    });
}

function startUserStatusPolling() {
    const userId = getUserIdFromUrl();

    function pollStatus() {
        fetch(`/api/users/${userId}/status`)
            .then(response => response.json())
            .then(data => {
                if (data.proxy_status) {
                    updateProxyStatuses(data.proxy_status);
                }
            })
            .catch(error => console.error('Error polling status:', error));
    }

    // Poll immediately and then every 10 seconds
    pollStatus();
    setInterval(pollStatus, 10000);
}

function updateProxyStatuses(proxyStatus) {
    Object.keys(proxyStatus).forEach(protocol => {
        const statusElement = document.getElementById(`${protocol}-status`);
        const textElement = document.getElementById(`${protocol}-status-text`);

        if (statusElement && textElement) {
            const isRunning = proxyStatus[protocol];
            statusElement.textContent = isRunning ? '🟢' : '🔴';
            textElement.textContent = isRunning ? 'Running' : 'Stopped';
        }
    });
}

// Utility Functions
function getUserIdFromUrl() {
    const path = window.location.pathname;
    const match = path.match(/\/user\/(\d+)/);
    return match ? match[1] : null;
}

function setLoading(element, loading) {
    if (loading) {
        element.disabled = true;
        element.classList.add('btn-loading');
        element.dataset.originalText = element.textContent;
        element.textContent = 'Loading...';
    } else {
        element.disabled = false;
        element.classList.remove('btn-loading');
        if (element.dataset.originalText) {
            element.textContent = element.dataset.originalText;
        }
    }
}

function showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `fixed top-4 right-4 p-4 rounded-md shadow-lg z-50 ${
        type === 'success' ? 'bg-green-500 text-white' :
        type === 'error' ? 'bg-red-500 text-white' :
        'bg-blue-500 text-white'
    }`;
    toast.textContent = message;

    document.body.appendChild(toast);

    // Remove after 3 seconds
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

// Form validation helpers
function validateUsername(username) {
    if (!username || username.length < 3 || username.length > 80) {
        return false;
    }
    return /^[a-zA-Z0-9_-]+$/.test(username);
}

function validatePassword(password) {
    return password && password.length >= 6;
}

function validateIP(ip) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

// Initialize toggle switches
document.addEventListener('DOMContentLoaded', function() {
    // Initialize toggle switches
    const toggles = document.querySelectorAll('.toggle-checkbox');
    toggles.forEach(toggle => {
        toggle.addEventListener('change', function() {
            const label = this.nextElementSibling;
            if (this.checked) {
                label.classList.add('bg-green-400');
                label.classList.remove('bg-gray-300');
            } else {
                label.classList.add('bg-gray-300');
                label.classList.remove('bg-green-400');
            }
        });
    });
});
