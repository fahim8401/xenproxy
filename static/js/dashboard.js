// IP Gateway Admin Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize dashboard functionality
    initializeDashboard();
    initializeUserDetail();
    initializeNetworkInterfaces();
    initializeIPManagement();
    initializeSystemMonitoring();
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

// Network Interfaces Functions
function initializeNetworkInterfaces() {
    const refreshBtn = document.getElementById('refreshInterfaces');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadNetworkInterfaces);
        // Load interfaces on page load
        loadNetworkInterfaces();
    }
}

function loadNetworkInterfaces() {
    const container = document.getElementById('interfacesContainer');
    const refreshBtn = document.getElementById('refreshInterfaces');

    if (!container) return;

    setLoading(refreshBtn, true);

    fetch('/api/system/interfaces')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast(data.error, 'error');
                return;
            }

            renderNetworkInterfaces(data.interfaces);
        })
        .catch(error => {
            console.error('Error loading interfaces:', error);
            showToast('Failed to load network interfaces', 'error');
        })
        .finally(() => {
            setLoading(refreshBtn, false);
        });
}

function renderNetworkInterfaces(interfaces) {
    const container = document.getElementById('interfacesContainer');

    if (!interfaces || interfaces.length === 0) {
        container.innerHTML = '<div class="col-span-full text-center text-gray-500">No network interfaces found</div>';
        return;
    }

    container.innerHTML = interfaces.map(iface => `
        <div class="bg-gray-50 p-4 rounded-lg">
            <div class="flex justify-between items-center mb-2">
                <h4 class="font-semibold text-gray-900">${iface.name}</h4>
                <span class="text-sm ${iface.ipv4.length > 0 ? 'text-green-600' : 'text-gray-400'}">
                    ${iface.ipv4.length > 0 ? '🟢' : '🔴'} ${iface.ipv4.length > 0 ? 'Up' : 'Down'}
                </span>
            </div>
            ${iface.mac ? `<p class="text-xs text-gray-600 mb-2">MAC: ${iface.mac}</p>` : ''}
            <div class="space-y-1">
                ${iface.ipv4.map(ip => `
                    <div class="text-sm">
                        <span class="font-mono bg-blue-100 px-2 py-1 rounded">${ip.addr}</span>
                        <span class="text-gray-500">/${ip.netmask}</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

// IP Management Functions
function initializeIPManagement() {
    const refreshBtn = document.getElementById('refreshIPs');
    const addBtn = document.getElementById('addIPBtn');

    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadIPManagement);
    }

    if (addBtn) {
        addBtn.addEventListener('click', showAddIPModal);
    }

    // Load IP management on page load
    loadIPManagement();
}

function loadIPManagement() {
    const refreshBtn = document.getElementById('refreshIPs');

    setLoading(refreshBtn, true);

    // Load both assigned and available IPs
    Promise.all([
        fetch('/api/system/assigned-ips').then(r => r.json()),
        fetch('/api/system/available-ips').then(r => r.json())
    ])
    .then(([assignedData, availableData]) => {
        if (assignedData.error) {
            showToast(assignedData.error, 'error');
            return;
        }
        if (availableData.error) {
            showToast(availableData.error, 'error');
            return;
        }

        renderAssignedIPs(assignedData.assigned_ips);
        renderAvailableIPs(availableData.available_ips);
    })
    .catch(error => {
        console.error('Error loading IP management:', error);
        showToast('Failed to load IP management', 'error');
    })
    .finally(() => {
        setLoading(refreshBtn, false);
    });
}

function renderAssignedIPs(assignedIPs) {
    const container = document.getElementById('assignedIPsContainer');

    if (!assignedIPs || Object.keys(assignedIPs).length === 0) {
        container.innerHTML = '<div class="col-span-full text-center text-gray-500">No assigned IPs</div>';
        return;
    }

    container.innerHTML = Object.entries(assignedIPs).map(([ip, info]) => `
        <div class="bg-green-100 border border-green-300 px-3 py-2 rounded flex justify-between items-center">
            <div>
                <span class="font-mono font-semibold">${ip}</span>
                <span class="text-sm text-gray-600 ml-2">(${info.interface})</span>
            </div>
            <button class="text-red-600 hover:text-red-800 text-sm remove-ip-btn" data-ip="${ip}">
                ✕
            </button>
        </div>
    `).join('');

    // Add event listeners for remove buttons
    document.querySelectorAll('.remove-ip-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            removeSystemIP(ip);
        });
    });
}

function renderAvailableIPs(availableIPs) {
    const container = document.getElementById('availableIPsContainer');

    if (!availableIPs || availableIPs.length === 0) {
        container.innerHTML = '<div class="text-center text-gray-500">No available IPs</div>';
        return;
    }

    container.innerHTML = availableIPs.map(ip => `
        <div class="bg-gray-100 px-3 py-2 rounded text-sm">${ip}</div>
    `).join('');
}

function showAddIPModal() {
    const ip = prompt('Enter IP address to add (e.g., 192.168.1.100):');
    if (!ip) return;

    const interface = prompt('Enter network interface (leave empty for default):') || '';

    addSystemIP(ip.trim(), interface.trim());
}

function addSystemIP(ip, interface) {
    fetch('/api/system/ips', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip, interface })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
        } else {
            showToast(data.message, 'success');
            loadIPManagement(); // Refresh the display
        }
    })
    .catch(error => {
        console.error('Error adding IP:', error);
        showToast('Failed to add IP', 'error');
    });
}

function removeSystemIP(ip) {
    if (!confirm(`Are you sure you want to remove IP ${ip} from the system?`)) {
        return;
    }

    fetch(`/api/system/ips/${ip}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            showToast(data.error, 'error');
        } else {
            showToast(data.message, 'success');
            loadIPManagement(); // Refresh the display
        }
    })
    .catch(error => {
        console.error('Error removing IP:', error);
        showToast('Failed to remove IP', 'error');
    });
}

// System Monitoring Functions
function initializeSystemMonitoring() {
    const refreshBtn = document.getElementById('refreshStats');

    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadSystemStats);
    }

    // Load stats immediately and then every 30 seconds
    loadSystemStats();
    setInterval(loadSystemStats, 30000);
}

function loadSystemStats() {
    const lastUpdate = document.getElementById('lastUpdate');

    fetch('/api/system/stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast(data.error, 'error');
                return;
            }

            updateSystemStats(data.stats);
            if (lastUpdate) {
                lastUpdate.textContent = new Date().toLocaleTimeString();
            }
        })
        .catch(error => {
            console.error('Error loading system stats:', error);
            if (lastUpdate) {
                lastUpdate.textContent = 'Error loading stats';
            }
        });
}

function updateSystemStats(stats) {
    if (!stats) return;

    // Update CPU
    const cpuPercent = stats.cpu ? stats.cpu.percent : 0;
    document.getElementById('cpuPercent').textContent = `${Math.round(cpuPercent)}%`;
    document.getElementById('cpuDetails').textContent = `${stats.cpu ? stats.cpu.count : 0} cores`;

    // Update CPU arc
    const cpuArc = document.getElementById('cpuArc');
    if (cpuArc) {
        const circumference = 2 * Math.PI * 15.9155;
        const dashArray = (cpuPercent / 100) * circumference;
        cpuArc.setAttribute('stroke-dasharray', `${dashArray},${circumference}`);
    }

    // Update Memory
    const memoryPercent = stats.memory ? stats.memory.percent : 0;
    const memoryUsed = stats.memory ? (stats.memory.used / (1024**3)).toFixed(1) : 0;
    const memoryTotal = stats.memory ? (stats.memory.total / (1024**3)).toFixed(1) : 0;

    document.getElementById('memoryPercent').textContent = `${Math.round(memoryPercent)}%`;
    document.getElementById('memoryDetails').textContent = `${memoryUsed}/${memoryTotal} GB`;

    // Update Memory arc
    const memoryArc = document.getElementById('memoryArc');
    if (memoryArc) {
        const circumference = 2 * Math.PI * 15.9155;
        const dashArray = (memoryPercent / 100) * circumference;
        memoryArc.setAttribute('stroke-dasharray', `${dashArray},${circumference}`);
    }

    // Update Disk
    const diskPercent = stats.disk ? stats.disk.percent : 0;
    const diskUsed = stats.disk ? (stats.disk.used / (1024**3)).toFixed(1) : 0;
    const diskTotal = stats.disk ? (stats.disk.total / (1024**3)).toFixed(1) : 0;

    document.getElementById('diskPercent').textContent = `${Math.round(diskPercent)}%`;
    document.getElementById('diskDetails').textContent = `${diskUsed}/${diskTotal} GB`;

    // Update Disk arc
    const diskArc = document.getElementById('diskArc');
    if (diskArc) {
        const circumference = 2 * Math.PI * 15.9155;
        const dashArray = (diskPercent / 100) * circumference;
        diskArc.setAttribute('stroke-dasharray', `${dashArray},${circumference}`);
    }

    // Update Network
    const networkBytesRecv = stats.network ? (stats.network.bytes_recv / (1024**2)).toFixed(1) : 0;
    const networkBytesSent = stats.network ? (stats.network.bytes_sent / (1024**2)).toFixed(1) : 0;

    document.getElementById('networkDetails').textContent = `${networkBytesRecv} MB in, ${networkBytesSent} MB out`;

    // Update additional stats
    document.getElementById('activeUsers').textContent = stats.active_users || 0;
    document.getElementById('totalUsers').textContent = stats.total_users || 0;
    document.getElementById('runningContainers').textContent = stats.running_containers || 0;

    // Update uptime
    if (stats.uptime) {
        const uptimeSeconds = Date.now() / 1000 - stats.uptime;
        const days = Math.floor(uptimeSeconds / 86400);
        document.getElementById('uptime').textContent = `${days}d`;
    }
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
