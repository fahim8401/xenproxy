#!/bin/bash
# XenProxy LXC Multi-Protocol IP Gateway Admin Panel Installer (SQLite version)
# Compatible with Ubuntu/Debian and AlmaLinux/CentOS/RHEL

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}==> $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Function to remove existing installation
remove_existing() {
    print_warning "Removing existing XenProxy installation..."

    # Stop any running instances
    pkill -f "python3 app.py" 2>/dev/null || true
    pkill -f "python3 -m flask" 2>/dev/null || true

    # Remove systemd service if exists
    if [ -f /etc/systemd/system/xenproxy.service ]; then
        systemctl stop xenproxy 2>/dev/null || true
        systemctl disable xenproxy 2>/dev/null || true
        rm -f /etc/systemd/system/xenproxy.service
        systemctl daemon-reload
    fi

    # Remove network bridge
    ip link set xenproxy0 down 2>/dev/null || true
    ip link delete xenproxy0 2>/dev/null || true

    # Remove iptables rules
    iptables -t nat -D POSTROUTING -s 172.16.100.0/24 -j MASQUERADE 2>/dev/null || true

    # Remove LXC containers created by XenProxy
    if command -v lxc-ls >/dev/null 2>&1; then
        for container in $(lxc-ls | grep "^ipgw-" || true); do
            print_info "Removing LXC container: $container"
            lxc-stop -n "$container" 2>/dev/null || true
            lxc-destroy -n "$container" 2>/dev/null || true
        done
    fi

    # Remove application files (but keep database if user wants)
    if [ "$FULL_REMOVE" = "true" ]; then
        print_warning "Performing full removal (including database)..."
        rm -rf venv instance lxc-templates static templates *.pyc __pycache__ *.log
    else
        print_info "Keeping database and user data..."
    fi

    print_status "Existing installation removed"
}

# Check command line arguments
FULL_REMOVE=false
if [ "$1" = "--remove" ] || [ "$1" = "-r" ]; then
    remove_existing
    exit 0
elif [ "$1" = "--full-remove" ] || [ "$1" = "--purge" ]; then
    FULL_REMOVE=true
    remove_existing
    exit 0
elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "XenProxy Installation Script"
    echo ""
    echo "Usage:"
    echo "  ./install.sh              # Install XenProxy"
    echo "  ./install.sh --remove     # Remove XenProxy (keep database)"
    echo "  ./install.sh --full-remove # Remove XenProxy completely (including database)"
    echo "  ./install.sh --help       # Show this help"
    echo ""
    echo "After installation, access the web interface at: http://localhost:3030"
    echo "Default credentials: admin / admin123 (change after first login!)"
    exit 0
fi

# Ensure LXC backend is installed and controllable before proceeding
# (see LXC verification block below)
print_status "[LXC] Verifying LXC installation and backend control..."
if ! command -v lxc-ls >/dev/null 2>&1; then
    print_error "LXC is not installed or not in PATH. Please check installation."
    exit 1
fi

# Test LXC backend control: try to list containers and check for errors
if ! lxc-ls >/dev/null 2>&1; then
    print_error "LXC backend is not responding. Please check LXC installation and permissions."
    exit 1
fi

# Check if lxc-templates directory exists and is writable
if [ ! -d "/var/lib/lxc" ]; then
    print_error "/var/lib/lxc does not exist. LXC may not be installed or initialized."
    exit 1
fi
if [ ! -w "/var/lib/lxc" ]; then
    print_error "No write permission to /var/lib/lxc. Please run as root or fix permissions."
    exit 1
fi

print_status "LXC installation and backend control verified."

# Check if already installed
if [ -d "venv" ] && [ -f "instance/ip_gateway.db" ]; then
    print_warning "XenProxy appears to be already installed."
    echo "Use './install.sh --remove' to remove existing installation first,"
    echo "or './install.sh --full-remove' to remove everything including database."
    exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  print_error "Please run as root (sudo su - or sudo ./install.sh)"
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  print_error "Cannot detect OS."
  exit 1
fi

print_status "[1/8] Installing system dependencies..."
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
  apt-get update
  apt-get install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables iproute2 git curl sqlite3 wget
elif [[ "$OS" == "almalinux" || "$OS" == "centos" || "$OS" == "rhel" ]]; then
  dnf install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables iproute git curl sqlite wget
else
  print_error "Unsupported OS: $OS"
  print_info "Supported OS: Ubuntu, Debian, AlmaLinux, CentOS, RHEL"
  exit 1
fi

print_status "[2/8] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

print_status "[3/8] Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

print_status "[4/8] Setting up LXC bridge (xenproxy0) and network..."
# Clean up any existing bridge
ip link set xenproxy0 down 2>/dev/null || true
ip link delete xenproxy0 2>/dev/null || true

# Create new bridge
ip link add name xenproxy0 type bridge
ip addr flush dev xenproxy0
ip addr add 172.16.100.1/24 dev xenproxy0
ip link set xenproxy0 up
sysctl -w net.ipv4.ip_forward=1

# Add iptables rule (check if it exists first)
if ! iptables -t nat -C POSTROUTING -s 172.16.100.0/24 -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 172.16.100.0/24 -j MASQUERADE
fi

print_status "[5/8] Setting up LXC templates and configuration..."
mkdir -p lxc-templates static/css static/js instance

# Copy LXC templates to system location
cp -f lxc-templates/alpine-config /var/lib/lxc/ 2>/dev/null || true
cp -f lxc-templates/setup-services.sh /var/lib/lxc/ 2>/dev/null || true

# Ensure templates exist
if [ ! -f lxc-templates/alpine-config ]; then
cat > lxc-templates/alpine-config <<'EOL'
lxc.include = /usr/share/lxc/config/alpine.common.conf
lxc.arch = x86_64
lxc.rootfs.path = dir:/var/lib/lxc/{{container_name}}/rootfs
lxc.uts.name = {{username}}
lxc.net.0.type = veth
lxc.net.0.link = {{bridge_name}}
lxc.net.0.flags = up
lxc.net.0.ipv4.address = {{ip_address}}/24
lxc.net.0.ipv4.gateway = auto
lxc.apparmor.profile = generated
lxc.idmap = u 0 100000 65536
lxc.idmap = g 0 100000 65536
lxc.cgroup2.cpu.max = {{cpu_limit_times_100000}} 100000
lxc.cgroup2.memory.max = {{memory_limit_bytes}}
EOL
fi

if [ ! -f lxc-templates/setup-services.sh ]; then
cat > lxc-templates/setup-services.sh <<'EOL'
#!/bin/sh
if [ "$ENABLE_SSH" = "true" ]; then
  apk add --no-cache openssh
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config
  echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
  echo "ListenAddress $CONTAINER_IP" >> /etc/ssh/sshd_config
  adduser -D -s /bin/sh $USERNAME
  mkdir -p /home/$USERNAME/.ssh
  echo "$SSH_KEY" > /home/$USERNAME/.ssh/authorized_keys
  chown -R $USERNAME:$USERNAME /home/$USERNAME/.ssh
fi
if [ "$ENABLE_SOCKS5" = "true" ]; then
  apk add --no-cache dante-server
fi
if [ "$ENABLE_HTTP" = "true" ]; then
  apk add --no-cache tinyproxy
fi
if [ "$ENABLE_WIREGUARD" = "true" ]; then
  apk add --no-cache wireguard-tools
fi
rc-service sshd start 2>/dev/null || true
rc-service danted start 2>/dev/null || true
rc-service tinyproxy start 2>/dev/null || true
EOL
chmod +x lxc-templates/setup-services.sh
fi

print_status "[6/8] Setting up static assets..."
# Create basic CSS if missing
if [ ! -f static/css/admin.css ]; then
mkdir -p static/css
cat > static/css/admin.css <<'EOL'
/* XenProxy Admin Panel Styles */
.sidebar-link {
    @apply block px-4 py-2 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors duration-200 rounded-md mx-2 my-1;
}

.sidebar-active {
    @apply bg-gray-700 text-white;
}

.btn {
    @apply px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors duration-200 inline-block;
}

.btn-sm {
    @apply px-3 py-1 text-sm;
}

.admin-table {
    @apply min-w-full divide-y divide-gray-200;
}

.admin-table th {
    @apply px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider;
}

.admin-table td {
    @apply px-6 py-4 whitespace-nowrap text-sm text-gray-900;
}

.admin-table tr:nth-child(even) {
    @apply bg-gray-50;
}
EOL
fi

# Create basic JS if missing
if [ ! -f static/js/admin.js ]; then
mkdir -p static/js
cat > static/js/admin.js <<'EOL'
// XenProxy Admin Panel JavaScript
function showModal(modalId) {
    document.getElementById(modalId).classList.remove('hidden');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
}

// Auto-hide alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            alert.style.opacity = '0';
            setTimeout(function() {
                alert.remove();
            }, 300);
        });
    }, 5000);
});
EOL
fi

print_status "[7/8] Initializing SQLite database..."
python3 init_db.py

print_status "[8/8] Setting up systemd service..."
# Install systemd service
if [ -f service/xenproxy.service ]; then
    INSTALL_DIR=$(pwd)
    PYTHON_PATH=$(which python3)
    sed -e "s|__INSTALL_DIR__|${INSTALL_DIR}|g" -e "s|__PYTHON_PATH__|${PYTHON_PATH}|g" service/xenproxy.service > /etc/systemd/system/xenproxy.service
    systemctl daemon-reload
    systemctl enable xenproxy
    print_info "Systemd service installed. Use 'systemctl start xenproxy' to start."
else
    print_warning "Systemd service file not found, skipping service installation."
fi

echo ""
print_status "Installation complete!"
echo ""
echo "==> Database Type: SQLite (stored in instance/ip_gateway.db)"
echo "==> Default Admin Credentials:"
echo "    Username: admin"
echo "    Password: admin123"
echo "    ⚠️  Please change these after first login!"
echo ""
echo "==> Web Interface: http://localhost:3030"
echo ""
echo "==> Useful commands:"
echo "  Start service:  systemctl start xenproxy"
echo "  Stop service:   systemctl stop xenproxy"
echo "  View logs:      journalctl -u xenproxy -f"
echo "  Restart app:    systemctl restart xenproxy"
echo "  Remove app:     ./install.sh --remove"
echo ""
echo "==> Starting application..."
systemctl start xenproxy 2>/dev/null || {
    print_warning "Systemd service failed, starting manually..."
    nohup python3 app.py > xenproxy.log 2>&1 &
    echo "App started manually. PID: $!"
}
echo ""
print_info "Installation finished! Access the web interface at: http://localhost:3030"