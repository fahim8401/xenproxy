#!/bin/bash

# IP Gateway Router Admin Dashboard - Ubuntu 20.04 Installation Script
# This script installs and configures the complete IP Gateway system

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
APP_NAME="IP Gateway Router Admin"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_SUBNET="192.168.1.0/24"
DEFAULT_INTERFACE="eth0"
DEFAULT_PORT=3030

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root. Please run as a regular user with sudo access."
        exit 1
    fi
}

# Check Ubuntu version
check_ubuntu_version() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot determine OS version. This script is designed for Ubuntu."
        exit 1
    fi

    . /etc/os-release
    if [[ "$ID" != "ubuntu" ]]; then
        error "This script is designed for Ubuntu. Detected: $ID"
        exit 1
    fi

    if [[ "${VERSION_ID%%.*}" -lt 18 ]]; then
        warning "This script is tested on Ubuntu 18.04+. Your version: $VERSION_ID"
    fi

    log "Detected Ubuntu $VERSION_ID"
}

# Update system packages
update_system() {
    log "Updating system packages..."
    sudo apt-get update
    sudo apt-get upgrade -y
    sudo apt-get autoremove -y
    sudo apt-get autoclean
}

# Install system dependencies
install_system_dependencies() {
    log "Installing system dependencies..."

    # Essential packages
    sudo apt-get install -y \
        curl \
        wget \
        git \
        vim \
        htop \
        net-tools \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release

    # Python 3 and pip
    sudo apt-get install -y \
        python3 \
        python3-pip \
        python3-dev \
        python3-venv \
        python3-setuptools

    # Network and system tools
    sudo apt-get install -y \
        iptables \
        iproute2 \
        netfilter-persistent \
        iptables-persistent \
        ufw \
        openssh-server

    # PPTP VPN server
    sudo apt-get install -y \
        pptpd \
        ppp

    # Development tools
    sudo apt-get install -y \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-wheel

    log "System dependencies installed successfully"
}

# Install and configure Docker
install_docker() {
    log "Installing Docker..."

    # Remove old versions
    sudo apt-get remove -y docker docker-engine docker.io containerd runc || true

    # Add Docker's official GPG key
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

    # Add Docker repository
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Start and enable Docker
    sudo systemctl start docker
    sudo systemctl enable docker

    # Add current user to docker group
    sudo usermod -aG docker $USER

    log "Docker installed and configured successfully"
    warning "You may need to log out and back in for Docker group changes to take effect"
}

# Install Python dependencies
install_python_dependencies() {
    log "Installing Python dependencies..."

    # Upgrade pip
    python3 -m pip install --user --upgrade pip

    # Install requirements
    if [[ -f "$APP_DIR/requirements.txt" ]]; then
        python3 -m pip install --user -r "$APP_DIR/requirements.txt"
        # Install netifaces separately if needed (may require system packages)
        python3 -m pip install --user netifaces || warning "netifaces installation failed - may need system dependencies"
    else
        error "requirements.txt not found in $APP_DIR"
        exit 1
    fi

    log "Python dependencies installed successfully"
}

# Configure system settings
configure_system() {
    log "Configuring system settings..."

    # Enable IP forwarding
    sudo sysctl -w net.ipv4.ip_forward=1
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

    # Configure iptables for NAT (will be managed by the application)
    sudo iptables -t nat -F
    sudo iptables -F

    # Save iptables rules
    sudo netfilter-persistent save || true

    # Configure UFW (allow SSH and application port)
    sudo ufw --force enable
    sudo ufw allow ssh
    sudo ufw allow $DEFAULT_PORT
    sudo ufw --force reload

    log "System configuration completed"
}

# Configure PPTP VPN
configure_pptp() {
    log "Configuring PPTP VPN..."

    # Backup original config
    sudo cp /etc/pptpd.conf /etc/pptpd.conf.backup 2>/dev/null || true
    sudo cp /etc/ppp/pptpd-options /etc/ppp/pptpd-options.backup 2>/dev/null || true

    # Configure pptpd.conf
    sudo tee /etc/pptpd.conf > /dev/null <<EOF
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.1.1
remoteip 192.168.1.10-192.168.1.254
EOF

    # Configure pptpd-options
    sudo tee /etc/ppp/pptpd-options > /dev/null <<EOF
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
proxyarp
lock
nobsdcomp
novj
novjccomp
nologfd
EOF

    # Enable and start PPTP service
    sudo systemctl enable pptpd
    sudo systemctl start pptpd

    log "PPTP VPN configured successfully"
}

# Configure application
configure_application() {
    log "Configuring application..."

    # Create necessary directories
    mkdir -p "$APP_DIR/templates"
    mkdir -p "$APP_DIR/static/css"
    mkdir -p "$APP_DIR/static/js"

    # Set executable permissions
    chmod +x "$APP_DIR/app.py"

    # Create .env file if it doesn't exist
    if [[ ! -f "$APP_DIR/.env" ]]; then
        cat > "$APP_DIR/.env" << EOF
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FLASK_ENV=production
EOF
        log ".env file created with random SECRET_KEY"
    fi

    # Configure system_manager.py with user input
    if [[ -f "$APP_DIR/system_manager.py" ]]; then
        read -p "Enter subnet range (default: $DEFAULT_SUBNET): " subnet_range
        subnet_range=${subnet_range:-$DEFAULT_SUBNET}

        read -p "Enter network interface (default: $DEFAULT_INTERFACE): " network_interface
        network_interface=${network_interface:-$DEFAULT_INTERFACE}

        # Update configuration in system_manager.py
        sed -i "s/SUBNET_RANGE = \".*\"/SUBNET_RANGE = \"$subnet_range\"/" "$APP_DIR/system_manager.py"
        sed -i "s/NETWORK_INTERFACE = \".*\"/NETWORK_INTERFACE = \"$network_interface\"/" "$APP_DIR/system_manager.py"

        log "Application configured with subnet: $subnet_range, interface: $network_interface"
    fi
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."

    local service_file="/etc/systemd/system/ip-gateway.service"

    sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=IP Gateway Router Admin Dashboard
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
Environment=PATH=$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$HOME/.local/bin/python3 $APP_DIR/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable ip-gateway

    log "Systemd service created and enabled"
}

# Test installation
test_installation() {
    log "Testing installation..."

    # Test Python imports
    if python3 -c "import flask, flask_sqlalchemy, werkzeug, psutil; print('Python imports successful')"; then
        log "✓ Python dependencies working"
    else
        error "✗ Python dependencies failed"
        return 1
    fi

    # Test Docker
    if sudo docker run --rm hello-world > /dev/null 2>&1; then
        log "✓ Docker working"
    else
        error "✗ Docker test failed"
        return 1
    fi

    # Test application import
    if cd "$APP_DIR" && python3 -c "import app; print('Application import successful')"; then
        log "✓ Application import working"
    else
        error "✗ Application import failed"
        return 1
    fi

    log "Installation tests passed!"
    return 0
}

# Start application
start_application() {
    log "Starting application..."

    cd "$APP_DIR"

    # Start using systemd
    sudo systemctl start ip-gateway

    # Wait a moment for startup
    sleep 3

    # Check if service is running
    if sudo systemctl is-active --quiet ip-gateway; then
        log "✓ Application started successfully via systemd"
        info "Application is running on port $DEFAULT_PORT"
        info "Access it at: http://$(hostname -I | awk '{print $1}'):$DEFAULT_PORT"
        info "Default admin credentials: admin / admin123"
        warning "CHANGE THE DEFAULT PASSWORD IMMEDIATELY AFTER FIRST LOGIN!"
    else
        error "✗ Failed to start application via systemd"
        error "Check logs with: sudo journalctl -u ip-gateway -f"
        return 1
    fi
}

# Display completion message
show_completion() {
    echo
    log "🎉 Installation completed successfully!"
    echo
    info "Application Details:"
    echo "  - Port: $DEFAULT_PORT"
    echo "  - URL: http://$(hostname -I | awk '{print $1}'):$DEFAULT_PORT"
    echo "  - Admin: admin / admin123"
    echo
    info "Management Commands:"
    echo "  - Start:   sudo systemctl start ip-gateway"
    echo "  - Stop:    sudo systemctl stop ip-gateway"
    echo "  - Restart: sudo systemctl restart ip-gateway"
    echo "  - Logs:    sudo journalctl -u ip-gateway -f"
    echo
    warning "Security Recommendations:"
    echo "  1. Change the default admin password immediately"
    echo "  2. Configure SSL/TLS for production use"
    echo "  3. Review firewall rules for your environment"
    echo "  4. Set up regular backups of the database"
    echo
    info "Documentation: See README.md for detailed usage instructions"
}

# Main installation function
main() {
    echo "========================================"
    echo "  IP Gateway Router Admin Installation"
    echo "========================================"
    echo

    check_root
    check_ubuntu_version

    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Installation cancelled by user"
        exit 0
    fi

    update_system
    install_system_dependencies
    install_docker
    install_python_dependencies
    configure_system
    configure_pptp
    configure_application
    create_systemd_service

    if test_installation; then
        start_application
        show_completion
    else
        error "Installation tests failed. Please check the errors above."
        exit 1
    fi
}

# Run main function
main "$@"
