#!/bin/bash
# XenProxy Production Deployment Script
# This script handles production deployment on a clean server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    print_error "Please run as root (sudo su - or sudo ./deploy.sh)"
    exit 1
fi

print_status "Starting XenProxy Production Deployment"

# Update system
print_status "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install git if not present
if ! command -v git >/dev/null 2>&1; then
    print_status "Installing git..."
    apt-get install -y git
fi

# Clone or update repository
if [ -d "xenproxy" ]; then
    print_info "Updating existing XenProxy installation..."
    cd xenproxy
    git pull origin main
else
    print_status "Cloning XenProxy repository..."
    git clone https://github.com/fahim8401/xenproxy.git
    cd xenproxy
fi

# Run the installation
print_status "Running XenProxy installation..."
chmod +x install.sh
./install.sh

# Create production environment file
if [ ! -f .env ]; then
    print_status "Creating production environment file..."
    cp .env.example .env
    print_warning "Please edit .env file with your production settings!"
    print_info "Especially change SECRET_KEY and admin credentials"
fi

# Set proper permissions
print_status "Setting proper permissions..."
chown -R root:root .
chmod 600 .env
chmod 600 instance/ip_gateway.db

# Enable and start service
print_status "Starting XenProxy service..."
systemctl enable xenproxy
systemctl start xenproxy

# Check service status
sleep 5
if systemctl is-active --quiet xenproxy; then
    print_status "XenProxy service started successfully!"
else
    print_error "XenProxy service failed to start. Check logs:"
    journalctl -u xenproxy -n 50 --no-pager
    exit 1
fi

# Show status
print_status "Deployment completed successfully!"
echo ""
echo "==> Service Status:"
systemctl status xenproxy --no-pager -l
echo ""
echo "==> Web Interface: http://$(hostname -I | awk '{print $1}'):3030"
echo "==> Default Credentials: admin / admin123 (change immediately!)"
echo ""
echo "==> Useful commands:"
echo "  View logs:        journalctl -u xenproxy -f"
echo "  Restart service:  systemctl restart xenproxy"
echo "  Stop service:     systemctl stop xenproxy"
echo "  Edit config:      nano .env"
echo ""
print_warning "Remember to:"
echo "  1. Change the default admin password"
echo "  2. Update SECRET_KEY in .env file"
echo "  3. Configure firewall rules if needed"
echo "  4. Set up SSL/TLS certificates for HTTPS"