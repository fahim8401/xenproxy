# IP Gateway Router Admin Dashboard

A comprehensive Flask-based web application for managing an advanced IP gateway router system with SSH, SOCKS5 proxy, HTTP proxy, and PPTP VPN capabilities.

## 🚀 Features

### Core Functionality
- **User Management**: Create, configure, and delete users with individual protocol settings
- **IP Address Management**: Automatic IP assignment from configurable subnet ranges
- **Multi-Protocol Support**:
  - SSH access with dedicated system users
  - SOCKS5 proxy via Docker containers (Dante server)
  - HTTP/HTTPS proxy via Docker containers (TinyProxy)
  - PPTP VPN with MS-CHAP-v2 authentication
- **Real-time Monitoring**: Live status updates for all services and proxies
- **System Configuration**: Web-based configuration of network settings and proxy ports

### Advanced Features
- **Audit Logging**: Complete audit trail of all administrative actions
- **System Health Monitoring**: Real-time CPU, memory, disk, and network monitoring
- **Bulk Operations**: CSV import/export for user management
- **Real-time Dashboards**: Live system metrics and performance charts

### Security Features
- Admin authentication with hashed passwords
- Rate limiting on login attempts
- Input validation and sanitization
- Session-based authentication
- CSRF protection (basic implementation)
- Docker container isolation for proxy services

### User Interface
- Modern, responsive web interface using Tailwind CSS
- Real-time status indicators
- AJAX-powered operations
- Intuitive protocol toggles
- Connection testing and troubleshooting tools

## 📋 Requirements

### System Requirements
- **Operating System**: Ubuntu/Debian Linux (recommended)
- **Python**: 3.8 or higher
- **Docker Engine**: For proxy container management
- **System Packages**:
  - `pptpd` (PPTP VPN server)
  - `iptables` (firewall management)
  - `iproute2` (network configuration)
  - `sudo` (privileged operations)

### Python Dependencies
```
Flask==2.3.3
Flask-SQLAlchemy==3.0.5
Flask-Login==0.6.3
Werkzeug==2.3.7
python-dotenv==1.0.0
ipaddress==1.0.23
```

## 🛠️ Installation & Setup

### Automated Installation (Recommended)

For Ubuntu 20.04/22.04 servers, use the automated installation script:

```bash
# Download or clone the repository
git clone https://github.com/your-repo/ip-gateway-router.git
cd ip-gateway-router

# Make script executable and run
chmod +x install.sh
./install.sh
```

The script will:
- ✅ Update system packages
- ✅ Install all system dependencies (Docker, PPTP, Python, etc.)
- ✅ Configure network settings and firewall
- ✅ Install Python dependencies
- ✅ Set up PPTP VPN server
- ✅ Configure systemd service for auto-start
- ✅ Test installation and start the application

### Manual Installation

If you prefer manual installation or are using a different Linux distribution:

#### 1. System Preparation
```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages
sudo apt-get install -y python3 python3-pip pptpd docker.io iptables iproute2

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add user to docker group (optional, for development)
sudo usermod -aG docker $USER
```

#### 2. Application Setup
```bash
# Clone or download the application
cd /path/to/application

# Install Python dependencies
pip3 install -r requirements.txt

# Configure environment (optional)
echo "SECRET_KEY=your-secret-key-here" > .env
echo "FLASK_ENV=production" >> .env
```

### 3. Initial Configuration
Edit `system_manager.py` to configure your network settings:
```python
SUBNET_RANGE = "192.168.1.0/24"  # Your subnet range
NETWORK_INTERFACE = "eth0"       # Your network interface
PROXY_BASE_PORT = 10000          # Base port for proxies
```

### 4. PPTP VPN Setup (One-time)
```bash
# Run the PPTP setup function (will be called automatically on first run)
python3 -c "from pptp_manager import setup_pptpd; setup_pptpd()"
```

### 5. Start the Application
```bash
# Development mode (runs on port 3030)
python3 app.py

# Run on a different port
python3 app.py 8080

# Production mode (recommended)
gunicorn --bind 0.0.0.0:3030 --workers 4 app:app
```

Access the application at `http://your-server-ip:3030`

## 🔐 Security Considerations

### Password Security
- Admin passwords are hashed using Werkzeug security
- User passwords are stored in plaintext (required for system/PPTP authentication)
- Change default admin credentials immediately after installation

### System Permissions
- Application runs as non-root user with sudo access for specific commands
- Docker containers run with limited privileges
- System commands are validated and restricted

### Network Security
- IP forwarding enabled for VPN/proxy functionality
- iptables rules configured for proper routing
- Firewall rules should be configured according to your security policy

### Production Deployment
- Use HTTPS with SSL/TLS certificates
- Configure Nginx reverse proxy
- Set up proper logging and monitoring
- Regular security updates and patches

## 📖 Usage Guide

### Admin Login
- Default credentials: `admin` / `admin123`
- **Change password immediately after first login**

### Creating Users
1. Navigate to Dashboard
2. Fill in username, password, and select IP address
3. Choose desired protocols (SSH, SOCKS5, HTTP, PPTP)
4. Click "Create User"

### User Management
- **View Details**: Click "View" to see user configuration and status
- **Protocol Control**: Toggle protocols on/off in real-time
- **Connection Testing**: Test proxy connections from user detail page
- **Delete Users**: Permanently remove users and all associated configurations

### Audit Logging
- **Complete Audit Trail**: All admin actions are logged with timestamps, IP addresses, and user agents
- **Advanced Filtering**: Filter logs by action type, resource type, admin user, and date range
- **Detailed Log View**: Click on any log entry to see full details including changes made
- **Pagination**: Efficiently browse through large numbers of log entries

### System Health Monitoring
- **Real-time Metrics**: Monitor CPU, memory, disk usage, and network I/O
- **Historical Charts**: View system performance over the last 24 hours
- **Container Monitoring**: Track running Docker containers and their status
- **System Information**: Display hardware specs and service status

### Bulk Operations
- **CSV Import**: Bulk create users from CSV files with validation and error reporting
- **CSV Export**: Export user data for backup or analysis
- **Template Download**: Get properly formatted CSV templates
- **Import Results**: Detailed feedback on successful imports and any errors encountered

### System Configuration
- Access advanced settings panel on dashboard
- Configure subnet range, network interface, and proxy ports
- Changes require application restart for full effect

## 🔧 API Reference

### User Management
```
POST   /api/users              # Create user
PUT    /api/users/<id>         # Update user
DELETE /api/users/<id>         # Delete user
GET    /api/users/<id>/status  # Get user status
POST   /api/users/bulk         # Bulk create users from CSV
```

### System Configuration
```
GET    /api/system/config      # Get system config
PUT    /api/system/config      # Update system config
GET    /api/system/available-ips # Get available IPs
```

### System Health & Monitoring
```
GET    /api/system/health      # Get current system health metrics
GET    /api/system/health/history # Get health history (last 24h)
```

### Audit Logging
```
GET    /api/audit-logs         # Get audit logs with filtering & pagination
```

### Authentication
```
POST   /login                  # Admin login
POST   /logout                 # Admin logout
```

### Web Pages
```
GET    /                        # Redirect to login
GET    /login                   # Admin login page
GET    /logout                  # Admin logout
GET    /dashboard               # Main dashboard
GET    /user/<id>               # User detail page
GET    /audit-logs              # Audit logs page
GET    /system-health           # System health dashboard
GET    /bulk-operations         # Bulk operations page
```

## 🐳 Docker Configuration

### SOCKS5 Proxy (Dante)
- **Image**: `vimagick/dante`
- **Configuration**: Generated per user in `/tmp/proxy_configs/<user_id>/dante.conf`
- **Ports**: `PROXY_BASE_PORT + user_id`
- **Authentication**: Username/password from database

### HTTP Proxy (TinyProxy)
- **Image**: `vimagick/tinyproxy`
- **Configuration**: Generated per user in `/tmp/proxy_configs/<user_id>/tinyproxy.conf`
- **Ports**: `20000 + user_id`
- **Authentication**: Basic auth with user credentials

## 📊 Monitoring & Troubleshooting

### Logs
- Application logs: `ip_gateway.log`
- System logs: `/var/log/syslog`
- Docker logs: `docker logs <container_name>`

### Common Issues
1. **Permission Denied**: Ensure user has sudo access for network commands
2. **Docker Not Running**: Start Docker service and check container status
3. **IP Conflicts**: Verify subnet configuration and existing IP assignments
4. **Port Conflicts**: Check if proxy ports are already in use

### Status Checking
```bash
# Check Docker containers
docker ps | grep proxy

# Check PPTP status
sudo systemctl status pptpd

# Check network interfaces
ip addr show

# Check iptables rules
sudo iptables -L -n -v
```

## 🚀 Production Deployment

### Using Gunicorn
```bash
# Install Gunicorn
pip3 install gunicorn

# Create systemd service
sudo tee /etc/systemd/system/ip-gateway.service > /dev/null <<EOF
[Unit]
Description=IP Gateway Router Admin
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/path/to/application
Environment="PATH=/path/to/venv/bin"
ExecStart=/path/to/venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 4 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl enable ip-gateway
sudo systemctl start ip-gateway
```

### Nginx Reverse Proxy
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### SSL Configuration
```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com
```

## 🔄 Backup & Recovery

### Database Backup
```bash
# SQLite database backup
cp ip_gateway.db ip_gateway.db.backup

# Automated backup script
#!/bin/bash
BACKUP_DIR="/var/backups/ip-gateway"
mkdir -p $BACKUP_DIR
cp ip_gateway.db $BACKUP_DIR/ip_gateway_$(date +%Y%m%d_%H%M%S).db

# Keep only last 7 backups
ls -t $BACKUP_DIR/ip_gateway_*.db | tail -n +8 | xargs rm -f
```

### Configuration Backup
```bash
# Backup configuration files
tar -czf config_backup.tar.gz \
    system_manager.py \
    pptp_manager.py \
    /etc/pptpd/ \
    /etc/ppp/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This software configures system-level networking and security settings. Use with caution and ensure you understand the implications for your network security. The authors are not responsible for any security vulnerabilities or network issues caused by improper configuration.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section above
2. Review application logs
3. Verify system requirements are met
4. Create an issue on GitHub with detailed information
