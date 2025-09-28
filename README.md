
# XenProxy - LXC Multi-Protocol Gateway (SQLite Edition)

A lightweight, production-ready LXC container management system with multi-protocol support (SSH, SOCKS5, HTTP proxy, WireGuard) and SQLite database backend. All monitoring, management, and configuration are accessible through a custom admin panel—no external monitoring tools required.

---

## 🏃‍♂️ Running the Application

### Installation

```bash
# Clone the repository
git clone https://github.com/fahim8401/xenproxy.git
cd xenproxy

# Run the installer (requires root)
sudo ./install.sh
```

### Installation Options

```bash
./install.sh              # Install XenProxy
./install.sh --remove     # Remove XenProxy (keep database)
./install.sh --full-remove # Remove XenProxy completely (including database)
./install.sh --help       # Show help
```


### Development Mode (Recommended for testing)

```bash
# Install dependencies
pip install -r requirements.txt

# (Example) Create network bridges and set up iptables rules as needed
# ...
```

## 📦 Quick Installation

```bash
# Run the automated installer (requires root)
chmod +x install.sh
sudo ./install.sh
# or: su - && ./install.sh
```

1. Set up Python virtual environment
2. Install Python packages
3. Configure LXC networking (bridge `xenproxy0`)
4. Initialize SQLite database with default settings

---

```bash
# Install system dependencies
apt update && apt install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables sqlite3
python3 -m venv venv
source venv/bin/activate
# Install Python dependencies
pip install -r requirements.txt
# Start application
python3 app.py
```

After installation, access the web panel at:

- **URL**: [http://your-server:3030](http://your-server:3030)
- **Default Username**: `admin`
- **Default Password**: `admin1234`

### SQLite Configuration

- **Database File**: `instance/ip_gateway.db`

```text
lxc_manager.py
models.py
monitor.py
system_manager.py
requirements.txt
init_db.py
instance/
    ip_gateway.db
    css/admin.css
    js/admin.js
    js/charts.js
templates/
    base.html
    dashboard.html
    containers.html
    container_detail.html
    login.html
    logs.html
    system_settings.html
    users.html
service/
    xenproxy.service
lxc-templates/
    alpine-config
    setup-services.sh
```

---

## 🛡️ Security

- Argon2 password hashing
- CSRF protection on all forms
- Input validation
- HTTPS recommended for production (set up reverse proxy)

---

## 📝 License

MIT License. See LICENSE file for details.



## 🚀 Features---



- **Container Management**: Create, start, stop, delete LXC containers## Features

- **Multi-Protocol Support**: SSH, SOCKS5, HTTP proxy, WireGuard

- **SQLite Database**: Lightweight, serverless database with no external dependencies- **LXC Container Orchestration:** One unprivileged container per IP, with resource limits and protocol selection (SSH, SOCKS5, HTTP, WireGuard).

- **Web Admin Panel**: Clean, responsive web interface- **Admin Panel:** Custom UI (Flask + Jinja2, no external CSS frameworks), real-time stats, dark/light mode, bulk actions, logs.

- **Resource Monitoring**: CPU, memory, disk, and network statistics- **Security:** Argon2 password hashing, CSRF protection, input validation, HTTPS-only in production.

- **Audit Logging**: Complete audit trail of all admin actions- **Monitoring:** Built-in host and container resource monitoring, abuse detection, auto-recovery, audit logs.

- **IP Management**: Automatic IP assignment with configurable subnets- **System Management:** Linux bridge, NAT, auto IP assignment, PostgreSQL backend.

- **Bridge Networking**: Automated bridge setup and NAT rules- **Fully Automated Install:** Use `install.sh` for A-Z setup (system deps, DB, LXC, templates, static, DB init).

- **Root-Compatible:** Works on both Ubuntu and AlmaLinux as root (or with sudo).


## 🛠️ Requirements

- **Systemd Service:** Start/stop/restart with `systemctl` for production

- **Auto-Start:** After install, the app runs in the background automatically.

- **OS**: Ubuntu 18+, Debian 10+, AlmaLinux 8+, CentOS 8+, RHEL 8+

- **Python**: 3.8+---

- **Root Access**: Required for LXC and network management

- **Memory**: 2GB+ recommended## Project Structure

- **Storage**: 10GB+ for containers and databases


```


## 📦 Quick Installation

```bash
# Clone the repository
git clone https://github.com/fahim8401/xenproxy.git
cd xenproxy
# Run the automated installer (requires root)
sudo ./install.sh
```

The installer will:
1. Install system dependencies (LXC, Python, SQLite)
2. Set up Python virtual environment
3. Install Python packages
4. Configure LXC networking (bridge `xenproxy0`)
5. Initialize SQLite database with default settings
6. Start the application

## 🔧 Manual Installation

    containers.html

If you prefer manual setup:    container_detail.html

    users.html

```bash    system_settings.html

# Install system dependencies    logs.html

apt update && apt install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables sqlite3service/

    xenproxy.service

# Create virtual environment```

python3 -m venv venv

source venv/bin/activate---



# Install Python dependencies## Quick Start (A-Z Automated, Ubuntu/AlmaLinux, root or sudo)

pip install -r requirements.txt

1. **Clone the repo and run the installer as root:**

# Initialize database    ```bash

python3 init_db.py    git clone https://github.com/fahim8401/xenproxy.git

    cd xenproxy

# Start application    chmod +x install.sh

python3 app.py    sudo ./install.sh

```    # or: su - && ./install.sh

    ```

## 🌐 Access & Login

2. **If you see "could not change directory to ... Permission denied" or "ERROR:  CREATE DATABASE cannot be executed from a function":**

After installation, access the web panel at:    - This is a PostgreSQL limitation: `CREATE DATABASE` cannot be run inside a DO block.

- **URL**: http://your-server:3030    - If the database does not exist, create it manually:

- **Default Username**: `admin`      ```bash

- **Default Password**: `admin123`      sudo -u postgres createdb ipgw

      sudo -u postgres psql -c "CREATE USER postgres WITH PASSWORD 'postgres';" || true

⚠️ **Security**: Change the default password immediately after first login!      ```

    - Then re-run `sudo ./install.sh` to continue.

## 🗄️ Database

3. **If you see "password authentication failed for user 'postgres'":**

### SQLite Configuration    - Edit `/etc/postgresql/*/main/pg_hba.conf` (Ubuntu) or `/var/lib/pgsql/data/pg_hba.conf` (AlmaLinux/CentOS).

- **Database File**: `instance/ip_gateway.db`    - Change the `METHOD` for `local` and `host` lines for user `postgres` to `md5` or `trust` (for local testing).

- **Backup**: Simply copy the database file    - Restart PostgreSQL:

- **Migration**: No external database server required      ```bash

      sudo systemctl restart postgresql

### Database Schema      ```

- `admins`: Admin users and authentication    - Set the password for the postgres user:

- `lxc_containers`: Container configuration and status      ```bash

- `system_config`: Global system settings      sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'postgres';"

- `audit_logs`: Complete audit trail      ```

    - Then re-run the application.

## 📊 System Configuration

4. **After install, the app runs in the background.**

Default network settings:    - View logs: `tail -f xenproxy.log`

- **Bridge**: `xenproxy0`    - Stop: `pkill -f 'python app.py'`

- **Subnet**: `172.16.100.0/24`    - To run as a service: see below.

- **Gateway**: `172.16.100.1`

- **Container IPs**: `172.16.100.10-254`5. **(Recommended) Run as a systemd service:**

    ```bash

These can be changed in the admin panel under System Settings.    sudo cp service/xenproxy.service /etc/systemd/system/xenproxy.service

    sudo systemctl daemon-reload

## 🐳 Container Management    sudo systemctl enable xenproxy

    sudo systemctl start xenproxy

### Creating Containers    # To stop: sudo systemctl stop xenproxy

1. Login to admin panel    # To restart: sudo systemctl restart xenproxy

2. Go to "Containers" section    # To check status: sudo systemctl status xenproxy

3. Click "Create Container"    ```

4. Configure:

   - Username6. **Access the admin panel:**  

   - IP address   [http://localhost:3030](http://localhost:3030)

   - SSH public key

   - Enabled protocols (SSH/SOCKS5/HTTP/WireGuard)---



### Container Protocols## Security



**SSH Access:**- Admin login with Argon2 hashed passwords

```bash- CSRF protection on all forms

ssh username@172.16.100.10- All API endpoints require admin authentication

```- Input validation for usernames, IPs, SSH keys

- Unprivileged LXC containers with resource limits

**SOCKS5 Proxy:**

```bash---

# Default port: 1080

curl --socks5 172.16.100.10:1080 http://example.com## Monitoring & Abuse Prevention

```

- Real-time host and container stats (CPU, memory, disk, bandwidth)

**HTTP Proxy:**- Health checks for all protocols (SSH, SOCKS5, HTTP, WireGuard)

```bash- Abuse detection: high bandwidth, port scanning, excessive connections

# Default port: 8888- Auto-disable containers on abuse, admin alerts

curl --proxy http://172.16.100.10:8888 http://example.com

```---



## 🔒 Security Features## Backup & Restore



- **Password Hashing**: Argon2 encryption for admin passwords- Database backup script included


- **Session Management**: Secure session handling- Restore procedure documented

- **Audit Logging**: Complete action logging with IP addresses

- **Network Isolation**: Containers run in isolated network namespace---



## 📋 System Service## OS Compatibility



To run as a systemd service:- **Ubuntu 22.04+** (Debian-based)

- **AlmaLinux 8+/CentOS/RHEL** (RedHat-based)

```bash- Must be run as root or with sudo for full automation

# Copy service file

sudo cp service/xenproxy.service /etc/systemd/system/---


# Reload systemd and start service## License


sudo systemctl start xenproxy

---


```

- Alpine Linux, LXC, Flask, Argon2, Chart.js

## 📊 Monitoring & Logs


### Application Logs

```bash
# View live logs
tail -f xenproxy.log

# View service logs
sudo journalctl -u xenproxy -f
```


### System Resources

- **Web Interface**: Real-time charts in admin panel
- **Command Line**: `htop`, `iotop`, `nethogs`

## 🧹 Maintenance


### Database Backup

```bash
# Backup SQLite database
cp instance/ip_gateway.db backup/ip_gateway_$(date +%Y%m%d).db
```


### Container Cleanup

```bash
# Remove stopped containers
sudo lxc-ls --stopped | xargs -r sudo lxc-destroy -n
```

### Log Rotation

```bash
# Setup logrotate for application logs
    delaycompress
}' > /etc/logrotate.d/xenproxy
```

## 🛠️ Troubleshooting




### 1. Bridge Creation Failed

```bash
ip link show xenproxy0

# Manually create bridge
sudo ip link add name xenproxy0 type bridge
sudo ip addr add 172.16.100.1/24 dev xenproxy0
sudo ip link set xenproxy0 up
```

### 2. Container Won't Start

```bash
# Check LXC status
sudo lxc-ls -f

# Check container config
sudo lxc-info -n container-name

# Check logs
sudo lxc-console -n container-name
```

### 3. Database Issues

```bash
# Recreate database
rm instance/ip_gateway.db
python3 init_db.py
```

### 4. Permission Errors

```bash
# Fix permissions
sudo chown -R root:root /path/to/xenproxy
sudo chmod +x install.sh init_db.py app.py
```

## 🔧 Configuration Files

- `app.py`: Main application server
- `models.py`: SQLite database models
- `init_db.py`: Database initialization
- `requirements.txt`: Python dependencies
- `install.sh`: Automated installer
- `service/xenproxy.service`: Systemd service file

## 📚 API Endpoints

The application provides REST API endpoints:

- `GET /api/host_stats`: Host system statistics
- `GET /api/container_stats/<name>`: Container-specific stats
- `GET /api/logs`: Recent audit log entries

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/new-feature`)
3. Commit changes (`git commit -am 'Add new feature'`)
4. Push to branch (`git push origin feature/new-feature`)
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

- **Issues**: GitHub Issues
- **Documentation**: This README and inline code comments
- **Logs**: Check `xenproxy.log` for detailed application logs

## 🔄 Migration from PostgreSQL

If migrating from the PostgreSQL version:

1. Export data from PostgreSQL
2. Install SQLite version
3. Import data using provided migration scripts
4. Update configuration files

---


---

Made with ❤️ for container enthusiasts
