#!/bin/bash
# XenProxy LXC Multi-Protocol IP Gateway Admin Panel Installer (SQLite version)
# Compatible with Ubuntu/Debian and AlmaLinux/CentOS/RHEL

set -e

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root (sudo su - or sudo ./install.sh)"
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  echo "Cannot detect OS."
  exit 1
fi

echo "==> [1/7] Installing system dependencies..."
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
  apt-get update
  apt-get install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables iproute2 git curl sqlite3
elif [[ "$OS" == "almalinux" || "$OS" == "centos" || "$OS" == "rhel" ]]; then
  dnf install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables iproute git curl sqlite
else
  echo "Unsupported OS: $OS"
  exit 1
fi

echo "==> [2/7] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "==> [3/7] Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

echo "==> [4/7] Setting up LXC bridge (xenproxy0) and network..."
ip link add name xenproxy0 type bridge || true
ip addr flush dev xenproxy0 || true
ip addr add 172.16.100.1/24 dev xenproxy0 || true
ip link set xenproxy0 up
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -s 172.16.100.0/24 -j MASQUERADE || iptables -t nat -A POSTROUTING -s 172.16.100.0/24 -j MASQUERADE

echo "==> [4b/7] Ensuring LXC templates are up to date for all protocols (SSH, SOCKS5, HTTP, WireGuard)..."
cp -f lxc-templates/alpine-config /var/lib/lxc/ || true
cp -f lxc-templates/setup-services.sh /var/lib/lxc/ || true

echo "==> [5/7] Creating folders for LXC templates and static assets..."
mkdir -p lxc-templates static/css static/js instance

echo "==> [6/7] Copying default LXC templates and static assets if missing..."
if [ ! -f lxc-templates/alpine-config ]; then
cat > lxc-templates/alpine-config <<EOL
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
  echo "ListenAddress \$CONTAINER_IP" >> /etc/ssh/sshd_config
  adduser -D -s /bin/sh \$USERNAME
  mkdir -p /home/\$USERNAME/.ssh
  echo "\$SSH_KEY" > /home/\$USERNAME/.ssh/authorized_keys
  chown -R \$USERNAME:\$USERNAME /home/\$USERNAME/.ssh
fi
if [ "\$ENABLE_SOCKS5" = "true" ]; then
  apk add --no-cache dante-server
fi
if [ "\$ENABLE_HTTP" = "true" ]; then
  apk add --no-cache tinyproxy
fi
if [ "\$ENABLE_WIREGUARD" = "true" ]; then
  apk add --no-cache wireguard-tools
fi
rc-service sshd start 2>/dev/null || true
rc-service danted start 2>/dev/null || true
rc-service tinyproxy start 2>/dev/null || true
EOL
chmod +x lxc-templates/setup-services.sh
fi

echo "==> [7/7] Initializing SQLite database..."
python3 init_db.py

echo ""
echo "==> Installation complete!"
echo "==> Database Type: SQLite (stored in instance/ip_gateway.db)"
echo "==> Default Admin Credentials:"
echo "    Username: admin"
echo "    Password: admin123"
echo "    ⚠️  Please change these after first login!"
echo ""
echo "Starting the application..."
nohup python3 app.py > xenproxy.log 2>&1 &
echo "App started in background. Access it at: http://localhost:3030"
echo ""
echo "Useful commands:"
echo "  View logs: tail -f xenproxy.log"
echo "  Stop app:  pkill -f 'python3 app.py'"
echo "  Restart:   ./install.sh"
echo ""
echo "To run as a systemd service, see service/xenproxy.service"