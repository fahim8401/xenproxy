#!/bin/bash
# LXC Multi-Protocol IP Gateway Admin Panel Automated Installer (A-Z)

set -e

echo "==> [1/8] Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables iproute2 postgresql postgresql-client git curl

echo "==> [2/8] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "==> [3/8] Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

echo "==> [4/8] Creating PostgreSQL database and user..."
sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo -u postgres psql <<EOF
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_database WHERE datname = 'ipgw') THEN
      CREATE DATABASE ipgw;
   END IF;
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'postgres') THEN
      CREATE USER postgres WITH PASSWORD 'postgres';
   END IF;
END
\$\$;
EOF

echo "==> [5/8] Setting up LXC bridge (br0) and network..."
sudo ip link add name br0 type bridge || true
sudo ip addr flush dev br0 || true
sudo ip addr add 203.0.113.1/24 dev br0 || true
sudo ip link set br0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -C POSTROUTING -s 203.0.113.0/24 -j MASQUERADE || sudo iptables -t nat -A POSTROUTING -s 203.0.113.0/24 -j MASQUERADE

echo "==> [6/8] Creating folders for LXC templates and static assets..."
mkdir -p lxc-templates static/css static/js

echo "==> [7/8] Copying default LXC templates and static assets if missing..."
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
rc-service sshd start 2>/dev/null || true
rc-service danted start 2>/dev/null || true
rc-service tinyproxy start 2>/dev/null || true
EOL
chmod +x lxc-templates/setup-services.sh
fi

echo "==> [8/8] Initializing database tables..."
export DATABASE_URL=postgresql://postgres:postgres@localhost/ipgw
python3 -c "from app import db; db.create_all()"

echo "==> Installation complete!"
echo "To run the app:"
echo "  source venv/bin/activate"
echo "  export DATABASE_URL=postgresql://postgres:postgres@localhost/ipgw"
echo "  python app.py"
