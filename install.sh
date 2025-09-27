#!/bin/bash
# LXC Multi-Protocol IP Gateway Admin Panel Installer

set -e

echo "==> Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv lxc lxc-templates bridge-utils iptables iproute2 postgresql postgresql-client

echo "==> Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "==> Installing Python requirements..."
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Creating PostgreSQL database and user..."
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

echo "==> Setting up LXC bridge (br0)..."
sudo ip link add name br0 type bridge || true
sudo ip addr flush dev br0 || true
sudo ip addr add 203.0.113.1/24 dev br0 || true
sudo ip link set br0 up
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 203.0.113.0/24 -j MASQUERADE

echo "==> Creating folders for LXC templates and static assets..."
mkdir -p lxc-templates static/css static/js

echo "==> Done."
echo "To run the app:"
echo "  source venv/bin/activate"
echo "  export DATABASE_URL=postgresql://postgres:postgres@localhost/ipgw"
echo "  python app.py"
