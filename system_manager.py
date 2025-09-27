import subprocess
import logging
import ipaddress
from models import SystemConfig, LxcContainer, db

logger = logging.getLogger(__name__)

def run_command(cmd, check=True):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        logger.error(f"Command failed: {cmd}\n{result.stderr}")
        raise RuntimeError(result.stderr)
    return result.stdout.strip()

def setup_lxc_bridge(bridge_name, subnet):
    """Create Linux bridge and assign subnet."""
    run_command(f"ip link add name {bridge_name} type bridge", check=False)
    run_command(f"ip addr flush dev {bridge_name}", check=False)
    run_command(f"ip addr add {subnet} dev {bridge_name}", check=False)
    run_command(f"ip link set {bridge_name} up")
    run_command("sysctl -w net.ipv4.ip_forward=1")
    run_command(f"iptables -t nat -A POSTROUTING -s {subnet} -j MASQUERADE", check=False)

def assign_ip_to_container(ip):
    """Validate and return available IP for assignment."""
    config = SystemConfig.query.first()
    if not config:
        raise RuntimeError("SystemConfig not set")
    network = ipaddress.ip_network(config.subnet_range, strict=False)
    if ipaddress.ip_address(ip) not in network:
        raise ValueError("IP not in allowed subnet")
    used_ips = {c.ip_address for c in LxcContainer.query.all()}
    if ip in used_ips:
        raise ValueError("IP already assigned")
    return ip

def setup_nat_rule(ip):
    """Add iptables MASQUERADE rule for container IP."""
    run_command(f"iptables -t nat -C POSTROUTING -s {ip} -j MASQUERADE", check=False)
    run_command(f"iptables -t nat -A POSTROUTING -s {ip} -j MASQUERADE", check=False)

def apply_all_system_rules():
    """Restore bridge, IPs, and NAT rules on startup."""
    config = SystemConfig.query.first()
    if not config:
        # Create default config if none exists
        config = SystemConfig(
            subnet_range='172.16.100.0/24',
            network_interface='eth0',
            bridge_name='xenproxy0',
            max_containers=254,
            auto_assign_ips=True,
            default_cpu_limit=0.1,
            default_memory_limit=64*1024*1024  # 64MB
        )
        db.session.add(config)
        db.session.commit()
        print("Created default SystemConfig in system_manager")
    
    setup_lxc_bridge(config.bridge_name, config.subnet_range)
    for container in LxcContainer.query.all():
        setup_nat_rule(container.ip_address)

def reconcile_db_with_lxc():
    """Detect and fix mismatches between DB and actual containers."""
    # List containers on disk
    from os import listdir
    lxc_dirs = set(listdir("/var/lib/lxc"))
    db_containers = set(c.container_name for c in LxcContainer.query.all())
    # Remove orphaned DB entries
    for cname in db_containers - lxc_dirs:
        c = LxcContainer.query.filter_by(container_name=cname).first()
        if c:
            db.session.delete(c)
    db.session.commit()
    # Optionally, clean up orphaned files (not implemented here)
