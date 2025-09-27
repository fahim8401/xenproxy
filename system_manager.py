import subprocess
import ipaddress
import logging
import psutil
import netifaces
from models import db, User

# Configuration - Update these for your network
SUBNET_RANGE = "192.168.1.0/24"  # Your subnet range
NETWORK_INTERFACE = "eth0"       # Your network interface
PROXY_BASE_PORT = 10000          # Base port for proxies

logger = logging.getLogger(__name__)

def run_command(command, check=True, capture_output=True):
    """Run a shell command with error handling."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True
        )
        if capture_output:
            return result.stdout.strip(), result.stderr.strip()
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {command}")
        logger.error(f"Error: {e.stderr}")
        raise

def validate_ip_in_subnet(ip):
    """Validate if IP is within the configured subnet."""
    try:
        network = ipaddress.ip_network(SUBNET_RANGE, strict=False)
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False

def assign_ip_to_interface(ip):
    """Assign IP address to network interface."""
    if not validate_ip_in_subnet(ip):
        raise ValueError(f"IP {ip} is not in subnet {SUBNET_RANGE}")

    command = f"sudo ip addr add {ip}/24 dev {NETWORK_INTERFACE}"
    run_command(command)
    logger.info(f"Assigned IP {ip} to interface {NETWORK_INTERFACE}")

def remove_ip_from_interface(ip):
    """Remove IP address from network interface."""
    command = f"sudo ip addr del {ip}/24 dev {NETWORK_INTERFACE}"
    try:
        run_command(command)
        logger.info(f"Removed IP {ip} from interface {NETWORK_INTERFACE}")
    except subprocess.CalledProcessError:
        # IP might not be assigned, ignore error
        logger.warning(f"IP {ip} was not assigned to interface")

def setup_nat_rule(ip):
    """Set up NAT rule for IP address."""
    # Add MASQUERADE rule for outgoing traffic from this IP
    command = f"sudo iptables -t nat -A POSTROUTING -s {ip} -o {NETWORK_INTERFACE} -j MASQUERADE"
    run_command(command)
    logger.info(f"Set up NAT rule for IP {ip}")

def remove_nat_rule(ip):
    """Remove NAT rule for IP address."""
    command = f"sudo iptables -t nat -D POSTROUTING -s {ip} -o {NETWORK_INTERFACE} -j MASQUERADE"
    try:
        run_command(command)
        logger.info(f"Removed NAT rule for IP {ip}")
    except subprocess.CalledProcessError:
        # Rule might not exist, ignore error
        logger.warning(f"NAT rule for IP {ip} was not found")

def create_linux_user(username, password):
    """Create Linux system user."""
    # Create user with home directory
    command = f"sudo useradd -m -s /bin/bash {username}"
    run_command(command)

    # Set password
    command = f"echo '{username}:{password}' | sudo chpasswd"
    run_command(command)

    logger.info(f"Created Linux user {username}")

def delete_linux_user(username):
    """Delete Linux system user and home directory."""
    command = f"sudo userdel -r {username}"
    try:
        run_command(command)
        logger.info(f"Deleted Linux user {username}")
    except subprocess.CalledProcessError:
        logger.warning(f"Failed to delete user {username}")

def get_available_ips():
    """Get list of available IPs in subnet (not assigned to users)."""
    network = ipaddress.ip_network(SUBNET_RANGE, strict=False)

    # Get all assigned IPs from database
    assigned_ips = set()
    users = User.query.filter_by(status='active').all()
    for user in users:
        assigned_ips.add(user.ip_address)

    # Return available IPs (exclude network and broadcast addresses)
    available = []
    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str not in assigned_ips:
            available.append(ip_str)

    return available

def apply_all_system_rules():
    """Apply all system rules on startup - restore IPs, NAT, and users."""
    logger.info("Applying all system rules on startup...")

    users = User.query.filter_by(status='active').all()

    for user in users:
        try:
            # Assign IP to interface
            assign_ip_to_interface(user.ip_address)

            # Set up NAT rule
            setup_nat_rule(user.ip_address)

            # Ensure Linux user exists
            create_linux_user(user.username, user.password)

        except Exception as e:
            logger.error(f"Failed to apply rules for user {user.username}: {e}")

    logger.info("System rules applied successfully")

def update_system_config(subnet_range=None, network_interface=None, proxy_base_port=None):
    """Update system configuration (called from web UI)."""
    global SUBNET_RANGE, NETWORK_INTERFACE, PROXY_BASE_PORT

    if subnet_range:
        # Validate subnet format
        try:
            ipaddress.ip_network(subnet_range, strict=False)
            SUBNET_RANGE = subnet_range
        except ValueError:
            raise ValueError("Invalid subnet range format")

    if network_interface:
        NETWORK_INTERFACE = network_interface

    if proxy_base_port:
        PROXY_BASE_PORT = int(proxy_base_port)

    logger.info(f"Updated system config: subnet={SUBNET_RANGE}, interface={NETWORK_INTERFACE}, proxy_port={PROXY_BASE_PORT}")

def get_system_config():
    """Get current system configuration."""
    return {
        'subnet_range': SUBNET_RANGE,
        'network_interface': NETWORK_INTERFACE,
        'proxy_base_port': PROXY_BASE_PORT
    }

def get_network_interfaces():
    """Get list of available network interfaces."""
    interfaces = []
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            interface_info = {
                'name': iface,
                'mac': None,
                'ipv4': [],
                'ipv6': []
            }

            # Get MAC address
            if netifaces.AF_LINK in addrs:
                interface_info['mac'] = addrs[netifaces.AF_LINK][0].get('addr')

            # Get IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    interface_info['ipv4'].append({
                        'addr': addr.get('addr'),
                        'netmask': addr.get('netmask'),
                        'broadcast': addr.get('broadcast')
                    })

            # Get IPv6 addresses
            if netifaces.AF_INET6 in addrs:
                for addr in addrs[netifaces.AF_INET6]:
                    interface_info['ipv6'].append({
                        'addr': addr.get('addr'),
                        'netmask': addr.get('netmask')
                    })

            interfaces.append(interface_info)
    except Exception as e:
        logger.error(f"Failed to get network interfaces: {e}")

    return interfaces

def get_assigned_ips():
    """Get all IPs currently assigned to interfaces."""
    assigned_ips = {}
    try:
        # Get IP addresses from all interfaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    if ip:
                        assigned_ips[ip] = {
                            'interface': iface,
                            'netmask': addr.get('netmask'),
                            'broadcast': addr.get('broadcast')
                        }
    except Exception as e:
        logger.error(f"Failed to get assigned IPs: {e}")

    return assigned_ips

def add_system_ip(ip, interface=None):
    """Add IP address to system interface."""
    target_interface = interface or NETWORK_INTERFACE

    if not validate_ip_in_subnet(ip):
        raise ValueError(f"IP {ip} is not in subnet {SUBNET_RANGE}")

    # Check if IP is already assigned
    assigned = get_assigned_ips()
    if ip in assigned:
        raise ValueError(f"IP {ip} is already assigned to {assigned[ip]['interface']}")

    command = f"sudo ip addr add {ip}/24 dev {target_interface}"
    run_command(command)
    setup_nat_rule(ip)

    logger.info(f"Added system IP {ip} to interface {target_interface}")
    return True

def remove_system_ip(ip):
    """Remove IP address from system interface."""
    assigned = get_assigned_ips()
    if ip not in assigned:
        raise ValueError(f"IP {ip} is not assigned to any interface")

    interface = assigned[ip]['interface']
    command = f"sudo ip addr del {ip}/24 dev {interface}"
    run_command(command)
    remove_nat_rule(ip)

    logger.info(f"Removed system IP {ip} from interface {interface}")
    return True

def get_system_stats():
    """Get real-time system statistics."""
    try:
        # CPU stats
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_count = psutil.cpu_count()
        cpu_freq = psutil.cpu_freq()

        # Memory stats
        memory = psutil.virtual_memory()
        memory_stats = {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'percent': memory.percent
        }

        # Disk stats
        disk = psutil.disk_usage('/')
        disk_stats = {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percent': disk.percent
        }

        # Network stats
        net_io = psutil.net_io_counters()
        network_stats = {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }

        # System load
        load_avg = psutil.getloadavg()

        return {
            'cpu': {
                'percent': cpu_percent,
                'count': cpu_count,
                'freq_current': cpu_freq.current if cpu_freq else None,
                'freq_max': cpu_freq.max if cpu_freq else None
            },
            'memory': memory_stats,
            'disk': disk_stats,
            'network': network_stats,
            'load_avg': load_avg,
            'uptime': psutil.boot_time()
        }
    except Exception as e:
        logger.error(f"Failed to get system stats: {e}")
        return {}

def get_network_traffic():
    """Get network traffic statistics."""
    try:
        # Get stats for all interfaces
        interfaces = {}
        net_stats = psutil.net_if_stats()
        net_io = psutil.net_if_io_counters(pernic=True)

        for iface, stats in net_stats.items():
            if iface in net_io:
                io_stats = net_io[iface]
                interfaces[iface] = {
                    'isup': stats.isup,
                    'duplex': stats.duplex,
                    'speed': stats.speed,
                    'mtu': stats.mtu,
                    'bytes_sent': io_stats.bytes_sent,
                    'bytes_recv': io_stats.bytes_recv,
                    'packets_sent': io_stats.packets_sent,
                    'packets_recv': io_stats.packets_recv,
                    'errin': io_stats.errin,
                    'errout': io_stats.errout,
                    'dropin': io_stats.dropin,
                    'dropout': io_stats.dropout
                }

        return interfaces
    except Exception as e:
        logger.error(f"Failed to get network traffic: {e}")
        return {}
