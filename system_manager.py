import subprocess
import ipaddress
import logging
from models import db, User

# Configurable settings - can be updated via web UI
SUBNET_RANGE = "203.0.113.0/24"  # RFC 5737 test range
NETWORK_INTERFACE = "eth0"
PROXY_BASE_PORT = 10000  # SOCKS5: 10000+, HTTP: 20000+

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
