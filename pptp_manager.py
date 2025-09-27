import subprocess
import logging
from system_manager import SUBNET_RANGE, NETWORK_INTERFACE

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

def setup_pptpd():
    """One-time setup for PPTP VPN server."""
    try:
        logger.info("Setting up PPTP VPN server...")

        # Install pptpd if not already installed
        run_command("sudo apt-get update")
        run_command("sudo apt-get install -y pptpd")

        # Configure pptpd options
        pptpd_options = f"""# PPTP VPN options
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
"""
        with open('/tmp/pptpd-options', 'w') as f:
            f.write(pptpd_options)

        run_command("sudo mv /tmp/pptpd-options /etc/ppp/pptpd-options")

        # Configure pptpd.conf
        pptpd_conf = f"""# PPTP VPN configuration
option /etc/ppp/pptpd-options
logwtmp
localip 192.168.0.1
remoteip {SUBNET_RANGE.replace('/24', '.100-200')}
"""
        with open('/tmp/pptpd.conf', 'w') as f:
            f.write(pptpd_conf)

        run_command("sudo mv /tmp/pptpd.conf /etc/pptpd.conf")

        # Enable IP forwarding
        run_command("sudo sysctl -w net.ipv4.ip_forward=1")
        run_command("sudo sh -c 'echo \"net.ipv4.ip_forward=1\" >> /etc/sysctl.conf'")

        # Add iptables NAT rule for PPTP
        run_command(f"sudo iptables -t nat -A POSTROUTING -s {SUBNET_RANGE} -o {NETWORK_INTERFACE} -j MASQUERADE")
        run_command("sudo iptables -A FORWARD -p tcp --dport 1723 -i ppp+ -j ACCEPT")
        run_command("sudo iptables -A FORWARD -p gre -i ppp+ -j ACCEPT")

        # Save iptables rules
        run_command("sudo sh -c 'iptables-save > /etc/iptables/rules.v4'")

        # Create chap-secrets file if it doesn't exist
        run_command("sudo touch /etc/ppp/chap-secrets")
        run_command("sudo chmod 600 /etc/ppp/chap-secrets")

        # Start and enable pptpd service
        run_command("sudo systemctl enable pptpd")
        run_command("sudo systemctl start pptpd")

        logger.info("PPTP VPN server setup completed")

    except Exception as e:
        logger.error(f"Failed to setup PPTP VPN: {e}")
        raise

def add_pptp_user(username, password, ip):
    """Add PPTP user to chap-secrets."""
    try:
        # Read existing chap-secrets
        with open('/etc/ppp/chap-secrets', 'r') as f:
            lines = f.readlines()

        # Remove existing entry for user if exists
        lines = [line for line in lines if not line.strip().startswith(username + ' ')]

        # Add new entry
        new_entry = f'{username} pptpd {password} {ip}\n'
        lines.append(new_entry)

        # Write back to file
        with open('/tmp/chap-secrets', 'w') as f:
            f.writelines(lines)

        run_command("sudo mv /tmp/chap-secrets /etc/ppp/chap-secrets")
        run_command("sudo chmod 600 /etc/ppp/chap-secrets")

        logger.info(f"Added PPTP user {username}")

    except Exception as e:
        logger.error(f"Failed to add PPTP user {username}: {e}")
        raise

def remove_pptp_user(username):
    """Remove PPTP user from chap-secrets."""
    try:
        # Read existing chap-secrets
        with open('/etc/ppp/chap-secrets', 'r') as f:
            lines = f.readlines()

        # Remove entry for user
        lines = [line for line in lines if not line.strip().startswith(username + ' ')]

        # Write back to file
        with open('/tmp/chap-secrets', 'w') as f:
            f.writelines(lines)

        run_command("sudo mv /tmp/chap-secrets /etc/ppp/chap-secrets")

        logger.info(f"Removed PPTP user {username}")

    except Exception as e:
        logger.error(f"Failed to remove PPTP user {username}: {e}")
        raise

def reload_pptpd():
    """Reload PPTP daemon."""
    try:
        run_command("sudo systemctl reload pptpd")
        logger.info("Reloaded PPTP daemon")
    except Exception as e:
        logger.error(f"Failed to reload PPTP daemon: {e}")
        raise

def get_pptp_users():
    """Get list of PPTP users from chap-secrets."""
    try:
        users = []
        with open('/etc/ppp/chap-secrets', 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 4:
                        users.append({
                            'username': parts[0],
                            'server': parts[1],
                            'ip': parts[3]
                        })
        return users
    except Exception as e:
        logger.error(f"Failed to get PPTP users: {e}")
        return []

def is_pptpd_running():
    """Check if PPTP daemon is running."""
    try:
        result = run_command("sudo systemctl is-active pptpd")
        return result[0].strip() == 'active'
    except Exception:
        return False
