import subprocess
import logging
import os
from system_manager import PROXY_BASE_PORT

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

def generate_dante_config(user):
    """Generate Dante SOCKS5 proxy configuration for user."""
    config = f"""# Dante SOCKS5 proxy config for user {user.username}
logoutput: syslog

internal: 0.0.0.0 port = {PROXY_BASE_PORT + user.id}
external: {user.ip_address}

method: username
user.privileged: root
user.notprivileged: nobody

client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    log: connect disconnect
}}

socks pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
    command: bind connect udpassociate
    log: connect disconnect
    method: username
}}
"""
    return config

def generate_tinyproxy_config(user):
    """Generate TinyProxy HTTP proxy configuration for user."""
    config = f"""# TinyProxy HTTP proxy config for user {user.username}
User nobody
Group nobody
Port {20000 + user.id}
Listen {user.ip_address}
Timeout 600
DefaultErrorFile "/usr/share/tinyproxy/default.html"
StatFile "/usr/share/tinyproxy/stats.html"
Logfile "/var/log/tinyproxy/tinyproxy.log"
LogLevel Info
PidFile "/var/run/tinyproxy/tinyproxy.pid"
MaxClients 100
MinSpareServers 5
MaxSpareServers 20
StartServers 10
MaxRequestsPerChild 0
Allow 127.0.0.1
Allow 192.168.0.0/16
Allow 172.16.0.0/12
Allow 10.0.0.0/8
BasicAuth {user.username} {user.password}
"""
    return config

def start_user_proxies(user):
    """Start SOCKS5 and HTTP proxy containers for user based on settings."""
    try:
        # Create config directory if it doesn't exist
        config_dir = f"/tmp/proxy_configs/{user.id}"
        os.makedirs(config_dir, exist_ok=True)

        if user.enable_socks5:
            # Generate Dante config
            dante_config = generate_dante_config(user)
            with open(f"{config_dir}/dante.conf", 'w') as f:
                f.write(dante_config)

            # Start Dante container
            container_name = f"socks5_{user.id}"
            command = f"""
            docker run -d --name {container_name} --restart unless-stopped
            -p {PROXY_BASE_PORT + user.id}:{PROXY_BASE_PORT + user.id}
            -v {config_dir}/dante.conf:/etc/dante.conf:ro
            --cap-add NET_ADMIN
            --network host
            vimagick/dante
            """
            run_command(command)
            logger.info(f"Started SOCKS5 proxy for user {user.username}")

        if user.enable_http:
            # Generate TinyProxy config
            tinyproxy_config = generate_tinyproxy_config(user)
            with open(f"{config_dir}/tinyproxy.conf", 'w') as f:
                f.write(tinyproxy_config)

            # Start TinyProxy container
            container_name = f"http_{user.id}"
            command = f"""
            docker run -d --name {container_name} --restart unless-stopped
            -p {20000 + user.id}:{20000 + user.id}
            -v {config_dir}/tinyproxy.conf:/etc/tinyproxy/tinyproxy.conf:ro
            --network host
            vimagick/tinyproxy
            """
            run_command(command)
            logger.info(f"Started HTTP proxy for user {user.username}")

    except Exception as e:
        logger.error(f"Failed to start proxies for user {user.username}: {e}")
        raise

def stop_user_proxies(user_id):
    """Stop and remove proxy containers for user."""
    containers = [f"socks5_{user_id}", f"http_{user_id}"]

    for container in containers:
        try:
            # Stop container
            run_command(f"docker stop {container}", check=False)
            # Remove container
            run_command(f"docker rm {container}", check=False)
            logger.info(f"Stopped and removed container {container}")
        except Exception as e:
            logger.warning(f"Failed to stop/remove container {container}: {e}")

    # Clean up config directory
    config_dir = f"/tmp/proxy_configs/{user_id}"
    try:
        run_command(f"rm -rf {config_dir}")
    except Exception as e:
        logger.warning(f"Failed to clean up config directory {config_dir}: {e}")

def get_user_proxy_ports(user_id):
    """Get proxy ports for user."""
    return {
        'socks5': PROXY_BASE_PORT + user_id,
        'http': 20000 + user_id
    }

def is_proxy_running(container_name):
    """Check if Docker container is running."""
    try:
        result = run_command("docker ps --filter name=^" + container_name + "$ --format '{{.Names}}'")
        return container_name in result[0] if result[0] else False
    except Exception:
        return False

def get_user_proxy_status(user):
    """Get status of all proxies for user."""
    status = {}

    if user.enable_socks5:
        container_name = f"socks5_{user.id}"
        status['socks5'] = is_proxy_running(container_name)

    if user.enable_http:
        container_name = f"http_{user.id}"
        status['http'] = is_proxy_running(container_name)

    return status
