import os
import subprocess
import logging
from models import LxcContainer, db, SystemConfig
from datetime import datetime

logger = logging.getLogger(__name__)

LXC_BASE_PATH = "/var/lib/lxc"
ALPINE_TEMPLATE = "lxc-templates/alpine-config"
SETUP_SCRIPT = "lxc-templates/setup-services.sh"

def run_command(cmd, check=True):
    """Run a shell command safely."""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        logger.error(f"Command failed: {cmd}\n{result.stderr}")
        raise RuntimeError(result.stderr)
    return result.stdout.strip()

def create_container(username, ip_address, ssh_key, protocols):
    """Create and configure a new unprivileged LXC container."""
    container_name = f"ipgw-{username}"
    config = SystemConfig.query.first()
    if not config:
        raise RuntimeError("SystemConfig not set")

    # Prepare LXC config
    lxc_config_path = f"{LXC_BASE_PATH}/{container_name}/config"
    os.makedirs(f"{LXC_BASE_PATH}/{container_name}", exist_ok=True)
    with open(ALPINE_TEMPLATE, "r") as tpl:
        lxc_config = tpl.read()
    lxc_config = lxc_config.replace("{{container_name}}", container_name)
    lxc_config = lxc_config.replace("{{username}}", username)
    lxc_config = lxc_config.replace("{{bridge_name}}", config.bridge_name)
    lxc_config = lxc_config.replace("{{ip_address}}", ip_address)
    lxc_config = lxc_config.replace("{{cpu_limit_times_100000}}", str(int(config.default_cpu_limit * 100000)))
    lxc_config = lxc_config.replace("{{memory_limit_bytes}}", str(config.default_memory_limit))
    with open(lxc_config_path, "w") as f:
        f.write(lxc_config)

    # Create container
    run_command(f"lxc-create -n {container_name} -t download -- -d alpine -r 3.18 -a amd64")
    run_command(f"cp {lxc_config_path} {LXC_BASE_PATH}/{container_name}/config")

    # Set up services
    env = {
        "ENABLE_SSH": str(protocols.get("ssh", True)).lower(),
        "ENABLE_SOCKS5": str(protocols.get("socks5", False)).lower(),
        "ENABLE_HTTP": str(protocols.get("http", False)).lower(),
        "ENABLE_WIREGUARD": str(protocols.get("wireguard", False)).lower(),
        "CONTAINER_IP": ip_address,
        "USERNAME": username,
        "SSH_KEY": ssh_key or "",
    }
    setup_script_path = os.path.abspath(SETUP_SCRIPT)
    run_command(f"lxc-start -n {container_name}")
    run_command(f"lxc-attach -n {container_name} -- sh {setup_script_path}", check=False)

    # Update DB
    container = LxcContainer(
        container_name=container_name,
        username=username,
        ip_address=ip_address,
        status="running",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        cpu_limit=config.default_cpu_limit,
        memory_limit=config.default_memory_limit,
        disk_limit=100*1024*1024,  # 100MB default
        enable_ssh=protocols.get("ssh", True),
        enable_socks5=protocols.get("socks5", False),
        enable_http=protocols.get("http", False),
        enable_wireguard=protocols.get("wireguard", False),
        ssh_public_key=ssh_key,
        health_status="healthy"
    )
    db.session.add(container)
    db.session.commit()
    return container

def delete_container(container_name):
    """Stop and delete an LXC container."""
    run_command(f"lxc-stop -n {container_name}", check=False)
    run_command(f"lxc-destroy -n {container_name}")
    container = LxcContainer.query.filter_by(container_name=container_name).first()
    if container:
        db.session.delete(container)
        db.session.commit()

def start_container(container_name):
    run_command(f"lxc-start -n {container_name}")
    container = LxcContainer.query.filter_by(container_name=container_name).first()
    if container:
        container.status = "running"
        container.updated_at = datetime.utcnow()
        db.session.commit()

def stop_container(container_name):
    run_command(f"lxc-stop -n {container_name}")
    container = LxcContainer.query.filter_by(container_name=container_name).first()
    if container:
        container.status = "stopped"
        container.updated_at = datetime.utcnow()
        db.session.commit()

def get_container_info(container_name):
    """Return detailed info for a container."""
    # This should parse lxc-info and resource stats
    info = {}
    try:
        output = run_command(f"lxc-info -n {container_name}")
        for line in output.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                info[k.strip()] = v.strip()
    except Exception as e:
        info['error'] = str(e)
    return info
