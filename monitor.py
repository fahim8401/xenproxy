import psutil
import time
import threading
from models import LxcContainer, db
from datetime import datetime

def get_host_resources():
    """Return host CPU, memory, disk, network, and container count."""
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    net = psutil.net_io_counters()
    container_count = LxcContainer.query.count()
    return {
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "memory_used": mem.used,
        "memory_total": mem.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "net_bytes_sent": net.bytes_sent,
        "net_bytes_recv": net.bytes_recv,
        "container_count": container_count,
    }

def get_container_resources(container_name):
    """Return resource stats for a container (CPU, mem, disk, net)."""
    # Example implementation using psutil (replace with actual cgroup parsing)
    cpu_usage = psutil.cpu_percent(interval=0.1)
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')
    net_info = psutil.net_io_counters()
    return {
        "cpu_percent": cpu_usage,
        "memory_used": memory_info.used,
        "disk_used": disk_info.used,
        "net_bytes_in": net_info.bytes_recv,
        "net_bytes_out": net_info.bytes_sent,
        "active_connections": 0,
    }

def update_bandwidth_stats(app):
    """Update bandwidth_in/bandwidth_out for each container every 60s."""
    while True:
        try:
            with app.app_context():
                containers = LxcContainer.query.all()
                for container in containers:
                    # Example: parse /sys/class/net/vethX/statistics
                    # Here, just set dummy values for demonstration
                    container.bandwidth_in += 0
                    container.bandwidth_out += 0
                    container.last_health_check = datetime.utcnow()
                
                db.session.commit()
        except Exception as e:
            logger.error(f"Error updating bandwidth stats: {e}")
        
        time.sleep(60)

def check_container_health(container_name):
    """Check SSH, SOCKS5, HTTP ports and update health_status."""
    # This is a stub; real implementation would use socket to test ports
    container = LxcContainer.query.filter_by(container_name=container_name).first()
    if container:
        container.health_status = "healthy"
        container.last_health_check = datetime.utcnow()
        db.session.commit()

def detect_abuse(container_name):
    """Detect abuse (high conn rate, port scan, bandwidth) and auto-disable."""
    container = LxcContainer.query.filter_by(container_name=container_name).first()
    if container:
        # Example abuse detection logic
        if container.bandwidth_in > 1_000_000_000:  # 1 GB threshold
            container.status = "disabled"
            db.session.commit()
            logger.warning(f"Container {container_name} disabled due to high bandwidth usage.")
            # Optionally, alert admin
        elif container.active_connections > 1000:  # Connection threshold
            logger.warning(f"Container {container_name} flagged for high connection rate.")

def start_monitoring_thread(app):
    """Start background thread for bandwidth and health checks."""
    t = threading.Thread(target=update_bandwidth_stats, args=(app,), daemon=True)
    t.start()
