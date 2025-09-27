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
    # This is a stub; real implementation would parse cgroup and veth stats
    # Example: parse /sys/fs/cgroup, /sys/class/net/veth*/statistics
    return {
        "cpu_percent": 0.0,
        "memory_used": 0,
        "disk_used": 0,
        "net_bytes_in": 0,
        "net_bytes_out": 0,
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
            print(f"Error updating bandwidth stats: {e}")
        
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
    # This is a stub; real implementation would analyze logs/stats
    container = LxcContainer.query.filter_by(container_name=container_name).first()
    if container and container.bandwidth_in > 1_000_000_000:
        container.status = "disabled"
        db.session.commit()
        # Optionally, alert admin

def start_monitoring_thread(app):
    """Start background thread for bandwidth and health checks."""
    t = threading.Thread(target=update_bandwidth_stats, args=(app,), daemon=True)
    t.start()
