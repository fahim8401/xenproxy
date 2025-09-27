import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
from models import db, Admin, LxcContainer, SystemConfig, AuditLog, LxcTemplate
from auth import login_required, authenticate_admin, create_admin
from lxc_manager import create_container, delete_container, start_container, stop_container, get_container_info
from system_manager import setup_lxc_bridge, apply_all_system_rules, reconcile_db_with_lxc
from monitor import get_host_resources, get_container_resources, check_container_health, detect_abuse, start_monitoring_thread

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_secret')

# SQLite database configuration
database_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'ip_gateway.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{database_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SQLite specific configuration for better performance and concurrency
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_timeout': 20,
    'pool_recycle': 300,
    'pool_pre_ping': True,
    'connect_args': {
        'timeout': 20,
        'check_same_thread': False  # Allow SQLite to be used across threads
    }
}

# Only use secure cookies in production
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# CSRF configuration - more lenient for development
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit
app.config['WTF_CSRF_SSL_STRICT'] = False  # Allow over HTTP in development

db.init_app(app)
csrf = CSRFProtect(app)

@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Limiter removed for compatibility

def initialize_application():
    """Initialize the application with database and default configuration."""
    # Check if we're in production environment
    is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('PRODUCTION') == 'true'
    
    # Ensure instance directory exists
    os.makedirs(os.path.dirname(database_path), exist_ok=True)
    
    # Create all database tables
    db.create_all()
    print("✓ Database tables created/verified")
    
    # Create default SystemConfig if none exists
    if not SystemConfig.query.first():
        default_config = SystemConfig(
            subnet_range='172.16.100.0/24',
            network_interface='eth0',
            bridge_name='xenproxy0',
            max_containers=254,
            auto_assign_ips=True,
            default_cpu_limit=0.1,
            default_memory_limit=64*1024*1024  # 64MB
        )
        db.session.add(default_config)
        db.session.commit()
        print("✓ Created default SystemConfig")
    else:
        print("✓ SystemConfig exists")
    
    # Ensure at least one admin user exists
    from auth import create_admin
    if not Admin.query.first():
        try:
            create_admin('admin', 'admin1234')
            print("✓ Created default admin user (admin/admin1234)")
        except Exception as e:
            print(f"⚠️  Warning: Could not create default admin user: {e}")
    else:
        print("✓ Admin user exists")

    # Apply system rules only in production environment
    if is_production:
        try:
            apply_all_system_rules()
            print("✓ System rules applied")
        except Exception as e:
            print(f"⚠️  Warning: Could not apply system rules: {e}")
    else:
        print("ⓘ  Skipping system rules application (not in production)")
    
    # Reconcile database with LXC only in production environment
    if is_production:
        try:
            reconcile_db_with_lxc()
            print("✓ Database reconciled with LXC")
        except Exception as e:
            print(f"⚠️  Warning: Could not reconcile with LXC: {e}")
    else:
        print("ⓘ  Skipping LXC reconciliation (not in production)")
    
    # Start monitoring thread only in production
    if is_production:
        try:
            start_monitoring_thread(app)
            print("✓ Monitoring thread started")
        except Exception as e:
            print(f"⚠️  Warning: Could not start monitoring: {e}")
    else:
        print("ⓘ  Skipping monitoring thread (not in production)")

with app.app_context():
    initialize_application()

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt  # Exempt login from CSRF protection
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = authenticate_admin(username, password)
        if admin:
            session['admin_id'] = admin.id
            admin.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log the admin login
            audit_log = AuditLog(admin_id=admin.id, action='login', details='Admin logged in', ip_address=request.remote_addr)
            db.session.add(audit_log)
            db.session.commit()
            
            # Handle redirect after login - check both URL parameter and session
            next_page = request.args.get('next') or session.pop('next_url', None)
            if next_page and next_page.startswith('/'):  # Security: only allow relative URLs
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    containers = LxcContainer.query.all()
    host_stats = get_host_resources()
    system_config = SystemConfig.query.first()
    return render_template('dashboard.html', containers=containers, host_stats=host_stats, system_config=system_config)

@app.route('/api/system-stats')
@login_required
def system_stats():
    stats = get_host_resources()
    running_containers = LxcContainer.query.filter_by(status='running').count()
    return render_template('system_stats.html', stats=stats, running_containers=running_containers)

@app.route('/containers')
@login_required
def containers():
    containers = LxcContainer.query.all()
    return render_template('containers.html', containers=containers)

@app.route('/containers/<name>')
@login_required
def container_detail(name):
    container = LxcContainer.query.filter_by(container_name=name).first_or_404()
    info = get_container_info(name)
    stats = get_container_resources(name)
    return render_template('container_detail.html', container=container, info=info, stats=stats)

@app.route('/containers/create', methods=['GET', 'POST'])
@login_required
def create_container_page():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        ip_address = data['ip_address']
        template_id = data.get('template_id')
        auth_method = data.get('auth_method', 'ssh')
        ssh_key = data.get('ssh_public_key', '')
        password = data.get('password', '')
        
        # Validate authentication
        if auth_method == 'ssh' and not ssh_key.strip():
            flash('SSH public key is required for SSH authentication', 'danger')
            return redirect(request.url)
        elif auth_method == 'password' and not password:
            flash('Password is required for password authentication', 'danger')
            return redirect(request.url)
        
        protocols = {
            "ssh": 'enable_ssh' in data,
            "socks5": 'enable_socks5' in data,
            "http": 'enable_http' in data,
            "wireguard": 'enable_wireguard' in data,
        }
        create_container(username, ip_address, ssh_key, protocols, password, auth_method, template_id)
        
        # Log the container creation
        audit_log = AuditLog(admin_id=session['admin_id'], action='create_container', details=f'Created {username} with template {template_id}', ip_address=request.remote_addr)
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Container created successfully', 'success')
        return redirect(url_for('containers'))
    
    # Get available templates for the form
    templates = LxcTemplate.query.order_by(LxcTemplate.name).all()
    return render_template('create_container.html', templates=templates)

@app.route('/containers/<name>/edit', methods=['GET', 'POST'])
@login_required
def edit_container_page(name):
    container = LxcContainer.query.filter_by(container_name=name).first_or_404()
    
    if request.method == 'POST':
        data = request.form
        auth_method = data.get('auth_method', 'ssh')
        ssh_key = data.get('ssh_public_key', '')
        password = data.get('password', '')
        
        # Validate authentication
        if auth_method == 'ssh' and not ssh_key.strip():
            flash('SSH public key is required for SSH authentication', 'danger')
            return redirect(request.url)
        elif auth_method == 'password' and not password:
            flash('Password is required for password authentication', 'danger')
            return redirect(request.url)
        
        container.username = data['username']
        container.ip_address = data['ip_address']
        container.ssh_public_key = ssh_key if auth_method == 'ssh' else None
        container.password = password if auth_method == 'password' else None
        container.enable_ssh = 'enable_ssh' in data
        container.enable_socks5 = 'enable_socks5' in data
        container.enable_http = 'enable_http' in data
        container.enable_wireguard = 'enable_wireguard' in data
        container.cpu_limit = float(data['cpu_limit'])
        container.memory_limit = int(data['memory_limit']) * 1024 * 1024  # Convert MB to bytes
        container.disk_limit = int(data['disk_limit']) * 1024 * 1024 * 1024  # Convert GB to bytes
        
        db.session.commit()
        
        # Log the container edit
        audit_log = AuditLog(admin_id=session['admin_id'], action='edit_container', details=f'Edited {name}', ip_address=request.remote_addr)
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Container updated successfully', 'success')
        return redirect(url_for('container_detail', name=name))
    
    return render_template('edit_container.html', container=container)

@app.route('/containers/<name>/delete', methods=['POST'])
@login_required
def delete_container_route(name):
    delete_container(name)
    
    # Log the container deletion
    audit_log = AuditLog(admin_id=session['admin_id'], action='delete_container', details=f'Deleted {name}', ip_address=request.remote_addr)
    db.session.add(audit_log)
    db.session.commit()
    
    flash('Container deleted', 'success')
    return redirect(url_for('containers'))

@app.route('/containers/<name>/start', methods=['POST'])
@login_required
def start_container_route(name):
    start_container(name)
    
    # Log the container start
    audit_log = AuditLog(admin_id=session['admin_id'], action='start_container', details=f'Started {name}', ip_address=request.remote_addr)
    db.session.add(audit_log)
    db.session.commit()
    
    flash('Container started', 'success')
    return redirect(url_for('containers'))

@app.route('/containers/<name>/stop', methods=['POST'])
@login_required
def stop_container_route(name):
    stop_container(name)
    
    # Log the container stop
    audit_log = AuditLog(admin_id=session['admin_id'], action='stop_container', details=f'Stopped {name}', ip_address=request.remote_addr)
    db.session.add(audit_log)
    db.session.commit()
    
    flash('Container stopped', 'success')
    return redirect(url_for('containers'))

@app.route('/system/settings', methods=['GET', 'POST'])
@login_required
def system_settings():
    config = SystemConfig.query.first()
    if request.method == 'POST':
        config.subnet_range = request.form['subnet_range']
        config.network_interface = request.form['network_interface']
        config.bridge_name = request.form['bridge_name']
        config.max_containers = int(request.form['max_containers'])
        config.auto_assign_ips = 'auto_assign_ips' in request.form
        config.default_cpu_limit = float(request.form['default_cpu_limit'])
        config.default_memory_limit = int(request.form['default_memory_limit'])
        db.session.commit()
        flash('System settings updated', 'success')
    return render_template('system_settings.html', config=config)

@app.route('/logs')
@login_required
def logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('logs.html', logs=logs)

@app.route('/api/host_stats')
@login_required
def api_host_stats():
    return jsonify(get_host_resources())

@app.route('/api/container_stats/<name>')
@login_required
def api_container_stats(name):
    return jsonify(get_container_resources(name))

@app.route('/api/logs')
@login_required
def api_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([{
        "admin": log.admin.username,
        "action": log.action,
        "details": log.details,
        "ip_address": log.ip_address,
        "timestamp": log.timestamp.isoformat()
    } for log in logs])

# IP Management API Routes
@app.route('/api/available-ips')
@login_required
def api_available_ips():
    """Get list of available IPs in the subnet"""
    config = SystemConfig.query.first()
    if not config:
        return jsonify({"error": "System config not found"}), 500
    
    # Parse subnet range (e.g., "172.16.100.0/24")
    import ipaddress
    try:
        network = ipaddress.ip_network(config.subnet_range, strict=False)
        # Get all IPs in subnet except network and broadcast
        all_ips = [str(ip) for ip in network.hosts()]
        
        # Get used IPs from containers
        used_ips = [c.ip_address for c in LxcContainer.query.all()]
        
        # Filter available IPs
        available_ips = [ip for ip in all_ips if ip not in used_ips]
        
        return jsonify({"ips": available_ips[:50]})  # Limit to 50 for performance
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/add-ip', methods=['POST'])
@login_required
def api_add_ip():
    """Add a single IP to the available pool"""
    data = request.get_json()
    ip = data.get('ip', '').strip()
    
    if not ip:
        return jsonify({"success": False, "message": "IP address is required"}), 400
    
    # Validate IP format
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
    except:
        return jsonify({"success": False, "message": "Invalid IP address format"}), 400
    
    # Check if IP is already in use
    existing = LxcContainer.query.filter_by(ip_address=ip).first()
    if existing:
        return jsonify({"success": False, "message": "IP address already in use"}), 400
    
    # For now, just return success (IP is implicitly available)
    # In a real implementation, you might want to store available IPs in a separate table
    
    # Log the action
    audit_log = AuditLog(admin_id=session['admin_id'], action='add_ip', details=f'Added IP {ip} to pool', ip_address=request.remote_addr)
    db.session.add(audit_log)
    db.session.commit()
    
    return jsonify({"success": True, "message": f"IP {ip} added to available pool"})

@app.route('/api/add-batch-ips', methods=['POST'])
@login_required
def api_add_batch_ips():
    """Add multiple IPs to the available pool"""
    data = request.get_json()
    ips = data.get('ips', [])
    
    if not ips:
        return jsonify({"success": False, "message": "IP addresses are required"}), 400
    
    added_count = 0
    errors = []
    
    import ipaddress
    
    for ip in ips:
        ip = ip.strip()
        if not ip:
            continue
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Check if IP is already in use
            existing = LxcContainer.query.filter_by(ip_address=ip).first()
            if existing:
                errors.append(f"IP {ip} already in use")
                continue
            
            added_count += 1
        except:
            errors.append(f"Invalid IP format: {ip}")
    
    # Log the action
    audit_log = AuditLog(admin_id=session['admin_id'], action='add_batch_ips', 
                        details=f'Added {added_count} IPs to pool', ip_address=request.remote_addr)
    db.session.add(audit_log)
    db.session.commit()
    
    message = f"Successfully added {added_count} IPs"
    if errors:
        message += f". Errors: {'; '.join(errors[:5])}"
    
    return jsonify({"success": True, "added_count": added_count, "message": message})

@app.route('/api/check-network')
@login_required
def api_check_network():
    """Check network configuration status"""
    import subprocess
    
    def run_cmd(cmd):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    config = SystemConfig.query.first()
    
    # Check bridge
    bridge_up = run_cmd(f"ip link show {config.bridge_name} | grep -q 'UP'")
    
    # Check interface
    interface_up = run_cmd(f"ip link show {config.network_interface} | grep -q 'UP'")
    
    # Check IP forwarding
    ip_forward = run_cmd("cat /proc/sys/net/ipv4/ip_forward | grep -q '1'")
    
    # Check NAT rules
    nat_rules = run_cmd(f"iptables -t nat -C POSTROUTING -s {config.subnet_range} -j MASQUERADE 2>/dev/null") if config else False
    
    return jsonify({
        "bridge_status": "UP" if bridge_up else "DOWN",
        "interface_status": "UP" if interface_up else "DOWN", 
        "ip_forwarding": "ENABLED" if ip_forward else "DISABLED",
        "nat_rules": "CONFIGURED" if nat_rules else "MISSING"
    })

@app.route('/api/scan-ips')
@login_required
def api_scan_ips():
    """Scan for available IPs in the subnet"""
    import subprocess
    import ipaddress
    
    config = SystemConfig.query.first()
    if not config:
        return jsonify({"error": "System config not found"}), 500
    
    try:
        network = ipaddress.ip_network(config.subnet_range, strict=False)
        all_ips = list(network.hosts())
        
        # Get used IPs
        used_ips = set(c.ip_address for c in LxcContainer.query.all())
        
        # For a simple scan, we'll just check which IPs are not in use
        # In a real implementation, you might want to ping them
        available_ips = [str(ip) for ip in all_ips if str(ip) not in used_ips]
        
        return jsonify({"ips": available_ips[:100]})  # Limit results
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/network-status')
@login_required
def api_network_status():
    """Get current network status"""
    return api_check_network()

@app.route('/api/ip-pool-status')
@login_required
def api_ip_pool_status():
    """Get IP pool utilization status"""
    config = SystemConfig.query.first()
    if not config:
        return jsonify({"error": "System config not found"}), 500
    
    import ipaddress
    try:
        network = ipaddress.ip_network(config.subnet_range, strict=False)
        total_ips = network.num_addresses - 2  # Subtract network and broadcast
        
        used_ips = LxcContainer.query.count()
        available_ips = total_ips - used_ips
        utilization = round((used_ips / total_ips) * 100, 1) if total_ips > 0 else 0
        
        return jsonify({
            "total": total_ips,
            "used": used_ips,
            "available": available_ips,
            "utilization": utilization
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/test-connectivity')
@login_required
def api_test_connectivity():
    """Test internet connectivity"""
    import subprocess
    
    def test_cmd(cmd, timeout=5):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
            return result.returncode == 0
        except:
            return False
    
    # Test internet connectivity
    internet = test_cmd("ping -c 1 -W 2 8.8.8.8")
    
    # Test DNS
    dns = test_cmd("nslookup google.com 8.8.8.8")
    
    # Test gateway (assuming default route)
    gateway = test_cmd("ip route show default | head -1 | grep -q via")
    
    return jsonify({
        "internet": internet,
        "dns": dns,
        "gateway": gateway
    })

# Template Management Routes
@app.route('/templates')
@login_required
def templates():
    """Display LXC templates management page"""
    templates = LxcTemplate.query.order_by(LxcTemplate.created_at.desc()).all()
    return render_template('templates.html', templates=templates)

@app.route('/api/templates', methods=['GET'])
@login_required
def api_get_templates():
    """Get all templates as JSON"""
    templates = LxcTemplate.query.order_by(LxcTemplate.created_at.desc()).all()
    return jsonify([{
        'id': t.id,
        'name': t.name,
        'description': t.description,
        'is_default': t.is_default,
        'created_at': t.created_at.isoformat() if t.created_at else None,
        'updated_at': t.updated_at.isoformat() if t.updated_at else None
    } for t in templates])

@app.route('/api/templates', methods=['POST'])
@login_required
def api_create_template():
    """Create a new LXC template"""
    data = request.get_json()
    
    if not data or not data.get('name') or not data.get('config_content'):
        return jsonify({"error": "Name and config content are required"}), 400
    
    # Check if template name already exists
    existing = LxcTemplate.query.filter_by(name=data['name']).first()
    if existing:
        return jsonify({"error": "Template name already exists"}), 400
    
    # If this is set as default, unset other defaults
    if data.get('is_default'):
        LxcTemplate.query.filter_by(is_default=True).update({'is_default': False})
    
    template = LxcTemplate(
        name=data['name'],
        description=data.get('description', ''),
        config_content=data['config_content'],
        is_default=data.get('is_default', False)
    )
    
    db.session.add(template)
    db.session.commit()
    
    # Log the action
    audit_log = AuditLog(
        admin_id=session['admin_id'],
        action='create_template',
        details=f"Created template: {template.name}",
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    return jsonify({
        'id': template.id,
        'name': template.name,
        'description': template.description,
        'is_default': template.is_default,
        'created_at': template.created_at.isoformat(),
        'updated_at': template.updated_at.isoformat()
    })

@app.route('/api/templates/<int:template_id>', methods=['PUT'])
@login_required
def api_update_template(template_id):
    """Update an existing LXC template"""
    template = LxcTemplate.query.get_or_404(template_id)
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Check name uniqueness if name is being changed
    if 'name' in data and data['name'] != template.name:
        existing = LxcTemplate.query.filter_by(name=data['name']).first()
        if existing:
            return jsonify({"error": "Template name already exists"}), 400
        template.name = data['name']
    
    if 'description' in data:
        template.description = data['description']
    
    if 'config_content' in data:
        template.config_content = data['config_content']
    
    # Handle default flag
    if 'is_default' in data:
        if data['is_default'] and not template.is_default:
            # Unset other defaults
            LxcTemplate.query.filter_by(is_default=True).update({'is_default': False})
        template.is_default = data['is_default']
    
    template.updated_at = datetime.now()
    db.session.commit()
    
    # Log the action
    audit_log = AuditLog(
        admin_id=session['admin_id'],
        action='update_template',
        details=f"Updated template: {template.name}",
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    return jsonify({
        'id': template.id,
        'name': template.name,
        'description': template.description,
        'is_default': template.is_default,
        'created_at': template.created_at.isoformat(),
        'updated_at': template.updated_at.isoformat()
    })

@app.route('/api/templates/<int:template_id>', methods=['DELETE'])
@login_required
def api_delete_template(template_id):
    """Delete an LXC template"""
    template = LxcTemplate.query.get_or_404(template_id)
    
    # Don't allow deletion of default template
    if template.is_default:
        return jsonify({"error": "Cannot delete default template"}), 400
    
    template_name = template.name
    db.session.delete(template)
    db.session.commit()
    
    # Log the action
    audit_log = AuditLog(
        admin_id=session['admin_id'],
        action='delete_template',
        details=f"Deleted template: {template_name}",
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    return jsonify({"message": "Template deleted successfully"})

@app.route('/api/templates/<int:template_id>/duplicate', methods=['POST'])
@login_required
def api_duplicate_template(template_id):
    """Duplicate an existing LXC template"""
    template = LxcTemplate.query.get_or_404(template_id)
    
    # Generate unique name
    base_name = template.name
    counter = 1
    new_name = f"{base_name} (Copy)"
    while LxcTemplate.query.filter_by(name=new_name).first():
        counter += 1
        new_name = f"{base_name} (Copy {counter})"
    
    new_template = LxcTemplate(
        name=new_name,
        description=f"Copy of {template.description or template.name}",
        config_content=template.config_content,
        is_default=False
    )
    
    db.session.add(new_template)
    db.session.commit()
    
    # Log the action
    audit_log = AuditLog(
        admin_id=session['admin_id'],
        action='duplicate_template',
        details=f"Duplicated template: {template.name} -> {new_name}",
        ip_address=request.remote_addr
    )
    db.session.add(audit_log)
    db.session.commit()
    
    return jsonify({
        'id': new_template.id,
        'name': new_template.name,
        'description': new_template.description,
        'is_default': new_template.is_default,
        'created_at': new_template.created_at.isoformat(),
        'updated_at': new_template.updated_at.isoformat()
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3030, debug=False)
