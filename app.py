import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
# from flask_limiter import Limiter
# from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from datetime import datetime
from models import db, Admin, LxcContainer, SystemConfig, AuditLog
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

    # Apply system rules (with error handling for development environments)
    try:
        apply_all_system_rules()
        print("✓ System rules applied")
    except Exception as e:
        print(f"⚠️  Warning: Could not apply system rules: {e}")
    
    # Reconcile database with LXC (with error handling)
    try:
        reconcile_db_with_lxc()
        print("✓ Database reconciled with LXC")
    except Exception as e:
        print(f"⚠️  Warning: Could not reconcile with LXC: {e}")
    
    # Start monitoring thread
    try:
        start_monitoring_thread()
        print("✓ Monitoring thread started")
    except Exception as e:
        print(f"⚠️  Warning: Could not start monitoring: {e}")

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

@app.route('/containers/create', methods=['POST'])
@login_required
def create_container_route():
    data = request.form
    username = data['username']
    ip_address = data['ip_address']
    ssh_key = data['ssh_public_key']
    protocols = {
        "ssh": 'enable_ssh' in data,
        "socks5": 'enable_socks5' in data,
        "http": 'enable_http' in data,
        "wireguard": 'enable_wireguard' in data,
    }
    create_container(username, ip_address, ssh_key, protocols)
    
    # Log the container creation
    audit_log = AuditLog(admin_id=session['admin_id'], action='create_container', details=f'Created {username}', ip_address=request.remote_addr)
    db.session.add(audit_log)
    db.session.commit()
    
    flash('Container created', 'success')
    return redirect(url_for('containers'))

@app.route('/containers/create', methods=['GET', 'POST'])
@login_required
def create_container_page():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        ip_address = data['ip_address']
        ssh_key = data['ssh_public_key']
        protocols = {
            "ssh": 'enable_ssh' in data,
            "socks5": 'enable_socks5' in data,
            "http": 'enable_http' in data,
            "wireguard": 'enable_wireguard' in data,
        }
        create_container(username, ip_address, ssh_key, protocols)
        
        # Log the container creation
        audit_log = AuditLog(admin_id=session['admin_id'], action='create_container', details=f'Created {username}', ip_address=request.remote_addr)
        db.session.add(audit_log)
        db.session.commit()
        
        flash('Container created successfully', 'success')
        return redirect(url_for('containers'))
    
    return render_template('create_container.html')

@app.route('/containers/<name>/edit', methods=['GET', 'POST'])
@login_required
def edit_container_page(name):
    container = LxcContainer.query.filter_by(container_name=name).first_or_404()
    
    if request.method == 'POST':
        data = request.form
        container.username = data['username']
        container.ip_address = data['ip_address']
        container.ssh_public_key = data['ssh_public_key']
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3030, debug=False)
