import os
import logging
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, abort
from werkzeug.security import check_password_hash
import re

from models import db, Admin, User, AuditLog, SystemHealth
from system_manager import (
    assign_ip_to_interface, remove_ip_from_interface,
    setup_nat_rule, remove_nat_rule,
    create_linux_user, delete_linux_user,
    get_available_ips, apply_all_system_rules,
    update_system_config, get_system_config,
    validate_ip_in_subnet, get_network_interfaces,
    get_assigned_ips, add_system_ip, remove_system_ip,
    get_system_stats, get_network_traffic
)
from proxy_manager import start_user_proxies, stop_user_proxies, get_user_proxy_ports, get_user_proxy_status
from pptp_manager import add_pptp_user, remove_pptp_user, reload_pptpd

# Configure logging
logging.basicConfig(
    filename='ip_gateway.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ip_gateway.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True  # Set to False for development without HTTPS
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

db.init_app(app)

# Rate limiting storage (simple in-memory for demo)
rate_limits = {}

def rate_limit(max_requests=10, window_seconds=60):
    """Simple rate limiting decorator."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            now = datetime.utcnow().timestamp()
            client_ip = request.remote_addr
            key = f"{client_ip}:{f.__name__}"

            if key not in rate_limits:
                rate_limits[key] = []

            # Clean old requests
            rate_limits[key] = [t for t in rate_limits[key] if now - t < window_seconds]

            if len(rate_limits[key]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429

            rate_limits[key].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

def login_required(f):
    """Decorator to require admin login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def validate_username(username):
    """Validate username format."""
    if not username or len(username) > 80:
        return False
    return re.match(r'^[a-zA-Z0-9_-]+$', username) is not None

def validate_password(password):
    """Validate password strength."""
    if not password or len(password) < 6:
        return False
    return True

def validate_ip(ip):
    """Validate IP address format."""
    return re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip) is not None

@app.route('/')
def index():
    """Redirect to login page."""
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 attempts per 5 minutes
def login():
    """Admin login page."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')

        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            session.permanent = True
            logger.info(f"Admin {username} logged in")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            logger.warning(f"Failed login attempt for username: {username}")

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Admin logout."""
    session.pop('admin_id', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard page."""
    users = User.query.all()
    system_config = get_system_config()
    available_ips = get_available_ips()

    # Get user stats
    total_users = len(users)
    active_users = len([u for u in users if u.status == 'active'])

    return render_template('dashboard.html',
                         users=users,
                         system_config=system_config,
                         available_ips=available_ips,
                         total_users=total_users,
                         active_users=active_users)

@app.route('/api/users', methods=['POST'])
@login_required
def create_user():
    """Create new user via API."""
    try:
        data = request.get_json()

        username = data.get('username', '').strip()
        password = data.get('password', '')
        ip_address = data.get('ip_address', '').strip()

        enable_ssh = data.get('enable_ssh', True)
        enable_socks5 = data.get('enable_socks5', False)
        enable_http = data.get('enable_http', False)
        enable_pptp = data.get('enable_pptp', False)

        # Validation
        if not validate_username(username):
            return jsonify({'error': 'Invalid username format'}), 400

        if not validate_password(password):
            return jsonify({'error': 'Password must be at least 6 characters'}), 400

        if not validate_ip(ip_address):
            return jsonify({'error': 'Invalid IP address format'}), 400

        if not validate_ip_in_subnet(ip_address):
            return jsonify({'error': 'IP address not in configured subnet'}), 400

        # Check if username or IP already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'error': 'Username already exists'}), 400

        if User.query.filter_by(ip_address=ip_address).first():
            return jsonify({'error': 'IP address already assigned'}), 400

        # Create user
        user = User(
            username=username,
            password=password,
            ip_address=ip_address,
            enable_ssh=enable_ssh,
            enable_socks5=enable_socks5,
            enable_http=enable_http,
            enable_pptp=enable_pptp
        )

        db.session.add(user)
        db.session.commit()

        # Apply system rules
        try:
            assign_ip_to_interface(ip_address)
            setup_nat_rule(ip_address)
            create_linux_user(username, password)

            if enable_pptp:
                add_pptp_user(username, password, ip_address)
                reload_pptpd()

            # Start proxies
            start_user_proxies(user)

        except Exception as e:
            logger.error(f"Failed to apply system rules for user {username}: {e}")
            # Rollback user creation
            db.session.delete(user)
            db.session.commit()
            return jsonify({'error': f'Failed to create user: {str(e)}'}), 500

        log_admin_action('user_created', 'user', user.id, f'Created user {username} with IP {ip_address}')
        logger.info(f"Created user {username} with IP {ip_address}")
        return jsonify({'message': 'User created successfully', 'user': user.to_dict()}), 201

    except Exception as e:
        logger.error(f"Error creating user: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    """Update user via API."""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()

        # Update protocols
        old_protocols = {
            'ssh': user.enable_ssh,
            'socks5': user.enable_socks5,
            'http': user.enable_http,
            'pptp': user.enable_pptp
        }

        user.enable_ssh = data.get('enable_ssh', user.enable_ssh)
        user.enable_socks5 = data.get('enable_socks5', user.enable_socks5)
        user.enable_http = data.get('enable_http', user.enable_http)
        user.enable_pptp = data.get('enable_pptp', user.enable_pptp)
        user.status = data.get('status', user.status)

        db.session.commit()

        # Update system if protocols changed
        try:
            if user.enable_pptp and not old_protocols['pptp']:
                add_pptp_user(user.username, user.password, user.ip_address)
                reload_pptpd()
            elif not user.enable_pptp and old_protocols['pptp']:
                remove_pptp_user(user.username)
                reload_pptpd()

            # Restart proxies
            stop_user_proxies(user.id)
            if user.status == 'active':
                start_user_proxies(user)

        except Exception as e:
            logger.error(f"Failed to update system rules for user {user.username}: {e}")

        log_admin_action('user_updated', 'user', user.id, f'Updated user {user.username}')
        logger.info(f"Updated user {user.username}")
        return jsonify({'message': 'User updated successfully', 'user': user.to_dict()})

    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    """Delete user via API."""
    try:
        user = User.query.get_or_404(user_id)

        # Remove system rules
        try:
            remove_ip_from_interface(user.ip_address)
            remove_nat_rule(user.ip_address)
            delete_linux_user(user.username)
            stop_user_proxies(user.id)

            if user.enable_pptp:
                remove_pptp_user(user.username)
                reload_pptpd()

        except Exception as e:
            logger.error(f"Failed to remove system rules for user {user.username}: {e}")

        # Mark as deleted
        user.status = 'deleted'
        db.session.commit()

        log_admin_action('user_deleted', 'user', user.id, f'Deleted user {user.username}')
        logger.info(f"Deleted user {user.username}")
        return jsonify({'message': 'User deleted successfully'})

    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/config', methods=['GET'])
@login_required
def get_system_config_api():
    """Get system configuration."""
    return jsonify(get_system_config())

@app.route('/api/system/config', methods=['PUT'])
@login_required
def update_system_config_api():
    """Update system configuration."""
    try:
        data = request.get_json()

        update_system_config(
            subnet_range=data.get('subnet_range'),
            network_interface=data.get('network_interface'),
            proxy_base_port=data.get('proxy_base_port')
        )

        log_admin_action('config_updated', 'system', None, f'Updated system config: {data}')
        logger.info("Updated system configuration")
        return jsonify({'message': 'System configuration updated successfully'})

    except Exception as e:
        logger.error(f"Error updating system config: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/users/<int:user_id>/status', methods=['GET'])
@login_required
def get_user_status(user_id):
    """Get real-time status for user."""
    try:
        user = User.query.get_or_404(user_id)

        proxy_status = get_user_proxy_status(user)

        return jsonify({
            'user_id': user.id,
            'username': user.username,
            'proxy_status': proxy_status
        })

    except Exception as e:
        logger.error(f"Error getting user status {user_id}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/available-ips', methods=['GET'])
@login_required
def get_available_ips_api():
    """Get list of available IPs."""
    try:
        available_ips = get_available_ips()
        return jsonify({'available_ips': available_ips})
    except Exception as e:
        logger.error(f"Error getting available IPs: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/interfaces', methods=['GET'])
@login_required
def get_network_interfaces_api():
    """Get network interfaces information."""
    try:
        interfaces = get_network_interfaces()
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/assigned-ips', methods=['GET'])
@login_required
def get_assigned_ips_api():
    """Get all assigned IPs."""
    try:
        assigned_ips = get_assigned_ips()
        return jsonify({'assigned_ips': assigned_ips})
    except Exception as e:
        logger.error(f"Error getting assigned IPs: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/ips', methods=['POST'])
@login_required
def add_system_ip_api():
    """Add IP address to system interface."""
    try:
        data = request.get_json()
        ip = data.get('ip', '').strip()
        interface = data.get('interface', '')

        if not validate_ip(ip):
            return jsonify({'error': 'Invalid IP address format'}), 400

        add_system_ip(ip, interface or None)

        log_admin_action('ip_added', 'system', None, f'Added system IP {ip} to interface {interface or "default"}')
        logger.info(f"Added system IP {ip}")
        return jsonify({'message': f'IP {ip} added successfully'})

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error adding system IP: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/ips/<ip>', methods=['DELETE'])
@login_required
def remove_system_ip_api(ip):
    """Remove IP address from system interface."""
    try:
        if not validate_ip(ip):
            return jsonify({'error': 'Invalid IP address format'}), 400

        remove_system_ip(ip)

        log_admin_action('ip_removed', 'system', None, f'Removed system IP {ip}')
        logger.info(f"Removed system IP {ip}")
        return jsonify({'message': f'IP {ip} removed successfully'})

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error removing system IP {ip}: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/stats', methods=['GET'])
@login_required
def get_system_stats_api():
    """Get real-time system statistics."""
    try:
        stats = get_system_stats()
        return jsonify({'stats': stats})
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/traffic', methods=['GET'])
@login_required
def get_network_traffic_api():
    """Get network traffic statistics."""
    try:
        traffic = get_network_traffic()
        return jsonify({'traffic': traffic})
    except Exception as e:
        logger.error(f"Error getting network traffic: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/user/<int:user_id>')
@login_required
def user_detail(user_id):
    """User detail page."""
    user = User.query.get_or_404(user_id)
    proxy_ports = get_user_proxy_ports(user.id)
    proxy_status = get_user_proxy_status(user)

    return render_template('user_detail.html',
                         user=user,
                         proxy_ports=proxy_ports,
                         proxy_status=proxy_status)

@app.route('/audit-logs')
@login_required
def audit_logs():
    """Audit logs page."""
    return render_template('audit_logs.html')

@app.route('/system-health')
@login_required
def system_health():
    """System health dashboard."""
    return render_template('system_health.html')

@app.route('/bulk-operations')
@login_required
def bulk_operations():
    """Bulk operations page."""
    return render_template('bulk_operations.html')

@app.route('/api/audit-logs', methods=['GET'])
@login_required
def get_audit_logs():
    """Get audit logs via API."""
    try:
        # Pagination parameters
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        offset = (page - 1) * per_page

        # Filtering parameters
        action_filter = request.args.get('action')
        resource_type_filter = request.args.get('resource_type')
        admin_filter = request.args.get('admin')

        query = AuditLog.query

        if action_filter:
            query = query.filter(AuditLog.action == action_filter)
        if resource_type_filter:
            query = query.filter(AuditLog.resource_type == resource_type_filter)
        if admin_filter:
            query = query.filter(AuditLog.admin_username == admin_filter)

        # Order by timestamp descending
        query = query.order_by(AuditLog.timestamp.desc())

        # Get total count for pagination
        total = query.count()

        # Apply pagination
        logs = query.offset(offset).limit(per_page).all()

        return jsonify({
            'logs': [log.to_dict() for log in logs],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        })

    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/health', methods=['GET'])
@login_required
def get_system_health():
    """Get current system health metrics."""
    try:
        import psutil
        import subprocess

        # Get system metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Get network stats (simple approximation)
        net_io = psutil.net_io_counters()
        network_rx = net_io.bytes_recv
        network_tx = net_io.bytes_sent

        # Get user and container stats
        total_users = User.query.count()
        active_users = User.query.filter_by(status='active').count()

        # Count running containers (simplified)
        try:
            result = subprocess.run(['docker', 'ps', '-q'], capture_output=True, text=True)
            running_containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        except:
            running_containers = 0

        # Create health record
        health = SystemHealth(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_percent=disk.percent,
            network_rx=network_rx,
            network_tx=network_tx,
            active_users=active_users,
            total_users=total_users,
            running_containers=running_containers
        )

        db.session.add(health)
        db.session.commit()

        return jsonify({
            'current': health.to_dict(),
            'system_info': {
                'cpu_count': psutil.cpu_count(),
                'memory_total': memory.total,
                'disk_total': disk.total
            }
        })

    except Exception as e:
        logger.error(f"Error getting system health: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/system/health/history', methods=['GET'])
@login_required
def get_system_health_history():
    """Get system health history."""
    try:
        hours = int(request.args.get('hours', 24))
        from datetime import datetime, timedelta

        since = datetime.utcnow() - timedelta(hours=hours)

        health_records = SystemHealth.query.filter(
            SystemHealth.timestamp >= since
        ).order_by(SystemHealth.timestamp.desc()).all()

        return jsonify({
            'history': [record.to_dict() for record in health_records]
        })

    except Exception as e:
        logger.error(f"Error getting health history: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/users/bulk', methods=['POST'])
@login_required
def bulk_create_users():
    """Bulk create users from CSV data."""
    try:
        import csv
        import io

        csv_data = request.form.get('csv_data')
        if not csv_data:
            return jsonify({'error': 'No CSV data provided'}), 400

        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        results = {'created': [], 'errors': []}

        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 to account for header
            try:
                username = row.get('username', '').strip()
                password = row.get('password', '')
                ip_address = row.get('ip_address', '').strip()

                if not username or not password or not ip_address:
                    results['errors'].append(f'Row {row_num}: Missing required fields')
                    continue

                # Basic validation
                if not validate_username(username):
                    results['errors'].append(f'Row {row_num}: Invalid username format')
                    continue

                if not validate_password(password):
                    results['errors'].append(f'Row {row_num}: Password too short')
                    continue

                if not validate_ip(ip_address):
                    results['errors'].append(f'Row {row_num}: Invalid IP address')
                    continue

                # Check for duplicates
                if User.query.filter_by(username=username).first():
                    results['errors'].append(f'Row {row_num}: Username {username} already exists')
                    continue

                if User.query.filter_by(ip_address=ip_address).first():
                    results['errors'].append(f'Row {row_num}: IP {ip_address} already assigned')
                    continue

                # Create user
                user = User(
                    username=username,
                    password=password,
                    ip_address=ip_address,
                    enable_ssh=row.get('enable_ssh', 'true').lower() == 'true',
                    enable_socks5=row.get('enable_socks5', 'false').lower() == 'true',
                    enable_http=row.get('enable_http', 'false').lower() == 'true',
                    enable_pptp=row.get('enable_pptp', 'false').lower() == 'true'
                )

                db.session.add(user)
                db.session.commit()

                # Apply system rules
                try:
                    assign_ip_to_interface(ip_address)
                    setup_nat_rule(ip_address)
                    create_linux_user(username, password)

                    if user.enable_pptp:
                        add_pptp_user(username, password, ip_address)
                        reload_pptpd()

                    start_user_proxies(user)

                except Exception as e:
                    logger.error(f"Failed to apply system rules for user {username}: {e}")
                    db.session.delete(user)
                    db.session.commit()
                    results['errors'].append(f'Row {row_num}: Failed to create user {username}: {str(e)}')
                    continue

                results['created'].append({
                    'username': username,
                    'ip_address': ip_address,
                    'id': user.id
                })

                log_admin_action('user_created_bulk', 'user', user.id, f'Bulk created user {username}')

            except Exception as e:
                results['errors'].append(f'Row {row_num}: {str(e)}')

        return jsonify(results)

    except Exception as e:
        logger.error(f"Error in bulk user creation: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def log_admin_action(action, resource_type, resource_id=None, details=None):
    """Log admin action for audit trail."""
    try:
        admin = Admin.query.get(session.get('admin_id'))
        if not admin:
            return

        audit_log = AuditLog(
            admin_username=admin.username,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id else None,
            details=str(details) if details else None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500]
        )

        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log admin action: {e}")

def create_initial_admin():
    """Create initial admin user if none exists."""
    if Admin.query.count() == 0:
        admin = Admin(username='admin')
        admin.set_password('admin123')  # Change this in production!
        db.session.add(admin)
        db.session.commit()
        logger.info("Created initial admin user")

if __name__ == '__main__':
    import sys
    port = 3030  # Default to 3030
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])

    with app.app_context():
        db.create_all()
        create_initial_admin()
        apply_all_system_rules()

    app.run(host='0.0.0.0', port=port, debug=False)  # Set debug=False for production
