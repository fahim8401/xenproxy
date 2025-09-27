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
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://postgres:postgres@localhost/ipgw')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True

db.init_app(app)
csrf = CSRFProtect(app)
# Limiter removed for compatibility

@app.before_first_request
def setup():
    db.create_all()
    apply_all_system_rules()
    reconcile_db_with_lxc()
    start_monitoring_thread()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = authenticate_admin(username, password)
        if admin:
            session['admin_id'] = admin.id
            admin.last_login = datetime.utcnow()
            db.session.commit()
            AuditLog(admin_id=admin.id, action='login', details='Admin logged in', ip_address=request.remote_addr).save()
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
    return render_template('dashboard.html', containers=containers, host_stats=host_stats)

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
    AuditLog(admin_id=session['admin_id'], action='create_container', details=f'Created {username}', ip_address=request.remote_addr).save()
    flash('Container created', 'success')
    return redirect(url_for('containers'))

@app.route('/containers/<name>/delete', methods=['POST'])
@login_required
def delete_container_route(name):
    delete_container(name)
    AuditLog(admin_id=session['admin_id'], action='delete_container', details=f'Deleted {name}', ip_address=request.remote_addr).save()
    flash('Container deleted', 'success')
    return redirect(url_for('containers'))

@app.route('/containers/<name>/start', methods=['POST'])
@login_required
def start_container_route(name):
    start_container(name)
    AuditLog(admin_id=session['admin_id'], action='start_container', details=f'Started {name}', ip_address=request.remote_addr).save()
    flash('Container started', 'success')
    return redirect(url_for('containers'))

@app.route('/containers/<name>/stop', methods=['POST'])
@login_required
def stop_container_route(name):
    stop_container(name)
    AuditLog(admin_id=session['admin_id'], action='stop_container', details=f'Stopped {name}', ip_address=request.remote_addr).save()
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
