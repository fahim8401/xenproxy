from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy import func
from datetime import datetime

db = SQLAlchemy()

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    last_login = db.Column(db.DateTime)

class LxcContainer(db.Model):
    __tablename__ = 'lxc_containers'
    id = db.Column(db.Integer, primary_key=True)
    container_name = db.Column(db.String(64), unique=True, nullable=False)
    username = db.Column(db.String(32), nullable=False)
    ip_address = db.Column(INET, unique=True, nullable=False)
    status = db.Column(db.String(16), nullable=False, default='creating')
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())
    cpu_limit = db.Column(db.Float, nullable=False)
    memory_limit = db.Column(db.Integer, nullable=False)
    disk_limit = db.Column(db.Integer, nullable=False)
    enable_ssh = db.Column(db.Boolean, default=True)
    enable_socks5 = db.Column(db.Boolean, default=False)
    enable_http = db.Column(db.Boolean, default=False)
    enable_wireguard = db.Column(db.Boolean, default=False)
    ssh_public_key = db.Column(db.Text)
    bandwidth_in = db.Column(db.BigInteger, default=0)
    bandwidth_out = db.Column(db.BigInteger, default=0)
    last_health_check = db.Column(db.DateTime)
    health_status = db.Column(db.String(16), default='healthy')

class SystemConfig(db.Model):
    __tablename__ = 'system_config'
    id = db.Column(db.Integer, primary_key=True, default=1)
    subnet_range = db.Column(db.String(32), nullable=False)
    network_interface = db.Column(db.String(32), nullable=False)
    bridge_name = db.Column(db.String(32), nullable=False)
    max_containers = db.Column(db.Integer, default=254)
    auto_assign_ips = db.Column(db.Boolean, default=True)
    default_cpu_limit = db.Column(db.Float, default=0.1)
    default_memory_limit = db.Column(db.Integer, default=64*1024*1024)  # 64MB

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)
    action = db.Column(db.String(64), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(INET)
    timestamp = db.Column(db.DateTime, default=func.now())

    admin = db.relationship('Admin', backref=db.backref('audit_logs', lazy=True))
