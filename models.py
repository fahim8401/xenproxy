from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Admin(db.Model):
    """Admin user model for authentication."""
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        """Hash and set the admin password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify the admin password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<Admin {self.username}>'

class User(db.Model):
    """User model for IP gateway management."""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)  # Stored in plaintext for system/PPTP
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    enable_ssh = db.Column(db.Boolean, default=True)
    enable_socks5 = db.Column(db.Boolean, default=False)
    enable_http = db.Column(db.Boolean, default=False)
    enable_pptp = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')  # active, disabled, deleted

    def __repr__(self):
        return f'<User {self.username} - {self.ip_address}>'

    def to_dict(self):
        """Convert user object to dictionary for API responses."""
        return {
            'id': self.id,
            'username': self.username,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'enable_ssh': self.enable_ssh,
            'enable_socks5': self.enable_socks5,
            'enable_http': self.enable_http,
            'enable_pptp': self.enable_pptp,
            'status': self.status
        }

class AuditLog(db.Model):
    """Audit log model for tracking admin actions."""
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    admin_username = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # e.g., 'user_created', 'user_deleted', 'config_updated'
    resource_type = db.Column(db.String(50), nullable=False)  # e.g., 'user', 'system', 'admin'
    resource_id = db.Column(db.String(100))  # ID of the affected resource
    details = db.Column(db.Text)  # JSON string with additional details
    ip_address = db.Column(db.String(45))  # IPv4/IPv6 address
    user_agent = db.Column(db.String(500))

    def __repr__(self):
        return f'<AuditLog {self.admin_username} {self.action} {self.timestamp}>'

    def to_dict(self):
        """Convert audit log to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'admin_username': self.admin_username,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent
        }

class SystemHealth(db.Model):
    """System health monitoring model."""
    __tablename__ = 'system_health'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_percent = db.Column(db.Float)
    memory_percent = db.Column(db.Float)
    disk_percent = db.Column(db.Float)
    network_rx = db.Column(db.BigInteger)  # bytes received
    network_tx = db.Column(db.BigInteger)  # bytes transmitted
    active_users = db.Column(db.Integer)
    total_users = db.Column(db.Integer)
    running_containers = db.Column(db.Integer)

    def to_dict(self):
        """Convert system health to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'disk_percent': self.disk_percent,
            'network_rx': self.network_rx,
            'network_tx': self.network_tx,
            'active_users': self.active_users,
            'total_users': self.total_users,
            'running_containers': self.running_containers
        }
