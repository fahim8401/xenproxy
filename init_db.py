#!/usr/bin/env python3
"""
Database initialization script for XenProxy
This script ensures the database is properly initialized with default settings
"""
import os
import sys
from flask import Flask
from models import db, SystemConfig, Admin, LxcTemplate
from auth import create_admin
from migrate_password import migrate

def init_database():
    """Initialize the database with default configuration and admin user."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_secret')
    # SQLite database configuration
    database_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'ip_gateway.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f'sqlite:///{database_path}')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # SQLite specific configuration
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_timeout': 20,
        'pool_recycle': 300,
        'pool_pre_ping': True,
        'connect_args': {
            'timeout': 20,
            'check_same_thread': False
        }
    }
    
    db.init_app(app)
    
    with app.app_context():
        # Ensure instance directory exists
        os.makedirs(os.path.dirname(database_path), exist_ok=True)
        
        print("Creating database tables...")
        db.create_all()
        
        # Run migrations
        print("Running database migrations...")
        migrate()
        
        # Create default SystemConfig if none exists
        if not SystemConfig.query.first():
            print("Creating default SystemConfig...")
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
            print("✓ Default SystemConfig created")
        else:
            print("✓ SystemConfig already exists")
        
        # Create default LXC template if none exists
        if not LxcTemplate.query.first():
            print("Creating default LXC template...")
            try:
                # Read the default template from file
                template_path = os.path.join(os.path.dirname(__file__), 'lxc-templates', 'alpine-config')
                with open(template_path, 'r') as f:
                    default_config = f.read()
                
                default_template = LxcTemplate(
                    name='Alpine Linux',
                    description='Default Alpine Linux LXC template with basic networking configuration',
                    config_content=default_config,
                    is_default=True
                )
                db.session.add(default_template)
                db.session.commit()
                print("✓ Default LXC template created")
            except Exception as e:
                print(f"✗ Failed to create default template: {e}")
        else:
            print("✓ LXC templates already exist")
        
        # Create default admin if none exists
        if not Admin.query.first():
            print("Creating default admin user...")
            admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
            
            try:
                create_admin(admin_username, admin_password)
                print(f"✓ Default admin user '{admin_username}' created")
                print(f"  Username: {admin_username}")
                print(f"  Password: {admin_password}")
                print("  ⚠️  Please change the default password after first login!")
            except Exception as e:
                print(f"✗ Failed to create admin user: {e}")
        else:
            print("✓ Admin user already exists")
        
        print("\nDatabase initialization completed successfully!")
        
        # Display current configuration
        config = SystemConfig.query.first()
        if config:
            print(f"\nCurrent SystemConfig:")
            print(f"  Bridge name: {config.bridge_name}")
            print(f"  Subnet range: {config.subnet_range}")
            print(f"  Network interface: {config.network_interface}")
            print(f"  Max containers: {config.max_containers}")

if __name__ == '__main__':
    init_database()