#!/usr/bin/env python3
"""
Migration script to add password column to LxcContainer table.
Run this after updating the models.py file.
"""

import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from models import db

def migrate():
    """Add password column to lxc_containers table if it doesn't exist."""
    app = Flask(__name__)
    database_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'ip_gateway.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    with app.app_context():
        # Check if password column exists
        inspector = db.inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('lxc_containers')]

        if 'password' not in columns:
            print("Adding password column to lxc_containers table...")
            # For SQLite, we need to recreate the table
            # First, backup existing data
            result = db.session.execute(db.text("SELECT * FROM lxc_containers")).fetchall()
            columns_data = [dict(row) for row in result]

            # Drop and recreate table with new schema
            db.session.execute(db.text("DROP TABLE lxc_containers"))
            db.create_all()

            # Restore data
            for row in columns_data:
                row['password'] = None  # Add empty password
                db.session.execute(
                    db.text("""
                        INSERT INTO lxc_containers
                        (id, container_name, username, ip_address, status, created_at, updated_at,
                         cpu_limit, memory_limit, disk_limit, enable_ssh, enable_socks5, enable_http,
                         enable_wireguard, ssh_public_key, password, bandwidth_in, bandwidth_out,
                         last_health_check, health_status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """),
                    (row['id'], row['container_name'], row['username'], row['ip_address'], row['status'],
                     row['created_at'], row['updated_at'], row['cpu_limit'], row['memory_limit'], row['disk_limit'],
                     row['enable_ssh'], row['enable_socks5'], row['enable_http'], row['enable_wireguard'],
                     row['ssh_public_key'], row['password'], row['bandwidth_in'], row['bandwidth_out'],
                     row['last_health_check'], row['health_status'])
                )

            db.session.commit()
            print("Migration completed successfully!")
        else:
            print("Password column already exists, no migration needed.")

if __name__ == '__main__':
    migrate()