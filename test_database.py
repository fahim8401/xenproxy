#!/usr/bin/env python3
"""
Test script to verify SQLite database operations work correctly
"""
import os
import sys
from flask import Flask
from models import db, SystemConfig, Admin, LxcContainer, AuditLog
from auth import create_admin

def test_database():
    """Test all database operations."""
    app = Flask(__name__)
    
    # SQLite database configuration
    database_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'test_db.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{database_path}'
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
        print("🧪 Testing SQLite Database Operations\n")
        
        # Ensure test directory exists
        os.makedirs(os.path.dirname(database_path), exist_ok=True)
        
        # Remove test database if exists
        if os.path.exists(database_path):
            os.remove(database_path)
            print("✓ Cleaned up previous test database")
        
        # Test 1: Create tables
        print("1️⃣  Testing table creation...")
        try:
            db.create_all()
            print("✅ All tables created successfully")
        except Exception as e:
            print(f"❌ Table creation failed: {e}")
            return False
        
        # Test 2: Create SystemConfig
        print("\n2️⃣  Testing SystemConfig creation...")
        try:
            config = SystemConfig(
                subnet_range='172.16.100.0/24',
                network_interface='eth0',
                bridge_name='xenproxy0',
                max_containers=254,
                auto_assign_ips=True,
                default_cpu_limit=0.1,
                default_memory_limit=64*1024*1024
            )
            db.session.add(config)
            db.session.commit()
            print("✅ SystemConfig created successfully")
        except Exception as e:
            print(f"❌ SystemConfig creation failed: {e}")
            return False
        
        # Test 3: Create Admin user
        print("\n3️⃣  Testing Admin creation...")
        try:
            admin = create_admin("testadmin", "testpassword123")
            print(f"✅ Admin user created: {admin.username}")
        except Exception as e:
            print(f"❌ Admin creation failed: {e}")
            return False
        
        # Test 4: Create Container
        print("\n4️⃣  Testing Container creation...")
        try:
            container = LxcContainer(
                container_name='test-container',
                username='testuser',
                ip_address='172.16.100.10',
                cpu_limit=0.5,
                memory_limit=128*1024*1024,
                disk_limit=1*1024*1024*1024,
                enable_ssh=True,
                enable_socks5=False,
                enable_http=False
            )
            db.session.add(container)
            db.session.commit()
            print(f"✅ Container created: {container.container_name}")
        except Exception as e:
            print(f"❌ Container creation failed: {e}")
            return False
        
        # Test 5: Create AuditLog
        print("\n5️⃣  Testing AuditLog creation...")
        try:
            audit_log = AuditLog(
                admin_id=admin.id,
                action='test_action',
                details='Test audit log entry',
                ip_address='127.0.0.1'
            )
            db.session.add(audit_log)
            db.session.commit()
            print("✅ AuditLog created successfully")
        except Exception as e:
            print(f"❌ AuditLog creation failed: {e}")
            return False
        
        # Test 6: Query operations
        print("\n6️⃣  Testing query operations...")
        try:
            # Test SystemConfig query
            config_count = SystemConfig.query.count()
            print(f"   SystemConfig records: {config_count}")
            
            # Test Admin query
            admin_count = Admin.query.count()
            print(f"   Admin records: {admin_count}")
            
            # Test Container query
            container_count = LxcContainer.query.count()
            print(f"   Container records: {container_count}")
            
            # Test AuditLog query
            log_count = AuditLog.query.count()
            print(f"   AuditLog records: {log_count}")
            
            print("✅ All queries executed successfully")
        except Exception as e:
            print(f"❌ Query operations failed: {e}")
            return False
        
        # Test 7: Relationship queries
        print("\n7️⃣  Testing relationship queries...")
        try:
            admin_with_logs = Admin.query.first()
            logs = admin_with_logs.audit_logs
            print(f"   Admin has {len(logs)} audit logs")
            
            log = AuditLog.query.first()
            log_admin = log.admin
            print(f"   AuditLog belongs to admin: {log_admin.username}")
            
            print("✅ Relationship queries work correctly")
        except Exception as e:
            print(f"❌ Relationship queries failed: {e}")
            return False
        
        # Test 8: Update operations
        print("\n8️⃣  Testing update operations...")
        try:
            container = LxcContainer.query.first()
            container.status = 'running'
            db.session.commit()
            
            updated_container = LxcContainer.query.first()
            assert updated_container.status == 'running'
            print("✅ Update operations work correctly")
        except Exception as e:
            print(f"❌ Update operations failed: {e}")
            return False
        
        print(f"\n🎉 All database tests passed!")
        print(f"📄 Test database created at: {database_path}")
        print("🧹 You can delete the test database file if desired")
        
        return True

if __name__ == '__main__':
    success = test_database()
    sys.exit(0 if success else 1)