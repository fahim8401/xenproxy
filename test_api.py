import pytest
from app import app, db
from models import Admin

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            if not Admin.query.filter_by(username='admin').first():
                admin = Admin(username='admin')
                admin.set_password('admin1234')
                db.session.add(admin)
                db.session.commit()
        yield client

def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)

def test_login_logout(client):
    rv = login(client, 'admin', 'admin1234')
    assert b'Dashboard' in rv.data
    rv = client.get('/logout', follow_redirects=True)
    assert b'Login' in rv.data

def test_dashboard_requires_login(client):
    rv = client.get('/', follow_redirects=True)
    assert b'Login' in rv.data

def test_api_host_stats(client):
    login(client, 'admin', 'admin1234')
    rv = client.get('/api/host_stats')
    assert rv.status_code == 200
    assert b'cpu' in rv.data or b'memory' in rv.data
