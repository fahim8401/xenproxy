import re
from flask import session, redirect, url_for, request, flash
from functools import wraps
from argon2 import PasswordHasher
from models import Admin, db

ph = PasswordHasher()

USERNAME_REGEX = re.compile(r'^[a-z][a-z0-9_]{2,30}$')

def hash_password(password):
    return ph.hash(password)

def verify_password(hash, password):
    try:
        return ph.verify(hash, password)
    except Exception:
        return False

def validate_username(username):
    return bool(USERNAME_REGEX.match(username))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            # Store the intended destination in the session instead of URL parameter
            session['next_url'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def authenticate_admin(username, password):
    admin = Admin.query.filter_by(username=username).first()
    if not admin:
        return None
    if verify_password(admin.password_hash, password):
        return admin
    return None

def create_admin(username, password, must_change_password=False):
    if not validate_username(username):
        raise ValueError("Invalid username format")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    admin = Admin(username=username, password_hash=hash_password(password), must_change_password=must_change_password)
    db.session.add(admin)
    db.session.commit()
    return admin
