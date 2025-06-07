from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt = get_jwt()
        if jwt.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def user_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        jwt = get_jwt()
        if jwt.get('role') not in ['admin', 'user']:
            return jsonify({'error': 'User access required'}), 403
        return fn(*args, **kwargs)
    return wrapper

def get_current_user_role():
    """Get the role of the currently authenticated user."""
    jwt = get_jwt()
    return jwt.get('role') 