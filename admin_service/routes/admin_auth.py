from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from admin_service.models import Admin
from shared.db import db

admin_auth_bp = Blueprint('admin_auth', __name__)

@admin_auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    admin = Admin.query.filter_by(username=data['username']).first()
    
    if not admin or not admin.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not admin.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Update last login
    admin.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(
        identity=str(admin.id),
        additional_claims={'role': admin.role}
    )
    
    return jsonify({
        'access_token': access_token,
        'admin': admin.to_dict()
    }), 200

@admin_auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    current_admin_id = get_jwt_identity()
    admin = Admin.query.get(current_admin_id)
    
    if not admin:
        return jsonify({'error': 'Admin not found'}), 404
    
    return jsonify({
        'message': 'Token is valid',
        'admin': admin.to_dict()
    }), 200 