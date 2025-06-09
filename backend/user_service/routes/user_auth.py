from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from user_service.models import User
from shared.db import db
from shared.utils.validators import validate_email, validate_password

user_auth_bp = Blueprint('user_auth', __name__)

@user_auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password', 'name']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Validate email and password
    if not validate_email(data['email']):
        return jsonify({'error': 'Invalid email format'}), 400
    
    password_validation_result = validate_password(data['password'])
    if password_validation_result is not True:
        return jsonify({'error': password_validation_result}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create new user
    user = User(
        username=data['username'],
        email=data['email'],
        name=data['name']
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict()
    }), 201

@user_auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or (not data.get('username_or_email') and not data.get('username') and not data.get('email')) or not data.get('password'):
        return jsonify({'error': 'Missing username/email or password'}), 400
    
    user = None
    login_identifier = data.get('username_or_email') or data.get('username') or data.get('email')

    if not login_identifier:
        return jsonify({'error': 'Missing username/email'}), 400

    # Try to find user by username or email
    user = User.query.filter_by(username=login_identifier).first()
    if not user:
        user = User.query.filter_by(email=login_identifier).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={'role': user.role}
    )
    
    return jsonify({
        'access_token': access_token,
        'user': user.to_dict()
    }), 200

@user_auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify({
        'message': 'Token is valid',
        'user': user.to_dict()
    }), 200 