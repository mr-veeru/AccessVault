from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from shared.models import User
from shared.db import db
from shared.utils.validators import validate_email, validate_password, validate_username
from shared.logger import setup_logging
from shared.utils.rate_limiter import auth_rate_limit, password_change_rate_limit

user_auth_bp = Blueprint('user_auth', __name__)
user_auth_logger = setup_logging(__name__)

@user_auth_bp.route('/register', methods=['POST'])
@auth_rate_limit
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password', 'name']
    if not all(field in data for field in required_fields):
        user_auth_logger.warning("User registration failed: Missing required fields.")
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Convert and validate email and username
    email = data['email'].lower()
    username = data['username'].lower()
    
    if not validate_email(email):
        user_auth_logger.warning(f"User registration failed for {email}: Invalid email format.")
        return jsonify({'error': 'Invalid email format'}), 400
    
    if not validate_username(username):
        user_auth_logger.warning(f"User registration failed for {username}: Invalid username format.")
        return jsonify({'error': 'Username can only contain lowercase letters, numbers, and underscores'}), 400
    
    password_validation_result = validate_password(data['password'])
    if password_validation_result is not True:
        user_auth_logger.warning(f"User registration failed for {username} ({email}): {password_validation_result}")
        return jsonify({'error': password_validation_result}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=username).first():
        user_auth_logger.warning(f"User registration failed: Username '{username}' already exists.")
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        user_auth_logger.warning(f"User registration failed: Email '{email}' already exists.")
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create new user
    user = User(
        username=username,
        email=email,
        name=data['name']
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    user_auth_logger.info(f"User '{username}' ({email}) registered successfully.")
    return jsonify({
        'message': 'User registered successfully',
        'user': user.to_dict()
    }), 201

@user_auth_bp.route('/login', methods=['POST'])
@auth_rate_limit
def login():
    data = request.get_json()
    
    if not data or (not data.get('username_or_email') and not data.get('username') and not data.get('email')) or not data.get('password'):
        user_auth_logger.warning("User login failed: Missing username/email or password.")
        return jsonify({'error': 'Missing username/email or password'}), 400
    
    login_identifier = (data.get('username_or_email') or data.get('username') or data.get('email')).lower()

    if not login_identifier:
        user_auth_logger.warning("User login failed: Missing username/email.")
        return jsonify({'error': 'Missing username/email'}), 400

    # Try to find user by username or email
    user = User.query.filter_by(username=login_identifier).first()
    if not user:
        user = User.query.filter_by(email=login_identifier).first()
    
    if not user or not user.check_password(data['password']):
        user_auth_logger.warning(f"User login failed for '{login_identifier}': Invalid credentials.")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        user_auth_logger.warning(f"User login failed for '{login_identifier}': Account is deactivated.")
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={'role': user.role}
    )
    user_auth_logger.info(f"User '{user.username}' ({user.email}) logged in successfully.")
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

@user_auth_bp.route('/change-password', methods=['PUT'])
@jwt_required()
@password_change_rate_limit
def change_password():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({'error': 'Missing old or new password'}), 400

    # Validate new password against strength rules
    password_validation_result = validate_password(new_password)
    if password_validation_result is not True:
        return jsonify({'error': password_validation_result}), 400

    if not user.check_password(old_password):
        return jsonify({'error': 'Invalid old password'}), 401

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password updated successfully'}), 200 

@user_auth_bp.route('/deactivate', methods=['POST'])
@jwt_required()
def deactivate_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Deactivate the user account
    user.is_active = False
    db.session.commit()

    user_auth_logger.info(f"User '{user.username}' ({user.email}) deactivated their account.")
    return jsonify({'message': 'Account deactivated successfully'}), 200 