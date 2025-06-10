from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from user_service.models import User
from shared.db import db
from shared.utils.auth_utils import admin_required
from shared.utils.validators import validate_email, validate_password, validate_username
from shared.logger import setup_logging

user_management = Blueprint('user_management', __name__)
user_management_logger = setup_logging(__name__)

@user_management.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([{
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'is_active': user.is_active,
        'created_at': user.created_at.isoformat() if user.created_at else None
    } for user in users])

@user_management.route('/users', methods=['POST'])
@jwt_required()
@admin_required
def create_user():
    data = request.get_json()

    required_fields = ['username', 'email', 'password', 'name']
    if not all(field in data for field in required_fields):
        user_management_logger.warning("User creation failed: Missing required fields.")
        return jsonify({'error': 'Missing required fields'}), 400

    email = data['email'].lower()
    username = data['username'].lower()
    password = data['password']
    name = data['name']

    if not validate_email(email):
        user_management_logger.warning(f"User creation failed for {email}: Invalid email format.")
        return jsonify({'error': 'Invalid email format'}), 400

    if not validate_username(username):
        user_management_logger.warning(f"User creation failed for {username}: Invalid username format.")
        return jsonify({'error': 'Username can only contain lowercase letters, numbers, and underscores'}), 400

    password_validation_result = validate_password(password)
    if password_validation_result is not True:
        user_management_logger.warning(f"User creation failed for {username} ({email}): {password_validation_result}")
        return jsonify({'error': password_validation_result}), 400

    if User.query.filter_by(username=username).first():
        user_management_logger.warning(f"User creation failed: Username '{username}' already exists.")
        return jsonify({'error': 'Username already exists'}), 400

    if User.query.filter_by(email=email).first():
        user_management_logger.warning(f"User creation failed: Email '{email}' already exists.")
        return jsonify({'error': 'Email already exists'}), 400

    user = User(
        username=username,
        email=email,
        name=name,
        is_active=True  # New users are active by default
    )
    user.set_password(password)

    db.session.add(user)
    db.session.commit()

    user_management_logger.info(f"User '{username}' ({email}) created successfully by admin.")
    return jsonify({
        'message': 'User created successfully',
        'user': user.to_dict()
    }), 201

@user_management.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    current_admin_id = get_jwt_identity()
    if user.id == current_admin_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500 