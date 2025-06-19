from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from shared.models import User
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
    # Only return regular users, not admins
    users = User.query.filter_by(role='user').all()
    user_management_logger.info("Admin fetched all regular users.")
    return jsonify([user.to_dict() for user in users]), 200

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
        role='user',  # Always create as regular user
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

@user_management.route('/users/<int:user_id>/role', methods=['PUT'])
@jwt_required()
@admin_required
def change_user_role(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    current_admin_id = get_jwt_identity()

    # Prevent admin from changing their own role
    if user.id == current_admin_id:
        user_management_logger.warning(f"Admin {current_admin_id} attempted to change their own role.")
        return jsonify({'error': 'Cannot change your own role'}), 400

    if 'role' not in data:
        return jsonify({'error': 'Role is required'}), 400

    new_role = data['role'].lower()
    if new_role not in ['user', 'admin']:
        user_management_logger.warning(f"Admin {current_admin_id} attempted to set invalid role '{new_role}' for user {user_id}.")
        return jsonify({'error': 'Invalid role. Must be either "user" or "admin"'}), 400

    user.role = new_role
    db.session.commit()
    
    user_management_logger.info(f"Admin {current_admin_id} changed role of user {user_id} to {new_role}.")
    return jsonify({
        'message': f'User role updated to {new_role}',
        'user': user.to_dict()
    }), 200

@user_management.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    current_admin_id = get_jwt_identity()

    # Prevent admin from editing their own account via user management
    if user.id == current_admin_id:
        user_management_logger.warning(f"Admin {current_admin_id} attempted to edit their own account via user management.")
        return jsonify({'error': 'Cannot edit your own account via this interface. Use the profile page instead.'}), 400

    if 'role' in data:
        new_role = data['role'].lower()
        if new_role not in ['user', 'admin']:
            user_management_logger.warning(f"Admin {current_admin_id} attempted to set invalid role '{new_role}' for user {user_id}.")
            return jsonify({'error': 'Invalid role. Must be either "user" or "admin"'}), 400
        user.role = new_role
        user_management_logger.info(f"Admin {current_admin_id} updated user {user_id} role to {new_role}.")

    if 'username' in data:
        new_username = data['username'].lower()
        if not validate_username(new_username):
            user_management_logger.warning(f"Admin {current_admin_id} failed to update user {user_id}: Invalid username format for {new_username}.")
            return jsonify({'error': 'Username can only contain lowercase letters, numbers, and underscores'}), 400
        if User.query.filter(User.id != user_id, User.username == new_username).first():
            user_management_logger.warning(f"Admin {current_admin_id} failed to update user {user_id}: Username '{new_username}' already exists.")
            return jsonify({'error': 'Username already exists'}), 400
        user.username = new_username
        user_management_logger.info(f"Admin {current_admin_id} updated user {user_id} username to {new_username}.")

    if 'name' in data:
        user.name = data['name']
        user_management_logger.info(f"Admin {current_admin_id} updated user {user_id} name to {data['name']}.")

    if 'email' in data:
        new_email = data['email'].lower()
        if not validate_email(new_email):
            user_management_logger.warning(f"Admin {current_admin_id} failed to update user {user_id}: Invalid email format for {new_email}.")
            return jsonify({'error': 'Invalid email format'}), 400
        if User.query.filter(User.id != user_id, User.email == new_email).first():
            user_management_logger.warning(f"Admin {current_admin_id} failed to update user {user_id}: Email '{new_email}' already exists.")
            return jsonify({'error': 'Email already exists'}), 400
        user.email = new_email
        user_management_logger.info(f"Admin {current_admin_id} updated user {user_id} email to {new_email}.")

    if 'is_active' in data:
        user.is_active = bool(data['is_active'])
        user_management_logger.info(f"Admin {current_admin_id} updated user {user_id} active status to {user.is_active}.")

    db.session.commit()
    return jsonify({
        'message': 'User updated successfully',
        'user': user.to_dict()
    }), 200

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

@user_management.route('/users/<int:user_id>/activate', methods=['POST'])
@jwt_required()
@admin_required
def activate_user(user_id):
    user = User.query.get_or_404(user_id)
    current_admin_id = get_jwt_identity()
    
    # Prevent admin from activating themselves
    if user.id == current_admin_id:
        return jsonify({'error': 'Cannot activate your own account'}), 400
    
    user.is_active = True
    db.session.commit()
    
    user_management_logger.info(f"Admin {current_admin_id} activated user {user_id}.")
    return jsonify({'message': 'User activated successfully'}), 200

@user_management.route('/users/<int:user_id>/deactivate', methods=['POST'])
@jwt_required()
@admin_required
def deactivate_user(user_id):
    user = User.query.get_or_404(user_id)
    current_admin_id = get_jwt_identity()
    
    # Prevent admin from deactivating themselves
    if user.id == current_admin_id:
        return jsonify({'error': 'Cannot deactivate your own account'}), 400
    
    user.is_active = False
    db.session.commit()
    
    user_management_logger.info(f"Admin {current_admin_id} deactivated user {user_id}.")
    return jsonify({'message': 'User deactivated successfully'}), 200 