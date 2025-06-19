from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from shared.models import User
from shared.db import db
from shared.utils.validators import validate_email, validate_username
from shared.logger import setup_logging
from shared.utils.rate_limiter import profile_rate_limit

user_profile_bp = Blueprint('user_profile', __name__)
user_profile_logger = setup_logging(__name__)

@user_profile_bp.route('/profile', methods=['GET'])
@jwt_required()
@profile_rate_limit
def get_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        user_profile_logger.warning(f"User profile fetch failed: User {current_user_id} not found.")
        return jsonify({'error': 'User not found'}), 404
    
    user_profile_logger.info(f"User profile for user {current_user_id} fetched successfully.")
    return jsonify({
        'user': user.to_dict()
    }), 200

@user_profile_bp.route('/profile', methods=['PUT'])
@jwt_required()
@profile_rate_limit
def update_profile():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        user_profile_logger.warning(f"User profile update failed: User {current_user_id} not found.")
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    # Update allowed fields
    if 'email' in data:
        email = data['email'].lower()
        if not validate_email(email):
            user_profile_logger.warning(f"User {current_user_id} profile update failed: Invalid email format provided for {email}.")
            return jsonify({'error': 'Invalid email format'}), 400
        if User.query.filter(User.id != current_user_id, User.email == email).first():
            user_profile_logger.warning(f"User {current_user_id} profile update failed: Email '{email}' already exists.")
            return jsonify({'error': 'Email already exists'}), 400
        user.email = email
        user_profile_logger.info(f"User {current_user_id} email updated to {email}.")
    
    if 'name' in data:
        user.name = data['name']
        user_profile_logger.info(f"User {current_user_id} name updated to {data['name']}.")
    
    if 'username' in data:
        username = data['username'].lower()
        if not validate_username(username):
            user_profile_logger.warning(f"User {current_user_id} profile update failed: Invalid username format provided for {username}.")
            return jsonify({'error': 'Username can only contain lowercase letters, numbers, and underscores'}), 400
        if User.query.filter(User.id != current_user_id, User.username == username).first():
            user_profile_logger.warning(f"User {current_user_id} profile update failed: Username '{username}' already exists.")
            return jsonify({'error': 'Username already exists'}), 400
        user.username = username
        user_profile_logger.info(f"User {current_user_id} username updated to {username}.")
    
    db.session.commit()
    
    user_profile_logger.info(f"User {current_user_id} profile updated successfully.")
    return jsonify({
        'message': 'Profile updated successfully',
        'user': user.to_dict()
    }), 200

@user_profile_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        user_profile_logger.warning(f"Password change failed: User {current_user_id} not found.")
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    if not data or not data.get('old_password') or not data.get('new_password'):
        user_profile_logger.warning(f"Password change failed for user {current_user_id}: Missing old or new password.")
        return jsonify({'error': 'Missing old or new password'}), 400
    
    if not user.check_password(data['old_password']):
        user_profile_logger.warning(f"Password change failed for user {current_user_id}: Current password incorrect.")
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    user.set_password(data['new_password'])
    db.session.commit()
    
    user_profile_logger.info(f"Password for user {current_user_id} changed successfully.")
    return jsonify({
        'message': 'Password changed successfully'
    }), 200

@user_profile_bp.route('/profile', methods=['DELETE'])
@jwt_required()
@profile_rate_limit
def delete_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        user_profile_logger.warning(f"User account deletion failed: User {current_user_id} not found.")
        return jsonify({'error': 'User not found'}), 404
    
    # Permanently delete the user account
    db.session.delete(user)
    db.session.commit()
    
    user_profile_logger.info(f"User {current_user_id} account deleted successfully.")
    return jsonify({
        'message': 'Account deleted successfully'
    }), 200

@user_profile_bp.route('/profile/deactivate', methods=['POST'])
@jwt_required()
@profile_rate_limit
def deactivate_account():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        user_profile_logger.warning(f"User account deactivation failed: User {current_user_id} not found.")
        return jsonify({'error': 'User not found'}), 404
    
    user.is_active = False
    db.session.commit()
    
    user_profile_logger.info(f"User {current_user_id} account deactivated successfully.")
    return jsonify({
        'message': 'Account deactivated successfully',
        'user': user.to_dict()
    }), 200 