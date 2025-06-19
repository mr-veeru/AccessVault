from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from shared.db import db
from shared.models import Account
from shared.utils.auth_utils import admin_required
from shared.utils.validators import validate_username, validate_email
from shared.logger import setup_logging

admin_management_bp = Blueprint('admin_management', __name__)
admin_management_logger = setup_logging(__name__)

@admin_management_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@admin_required
def get_user(user_id):
    user = Account.query.get(user_id)
    if not user:
        admin_management_logger.warning(f"Failed to fetch user {user_id}: User not found.")
        return jsonify({'error': 'User not found'}), 404
    admin_management_logger.info(f"Admin fetched details for user '{user.username}' (ID: {user_id}).")
    return jsonify(user.to_dict()), 200

@admin_management_bp.route('/settings', methods=['GET'])
@jwt_required()
@admin_required
def get_system_settings():
    admin_management_logger.info("Admin attempting to fetch system settings.")
    # This would typically fetch system settings
    return jsonify({
        'message': 'System settings would be returned here'
    }), 200

@admin_management_bp.route('/settings', methods=['PUT'])
@jwt_required()
@admin_required
def update_system_settings():
    admin_management_logger.info("Admin attempting to update system settings.")
    # This would typically update system settings
    data = request.get_json()
    return jsonify({
        'message': 'System settings have been updated',
        'settings': data
    }), 200

@admin_management_bp.route('/profile', methods=['PUT'])
@jwt_required()
@admin_required
def update_admin_profile():
    current_admin_id = get_jwt_identity()
    user = Account.query.get(current_admin_id)

    if not user or not user.is_admin():
        admin_management_logger.warning(f"Admin profile update failed: Admin {current_admin_id} not found or not admin.")
        return jsonify({'error': 'Admin not found'}), 404

    data = request.get_json()
    if not data:
        admin_management_logger.warning(f"Admin profile update failed for admin {current_admin_id}: No input data provided.")
        return jsonify({'error': 'No input data provided'}), 400

    # Update admin fields
    if 'username' in data:
        username = data['username'].lower()
        if not validate_username(username):
            admin_management_logger.warning(f"Admin {current_admin_id} profile update failed: Invalid username format provided for {username}.")
            return jsonify({'error': 'Username can only contain lowercase letters, numbers, and underscores'}), 400
        if Account.query.filter(Account.id != current_admin_id, Account.username == username).first():
            admin_management_logger.warning(f"Admin {current_admin_id} profile update failed: Username '{username}' already exists.")
            return jsonify({'error': 'Username already exists'}), 400
        user.username = username
        admin_management_logger.info(f"Admin {current_admin_id} username updated to {username}.")
    if 'email' in data:
        email = data['email'].lower()
        if not validate_email(email):
            admin_management_logger.warning(f"Admin {current_admin_id} profile update failed: Invalid email format provided for {email}.")
            return jsonify({'error': 'Invalid email format'}), 400
        if Account.query.filter(Account.id != current_admin_id, Account.email == email).first():
            admin_management_logger.warning(f"Admin {current_admin_id} profile update failed: Email '{email}' already exists.")
            return jsonify({'error': 'Email already exists'}), 400
        user.email = email
        admin_management_logger.info(f"Admin {current_admin_id} email updated to {email}.")
    if 'name' in data:
        user.name = data['name']
        admin_management_logger.info(f"Admin {current_admin_id} name updated to {data['name']}.")

    db.session.commit()

    admin_management_logger.info(f"Admin profile for {current_admin_id} updated successfully.")
    return jsonify({
        'message': 'Admin profile updated successfully!',
        'admin': user.to_dict()
    }), 200 