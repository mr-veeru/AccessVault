from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from admin_service.models import Admin
from user_service.models import User
from shared.db import db
from shared.utils.validators import validate_password
from shared.logger import setup_logging

admin_auth_bp = Blueprint('admin_auth', __name__)
admin_auth_logger = setup_logging(__name__)

@admin_auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or (not data.get('username_or_email') and not data.get('username') and not data.get('email')) or not data.get('password'):
        admin_auth_logger.warning("Admin login failed: Missing username/email or password.")
        return jsonify({'error': 'Missing username/email or password'}), 400
    
    admin = None
    login_identifier = (data.get('username_or_email') or data.get('username') or data.get('email')).lower()

    if not login_identifier:
        admin_auth_logger.warning("Admin login failed: Missing username/email.")
        return jsonify({'error': 'Missing username/email'}), 400

    # First try to find admin in admins table
    admin = Admin.query.filter_by(username=login_identifier).first()
    if not admin:
        admin = Admin.query.filter_by(email=login_identifier).first()
    
    # If not found in admins table, check users table for users with admin role
    if not admin:
        user = User.query.filter_by(username=login_identifier).first()
        if not user:
            user = User.query.filter_by(email=login_identifier).first()
        
        if user and user.role == 'admin' and user.check_password(data['password']):
            if not user.is_active:
                admin_auth_logger.warning(f"Admin login failed for '{login_identifier}': Account is deactivated.")
                return jsonify({'error': 'Account is deactivated'}), 403
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Create access token
            access_token = create_access_token(
                identity=str(user.id),
                additional_claims={'role': user.role}
            )
            admin_auth_logger.info(f"Admin user '{user.username}' ({user.email}) logged in successfully.")
            return jsonify({
                'access_token': access_token,
                'admin': user.to_dict()
            }), 200
    
    if not admin or not admin.check_password(data['password']):
        admin_auth_logger.warning(f"Admin login failed for '{login_identifier}': Invalid credentials.")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not admin.is_active:
        admin_auth_logger.warning(f"Admin login failed for '{login_identifier}': Account is deactivated.")
        return jsonify({'error': 'Account is deactivated'}), 403
    
    # Update last login
    admin.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create access token
    access_token = create_access_token(
        identity=str(admin.id),
        additional_claims={'role': admin.role}
    )
    admin_auth_logger.info(f"Admin '{admin.username}' ({admin.email}) logged in successfully.")
    return jsonify({
        'access_token': access_token,
        'admin': admin.to_dict()
    }), 200

@admin_auth_bp.route('/verify', methods=['GET'])
@jwt_required()
def verify_token():
    admin_id = get_jwt_identity()
    admin = Admin.query.get(admin_id)
    
    # If not found in admins table, check users table
    if not admin:
        user = User.query.get(admin_id)
        if user and user.role == 'admin':
            admin_auth_logger.info(f"Admin token verified for user '{user.username}' ({user.email}).")
            return jsonify({
                'admin': user.to_dict(),
                'message': 'Token is valid'
            }), 200
    
    if not admin:
        admin_auth_logger.warning(f"Admin token verification failed: Admin {admin_id} not found.")
        return jsonify({'error': 'Admin not found'}), 404
    
    admin_auth_logger.info(f"Admin token verified for '{admin.username}' ({admin.email}).")
    return jsonify({
        'admin': admin.to_dict(),
        'message': 'Token is valid'
    }), 200

@admin_auth_bp.route('/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    current_admin_id = get_jwt_identity()
    admin = Admin.query.get(current_admin_id)

    if not admin:
        admin_auth_logger.warning(f"Admin password change failed: Admin {current_admin_id} not found.")
        return jsonify({'error': 'Admin not found'}), 404

    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        admin_auth_logger.warning(f"Admin password change failed for admin {current_admin_id}: Missing old or new password.")
        return jsonify({'error': 'Missing old or new password'}), 400

    # Validate new password against strength rules
    password_validation_result = validate_password(new_password)
    if password_validation_result is not True:
        admin_auth_logger.warning(f"Admin password change failed for admin {current_admin_id}: {password_validation_result}")
        return jsonify({'error': password_validation_result}), 400

    if not admin.check_password(old_password):
        admin_auth_logger.warning(f"Admin password change failed for admin {current_admin_id}: Invalid old password.")
        return jsonify({'error': 'Invalid old password'}), 401

    admin.set_password(new_password)
    db.session.commit()

    admin_auth_logger.info(f"Password for admin {current_admin_id} changed successfully.")
    return jsonify({'message': 'Password updated successfully'}), 200 