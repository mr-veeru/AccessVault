from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from shared.db import db
from user_service.models import User
from shared.utils.auth_utils import admin_required

admin_management_bp = Blueprint('admin_management', __name__)

@admin_management_bp.route('/users', methods=['GET'])
@jwt_required()
@admin_required
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

@admin_management_bp.route('/users/<int:user_id>', methods=['GET'])
@jwt_required()
@admin_required
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    return jsonify(user.to_dict()), 200

@admin_management_bp.route('/users/<int:user_id>/deactivate', methods=['POST'])
@jwt_required()
@admin_required
def deactivate_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user.is_active = False
    db.session.commit()
    
    return jsonify({
        'message': f'User {user_id} has been deactivated',
        'user': user.to_dict()
    }), 200

@admin_management_bp.route('/users/<int:user_id>/activate', methods=['POST'])
@jwt_required()
@admin_required
def activate_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user.is_active = True
    db.session.commit()
    
    return jsonify({
        'message': f'User {user_id} has been activated',
        'user': user.to_dict()
    }), 200

@admin_management_bp.route('/settings', methods=['GET'])
@jwt_required()
@admin_required
def get_system_settings():
    # This would typically fetch system settings
    return jsonify({
        'message': 'System settings would be returned here'
    }), 200

@admin_management_bp.route('/settings', methods=['PUT'])
@jwt_required()
@admin_required
def update_system_settings():
    # This would typically update system settings
    data = request.get_json()
    return jsonify({
        'message': 'System settings have been updated',
        'settings': data
    }), 200 