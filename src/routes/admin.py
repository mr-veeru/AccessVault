"""
Admin Routes Module

This module contains administrative routes for user management, system statistics,
and password reset token generation. All routes require admin role and JWT authentication.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.decorators import role_required
from src.extensions import db, bcrypt, api, limiter
from src.models import User, PasswordResetToken, RevokedToken
from src.logger import logger
from src.routes.auth import USERNAME_REGEX
import re
import secrets
from datetime import datetime, timedelta

# Create admin namespace
admin_ns = Namespace('admin', description='Administrative operations')

# Request/Response models for Swagger documentation
user_model = api.model('User', {
    'id': fields.Integer(description='User ID'),
    'name': fields.String(description='Full name'),
    'username': fields.String(description='Username'),
    'role': fields.String(description='User role'),
    'status': fields.String(description='Account status')
})

create_user_model = api.model('CreateUser', {
    'name': fields.String(required=True, description='Full name', example='John Doe'),
    'username': fields.String(required=True, description='Username (3+ chars, letters+numbers)', example='johndoe123'),
    'role': fields.String(required=True, description='User role', example='user', enum=['user', 'admin'])
})

update_user_model = api.model('UpdateUser', {
    'name': fields.String(description='Full name', example='John Doe'),
    'username': fields.String(description='Username (3+ chars, letters+numbers)', example='johndoe123'),
    'role': fields.String(description='User role', example='user', enum=['user', 'admin'])
})

stats_model = api.model('Stats', {
    'total_users': fields.Integer(description='Total number of users'),
    'active_users': fields.Integer(description='Number of active users'),
    'inactive_users': fields.Integer(description='Number of inactive users'),
    'admins': fields.Integer(description='Number of admin users'),
    'regular_users': fields.Integer(description='Number of regular users')
})

# Password reset models
reset_token_response_model = api.model('ResetTokenResponse', {
    'message': fields.String(description='Response message'),
    'token': fields.String(description='Password reset token'),
    'expires_at': fields.String(description='Token expiration time'),
    'user': fields.Raw(description='User information')
})

reset_token_model = api.model('ResetToken', {
    'token': fields.String(description='Reset token'),
    'expires_at': fields.String(description='Token expiration time'),
    'user': fields.Nested(user_model, description='User information')
})

message_response_model = api.model('MessageResponse', {
    'message': fields.String(description='Response message')
})

@admin_ns.route('/stats')
class Stats(Resource):
    @limiter.limit("30 per minute")
    @admin_ns.marshal_with(stats_model, code=200)
    @jwt_required()
    @role_required("admin")
    def get(self):
        """Get comprehensive system statistics"""
        total_users = User.query.count()
        active_users = User.query.filter_by(status="active").count()
        inactive_users = User.query.filter_by(status="inactive").count()
        admins = User.query.filter_by(role="admin").count()
        regular_users = User.query.filter_by(role="user").count()
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "admins": admins,
            "regular_users": regular_users
        }, 200

@admin_ns.route('/users')
class Users(Resource):
    @limiter.limit("60 per minute")
    @admin_ns.marshal_list_with(user_model, code=200)
    @jwt_required()
    @role_required("admin")
    def get(self):
        """Get all users in the system"""
        users = User.query.all()
        return [
            {
                "id": user.id,
                "name": user.name,
                "username": user.username,
                "role": user.role,
                "status": user.status
            }
            for user in users
        ], 200

    @limiter.limit("10 per hour")
    @admin_ns.expect(create_user_model)
    @jwt_required()
    @role_required("admin")
    def post(self):
        """Create a new user with default password"""
        data = request.get_json()
        
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Check for required fields
        required_fields = ["name", "username", "role"]
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            return {
                "error": "Missing required fields",
                "missing_fields": missing_fields,
                "required_fields": required_fields
            }, 400
        
        # Check for unexpected fields
        expected_fields = set(required_fields)
        provided_fields = set(data.keys())
        unexpected_fields = provided_fields - expected_fields
        
        if unexpected_fields:
            return {
                "error": "Unexpected fields provided",
                "unexpected_fields": list(unexpected_fields),
                "expected_fields": list(expected_fields)
            }, 400
        
        name = data["name"].strip()
        username = data["username"].strip().lower()  # Convert to lowercase for case-insensitive usernames
        role = data["role"].strip()
        
        # Validate name
        if not name or len(name) < 2:
            return {"error": "Name must be at least 2 characters long"}, 400
        
        # Validate username format
        if not re.match(USERNAME_REGEX, username):
            return {
                "error": "Username must be at least 3 characters, contain only letters and numbers, and have at least one letter and one number"
            }, 400
        
        # Validate role
        if role not in ["user", "admin"]:
            return {"error": "Role must be either 'user' or 'admin'"}, 400
        
        # Check if username already exists
        if User.query.filter_by(username=username).first():
            return {"error": "Username already exists"}, 400
        
        # Create new user with default password
        default_password = "User@123"
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        
        new_user = User(
            name=name,
            username=username,
            password=hashed_password,
            role=role,
            status="active"
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f"New user created by admin: {username} (ID: {new_user.id}) from IP: {request.remote_addr}")
        
        return {
            "message": "User created successfully",
            "default_password": default_password,
            "user": {
                "id": new_user.id,
                "name": new_user.name,
                "username": new_user.username,
                "role": new_user.role,
                "status": new_user.status
            }
        }, 201

@admin_ns.route('/users/active')
class ActiveUsers(Resource):
    @admin_ns.marshal_list_with(user_model, code=200)
    @jwt_required()
    @role_required("admin")
    def get(self):
        """Get all active users"""
        users = User.query.filter_by(status="active").all()
        return [
            {
                "id": user.id,
                "name": user.name,
                "username": user.username,
                "role": user.role,
                "status": user.status
            }
            for user in users
        ], 200

@admin_ns.route('/users/inactive')
class InactiveUsers(Resource):
    @admin_ns.marshal_list_with(user_model, code=200)
    @jwt_required()
    @role_required("admin")
    def get(self):
        """Get all inactive users"""
        users = User.query.filter_by(status="inactive").all()
        return [
            {
                "id": user.id,
                "name": user.name,
                "username": user.username,
                "role": user.role,
                "status": user.status
            }
            for user in users
        ], 200

@admin_ns.route('/users/search/username/<username>')
class SearchByUsername(Resource):
    @admin_ns.marshal_list_with(user_model, code=200)
    @jwt_required()
    @role_required("admin")
    def get(self, username):
        """Search users by username (case-insensitive partial match)"""
        users = User.query.filter(User.username.ilike(f"%{username}%")).all()
        return [
            {
                "id": user.id,
                "name": user.name,
                "username": user.username,
                "role": user.role,
                "status": user.status
            }
            for user in users
        ], 200

@admin_ns.route('/users/search/name/<name>')
class SearchByName(Resource):
    @admin_ns.marshal_list_with(user_model, code=200)
    @jwt_required()
    @role_required("admin")
    def get(self, name):
        """Search users by full name (case-insensitive partial match)"""
        users = User.query.filter(User.name.ilike(f"%{name}%")).all()
        return [
            {
                "id": user.id,
                "name": user.name,
                "username": user.username,
                "role": user.role,
                "status": user.status
            }
            for user in users
        ], 200

@admin_ns.route('/users/<int:user_id>')
class FindUserById(Resource):
    @limiter.limit("60 per minute")
    @jwt_required()
    @role_required("admin")
    def get(self, user_id):
        """Get user by ID"""
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        
        return {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

    @limiter.limit("20 per hour")
    @admin_ns.expect(update_user_model)
    @jwt_required()
    @role_required("admin")
    def patch(self, user_id):
        """Update user by ID"""
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        
        data = request.get_json()
        
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Check if at least one field is provided
        if not any(field in data for field in ["name", "username", "role"]):
            return {"error": "At least one field (name, username, or role) must be provided"}, 400
        
        # Update name if provided
        if "name" in data:
            name = data["name"].strip() if data["name"] else ""
            if not name or len(name) < 2:
                return {"error": "Name must be at least 2 characters long"}, 400
            user.name = name
        
        # Update username if provided
        if "username" in data:
            username = data["username"].strip().lower() if data["username"] else ""
            if not username:
                return {"error": "Username cannot be empty"}, 400
            
            # Validate username format
            if not re.match(USERNAME_REGEX, username):
                return {
                    "error": "Username must be at least 3 characters, contain only letters and numbers, and have at least one letter and one number"
                }, 400
            
            # Check if username already exists (excluding current user)
            existing_user = User.query.filter(User.username == username, User.id != user.id).first()
            if existing_user:
                return {"error": "Username already exists"}, 400
            
            user.username = username
        
        # Update role if provided
        if "role" in data:
            role = data["role"].strip() if data["role"] else ""
            if role not in ["user", "admin"]:
                return {"error": "Role must be either 'user' or 'admin'"}, 400
            user.role = role
        
        db.session.commit()
        
        logger.info(f"User updated by admin: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

    @limiter.limit("5 per hour")
    @jwt_required()
    @role_required("admin")
    def delete(self, user_id):
        """Delete user by ID"""
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        
        # Prevent admin from deleting their own account
        current_user_id = int(get_jwt_identity())  # JWT identity is now a string
        if user_id == current_user_id:
            return {"error": "Cannot delete your own account"}, 400
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        logger.info(f"User deleted by admin: {username} (ID: {user_id}) from IP: {request.remote_addr}")
        
        return {"message": f"User {username} deleted successfully"}, 200

@admin_ns.route('/users/<int:user_id>/activate')
class ActivateUser(Resource):
    @limiter.limit("20 per hour")
    @jwt_required()
    @role_required("admin")
    def patch(self, user_id):
        """Activate user account"""
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        
        user.status = "active"
        db.session.commit()
        
        logger.info(f"User activated by admin: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

@admin_ns.route('/users/<int:user_id>/deactivate')
class DeactivateUser(Resource):
    @limiter.limit("20 per hour")
    @jwt_required()
    @role_required("admin")
    def patch(self, user_id):
        """Deactivate user account"""
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        
        user.status = "inactive"
        db.session.commit()
        
        logger.info(f"User deactivated by admin: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200


@admin_ns.route('/users/<int:user_id>/generate-reset-token')
class GenerateResetToken(Resource):
    @limiter.limit("10 per hour")
    @admin_ns.marshal_with(reset_token_response_model, code=200)
    @jwt_required()
    @role_required('admin')
    def get(self, user_id):
        """
        Generate password reset token for a specific user (Admin only).
        
        This endpoint allows admins to generate a password reset token for a specific user
        by their user ID. The token expires in 24 hours and can only be used once.
        """
        # Find the user by ID
        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404
        
        # Check if user is active
        if user.status != "active":
            return {"error": "Cannot generate reset token for inactive user"}, 400
        
        # Generate secure token (24 bytes = 32 characters when base64 encoded)
        token = secrets.token_urlsafe(24)
        
        # Set expiration (24 hours from now)
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Create password reset token
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at
        )
        
        db.session.add(reset_token)
        db.session.commit()
        
        logger.info(f"Password reset token generated for user: {user.username} (ID: {user.id}) by admin from IP: {request.remote_addr}")
        
        return {
            "message": "Password reset token generated successfully",
            "token": token,
            "expires_at": expires_at.isoformat() + "Z",
            "user": {
                "id": user.id,
                "name": user.name,
                "username": user.username
            }
        }, 200


@admin_ns.route('/cleanup-expired-tokens')
class CleanupExpiredTokens(Resource):
    @limiter.limit("5 per hour")
    @admin_ns.marshal_with(message_response_model, code=200)
    @jwt_required()
    @role_required('admin')
    def delete(self):
        """
        Clean up expired tokens from the database (Admin only).
        
        This endpoint removes all expired JWT tokens and password reset tokens
        from the database to improve performance and reduce storage usage.
        """
        current_time = datetime.utcnow()
        
        # Clean up expired JWT tokens
        expired_jwt_tokens = RevokedToken.query.filter(
            RevokedToken.revoked_at < current_time - timedelta(days=7)
        ).all()
        
        jwt_count = len(expired_jwt_tokens)
        for token in expired_jwt_tokens:
            db.session.delete(token)
        
        # Clean up expired password reset tokens
        expired_reset_tokens = PasswordResetToken.query.filter(
            PasswordResetToken.expires_at < current_time
        ).all()
        
        reset_count = len(expired_reset_tokens)
        for token in expired_reset_tokens:
            db.session.delete(token)
        
        db.session.commit()
        
        total_cleaned = jwt_count + reset_count
        
        logger.info(f"Token cleanup completed by admin: {jwt_count} expired JWT tokens, {reset_count} expired reset tokens removed from IP: {request.remote_addr}")
        
        return {
            "message": f"Cleanup completed successfully. Removed {total_cleaned} expired tokens ({jwt_count} JWT tokens, {reset_count} reset tokens)"
        }, 200
