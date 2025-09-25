"""
Profile Routes Module

This module handles user profile management operations including viewing,
updating profile information, changing passwords, and account management.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models import User
from src.decorators import active_required
from src.extensions import api, db, bcrypt, limiter
from src.logger import logger
from src.routes.auth import USERNAME_REGEX, PASSWORD_REGEX
import re

# Create profile namespace
profile_ns = Namespace('profile', description='Profile management operations')

# Request/Response models for Swagger documentation
profile_model = api.model('Profile', {
    'user_id': fields.Integer(description='User ID'),
    'name': fields.String(description='Full name'),
    'username': fields.String(description='Username'),
    'role': fields.String(description='User role'),
    'status': fields.String(description='Account status')
})

update_profile_model = api.model('UpdateProfile', {
    'name': fields.String(description='Full name', example='John Doe'),
    'username': fields.String(description='Username (3+ chars, letters+numbers)', example='johndoe123')
})

update_password_model = api.model('UpdatePassword', {
    'old_password': fields.String(required=True, description='Current password', example='OldPassword123!'),
    'new_password': fields.String(required=True, description='New password', example='NewPassword123!'),
    'confirm_password': fields.String(required=True, description='Confirm new password', example='NewPassword123!')
})

@profile_ns.route('/')
class Profile(Resource):
    @limiter.limit("60 per minute")
    @profile_ns.marshal_with(profile_model, code=200)
    @jwt_required()
    @active_required
    def get(self):
        """Get current user's profile information"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        logger.info(f"User profile fetched successfully: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

    @limiter.limit("20 per minute")
    @profile_ns.expect(update_profile_model)
    @jwt_required()
    @active_required
    def patch(self):
        """Update current user's profile information"""
        data = request.get_json()
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
                
        if not data:
            logger.warning(f"Profile update failed - no JSON data provided from IP: {request.remote_addr}")
            return {"error": "No JSON data provided"}, 400
        
        # Check if at least one field is provided
        if not any(field in data for field in ["name", "username"]):
            logger.warning(f"Profile update failed - no fields provided from IP: {request.remote_addr}")
            return {"error": "At least one field (name or username) must be provided"}, 400

        # Reject requests with unexpected fields for security
        unexpected_fields = [key for key in data.keys() if key not in ["name", "username"]]
        if unexpected_fields:
            logger.warning(f"Profile update failed - unexpected fields: {unexpected_fields} from IP: {request.remote_addr}")
            return {
                "error": "Unexpected fields in request",
                "unexpected_fields": unexpected_fields,
                "allowed_fields": ["name", "username"]
            }, 400
        
        # Update name if provided
        if "name" in data:
            name = data["name"].strip() if data["name"] else ""
            if not name or len(name) < 2:
                logger.warning(f"Profile update failed - invalid name from IP: {request.remote_addr}")
                return {"error": "Name must be at least 2 characters long"}, 400
            user.name = name
        
        # Update username if provided
        if "username" in data:
            username = data["username"].strip().lower() if data["username"] else ""
            if not username:
                logger.warning(f"Profile update failed - empty username from IP: {request.remote_addr}")
                return {"error": "Username cannot be empty"}, 400
            
            # Validate username format
            if not re.match(USERNAME_REGEX, username):
                logger.warning(f"Profile update failed - invalid username format from IP: {request.remote_addr}")
                return {
                    "error": "Username must be at least 3 characters, contain only letters and numbers, and have at least one letter and one number"
                }, 400
            
            # Check if username already exists (excluding current user)
            existing_user = User.query.filter(User.username == username, User.id != user.id).first()
            if existing_user:
                logger.warning(f"Profile update failed - username already exists from IP: {request.remote_addr}")
                return {"error": "Username already exists"}, 400
            
            user.username = username
        
        # Save changes to database
        db.session.commit()
        logger.info(f"User profile updated successfully: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        # Return updated profile data
        return {
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

@profile_ns.route('/password')
class UpdatePassword(Resource):
    @limiter.limit("5 per hour")
    @profile_ns.expect(update_password_model)
    @jwt_required()
    @active_required
    def patch(self):
        """Update user password"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        
        data = request.get_json()
        
        if not data:
            logger.warning(f"Password update failed - no JSON data provided from IP: {request.remote_addr}")
            return {"error": "No JSON data provided"}, 400
        
        # Check for required fields
        required_fields = ["old_password", "new_password", "confirm_password"]
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
            logger.warning(f"Password update failed - missing fields from IP: {request.remote_addr}")
            return {
                "error": "Missing required fields",
                "missing_fields": missing_fields,
                "required_fields": required_fields
            }, 400
        
        old_password = data["old_password"]
        new_password = data["new_password"]
        confirm_password = data["confirm_password"]
        
        # Validate old password
        if not bcrypt.check_password_hash(user.password, old_password):
            logger.warning(f"Password update failed - incorrect old password from IP: {request.remote_addr}")
            return {"error": "Current password is incorrect"}, 400
        
        # Validate new password format
        if not re.match(PASSWORD_REGEX, new_password):
            logger.warning(f"Password update failed - invalid new password format from IP: {request.remote_addr}")
            return {
                "error": "Password must be at least 6 characters with at least one uppercase letter, one number, and one special character (@ # $ % & * ! ?)"
            }, 400
        
        # Check if passwords match
        if new_password != confirm_password:
            logger.warning(f"Password update failed - new passwords do not match from IP: {request.remote_addr}")
            return {"error": "New passwords do not match"}, 400
        
        # Check if new password is different from old password
        if bcrypt.check_password_hash(user.password, new_password):
            logger.warning(f"Password update failed - new password must be different from current password from IP: {request.remote_addr}")
            return {"error": "New password must be different from current password"}, 400
        
        # Update password
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        
        logger.info(f"Password updated for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {"message": "Password updated successfully"}, 200

@profile_ns.route('/deactivate')
class DeactivateAccount(Resource):
    @limiter.limit("3 per hour")
    @jwt_required()
    @active_required
    def patch(self):
        """Deactivate current user's account"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        
        user.status = "inactive"
        db.session.commit()
        
        logger.info(f"Account deactivated for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {"message": "Account deactivated successfully"}, 200

@profile_ns.route('/delete')
class DeleteAccount(Resource):
    @limiter.limit("1 per hour")
    @jwt_required()
    @active_required
    def delete(self):
        """Permanently delete current user's account"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        
        username = user.username
        db.session.delete(user)
        db.session.commit()
        
        logger.info(f"Account deleted for user: {username} (ID: {user_id}) from IP: {request.remote_addr}")
        
        return {"message": f"Account {username} deleted successfully"}, 200
