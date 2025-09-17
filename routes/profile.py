"""
Profile Routes Module

This module handles user profile management operations including viewing,
updating profile information, changing passwords, and account management.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User
from decorators import active_required
from extensions import db, bcrypt, limiter, api
from logger import logger
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

# Regex validation patterns
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%&*!?])[A-Za-z\d@#$%&*!?]{6,}$" # Requires: at least 6 chars, one uppercase, one digit, one special character
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit

@profile_ns.route('/')
class Profile(Resource):
    @profile_ns.marshal_with(profile_model, code=200)
    @jwt_required()
    @active_required
    def get(self):
        """Get current user's profile information"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        
        return {
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

    @profile_ns.expect(update_profile_model)
    @profile_ns.marshal_with(profile_model, code=200)
    @jwt_required()
    @active_required
    def patch(self):
        """Update user profile information"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        
        data = request.get_json()
        
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Check if at least one field is provided
        if not any(field in data for field in ["name", "username"]):
            return {"error": "At least one field (name or username) must be provided"}, 400
        
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
        
        db.session.commit()
        
        logger.info(f"Profile updated for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200

@profile_ns.route('/password')
class UpdatePassword(Resource):
    @profile_ns.expect(update_password_model)
    @jwt_required()
    @active_required
    @limiter.limit("5 per hour")
    def patch(self):
        """Update user password"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        
        data = request.get_json()
        
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Check for required fields
        required_fields = ["old_password", "new_password", "confirm_password"]
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        if missing_fields:
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
            return {"error": "Current password is incorrect"}, 400
        
        # Validate new password format
        if not re.match(PASSWORD_REGEX, new_password):
            return {
                "error": "Password must be at least 6 characters with at least one uppercase letter, one number, and one special character (@ # $ % & * ! ?)"
            }, 400
        
        # Check if passwords match
        if new_password != confirm_password:
            return {"error": "New passwords do not match"}, 400
        
        # Check if new password is different from old password
        if bcrypt.check_password_hash(user.password, new_password):
            return {"error": "New password must be different from current password"}, 400
        
        # Update password
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        
        logger.info(f"Password updated for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {"message": "Password updated successfully"}, 200

@profile_ns.route('/deactivate')
class DeactivateAccount(Resource):
    @jwt_required()
    @active_required
    @limiter.limit("3 per hour")
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