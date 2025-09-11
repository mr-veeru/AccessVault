"""
Profile Routes Module

This module handles user profile management operations including viewing,
updating profile information, changing passwords, and account management.
All routes are prefixed with '/profile' and require authentication.
"""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from model import User
from decorators import active_required
from extensions import db, bcrypt
import re

# Create profile blueprint
profile_bp = Blueprint("profile", __name__)

# Regex validation patterns
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%&*!?])[A-Za-z\d@#$%&*!?]{6,}$" # Requires: at least 6 chars, one uppercase, one digit, one special character
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit

@profile_bp.route("/", methods=["GET"])
@jwt_required()
@active_required
def get_my_profile():
    """
    Retrieve the current user's profile information.
    
    Requires:
        Valid JWT access token in Authorization header
        Active account status
    
    Returns:
        JSON response with user profile details (excluding password)
    """
    try:
        # Get user ID from JWT token and convert to integer for database query
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        # Return user profile information (excluding sensitive data like password)
        return jsonify({
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }), 200
    except Exception as e:
        # Handle unexpected errors gracefully
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500


@profile_bp.route("/", methods=["PATCH"])
@jwt_required()
@active_required
def update_profile():
    """
    Update user's profile information (name and/or username).
    
    Expected JSON payload:
    {
        "name": "New Full Name",        // Optional
        "username": "new_username"      // Optional
    }
    
    Requires:
        Valid JWT access token in Authorization header
        Active account status
        At least one field to update
    
    Returns:
        JSON response with updated user information
    """
    # Get user ID from JWT token
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    # Get request data
    data = request.get_json() or {}
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Validate that at least one updatable field is provided
    if not any(key in data for key in ["name", "username"]):
        return jsonify({"error": "At least one field (name or username) is required"}), 400

    # Validate that only allowed fields are provided
    allowed_fields = {"name", "username"}
    if any(key not in allowed_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request. Only 'name' and 'username' are allowed"}), 400

    # Update name if provided
    if "name" in data:
        new_name = data.get("name")
        if not new_name or not new_name.strip():
            return jsonify({"error": "Name cannot be empty"}), 400
        
        # Validate name length
        if len(new_name.strip()) > 100:
            return jsonify({"error": "Name cannot exceed 100 characters"}), 400
        
        user.name = new_name.strip()

    # Update username if provided (with uniqueness check)
    if "username" in data:
        new_username = data.get("username").lower().strip()
        if not new_username:
            return jsonify({"error": "Username cannot be empty"}), 400
        
        # Validate username format
        if not re.match(USERNAME_REGEX, new_username):
            return jsonify({
                "error": "Invalid username: must be alphanumeric, at least 3 characters, and contain at least one letter and one digit"
            }), 400
        
        # Only update if username is actually changing
        if new_username != user.username:
            # Check if new username already exists
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                return jsonify({"error": "Username already exists"}), 400
            user.username = new_username

    # Save changes to database
    db.session.commit()
    
    # Return success response with updated user information
    return jsonify({
        "message": "Profile updated successfully",
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }
    }), 200


@profile_bp.route("/password", methods=["PATCH"])
@jwt_required()
@active_required
def update_password():
    """
    Update user's password with validation and security checks.
    
    Expected JSON payload:
    {
        "old_password": "current_password",
        "new_password": "NewSecurePassword123!",
        "confirm_password": "NewSecurePassword123!"
    }
    
    Requires:
        Valid JWT access token in Authorization header
        Active account status
        Correct current password
    
    Returns:
        JSON response confirming password update
    """
    # Get user ID from JWT token
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    # Define required fields for password update
    required_fields = {"old_password", "new_password", "confirm_password"}
    data = request.get_json() or {}
    
    # Validate request data
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Check for missing required fields
    if not all(field in data for field in required_fields):
        return jsonify({"error": "all fields required"}), 400
    
    # Reject unknown fields for security
    if any(key not in required_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    # Extract password fields
    old_password = data.get("old_password").strip()
    new_password = data.get("new_password").strip()
    confirm_password = data.get("confirm_password").strip()
    
    # Check that fields are not empty
    if not all([old_password, new_password, confirm_password]):
        return jsonify({"error": "Fields cannot be empty or only whitespace"}), 400
    
    # Verify current password is correct
    if not bcrypt.check_password_hash(user.password, old_password):
        return jsonify({"error": "Old password is incorrect"}), 400
    
    # Verify new password and confirmation match
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400
    
    # Check if new password is different from old password
    if bcrypt.check_password_hash(user.password, new_password):
        return jsonify({"error": "New password must be different from current password"}), 400
    
    # Validate new password strength using regex
    if not re.match(PASSWORD_REGEX, new_password):
        return jsonify({
            "error": "Password must be at least 6 characters long, include one uppercase letter, one number, and one special character (@,#,$,%,&,*,!,?)"
        }), 400
        
    # Hash new password and update user record
    user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    
    # Save changes to database with error handling
    db.session.commit()
    return jsonify({"message": "Password updated successfully"}), 200


@profile_bp.route("/deactivate", methods=["PATCH"])
@jwt_required()
@active_required
def deactivate_account():
    """
    Deactivate the current user's account (soft delete).
    
    This sets the user's status to 'inactive' but preserves the account data.
    The user will not be able to log in until reactivated by an admin.
    
    Requires:
        Valid JWT access token in Authorization header
        Active account status
    
    Returns:
        JSON response confirming account deactivation
    """
    # Get user ID from JWT token
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    # Set account status to inactive
    user.status = "inactive"
    
    # Save changes to database with error handling
    db.session.commit()
    return jsonify({"message": "Account deactivated successfully"}), 200


@profile_bp.route("/", methods=["DELETE"])
@jwt_required()
@active_required
def delete_account():
    """
    Permanently delete the current user's account (hard delete).
    
    This completely removes the user account and all associated data from the database.
    This action cannot be undone.
    
    Requires:
        Valid JWT access token in Authorization header
        Active account status
    
    Returns:
        JSON response confirming account deletion
    """
    # Get user ID from JWT token
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    
    # Permanently delete user account from database
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "Account deleted successfully"}), 200