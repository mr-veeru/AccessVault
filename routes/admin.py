"""
Admin Routes Module

This module contains administrative routes that require admin role access.
All routes are prefixed with '/admin' and handle user management operations
including CRUD operations, user activation/deactivation, and user creation.
"""

from decorators import role_required, active_required
from flask import jsonify, Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User
from extensions import db, bcrypt, limiter
from logger import logger
import re

# Create admin blueprint
admin_bp = Blueprint("admin", __name__)

# Regex validation patterns
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit


# ----------------------- GET ROUTES (Read Operations) -----------------------

@admin_bp.route("/stats", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def get_stats():
    """
    Get comprehensive system statistics for admin dashboard.
    
    Provides counts of users by status and role for administrative oversight.
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response with system statistics including:
        - Total user count
        - Active/inactive user counts
        - Admin/user role counts
    """
    # Query user counts from database
    total_users = User.query.count()
    active_users = User.query.filter_by(status="active").count()
    inactive_users = User.query.filter_by(status="inactive").count()
    admins = User.query.filter_by(role="admin").count()
    users = User.query.filter_by(role="user").count()
    
    return jsonify({
        "message": "System statistics retrieved successfully",
        "statistics": {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": inactive_users,
            "admins": admins,
            "regular_users": users
        }
    }), 200

@admin_bp.route("/users", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def get_all_users():
    """
    Retrieve all users in the system.
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON array of all users with their details
    """
    # Query all users from database
    users = User.query.all()
    
    # Return user list with selected fields (excluding passwords)
    return jsonify([
        {
            "id": u.id, 
            "name": u.name, 
            "username": u.username, 
            "role": u.role, 
            "status": u.status
        } for u in users
    ]), 200

@admin_bp.route("/users/active", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def get_all_active_users():
    """
    Get all active users.
    
    This allows a previously deactivated user to log in again.
    
    Args:
        None
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response with active users information
    """
    # Query all active users from database
    users = User.query.filter_by(status="active").all()
    
    # Check if active users exist
    if not users:
        return jsonify({"error": "No active users found"}), 404
    
    # Return success response with active users information
    return jsonify({
        "message": "Active users found",
        "users": [{
            "id": u.id, 
            "name": u.name, 
            "username": u.username, 
            "role": u.role, 
            "status": u.status
        } for u in users]
    }), 200

@admin_bp.route("/users/inactive", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def get_all_inactive_users():
    """
    Get all inactive users.
    """
    # Query all inactive users from database
    users = User.query.filter_by(status="inactive").all()
    
    # Check if inactive users exist
    if not users:
        return jsonify({"error": "No inactive users found"}), 404
    
    # Return success response with inactive users information
    return jsonify({
        "message": "Inactive users found",
        "users": [{
            "id": u.id, 
            "name": u.name, 
            "username": u.username, 
            "role": u.role, 
            "status": u.status
        } for u in users]
    }), 200


@admin_bp.route("/users/search/username/<string:username>", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def search_users_by_username(username):
    """
    Search for users by username (case-insensitive partial match).
    
    Args:
        username (str): Username to search for (partial match supported)
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response with matching users or empty array if no matches found
    """
    # Validate search query
    if not username or not username.strip():
        return jsonify({"error": "Username search query cannot be empty"}), 400
    
    # Search for users with partial username match (case-insensitive)
    users = User.query.filter(User.username.ilike(f"%{username.strip()}%")).all()
    
    return jsonify({
        "message": f"Found {len(users)} user(s) matching '{username}'",
        "users": [{
            "id": u.id, 
            "name": u.name, 
            "username": u.username, 
            "role": u.role, 
            "status": u.status
        } for u in users]
    }), 200

@admin_bp.route("/users/search/name/<string:name>", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def search_users_by_name(name):
    """
    Search for users by full name (case-insensitive partial match).
    
    Args:
        name (str): Full name to search for (partial match supported)
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response with matching users or empty array if no matches found
    """
    # Validate search query
    if not name or not name.strip():
        return jsonify({"error": "Name search query cannot be empty"}), 400
    
    # Search for users with partial name match (case-insensitive)
    users = User.query.filter(User.name.ilike(f"%{name.strip()}%")).all()
    
    return jsonify({
        "message": f"Found {len(users)} user(s) matching '{name}'",
        "users": [{
            "id": u.id, 
            "name": u.name, 
            "username": u.username, 
            "role": u.role, 
            "status": u.status
        } for u in users]
    }), 200

@admin_bp.route("/users/<int:user_id>", methods=["GET"])
@jwt_required()
@role_required("admin")
@active_required
def get_user(user_id):
    """
    Retrieve a specific user by their ID.
    
    Args:
        user_id (int): The ID of the user to retrieve
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response with user details or 404 if not found
    """
    # Query user by ID from database
    user = User.query.get(user_id)
    
    # Check if user exists
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Return user information (excluding sensitive data like password)
    return jsonify({
        "id": user.id, 
        "name": user.name, 
        "username": user.username, 
        "role": user.role, 
        "status": user.status
    }), 200
    
# ----------------------- POST ROUTES (Create Operations) -----------------------

@admin_bp.route("/users", methods=["POST"])
@limiter.limit("10 per hour")  # max 10 user creations per hour per IP
@jwt_required()
@role_required("admin")
@active_required
def create_user():
    """
    Create a new user account with default password.
    
    Expected JSON payload:
    {
        "name": "User Full Name",
        "username": "unique_username",
        "role": "user"  // or "admin"
    }
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response with new user details and default password
    """
    # Get admin user ID from JWT token for logging
    admin_id = int(get_jwt_identity())
    admin_user = User.query.get(admin_id)
    logger.info(f"User creation attempt by admin: {admin_user.username} (ID: {admin_id}) from IP: {request.remote_addr}")
    
    # Get request data
    data = request.get_json() or {}

    # Validate required fields
    required_fields = {"name", "username", "role"}
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        return jsonify({
            "error": "Missing required fields",
            "required_fields": list(required_fields),
            "missing_fields": missing_fields
        }), 400

    # Validate that only allowed fields are provided
    if any(key not in required_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400

    # Validate field values
    if not data["name"] or not data["name"].strip():
        return jsonify({"error": "Name cannot be empty"}), 400
    
    if not data["username"] or not data["username"].strip():
        return jsonify({"error": "Username cannot be empty"}), 400
    
    if not data["role"] or not data["role"].strip():
        return jsonify({"error": "Role cannot be empty"}), 400

    # Validate name length
    if len(data["name"].strip()) > 100:
        return jsonify({"error": "Name cannot exceed 100 characters"}), 400

    # Validate username format
    username = data["username"].lower().strip()
    if not re.match(USERNAME_REGEX, username):
        return jsonify({
            "error": "Invalid username: must be alphanumeric, at least 3 characters, and contain at least one letter and one digit"
        }), 400

    # Validate role value
    if data["role"] not in ["user", "admin"]:
        return jsonify({"error": "Invalid role. Allowed: user, admin"}), 400

    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    # Generate default password and hash it
    default_password = "User@123"
    hashed_pwd = bcrypt.generate_password_hash(default_password).decode("utf-8")

    # Create new user instance with provided data and default password
    new_user = User(
        name=data["name"].strip(),
        username=username,
        password=hashed_pwd,
        role=data["role"],
        status="active"
    )
    
    # Save new user to database
    db.session.add(new_user)
    db.session.commit()
    
    logger.info(f"User created successfully: {new_user.username} (ID: {new_user.id}) by admin: {admin_user.username} (ID: {admin_id}) from IP: {request.remote_addr}")
    
    # Return success response with user details and default password
    return jsonify({
        "message": "New user created successfully",
        "default_password": default_password,
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "username": new_user.username,
            "role": new_user.role,
            "status": new_user.status
        }
    }), 201

# ----------------------- PATCH ROUTES (Update Operations) -----------------------

@admin_bp.route("/users/<int:user_id>", methods=["PATCH"])
@jwt_required()
@role_required("admin")
@active_required
def update_user(user_id):
    """
    Update a user's information (name, username, role).
    
    Args:
        user_id (int): The ID of the user to update
    
    Expected JSON payload:
    {
        "name": "Updated Name",        // Optional
        "username": "new_username",    // Optional
        "role": "admin"                // Optional
    }
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response confirming successful update
    """
    # Query user by ID from database
    user = User.query.get(user_id)
    
    # Check if user exists
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get request data
    data = request.get_json() or {}
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Validate that at least one updatable field is provided
    if not any(key in data for key in ["name", "username", "role"]):
        return jsonify({"error": "At least one field (name or username or role) is required"}), 400
        
    # Reject unknown fields for security
    allowed_fields = {"name", "username", "role"}
    if any(key not in allowed_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    # Update name if provided
    if "name" in data:
        new_name = data.get("name")
        if not new_name or not new_name.strip():
            return jsonify({"error": "Name cannot be empty"}), 400
        new_name = new_name.strip()
        
        # Validate name length
        if len(new_name) > 100:
            return jsonify({"error": "Name cannot exceed 100 characters"}), 400
        
        user.name = new_name
    
    # Update username if provided (with uniqueness check)
    if "username" in data:
        new_username = data.get("username")
        if not new_username or not new_username.strip():
            return jsonify({"error": "Username cannot be empty"}), 400
        new_username = new_username.lower().strip()
        
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
   
    # Update role if provided (with validation)
    if "role" in data:
        new_role = data.get("role")
        if not new_role or not new_role.strip():
            return jsonify({"error": "Role cannot be empty"}), 400
        new_role = new_role.strip()
        
        # Validate role value
        if new_role not in ["user", "admin"]:
            return jsonify({"error": "Invalid role. Allowed: user, admin"}), 400

        user.role = new_role

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

@admin_bp.route("/users/<int:user_id>/activate", methods=["PATCH"])
@limiter.limit("20 per hour")  # max 20 activations per hour per IP
@jwt_required()
@role_required("admin")
@active_required
def activate_user(user_id):
    """
    Activate a user account (set status to 'active').
    
    This allows a previously deactivated user to log in again.
    
    Args:
        user_id (int): The ID of the user to activate
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response confirming activation or current status
    """
    # Query user by ID from database
    user = User.query.get(user_id)
    
    # Check if user exists
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Check if user is already active
    if user.status == "active":
        return jsonify({"message": f"User {user.username} is already active"}), 200
    
    # Set user status to active
    user.status = "active"
    db.session.commit()

    # Return success response with updated user information
    return jsonify({
        "message": "User activated successfully",
        "user": {
            "id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }
    }), 200


@admin_bp.route("/users/<int:user_id>/deactivate", methods=["PATCH"])
@limiter.limit("20 per hour")  # max 20 deactivations per hour per IP
@jwt_required()
@role_required("admin")
@active_required
def deactivate_user(user_id):
    """
    Deactivate a user account (set status to 'inactive').
    
    This prevents the user from logging in while preserving their account data.
    The user can be reactivated later by an admin.
    
    Args:
        user_id (int): The ID of the user to deactivate
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response confirming deactivation or current status
    """
    # Query user by ID from database
    user = User.query.get(user_id)
    
    # Check if user exists
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Check if user is already inactive
    if user.status == "inactive":
        return jsonify({"message": f"User {user.username} is already inactive"}), 200
    
    # Set user status to inactive
    user.status = "inactive"
    db.session.commit()
    return jsonify({"message": f"User {user.username} deactivated"}), 200

# ----------------------- DELETE ROUTES (Delete Operations) -----------------------

@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@limiter.limit("5 per hour")  # max 5 deletions per hour per IP
@jwt_required()
@role_required("admin")
@active_required
def delete_user(user_id):
    """
    Permanently delete a user account (hard delete).
    
    This completely removes the user and all associated data from the database.
    This action cannot be undone.
    
    Args:
        user_id (int): The ID of the user to delete
    
    Requires:
        Admin role and active account status
        Authorization header with valid access token
    
    Returns:
        JSON response confirming deletion
    
    Edge Cases:
        - Prevents admin from deleting themselves
        - Validates user exists before deletion
    """
    # Get current admin user ID for self-deletion check
    admin_id = int(get_jwt_identity())
    
    # Prevent admin from deleting themselves
    if user_id == admin_id:
        return jsonify({"error": "Cannot delete your own account"}), 400
    
    # Query user by ID from database
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Permanently delete user from database
    deleted_username = user.username
    deleted_user_id = user.id
    admin_user = User.query.get(admin_id)
    
    db.session.delete(user)
    db.session.commit()
    
    logger.warning(f"User deleted permanently: {deleted_username} (ID: {deleted_user_id}) by admin: {admin_user.username} (ID: {admin_id}) from IP: {request.remote_addr}")
    return jsonify({"message": f"User {deleted_username} deleted successfully"}), 200
