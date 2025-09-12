"""
Authentication Routes Module

This module handles user authentication including registration, and login.
All routes are prefixed with '/auth' and handle user account creation and authentication.
"""

from flask import Blueprint, request, jsonify
from extensions import db, bcrypt
from models import User
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity

import re

# Create authentication blueprint
auth_bp = Blueprint("auth", __name__)

# Regex validation patterns
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%&*!?])[A-Za-z\d@#$%&*!?]{6,}$" # Requires: at least 6 chars, one uppercase, one digit, one special character
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit

@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Register a new user account.
    
    Expected JSON payload:
    {
        "name": "User's full name",
        "username": "unique_username",
        "password": "SecurePassword123!",
        "confirm_password": "SecurePassword123!"
    }
    
    Returns:
        JSON response with success message or error details
    """
    # Define required fields for user registration
    required_fields = {"name", "username", "password", "confirm_password"}
    data = request.get_json()
    
    # Validate that all required fields are present
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        return jsonify({
            "error": "Missing required fields",
            "required_fields": list(required_fields),
            "missing_fields": missing_fields
        }), 400
    
    # Reject requests with unexpected fields for security
    if any(key not in required_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    # Extract data from request
    name = data.get("name")
    username = data.get("username").lower().strip()
    password = data.get("password")
    confirm_password = data.get("confirm_password")
    
    # Check if username already exists in database
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exist"}), 400
    
    # Validate that password and confirmation match
    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    # Validate username format
    if not re.match(USERNAME_REGEX, username):
        return jsonify({
            "error": "Invalid username: must be alphanumeric, at least 3 characters, and contain at least one letter and one digit"
        }), 400
    
    # Validate password strength using regex pattern
    if not re.match(PASSWORD_REGEX, password):
        return jsonify({
            "error": "Password must be at least 6 characters long, include one uppercase letter, one number, and one special character (@,#,$,%,&,*,!,?)"
        }), 400
    
    # Hash the password using bcrypt for secure storage
    hashed_pwd = bcrypt.generate_password_hash(password).decode("utf-8")
    
    # Create new user instance with hashed password
    new_user = User(name=name, username=username, password=hashed_pwd)
    
    # Save user to database
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201
    

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Authenticate user and return JWT tokens.
    
    Expected JSON payload:
    {
        "username": "user_username",
        "password": "user_password"
    }
    
    Returns:
        JSON response with access and refresh tokens on success
    """
    # Define required fields for login
    required_fields = {"username", "password"}
    data = request.get_json()
    
    # Validate that all required fields are present
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        return jsonify({
            "error": "Missing required fields",
            "required_fields": list(required_fields),
            "missing_fields": missing_fields
        }), 400
    
    # Reject requests with unexpected fields for security
    if any(key not in required_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    # Extract credentials from request
    username = data.get("username").lower().strip()
    password = data.get("password")

    # Find the user by username in database
    user = User.query.filter_by(username=username).first()
    
    # Verify user exists and password is correct using bcrypt
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Invalid username or password"}), 400
    
    # Check if user account is active
    if user.status != "active":
        return jsonify({"error": "Account is deactivated. Please contact admin."}), 403
    
    # Create JWT tokens with user information and role-based claims
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "status": user.status}
    )
    refresh_token = create_refresh_token(identity=str(user.id))

    # Return success response with both tokens
    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
    }), 200

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)  # requires a refresh token
def refresh():
    """Generate a new access token using refresh token"""
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.status != "active":
        return jsonify({"error": "User not found or inactive"}), 404

    # issue new access token
    new_access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "status": user.status}
    )

    return jsonify({
        "message": "New access token generated",
        "access_token": new_access_token
    }), 200