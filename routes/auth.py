"""
Authentication Routes Module

This module handles user authentication including registration, and login.
All routes are prefixed with '/auth' and handle user account creation and authentication.
"""

from flask import Blueprint, request, jsonify
from extensions import db, bcrypt, limiter
from models import User, PasswordResetToken
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from logger import logger
import re
from datetime import datetime

# Create authentication blueprint
auth_bp = Blueprint("auth", __name__)

# Regex validation patterns
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%&*!?])[A-Za-z\d@#$%&*!?]{6,}$" # Requires: at least 6 chars, one uppercase, one digit, one special character
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per hour")  # allow 5 registrations per hour per IP
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
    logger.info(f"Registration attempt from IP: {request.remote_addr}")
    
    # Define required fields for user registration
    required_fields = {"name", "username", "password", "confirm_password"}
    data = request.get_json()
    
    # Validate that all required fields are present
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        logger.warning(f"Registration failed - missing fields: {missing_fields} from IP: {request.remote_addr}")
        return jsonify({
            "error": "Missing required fields",
            "required_fields": list(required_fields),
            "missing_fields": missing_fields
        }), 400
    
    # Reject requests with unexpected fields for security
    if any(key not in required_fields for key in data.keys()):
        logger.warning(f"Registration failed - unexpected fields from IP: {request.remote_addr}")
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    # Extract data from request
    name = data.get("name")
    username = data.get("username").lower().strip()
    password = data.get("password")
    confirm_password = data.get("confirm_password")
    
    # Check if username already exists in database
    if User.query.filter_by(username=username).first():
        logger.warning(f"Registration failed - username already exists: {username} from IP: {request.remote_addr}")
        return jsonify({"error": "Username already exist"}), 400
    
    # Validate that password and confirmation match
    if password != confirm_password:
        logger.warning(f"Registration failed - password mismatch from IP: {request.remote_addr}")
        return jsonify({"error": "Passwords do not match"}), 400

    # Validate username format
    if not re.match(USERNAME_REGEX, username):
        logger.warning(f"Registration failed - invalid username format: {username} from IP: {request.remote_addr}")
        return jsonify({
            "error": "Invalid username: must be alphanumeric, at least 3 characters, and contain at least one letter and one digit"
        }), 400
    
    # Validate password strength using regex pattern
    if not re.match(PASSWORD_REGEX, password):
        logger.warning(f"Registration failed - weak password from IP: {request.remote_addr}")
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
    logger.info(f"User registered successfully: {username} (ID: {new_user.id}) from IP: {request.remote_addr}")
    return jsonify({"message": "User registered successfully"}), 201
    

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")  # max 5 logins per minute per IP
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
    logger.info(f"Login attempt from IP: {request.remote_addr}")
    
    # Define required fields for login
    required_fields = {"username", "password"}
    data = request.get_json()
    
    # Validate that all required fields are present
    if not all(field in data for field in required_fields):
        missing_fields = [field for field in required_fields if field not in data]
        logger.warning(f"Login failed - missing fields: {missing_fields} from IP: {request.remote_addr}")
        return jsonify({
            "error": "Missing required fields",
            "required_fields": list(required_fields),
            "missing_fields": missing_fields
        }), 400
    
    # Reject requests with unexpected fields for security
    if any(key not in required_fields for key in data.keys()):
        logger.warning(f"Login failed - unexpected fields from IP: {request.remote_addr}")
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    # Extract credentials from request
    username = data.get("username").lower().strip()
    password = data.get("password")

    # Find the user by username in database
    user = User.query.filter_by(username=username).first()
    
    # Verify user exists and password is correct using bcrypt
    if not user or not bcrypt.check_password_hash(user.password, password):
        logger.warning(f"Login failed - invalid credentials for username: {username} from IP: {request.remote_addr}")
        return jsonify({"error": "Invalid username or password"}), 400
    
    # Check if user account is active
    if user.status != "active":
        logger.warning(f"Login failed - account deactivated for username: {username} from IP: {request.remote_addr}")
        return jsonify({"error": "Account is deactivated. Please contact admin."}), 403
    
    # Create JWT tokens with user information and role-based claims
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "status": user.status}
    )
    refresh_token = create_refresh_token(identity=str(user.id))

    # Return success response with both tokens
    logger.info(f"Login successful for user: {username} (ID: {user.id}) from IP: {request.remote_addr}")
    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token,
    }), 200

@auth_bp.route("/refresh", methods=["POST"])
@limiter.limit("10 per minute")  # max 10 refresh attempts per minute per IP
@jwt_required(refresh=True)  # requires a refresh token
def refresh():
    """Generate a new access token using refresh token"""
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    if not user or user.status != "active":
        logger.warning(f"Token refresh failed - user not found or inactive: {user_id} from IP: {request.remote_addr}")
        return jsonify({"error": "User not found or inactive"}), 404

    # issue new access token
    new_access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "status": user.status}
    )

    logger.info(f"Token refreshed successfully for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
    return jsonify({
        "message": "New access token generated",
        "access_token": new_access_token
    }), 200

@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    """Reset password using reset token (given by admin)"""
    data = request.get_json()
    token = data.get("token")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    # Validate input
    if not all([token, new_password, confirm_password]):
        return jsonify({"error": "All fields are required"}), 400

    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if not re.match(PASSWORD_REGEX, new_password):
        return jsonify({"error": "Password does not meet requirements"}), 400

    # Lookup token in DB
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    if not reset_token:
        return jsonify({"error": "Invalid or already used token"}), 400

    if reset_token.expires_at < datetime.utcnow():
        return jsonify({"error": "Token has expired"}), 400

    # Update user password
    user = User.query.get(reset_token.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
    reset_token.used = True  # Mark token as consumed

    db.session.commit()
    return jsonify({"message": "Password reset successful"}), 200