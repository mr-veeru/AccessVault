"""
Authentication Routes Module

This module handles user authentication including registration, and login.
All routes are prefixed with '/auth' and handle user account creation, authentication, password reset, and token refresh.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from src.extensions import db, bcrypt, limiter, api
from src.models import User, PasswordResetToken
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from src.logger import logger
import re
from datetime import datetime

# Create authentication namespace
auth_ns = Namespace('auth', description='Authentication operations')

# Request models for Swagger documentation (only what's needed for validation)
register_model = api.model('Register', {
    'name': fields.String(required=True, description='Full name', example='Veerendra'),
    'username': fields.String(required=True, description='Username (3+ chars, letters+numbers)', example='veeru68'),
    'password': fields.String(required=True, description='Password (6+ chars, uppercase+number+special)', example='Password123!'),
    'confirm_password': fields.String(required=True, description='Confirm password', example='Password123!')
})

login_model = api.model('Login', {
    'username': fields.String(required=True, description='Username', example='veeru68'),
    'password': fields.String(required=True, description='Password', example='Password123!')
})

reset_password_model = api.model('ResetPassword', {
    'token': fields.String(required=True, description='Reset token from admin', example='abc123def456'),
    'new_password': fields.String(required=True, description='New password', example='NewPassword123!'),
    'confirm_password': fields.String(required=True, description='Confirm new password', example='NewPassword123!')
})

# Regex validation patterns
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%&*!?])[A-Za-z\d@#$%&*!?]{6,}$" # Requires: at least 6 chars, one uppercase, one digit, one special character
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model)
    @limiter.limit("10 per hour")
    def post(self):
        """Register a new user account"""
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Validate that all required fields are present
        required_fields = {"name", "username", "password", "confirm_password"}
        missing_fields = [field for field in required_fields if field not in data]
        if not all(field in data for field in required_fields):
            logger.warning(f"Registration failed - missing fields: {missing_fields} from IP: {request.remote_addr}")
            return {
                "error": "Missing required fields",
                "required_fields": list(required_fields),
                "missing_fields": missing_fields
            }, 400
        
        # Reject requests with unexpected fields for security
        if any(key not in required_fields for key in data.keys()):
            logger.warning(f"Registration failed - unexpected fields from IP: {request.remote_addr}")
            return {
                "error": "Unexpected fields in request",
                "required_fields": list(required_fields),
            }, 400
        
        # Extract data from request
        name = data.get("name", "").strip()
        username = data.get("username", "").strip().lower()  # Convert to lowercase for case-insensitive usernames
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        
        # Validate name
        if not name or len(name) < 2:
            logger.warning(f"Registration failed - invalid name from IP: {request.remote_addr}")
            return {"error": "Name must be at least 2 characters long"}, 400
        
        # Check if username already exists in database
        if User.query.filter_by(username=username).first():
            logger.warning(f"Registration failed - username already exists: {username} from IP: {request.remote_addr}")
            return {"error": "Username already exist"}, 400
        
        # Validate that password and confirmation match
        if password != confirm_password:
            logger.warning(f"Registration failed - password mismatch from IP: {request.remote_addr}")
            return {"error": "Passwords do not match"}, 400

        # Validate username format
        if not re.match(USERNAME_REGEX, username):
            logger.warning(f"Registration failed - invalid username format: {username} from IP: {request.remote_addr}")
            return {
                "error": "Invalid username: must be alphanumeric, at least 3 characters, and contain at least one letter and one digit"
            }, 400
        
        # Validate password strength using regex pattern
        if not re.match(PASSWORD_REGEX, password):
            logger.warning(f"Registration failed - weak password from IP: {request.remote_addr}")
            return {
                "error": "Password must be at least 6 characters long, include one uppercase letter, one number, and one special character (@,#,$,%,&,*,!,?)"
            }, 400
        
        # Hash the password using bcrypt for secure storage
        hashed_pwd = bcrypt.generate_password_hash(password).decode("utf-8")
        
        # Create new user instance with hashed password
        new_user = User(name=name, username=username, password=hashed_pwd)
        
        # Save user to database
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User registered successfully: {username} (ID: {new_user.id}) from IP: {request.remote_addr}")
        return {"message": "User registered successfully"}, 201
    

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @limiter.limit("5 per minute")
    def post(self):
        """Authenticate user and receive JWT tokens"""
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Check for required fields
        required_fields = {"username", "password"}
        missing_fields = [field for field in required_fields if not data.get(field)]
        
        # Validate that all required fields are present
        if not all(field in data for field in required_fields):
            logger.warning(f"Login failed - missing fields: {missing_fields} from IP: {request.remote_addr}")
            return {
                "error": "Missing required fields",
                "required_fields": list(required_fields),
                "missing_fields": missing_fields
            }, 400
    
        # Reject requests with unexpected fields for security
        if any(key not in required_fields for key in data.keys()):
            logger.warning(f"Login failed - unexpected fields from IP: {request.remote_addr}")
            return {
                "error": "Unexpected fields in request",
                "required_fields": list(required_fields),
            }, 400
        
        # Extract credentials from request
        username = data.get("username", "").strip().lower()  # Convert to lowercase for case-insensitive usernames
        password = data.get("password")

        # Find the user by username in database
        user = User.query.filter_by(username=username).first()
        
        # Verify user exists and password is correct using bcrypt
        if not user or not bcrypt.check_password_hash(user.password, password):
            logger.warning(f"Login failed - invalid credentials for username: {username} from IP: {request.remote_addr}")
            return {"error": "Invalid username or password"}, 400
        
        # Check if user account is active
        if user.status != "active":
            logger.warning(f"Login failed - account deactivated for username: {username} from IP: {request.remote_addr}")
            return {"error": "Account is deactivated. Please contact admin."}, 403
        
        # Create JWT tokens with user information and role-based claims
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "status": user.status}
        )
        refresh_token = create_refresh_token(identity=str(user.id))

        # Return success response with both tokens
        logger.info(f"Login successful for user: {username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }, 200

@auth_ns.route('/refresh')
class Refresh(Resource):
    @jwt_required(refresh=True)
    @limiter.limit("10 per minute")
    def get(self):
        """Generate new access token and refresh token using current refresh token (refresh token rotation)"""
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        
        if not user or user.status != "active":
            logger.warning(f"Token refresh failed - user not found or inactive: {user_id} from IP: {request.remote_addr}")
            return {"error": "User not found or inactive"}, 404

        # Generate new access token
        new_access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "status": user.status}
        )

        # Generate new refresh token (refresh token rotation)
        new_refresh_token = create_refresh_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "status": user.status}
        )

        logger.info(f"Tokens refreshed successfully for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {
            "message": "New access token and refresh token generated",
            "access_token": new_access_token,
            "refresh_token": new_refresh_token
        }, 200

@auth_ns.route('/reset-password')
class ResetPassword(Resource):
    @auth_ns.expect(reset_password_model)
    def post(self):
        """Reset user password using admin-generated token"""
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided"}, 400

        required_fields = {"token", "new_password", "confirm_password"}
        missing_fields = [field for field in required_fields if not data.get(field)]
        if not all(field in data for field in required_fields):
            logger.warning(f"Reset password failed - missing fields: {missing_fields} from IP: {request.remote_addr}")
            return {
                "error": "Missing required fields",
                "missing_fields": missing_fields,
                "required_fields": required_fields
            }, 400
        
        token = data.get("token")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if new_password != confirm_password:
            logger.warning(f"Reset password failed - passwords do not match from IP: {request.remote_addr}")
            return {"error": "Passwords do not match"}, 400

        if not re.match(PASSWORD_REGEX, new_password):
            logger.warning(f"Reset password failed - password does not meet requirements from IP: {request.remote_addr}")
            return {"error": "Password does not meet requirements"}, 400

        # Lookup token in DB
        reset_token = PasswordResetToken.query.filter_by(token=token, is_used=False).first()
        if not reset_token:
            logger.warning(f"Reset password failed - invalid or already used token from IP: {request.remote_addr}")
            return {"error": "Invalid or already used token"}, 400

        if reset_token.expires_at < datetime.utcnow():
            logger.warning(f"Reset password failed - token has expired from IP: {request.remote_addr}")
            return {"error": "Token has expired"}, 400

        # Update user password
        user = User.query.get(reset_token.user_id)
        if not user:
            logger.warning(f"Reset password failed - user not found from IP: {request.remote_addr}")
            return {"error": "User not found"}, 404

        user.password = bcrypt.generate_password_hash(new_password).decode("utf-8")
        reset_token.is_used = True  # Mark token as consumed

        db.session.commit()
        logger.info(f"Password reset successful for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {"message": "Password reset successful"}, 200