"""
Authentication Routes Module

This module handles user authentication including registration, and login.
All routes are prefixed with '/auth' and handle user account creation, authentication, password reset, and token refresh.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from src.extensions import db, bcrypt, api, limiter
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from src.models import User, RevokedToken, PasswordResetToken
from src.logger import logger
import re
from src.decorators import active_required
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

# Response models for Swagger documentation
token_response_model = api.model('TokenResponse', {
    'message': fields.String(description='Response message'),
    'access_token': fields.String(description='JWT access token (expires in 1 hour)'),
    'refresh_token': fields.String(description='JWT refresh token (expires in 7 days)')
})

message_response_model = api.model('MessageResponse', {
    'message': fields.String(description='Response message')
})

# Password reset models
reset_password_model = api.model('ResetPassword', {
    'token': fields.String(required=True, description='Password reset token', example='abc123def456'),
    'new_password': fields.String(required=True, description='New password', example='NewPassword123!'),
    'confirm_password': fields.String(required=True, description='Confirm new password', example='NewPassword123!')
})

# Regex validation patterns
PASSWORD_REGEX = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%&*!?])[A-Za-z\d@#$%&*!?]{8,}$" # Requires: at least 6 chars, one uppercase, one digit, one special character
USERNAME_REGEX = r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z0-9]{3,}$" # Requires: at least 3 chars, alphanumeric only, at least one letter and one digit

def is_token_revoked(jwt_header, jwt_payload):
    """
    Callback function to check if a JWT token has been revoked.
    This function is called by Flask-JWT-Extended for every protected endpoint.
    Uses database-backed token management for production security.
    """
    jti = jwt_payload.get('jti')
    return RevokedToken.query.filter_by(jti=jti).first() is not None

def revoke_token(jti, user_id):
    """
    Revoke a JWT token by adding it to the revoked tokens table.
    """
    # Check if token is already revoked
    if RevokedToken.query.filter_by(jti=jti).first():
        return
    
    # Add to revoked tokens table
    revoked_token = RevokedToken(jti=jti, user_id=user_id)
    db.session.add(revoked_token)
    db.session.commit()

@auth_ns.route('/register')
class Register(Resource):
    @limiter.limit("5 per minute")
    @auth_ns.expect(register_model)
    def post(self):
        """
        Register a new user account.
        
        Creates a new user account with validated credentials. Performs comprehensive
        validation including field presence, format validation, and security checks.
        
        Returns:
            tuple: (dict, int) - Success message with 201 status or error with 400/500 status
            
        Raises:
            SQLAlchemyError: Database errors are handled globally
            
        Example:
            POST /api/auth/register
            {
                "name": "John Doe",
                "username": "johndoe123", 
                "password": "SecurePass123!",
                "confirm_password": "SecurePass123!"
            }
        """
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        # Validate that all required fields are present
        # This prevents incomplete registration attempts and provides clear error messages
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
        # This prevents potential injection attacks and ensures strict input validation
        if any(key not in required_fields for key in data.keys()):
            logger.warning(f"Registration failed - unexpected fields from IP: {request.remote_addr}")
            return {
                "error": "Unexpected fields in request",
                "required_fields": list(required_fields),
            }, 400
        
        # Extract data from request with length validation
        name = data.get("name", "").strip()
        username = data.get("username", "").strip().lower()  # Convert to lowercase for case-insensitive usernames
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        
        # Validate input lengths to prevent DoS attacks
        # These limits match the database column constraints and prevent memory exhaustion
        if len(name) > 100:
            return {"error": "Name too long (max 100 characters)"}, 400
        if len(username) > 80:
            return {"error": "Username too long (max 80 characters)"}, 400
        if len(password) > 200:
            return {"error": "Password too long (max 200 characters)"}, 400
        
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
    @limiter.limit("3 per minute")
    @auth_ns.expect(login_model)
    @auth_ns.marshal_with(token_response_model, code=200)
    def post(self):
        """
        Authenticate user and receive JWT tokens.
        
        Validates user credentials and returns access and refresh tokens upon successful
        authentication. Implements rate limiting to prevent brute force attacks.
        
        Returns:
            tuple: (dict, int) - Token response with 200 status or error with 400 status
            
        Security Features:
            - Rate limited to 3 attempts per minute
            - Case-insensitive username matching
            - Secure password verification with bcrypt
            - Account status validation (active users only)
            
        Example:
            POST /api/auth/login
            {
                "username": "johndoe123",
                "password": "SecurePass123!"
            }
        """
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

        refresh_token = create_refresh_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "status": user.status}
        )
        
        # Return success response with both tokens
        logger.info(f"Login successful for user: {username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }, 200


@auth_ns.route('/logout')
class Logout(Resource):
    @limiter.limit("20 per minute")
    @auth_ns.marshal_with(message_response_model, code=200)
    @jwt_required()
    def post(self):
        """
        Logout user by revoking the current access token.
        
        Immediately invalidates the current access token by adding it to the revoked
        tokens table. This ensures the token cannot be used for further API calls.
        
        Returns:
            tuple: (dict, int) - Success message with 200 status or error with 404 status
            
        Security Features:
            - Token revocation is immediate and permanent
            - Database-backed token blacklist
            - User existence validation
            
        Example:
            POST /api/auth/logout
            Headers: Authorization: Bearer <access_token>
        """
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        
        if not user:
            return {"error": "User not found"}, 404

        # Revoke the current access token
        jti = get_jwt()['jti']  # JWT ID
        revoke_token(jti, user.id)
        logger.info(f"User logged out successfully: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {"message": "Logged out successfully"}, 200


@auth_ns.route('/refresh')
class Refresh(Resource):
    @limiter.limit("30 per minute")
    @auth_ns.marshal_with(token_response_model, code=200)
    @jwt_required(refresh=True)
    @active_required
    def post(self):
        """
        Refresh JWT tokens with token rotation for security.
        
        Generates new access and refresh tokens while revoking the old refresh token.
        Implements token rotation for enhanced security. Requires valid refresh token.
        
        Returns:
            tuple: (dict, int) - New token response with 200 status or error with 404 status
            
        Security Features:
            - Token rotation: old refresh token is immediately revoked
            - User must be active (enforced by @active_required)
            - Rate limited to 30 attempts per minute
            - Database-backed token revocation
            
        Example:
            POST /api/auth/refresh
            Headers: Authorization: Bearer <refresh_token>
        """
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))
        
        # Get the current refresh token's JTI to revoke it
        current_jti = get_jwt()['jti']
        
        # Revoke the current refresh token (token rotation)
        revoke_token(current_jti, user.id)
        
        # Create new tokens
        access_token = create_access_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "status": user.status}
        )
        refresh_token = create_refresh_token(
            identity=str(user.id),
            additional_claims={"role": user.role, "status": user.status}
        )
        
        logger.info(f"Tokens refreshed successfully for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {
            "message": "Tokens refreshed successfully",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }, 200


@auth_ns.route('/reset-password')
class ResetPassword(Resource):
    @limiter.limit("5 per minute")
    @auth_ns.expect(reset_password_model)
    @auth_ns.marshal_with(message_response_model, code=200)
    def post(self):
        """
        Reset user password using reset token.
        
        This endpoint allows users to reset their password using a valid
        reset token provided by an admin.
        """
        data = request.get_json()
        if not data:
            return {"error": "No JSON data provided"}, 400
        
        token = data.get("token", "").strip()
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")
        
        if not token:
            return {"error": "Reset token is required"}, 400
        
        if not new_password or not confirm_password:
            return {"error": "New password and confirmation are required"}, 400
        
        # Validate password confirmation
        if new_password != confirm_password:
            return {"error": "Passwords do not match"}, 400
        
        # Validate password strength
        if not re.match(PASSWORD_REGEX, new_password):
            return {
                "error": "Password must be at least 8 characters long, include one uppercase letter, one number, and one special character (@,#,$,%,&,*,!,?)"
            }, 400
        
        # Find the reset token
        reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
        if not reset_token:
            return {"error": "Invalid or expired reset token"}, 400
        
        # Check if token is expired
        if datetime.utcnow() > reset_token.expires_at:
            return {"error": "Reset token has expired"}, 400
        
        # Get the user
        user = User.query.get(reset_token.user_id)
        if not user or user.status != "active":
            return {"error": "User not found or inactive"}, 400
        
        # Check if new password is different from current password
        if bcrypt.check_password_hash(user.password, new_password):
            return {"error": "New password must be different from current password"}, 400
        
        # Update password
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        # Mark token as used
        reset_token.used = True
        
        db.session.commit()
        
        logger.info(f"Password reset successfully for user: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        
        return {"message": "Password reset successfully"}, 200
