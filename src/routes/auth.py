"""
Authentication Routes Module

This module handles user authentication including registration, and login.
All routes are prefixed with '/auth' and handle user account creation, authentication, password reset, and token refresh.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from src.extensions import db, bcrypt, api
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jti, get_jwt
from src.models import User, RevokedToken
from src.logger import logger
import re
from src.decorators import active_required

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
    @auth_ns.expect(register_model)
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
    @jwt_required()
    def post(self):
        """Logout user by revoking the current access token"""
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
    @jwt_required(refresh=True)
    @active_required
    def post(self):
        """Refresh JWT tokens with token rotation for security"""
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
