"""
Database Models Module

This module defines the SQLAlchemy models for the AccessVault application.
Currently contains the User model which represents user accounts in the system.
"""

from src.extensions import db 


class User(db.Model):
    """
    User model representing user accounts in the AccessVault system.
    
    Attributes:
        id (int): Primary key, auto-incrementing user ID
        name (str): User's full name (max 100 characters)
        username (str): Unique username for login (max 80 characters)
        password (str): Hashed password for authentication (max 200 characters)
        role (str): User role - either 'user' or 'admin' (default: 'user')
        status (str): Account status - either 'active' or 'inactive' (default: 'active')
    """
    __tablename__ = "users"
    
    # Primary key - auto-incrementing integer
    id = db.Column(db.Integer, primary_key=True)
    
    # User information fields
    name = db.Column(db.String(100), nullable=False)                    # User's full name
    username = db.Column(db.String(80), unique=True, nullable=False)    # Unique username for login
    password = db.Column(db.String(200), nullable=False)                # Hashed password
    
    # Role-based access control fields
    role = db.Column(db.String(20), default="user")      # User role: 'user' or 'admin'
    status = db.Column(db.String(20), default="active")  # Account status: 'active' or 'inactive'
    
    def __repr__(self):
        """String representation of the User object for debugging."""
        return f"<User {self.username}>"
    

class RefreshToken(db.Model):
    """
    Refresh Token model for secure token rotation and device binding.
    
    Attributes:
        id (int): Primary key, auto-incrementing token ID
        user_id (int): Foreign key to User model
        token (str): Unique refresh token (max 128 characters)
        device_info (str): Device/browser information for tracking
        ip_address (str): IP address when token was created
        created_at (datetime): Date and time the token was created
        expires_at (datetime): Expiration date and time for the token
        is_revoked (bool): Indicates if the token has been revoked (default: False)
    """
    __tablename__ = "refresh_tokens"

    # Primary key - auto-incrementing integer
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to User model
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Refresh token fields
    token = db.Column(db.String(128), unique=True, nullable=False)
    device_info = db.Column(db.String(200), nullable=True)  # Browser/device info
    ip_address = db.Column(db.String(45), nullable=False)   # IPv4/IPv6 support
    created_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False)

    def __repr__(self):
        """String representation of the RefreshToken object for debugging."""
        return f"<RefreshToken {self.token[:8]}... for User {self.user_id}>"


class PasswordResetToken(db.Model):
    """
    Password Reset Token model representing password reset tokens in the system.
    
    Attributes:
        id (int): Primary key, auto-incrementing token ID
        user_id (int): Foreign key to User model
        token (str): Unique token for password reset (max 128 characters)
        created_at (datetime): Date and time the token was created
        expires_at (datetime): Expiration date and time for the token
        used (bool): Indicates if the token has been used (default: False)
    """
    __tablename__ = "password_reset_tokens"

    # Primary key - auto-incrementing integer
    id = db.Column(db.Integer, primary_key=True)
    
    # Foreign key to User model
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # Password reset token fields
    token = db.Column(db.String(128), unique=True, nullable=False) # Unique token for password reset (max 128 characters)
    created_at = db.Column(db.DateTime, nullable=False) # Date and time the token was created
    expires_at = db.Column(db.DateTime, nullable=False) # Expiration date and time for the token
    used = db.Column(db.Boolean, default=False) # Indicates if the token has been used (default: False)
