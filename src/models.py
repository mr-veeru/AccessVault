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


class RevokedToken(db.Model):
    """
    RevokedToken model representing revoked JWT tokens in the AccessVault system.
    
    This model stores information about JWT tokens that have been revoked for security
    purposes. When a user logs out or refreshes their tokens, the old tokens are
    added to this table to prevent their reuse.
    
    Attributes:
        jti (str): Primary key, JWT ID (unique identifier for the token)
        user_id (int): Foreign key referencing the user who owned the token
        revoked_at (datetime): Timestamp when the token was revoked
    """
    __tablename__ = "revoked_tokens"
    
    # Primary key - JWT ID (unique identifier)
    jti = db.Column(db.String(36), primary_key=True)
    
    # Token metadata
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    
    def __repr__(self):
        """String representation of the RevokedToken object for debugging."""
        return f"<RevokedToken {self.jti}>"
