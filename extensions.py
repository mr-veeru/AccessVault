"""
Flask Extensions Module

This module initializes Flask extensions that are used throughout the application.
Extensions are initialized here to avoid circular imports and enable proper
initialization order.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Initialize Flask extensions
# These will be initialized with the app in the create_app() function
db = SQLAlchemy()      # Database ORM for PostgreSQL operations
jwt = JWTManager()     # JSON Web Token manager for authentication
bcrypt = Bcrypt()      # Bcrypt for password hashing

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,   # identifies client by IP
    default_limits=["100 per day", "20 per hour", "5 per minute"]  # fallback limits
)