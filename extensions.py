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
from flask_restx import Api

# Initialize Flask extensions
# These will be initialized with the app in the create_app() function
db = SQLAlchemy()      # Database ORM for PostgreSQL operations
jwt = JWTManager()     # JSON Web Token manager for authentication
bcrypt = Bcrypt()      # Bcrypt for password hashing

# Rate limiting with memory storage (acceptable for development)
# For production, consider using Redis: storage_uri="redis://localhost:6379"
limiter = Limiter(
    key_func=get_remote_address,   # identifies client by IP
    default_limits=["100 per day", "20 per hour", "5 per minute"]  # fallback limits
)

# Flask-RESTX API for automatic Swagger documentation
api = Api(
    title='AccessVault API',
    version='1.0',
    description='Secure User Management API with JWT Authentication',
    doc='/swagger-ui/'
)