"""
Flask Extensions Module

This module initializes Flask extensions that are used throughout the application.
Extensions are initialized here to avoid circular imports and enable proper
initialization order.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_migrate import Migrate
import os

# Initialize Flask extensions
# These will be initialized with the app in the create_app() function
db = SQLAlchemy()      # Database ORM for PostgreSQL operations
jwt = JWTManager()
bcrypt = Bcrypt()
cors = CORS()          # CORS support for cross-origin requests
migrate = Migrate()    # Database migration management (initialized with app and db)

# Flask-RESTX API for automatic Swagger documentation
api = Api(
    title='AccessVault API',
    version='1.0',
    description='Secure User Management API with JWT Authentication',
    doc='/api/swagger-ui/',
    prefix="/api"
)

# Get Redis URL from environment, fallback to in-memory for development
redis_url = os.getenv("RATELIMIT_STORAGE_URL", "memory://")

limiter = Limiter(
    key_func=get_remote_address,   # identifies client by IP
    storage_uri=redis_url,         # Redis storage for rate limiting
    default_limits=["100 per day", "20 per hour", "5 per minute"],  # fallback limits
    swallow_errors=True            # Don't fail if Redis is unavailable
)