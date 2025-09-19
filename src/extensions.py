"""
Flask Extensions Module

This module initializes Flask extensions that are used throughout the application.
Extensions are initialized here to avoid circular imports and enable proper
initialization order.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api

# Initialize Flask extensions
# These will be initialized with the app in the create_app() function
db = SQLAlchemy()      # Database ORM for PostgreSQL operations

# Flask-RESTX API for automatic Swagger documentation
api = Api(
    title='AccessVault API',
    version='1.0',
    description='Secure User Management API with JWT Authentication',
    doc='/api/swagger-ui/',
    prefix="/api"
)