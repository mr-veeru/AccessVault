import os
from datetime import timedelta

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@localhost:5432/accessvault')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')  # Change in production
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Application configuration
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Admin service configuration
    ADMIN_SERVICE_PORT = int(os.getenv('ADMIN_SERVICE_PORT', 5001))
    
    # User service configuration
    USER_SERVICE_PORT = int(os.getenv('USER_SERVICE_PORT', 5002))
    
    # Security configuration
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGIT = True
    PASSWORD_REQUIRE_SPECIAL = True 