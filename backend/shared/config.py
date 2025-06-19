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
    
    # Rate limiting configuration
    RATE_LIMIT_DEFAULT = "200 per day, 50 per hour"
    RATE_LIMIT_AUTH = "5 per minute, 50 per hour"
    RATE_LIMIT_AUTH_ADMIN = "10 per minute, 100 per hour"
    RATE_LIMIT_PASSWORD_CHANGE = "3 per hour"
    RATE_LIMIT_USER_MANAGEMENT = "30 per minute, 1000 per hour"
    RATE_LIMIT_PROFILE = "60 per minute, 2000 per hour"
    
    # Logging configuration
    LOG_MAX_FILE_SIZE_MB = int(os.getenv('LOG_MAX_FILE_SIZE_MB', 5))
    LOG_BACKUP_COUNT = int(os.getenv('LOG_BACKUP_COUNT', 3))
    LOG_RETENTION_DAYS = int(os.getenv('LOG_RETENTION_DAYS', 3))
    LOG_MAX_TOTAL_SIZE_MB = int(os.getenv('LOG_MAX_TOTAL_SIZE_MB', 100))
    
    # Frontend configuration
    REACT_APP_ORIGIN = os.getenv('REACT_APP_ORIGIN', 'http://localhost:3000') 