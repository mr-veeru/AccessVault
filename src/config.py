"""
AccessVault Configuration Module

This module contains all configuration settings for the Flask application.
It includes database connection, and security configurations.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()   # loads environment variables from .env

class Config:
    """Configuration class for Flask application"""
    SECRET_KEY = os.getenv("SECRET_KEY")    # Flask secret key for session management and security
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")    # JWT secret key for authentication
    SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")    # Database connection configuration
    SQLALCHEMY_TRACK_MODIFICATIONS = False    # Disable SQLAlchemy event system
    
    # JWT Token Configuration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)  # Access token expires in 1 hour
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)  # Refresh token expires in 7 days