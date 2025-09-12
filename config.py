"""
AccessVault Configuration Module

This module contains all configuration settings for the Flask application.
It includes database connection, and security configurations.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()   # loads environment variables from .env

SECRET_KEY = os.getenv("SECRET_KEY")    # Flask secret key for session management and security
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")    # JWT secret key for token signing  
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", 15)))  # JWT token expiration settings
JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", 7)))  # JWT refresh token expiration settings
SQLALCHEMY_DATABASE_URI = os.getenv("SQLALCHEMY_DATABASE_URI")    # Database connection configuration
SQLALCHEMY_TRACK_MODIFICATIONS = False    # Disable SQLAlchemy event system
