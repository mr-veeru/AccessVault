import os
from datetime import timedelta

class Config:
    # Database configuration
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres.gbreqktwgmgtpzgcbymw:mrveeru%40143@aws-0-ap-south-1.pooler.supabase.com:5432/postgres'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT configuration
    JWT_SECRET_KEY = 'your-secret-key'  # In production, use environment variable
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Service configuration
    AUTH_SERVICE_PORT = 5000
    USER_SERVICE_PORT = 5001 