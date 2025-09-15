"""
Admin User Creation Script

This script creates a default admin user for the AccessVault system.
It should be run after the database has been initialized to create
the initial administrative account.

Default admin credentials:
- Name: Administrator
- Username: admin66
- Password: Admin@123
- Role: admin
- Status: active
"""

import sys
import os

# Add the parent directory to the Python path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from extensions import bcrypt, db
from models import User
from app import create_app

# Create Flask app instance
app = create_app()

# Execute admin creation within app context
with app.app_context():
    # Default admin credentials
    username = "admin66"
    raw_password = "Admin@123"
    name = "Administrator"

    # Hash the password using bcrypt for secure storage
    hashed_pwd = bcrypt.generate_password_hash(raw_password).decode("utf-8")

    # Create admin user instance with admin role and active status
    admin = User(name=name, username=username, password=hashed_pwd, role="admin")
    
    # Save admin to database
    db.session.add(admin)
    db.session.commit()
    print("Admin created successfully!")
