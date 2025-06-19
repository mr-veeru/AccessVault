import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
sys.path.append(project_root)

# Load environment variables
load_dotenv(os.path.join(project_root, '.env'))

from shared.db import db, init_db
from shared.config import Config
from shared.models import User
from flask import Flask

def create_admin(username, email, password, name):
    """Create the first admin user."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    with app.app_context():
        init_db(app)
        
        # Check if admin already exists
        if User.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists.")
            return
        
        # Create admin user
        admin = User(
            username=username,
            email=email,
            name=name,
            role='admin'
        )
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        
        print(f"Admin user '{username}' created successfully.")
        print(f"   Email: {email}")
        print(f"   Name: {name}")
        print(f"   Role: admin")

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python init_db.py <username> <email> <password> <name>")
        print("Example: python init_db.py admin admin@example.com StrongPass!123 Admin User")
        sys.exit(1)
    
    username = sys.argv[1]
    email = sys.argv[2]
    password = sys.argv[3]
    name = sys.argv[4]
    
    create_admin(username, email, password, name) 