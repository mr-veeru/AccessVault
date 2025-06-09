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
from admin_service.models import Admin
from flask import Flask

def create_admin(username, email, password):
    """Create the first admin user."""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    with app.app_context():
        init_db(app)
        
        # Check if admin already exists
        if Admin.query.filter_by(username=username).first():
            print(f"Admin user '{username}' already exists.")
            return
        
        # Create admin user
        admin = Admin(
            username=username,
            email=email,
            role='admin'
        )
        admin.set_password(password)
        
        db.session.add(admin)
        db.session.commit()
        
        print(f"Admin user '{username}' created successfully.")

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python init_db.py <username> <email> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    email = sys.argv[2]
    password = sys.argv[3]
    
    create_admin(username, email, password) 