import os
import sys

# Add the project root directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shared.db import db
from auth_service.app import create_app
from auth_service.models import UserAuth

def create_admin():
    app = create_app()
    with app.app_context():
        # Check if admin already exists
        admin = UserAuth.query.filter_by(name="admin").first()
        if admin:
            print("Admin user already exists")
            return

        # Create admin user
        admin = UserAuth(
            name="admin",
            age=30,
            role="admin"
        )
        admin.set_password("admin123")
        
        db.session.add(admin)
        db.session.commit()
        print("Admin user created successfully")

if __name__ == "__main__":
    create_admin() 