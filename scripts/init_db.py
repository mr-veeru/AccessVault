"""
Database Initialization Script

This script initializes the database by creating all tables defined in the models.
It should be run before starting the application to ensure the database schema
is properly set up.

Note: This uses SQLAlchemy's create_all() method.
"""

from app import create_app
from extensions import db

# Create Flask app instance
app = create_app()

# Initialize database within app context
with app.app_context():
    try:
        # Create all tables defined in the models
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Error creating database tables: {str(e)}")
        exit(1)
