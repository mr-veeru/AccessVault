"""
Database Initialization Script

This script initializes the database by creating all tables defined in the models.
It should be run before starting the application to ensure the database schema
is properly set up.

Note: This uses SQLAlchemy's create_all() method.
"""

from app import create_app
from src.extensions import db

# Create Flask app instance
app = create_app()

# Initialize database within app context
with app.app_context():
    try:
        # Create all tables defined in the models
        db.create_all()
        print("Database tables created successfully")
    except Exception as e:
        exit(f"Error creating database tables: {str(e)}")
