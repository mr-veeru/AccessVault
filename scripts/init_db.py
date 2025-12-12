"""
Database Initialization Script

This script initializes the database using Flask-Migrate.
It creates the initial migration and applies it to create all tables.

Usage:
    # Automated (recommended for first-time setup)
    python -m scripts.init_db
    
    # Manual (for more control)
    flask db init
    flask db migrate -m "Initial migration"
    flask db upgrade
"""

from app import create_app
from src.extensions import db
from flask_migrate import init, migrate, upgrade
import sys
import os

# Create Flask app instance
app = create_app()

# Initialize database within app context
with app.app_context():
    try:
        # Get project root directory
        project_root = os.path.dirname(os.path.dirname(__file__))
        migrations_dir = os.path.join(project_root, 'migrations')
        
        # Check if migrations directory exists
        if not os.path.exists(migrations_dir):
            print("Initializing migrations directory...")
            init()
            print("✓ Migrations directory created")
        else:
            print("✓ Migrations directory already exists")
        
        # Create initial migration (only if no migrations exist)
        versions_dir = os.path.join(migrations_dir, 'versions')
        if not os.path.exists(versions_dir) or not os.listdir(versions_dir):
            print("Creating initial migration from models...")
            migrate(message="Initial migration")
            print("✓ Migration created")
        else:
            print("✓ Migrations already exist")
        
        # Apply migration to create tables
        print("Applying migration to database...")
        upgrade()
        print("✓ Database tables created successfully")
        print("\n✅ Database initialization complete!")
        print("\nFor future schema changes:")
        print("  1. flask db migrate -m 'Description of changes'")
        print("  2. flask db upgrade")
        
    except Exception as e:
        print(f"\n❌ Error initializing database: {str(e)}")
        print("\nIf migrations already exist, you can manually run:")
        print("  flask db upgrade")
        print("\nOr create a new migration:")
        print("  flask db migrate -m 'Migration message'")
        print("  flask db upgrade")
        sys.exit(1)
