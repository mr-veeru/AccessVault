from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """Initialize the database with the Flask app."""
    db.init_app(app)
    
    with app.app_context():
        # Import all models here to ensure they are registered with SQLAlchemy
        from admin_service.models import Admin
        from user_service.models import User
        
        # Create all tables
        db.create_all() 