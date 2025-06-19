from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def init_db(app):
    """Initialize the database with the Flask app."""
    db.init_app(app)
    
    with app.app_context():
        # Import the single Account model
        from shared.models import Account
        
        # Create all tables
        db.create_all() 