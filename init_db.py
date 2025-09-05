from app import create_app, db
from model import User  # Import the User model so SQLAlchemy knows about it

app = create_app()

with app.app_context():
    db.create_all()
