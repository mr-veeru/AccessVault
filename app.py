"""
AccessVault Flask Application Factory

This module contains the Flask application factory pattern implementation.
It initializes all extensions, registers blueprints
"""

from flask import Flask, jsonify
from extensions import db, jwt, bcrypt
from routes.auth import auth_bp
from routes.profile import profile_bp
from routes.admin import admin_bp


def create_app():
    """
    Application factory function that creates and configures the Flask app.
    
    Returns:
        Flask: Configured Flask application instance
    """
    # Create Flask application instance and load configuration from config.py
    app = Flask(__name__)
    app.config.from_object("config")
    
    # Initialize Flask extensions with the app
    db.init_app(app)      # SQLAlchemy for database operations
    jwt.init_app(app)     # JWT for authentication
    bcrypt.init_app(app)  # Bcrypt for password hashing

    # Register blueprints with URL prefixes
    app.register_blueprint(auth_bp, url_prefix="/auth")        # Authentication routes
    app.register_blueprint(profile_bp, url_prefix="/profile")    # Profile routes
    app.register_blueprint(admin_bp, url_prefix="/admin")       # Admin routes

    # Health check endpoint - simple route to verify API is running
    @app.route("/")
    def home():
        """Health check endpoint that returns API status."""
        return jsonify({"message": "AccessVault API is running..."})

    return app


# Run the server only if this file is executed directly
if __name__ == "__main__":
    # Create app instance and run in debug mode
    # Note: debug=True should be disabled in production
    app = create_app()
    app.run(debug=True)
    