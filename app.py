"""
AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management.
Features JWT authentication, role-based access control, rate limiting, and comprehensive logging.

Author: Veerendra
Version: 1.0.0
"""

from flask import Flask, jsonify
from src.extensions import db, jwt, bcrypt, limiter, api
from src.routes import auth_ns, profile_ns, admin_ns, health_ns
from src.config import Config
from src import register_error_handlers

# Create app
def create_app():
    """
    Application factory function that creates and configures the Flask app.
    
    Returns:
        Flask: Configured Flask application instance
    """
    # Create Flask application instance and load configuration from config.py
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize Flask extensions with the app
    db.init_app(app)      # SQLAlchemy for database operations
    jwt.init_app(app)     # JWT for authentication
    bcrypt.init_app(app)  # Bcrypt for password hashing
    limiter.init_app(app) # Rate limiting
    api.init_app(app)     # Flask-RESTX for Swagger documentation

    # Register all namespaces for Swagger documentation
    api.add_namespace(health_ns)    # Health check routes
    api.add_namespace(auth_ns)      # Authentication routes
    api.add_namespace(profile_ns)   # Profile routes
    api.add_namespace(admin_ns)     # Admin routes

    # Register error handlers
    register_error_handlers(app)

    # Simple home endpoint (register last to override Flask-RESTX root)
    @app.route('/')
    def home():
        """Simple home endpoint"""
        return jsonify({
            "message": "AccessVault API is running 🚀",
            "status": "healthy",
            "version": "1.0.0",
            "endpoints": {
                "health": "/health",
                "swagger": "/swagger-ui/"
            }
        })
    
    return app


# Create the Flask application instance for Gunicorn
app = create_app()

# Run the server only if this file is executed directly
if __name__ == "__main__":
    # For local development
    app.run(debug=False)