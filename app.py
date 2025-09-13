"""
AccessVault Flask Application Factory

This module contains the Flask application factory pattern implementation.
It initializes all extensions, registers blueprints
"""

from flask import Flask, jsonify
from sqlalchemy.exc import SQLAlchemyError
from extensions import db, jwt, bcrypt, limiter
from routes.auth import auth_bp
from routes.profile import profile_bp
from routes.admin import admin_bp
from routes.health import health_bp


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
    limiter.init_app(app) # Rate limiting

    # Register blueprints with URL prefixes
    app.register_blueprint(auth_bp, url_prefix="/auth")         # Authentication routes
    app.register_blueprint(profile_bp, url_prefix="/profile")   # Profile routes
    app.register_blueprint(admin_bp, url_prefix="/admin")       # Admin routes
    app.register_blueprint(health_bp)                           # Health check routes


    # ---------- Global error handlers (consistent JSON responses) ----------
    @app.errorhandler(404)
    def handle_404(_):
        """Handle 404 Not Found errors with consistent JSON response."""
        return jsonify({"error": "Not Found"}), 404

    @app.errorhandler(405)
    def handle_405(_):
        """Handle 405 Method Not Allowed errors with consistent JSON response."""
        return jsonify({"error": "Method Not Allowed"}), 405

    @app.errorhandler(SQLAlchemyError)
    def handle_sqlalchemy_error(err: SQLAlchemyError):
        """Handle database-related errors with rollback and error response."""
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(err)}"}), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        """Handle unexpected errors with generic error response."""
        return jsonify({"error": f"Internal server error: {str(err)}"}), 500

    return app


# Run the server only if this file is executed directly
if __name__ == "__main__":
    # Create app instance and run in debug mode
    # Note: debug=True should be disabled in production
    app = create_app()
    app.run(debug=True)
    