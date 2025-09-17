"""
AccessVault Flask Application Factory

This module contains the Flask application factory pattern implementation.
It initializes all extensions, registers blueprints, and scheduled tasks.
"""

from flask import Flask, jsonify
from sqlalchemy.exc import SQLAlchemyError
from extensions import db, jwt, bcrypt, limiter, api
from routes.auth import auth_ns
from routes.profile import profile_ns
from routes.admin import admin_ns
from routes.health import health_ns
from logger import logger
from flask_apscheduler import APScheduler
from datetime import datetime, timedelta
from models import PasswordResetToken


# Initialize APScheduler
scheduler = APScheduler()

# Cleanup expired password reset tokens
def cleanup_tokens():
    with scheduler.app.app_context():
        cutoff = datetime.utcnow() - timedelta(days=30)
        expired_tokens = PasswordResetToken.query.filter(
            PasswordResetToken.expires_at < cutoff
        ).all()

        count = len(expired_tokens)
        for token in expired_tokens:
            db.session.delete(token)

        db.session.commit()
        logger.info(f"[Cleanup] Deleted {count} expired tokens older than 30 days")

# Create app
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
    api.init_app(app)     # Flask-RESTX for Swagger documentation

    # Register all namespaces for Swagger documentation
    api.add_namespace(auth_ns)      # Authentication routes
    api.add_namespace(profile_ns)   # Profile routes
    api.add_namespace(admin_ns)     # Admin routes
    api.add_namespace(health_ns)    # Health check routes


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
        logger.error(f"Database error occurred: {str(err)}")
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(err)}"}), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        """Handle unexpected errors with generic error response."""
        logger.error(f"Unexpected error occurred: {str(err)}")
        return jsonify({"error": f"Internal server error: {str(err)}"}), 500

    return app


# Run the server only if this file is executed directly
if __name__ == "__main__":
    # Create app instance and run in debug mode
    # Note: debug=True should be disabled in production
    app = create_app()
    app.run(debug=True)
    