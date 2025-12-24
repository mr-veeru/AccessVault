"""
AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management.

Author: Veerendra
Version: 1.0.0
"""

from flask import Flask, jsonify, g, request
from src.config import Config
from src.extensions import db, jwt, bcrypt, limiter, cors, migrate, init_redis_blocklist
from src.routes import health_ns, auth_ns, profile_ns, admin_ns
from src import register_error_handlers
from src.logger import logger
from src.extensions import api
from src.routes.auth import is_token_revoked
import uuid


# Create the Flask app
def create_app():
    """Create and configure the Flask application."""
    # Create Flask application instance and load configuration from config.py
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)  # Initialize Flask-Migrate for database migrations
    api.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    
    # Initialize Redis for token blocklisting
    init_redis_blocklist()
    
    # Configure CORS
    cors.init_app(app, resources={
        r"/api/*": {
            "origins": Config.CORS_ORIGINS,
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Request-ID"],
            "expose_headers": ["Content-Type", "X-Request-ID"],
            "supports_credentials": True
        }
    })
    
    # Register JWT token revocation callback
    jwt.token_in_blocklist_loader(is_token_revoked)

    # Register namespaces
    api.add_namespace(health_ns)
    api.add_namespace(auth_ns)
    api.add_namespace(profile_ns)
    api.add_namespace(admin_ns)

    # Register error handlers
    register_error_handlers(app)
    
    # Request ID tracking middleware
    @app.before_request
    def add_request_id():
        """Generate and attach request ID to all requests."""
        # Check if request ID is provided in headers (for distributed tracing)
        request_id = request.headers.get('X-Request-ID')
        if not request_id:
            request_id = str(uuid.uuid4())
        g.request_id = request_id
    
    @app.after_request
    def add_request_id_header(response):
        """Add request ID to response headers."""
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response

    # Simple home endpoint (register last to override Flask-RESTX root)
    @app.route('/')
    def home():
        """Simple home endpoint"""
        logger.info("Home endpoint called")
        return jsonify({
            "message": "AccessVault API is running",
            "status": "healthy",
            "version": "1.0.0",
            "endpoints": {
                "health": "/api/health",
                "swagger": "/api/swagger-ui/"
            }
        })

    return app

# Create the Flask application instance
app = create_app()

# Run the server only if this file is executed directly
if __name__ == "__main__":
    app.run(debug=app.config.get('DEBUG', False))