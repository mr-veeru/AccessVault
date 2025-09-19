"""
AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management.

Author: Veerendra
Version: 1.0.0
"""

from flask import Flask, jsonify
from src.config import Config
from src.extensions import db
from src.routes import health_ns
from src import register_error_handlers
from src.logger import logger
from src.extensions import api


# Create the Flask app
def create_app():
    """Create and configure the Flask application."""
    # Create Flask application instance and load configuration from config.py
    app = Flask(__name__)
    app.config.from_object(Config)

    logger.info("Initializing Flask application")

    # Initialize extensions
    db.init_app(app)
    api.init_app(app)

    # Register namespaces
    api.add_namespace(health_ns)

    # Register error handlers
    register_error_handlers(app)

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
                "health": "/health",
                "swagger": "/api/swagger-ui/"
            }
        })

    return app

# Create the Flask application instance
app = create_app()

# Run the server only if this file is executed directly
if __name__ == "__main__":
    app.run(debug=True)
