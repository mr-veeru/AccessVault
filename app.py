"""
AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management.

Author: Veerendra
Version: 1.0.0
"""

from flask import Flask, jsonify
from src.config import Config
from src.extensions import db
from src.routes import health_bp

# Create the Flask app
def create_app():
    """Create and configure the Flask application."""

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    app.register_blueprint(health_bp, url_prefix='/health')

    # Simple home endpoint (register last to override Flask-RESTX root)
    @app.route('/')
    def home():
        """Simple home endpoint"""
        return jsonify({
            "message": "AccessVault API is running",
            "status": "healthy",
            "version": "1.0.0"
        })

    return app

# Create the Flask application instance
app = create_app()

# Run the server only if this file is executed directly
if __name__ == "__main__":
    app.run(debug=True)
