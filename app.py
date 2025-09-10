"""
AccessVault Flask Application Factory

This module contains the Flask application factory pattern implementation.
It initializes all extensions
"""

from flask import Flask, jsonify
from extensions import db


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
    