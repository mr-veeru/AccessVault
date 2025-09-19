"""
AccessVault Application Package

This package contains error handling and global configurations
for the Flask application.
"""

from flask import jsonify
from src.logger import logger
from sqlalchemy.exc import SQLAlchemyError


def register_error_handlers(app):
    """
    Register global error handlers for the Flask application.
    
    Args:
        app: Flask application instance
    """
    # ---------- Global error handlers (consistent JSON responses) ----------

    @app.errorhandler(400)
    def handle_400(_):
        """Handle 400 Bad Request errors with consistent JSON response."""
        return jsonify({"error": "Bad Request"}), 400

    @app.errorhandler(401)
    def handle_401(_):
        """Handle 401 Unauthorized errors with consistent JSON response."""
        return jsonify({"error": "Unauthorized"}), 401

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
        from src.extensions import db
        db.session.rollback()
        return jsonify({"error": f"Database error: {str(err)}"}), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        """Handle unexpected errors with generic error response."""
        logger.error(f"Unexpected error occurred: {str(err)}")
        return jsonify({"error": f"Internal server error: {str(err)}"}), 500