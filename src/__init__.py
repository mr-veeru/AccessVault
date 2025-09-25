"""
AccessVault Application Package

This package contains error handling and global configurations
for the Flask application.
"""

from flask import jsonify
from src.logger import logger
from sqlalchemy.exc import SQLAlchemyError
import redis


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

    @app.errorhandler(429)
    def handle_rate_limit_exceeded(err):
        """Handle rate limit exceeded errors."""
        logger.warning(f"Rate limit exceeded: {str(err)}")
        return jsonify({
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later."
        }), 429

    @app.errorhandler(422)
    def handle_jwt_errors(err):
        """Handle JWT token errors."""
        logger.warning(f"JWT error: {str(err)}")
        return jsonify({
            "error": "Invalid token",
            "message": "Please login again."
        }), 422

    @app.errorhandler(redis.ConnectionError)
    def handle_redis_connection_error(err):
        """Handle Redis connection errors gracefully."""
        logger.warning(f"Redis connection error: {str(err)}")
        return jsonify({
            "error": "Service temporarily unavailable",
            "message": "Rate limiting service is currently unavailable. Please try again later.",
            "status": "degraded"
        }), 503

    @app.errorhandler(redis.RedisError)
    def handle_redis_error(err):
        """Handle general Redis errors."""
        logger.warning(f"Redis error: {str(err)}")
        return jsonify({
            "error": "Service temporarily unavailable",
            "message": "Rate limiting service error. Please try again later.",
            "status": "degraded"
        }), 503

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        """Handle unexpected errors with generic error response."""
        logger.error(f"Unexpected error occurred: {str(err)}")
        return jsonify({
            "error": "Internal server error",
            "message": "An unexpected error occurred. Please try again later."
        }), 500