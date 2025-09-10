"""
Profile Routes Module

This module handles user profile management operations.
All routes are prefixed with '/profile' and require authentication.
"""

from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from model import User
from decorators import active_required

# Create profile blueprint
profile_bp = Blueprint("profile", __name__)


@profile_bp.route("/", methods=["GET"])
@jwt_required()
@active_required
def get_my_profile():
    """
    Retrieve the current user's profile information.
    
    Requires:
        Valid JWT access token in Authorization header
        Active account status
    
    Returns:
        JSON response with user profile details (excluding password)
    """
    try:
        # Get user ID from JWT token and convert to integer for database query
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        # Verify user exists
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Return user profile information (excluding sensitive data like password)
        return jsonify({
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }), 200
    except Exception as e:
        # Handle unexpected errors gracefully
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500
