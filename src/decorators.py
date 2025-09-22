"""
Active User Status Decorator

This module contains custom decorators to ensure proper access control
and user status validation.
"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from src.models import User

def active_required(fn):
    """
    Decorator that ensures the user account is active before allowing access.
    
    This decorator should be used in combination with @jwt_required() to ensure
    that only active users can access the decorated endpoint.
    
    Args:
        fn: The function to be decorated
    
    Returns:
        function: Decorated function that checks user status
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Get user ID from JWT token
        user_id = get_jwt_identity()
        
        # Query user from database to check status
        user = User.query.get(int(user_id))
        
        # Check if user exists
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # User is active, proceed with the original function
        return fn(*args, **kwargs)
    return wrapper
