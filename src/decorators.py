"""
Active User Status Decorator

This module contains custom decorators to ensure proper access control
and user status validation.
"""

from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required, get_jwt
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
            return {"error": "User not found"}, 404

        # Check if user is active
        if user.status != "active":
            return {"error": "Account is deactivated. Please contact admin."}, 403
        
        # User is active, proceed with the original function
        return fn(*args, **kwargs)
    return wrapper


def role_required(required_role):
    """
    Decorator factory that creates a decorator to check if the user has the required role.
    This decorator automatically includes JWT verification.
    
    Args:
        required_role (str): The role required to access the decorated function ('user' or 'admin')
    
    Returns:
        function: Decorator that verifies JWT and checks user role
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            # Get JWT claims
            claims = get_jwt()
            
            # Check if role information is present in the JWT claims
            if not claims or "role" not in claims:
                return jsonify({"error": "Role information missing"}), 403
            
            # Check if user has the required role
            user_role = claims["role"]
            if user_role != required_role:
                return jsonify({"error": f"Forbidden. {required_role.title()} role required!"}), 403
            
            # User has required role, proceed with the original function
            return fn(*args, **kwargs)
        return wrapper
    return decorator
