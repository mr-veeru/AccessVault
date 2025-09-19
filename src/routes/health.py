"""
Health Check Routes Module

This module contains health check endpoints for the AccessVault API.
"""

from datetime import datetime, timezone
import sys
from sqlalchemy import text
from flask import Blueprint, current_app as app
from src.extensions import db
import flask

# Create the health blueprint
health_bp = Blueprint('health', __name__)


# Health check endpoint
@health_bp.route('/')
def health_status():
    """
    Comprehensive health check for monitoring and load balancers.
    Checks database connectivity, JWT configuration, and Flask setup.
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "service": "AccessVault API",
        "version": "1.0.0",
        "checks": {},
        "system": {
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "flask_version": flask.__version__,
            "environment": app.config.get("ENV", "development"),
            "debug_mode": app.config.get("DEBUG", False)
        }
    }
    
    overall_healthy = True
    
    # Check database connectivity
    try:
        db.session.execute(text("SELECT 1"))
        health_status["checks"]["database"] = {
            "status": "healthy",
            "message": "Database connection successful"
        }
    except Exception as e:
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}"
        }
        overall_healthy = False
    

    # Check JWT configuration
    try:
        jwt_secret = app.config.get("JWT_SECRET_KEY")
        if jwt_secret:
            health_status["checks"]["jwt"] = {
                "status": "healthy",
                "message": "JWT configuration valid"
            }
        else:
            health_status["checks"]["jwt"] = {
                "status": "unhealthy",
                "message": "JWT secret key not configured"
            }
            overall_healthy = False
    except Exception as e:
        health_status["checks"]["jwt"] = {
            "status": "unhealthy",
            "message": f"JWT configuration error: {str(e)}"
        }
        overall_healthy = False
    

    # Check Flask configuration
    try:
        secret_key = app.config.get("SECRET_KEY")
        if secret_key:
            health_status["checks"]["flask"] = {
                "status": "healthy",
                "message": "Flask configuration valid"
            }
        else:
            health_status["checks"]["flask"] = {
                "status": "unhealthy",
                "message": "Flask secret key not configured"
            }
            overall_healthy = False
    except Exception as e:
        health_status["checks"]["flask"] = {
            "status": "unhealthy",
            "message": f"Flask configuration error: {str(e)}"
        }
        overall_healthy = False
    
    # Set overall status
    health_status["status"] = "healthy" if overall_healthy else "unhealthy"
    
    # Return appropriate status code
    status_code = 200 if overall_healthy else 503
    return health_status, status_code