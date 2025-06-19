from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from shared.logger import setup_logging
from shared.config import Config

logger = setup_logging(__name__)

# Global limiter instance
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT_DEFAULT],
    storage_uri="memory://"
)

def apply_rate_limits(app):
    """
    Apply rate limits to the Flask app.
    
    Args:
        app: Flask app instance
    """
    limiter.init_app(app)

# Simple decorator functions that use Flask-Limiter's decorator approach
def auth_rate_limit(f):
    """Rate limit for authentication endpoints"""
    @limiter.limit(Config.RATE_LIMIT_AUTH)
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper

def password_change_rate_limit(f):
    """Rate limit for password change endpoints"""
    @limiter.limit(Config.RATE_LIMIT_PASSWORD_CHANGE)
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper

def user_management_rate_limit(f):
    """Rate limit for user management endpoints"""
    @limiter.limit(Config.RATE_LIMIT_USER_MANAGEMENT)
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper

def profile_rate_limit(f):
    """Rate limit for profile management endpoints"""
    @limiter.limit(Config.RATE_LIMIT_PROFILE)
    @wraps(f)
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper 