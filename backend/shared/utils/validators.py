import re
from shared.config import Config

def validate_email(email):
    """Validate email format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """Validate password strength."""
    if len(password) < Config.PASSWORD_MIN_LENGTH:
        return f'Password must be at least {Config.PASSWORD_MIN_LENGTH} characters long.'
    
    if Config.PASSWORD_REQUIRE_UPPER and not re.search(r'[A-Z]', password):
        return 'Password must contain at least one uppercase letter.'
    
    if Config.PASSWORD_REQUIRE_LOWER and not re.search(r'[a-z]', password):
        return 'Password must contain at least one lowercase letter.'
    
    if Config.PASSWORD_REQUIRE_DIGIT and not re.search(r'\d', password):
        return 'Password must contain at least one digit.'
    
    if Config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return 'Password must contain at least one special character.'
    
    return True

def validate_username(username):
    """Validate username format."""
    # Username should be 3-20 characters long and contain only letters, numbers, and underscores
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return bool(re.match(pattern, username)) 