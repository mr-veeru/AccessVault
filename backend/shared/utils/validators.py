import re
from shared.config import Config

def validate_email(email):
    """Validate email format and convert to lowercase."""
    if not email:
        return False
    email = email.lower()
    pattern = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username):
    """Validate username format and convert to lowercase."""
    if not username:
        return False
    username = username.lower()
    # Username should only contain lowercase letters, numbers, and underscores
    pattern = r'^[a-z0-9_]+$'
    return bool(re.match(pattern, username))

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