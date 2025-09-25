#!/usr/bin/env python3
"""
Token Cleanup Script

This script cleans up expired tokens from the database.
Can be run manually or scheduled as a cron job.

Usage:
    python -m scripts.cleanup_tokens
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from src.extensions import db
from src.models import RevokedToken, PasswordResetToken
from datetime import datetime, timedelta

def cleanup_expired_tokens():
    """Clean up expired tokens from the database."""
    app = create_app()
    
    with app.app_context():
        current_time = datetime.utcnow()
        
        # Clean up expired JWT tokens (older than 7 days)
        expired_jwt_tokens = RevokedToken.query.filter(
            RevokedToken.revoked_at < current_time - timedelta(days=7)
        ).all()
        
        jwt_count = len(expired_jwt_tokens)
        for token in expired_jwt_tokens:
            db.session.delete(token)
        
        # Clean up expired password reset tokens
        expired_reset_tokens = PasswordResetToken.query.filter(
            PasswordResetToken.expires_at < current_time
        ).all()
        
        reset_count = len(expired_reset_tokens)
        for token in expired_reset_tokens:
            db.session.delete(token)
        
        db.session.commit()
        
        print(f"✅ Cleanup completed successfully!")
        print(f"   - Removed {jwt_count} expired JWT tokens")
        print(f"   - Removed {reset_count} expired password reset tokens")
        print(f"   - Total: {jwt_count + reset_count} tokens cleaned")

if __name__ == "__main__":
    try:
        cleanup_expired_tokens()
    except Exception as e:
        print(f"❌ Error during cleanup: {str(e)}")
        sys.exit(1)
