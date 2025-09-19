#!/usr/bin/env python3
"""
Token Cleanup Script

This script cleans up expired and revoked refresh tokens from the database.
It should be run periodically (e.g., via cron job) to maintain database hygiene.

Usage:
    python scripts/cleanup_tokens.py
"""

import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from src.extensions import db
from src.models import RefreshToken, PasswordResetToken
from src.logger import logger
from datetime import datetime, timedelta

def cleanup_tokens():
    """Clean up expired and revoked refresh tokens and password reset tokens"""
    app = create_app()
    
    with app.app_context():
        try:
            # Clean up RefreshTokens
            expired_refresh = RefreshToken.query.filter(
                RefreshToken.expires_at < datetime.utcnow()
            ).delete()
            
            revoked_refresh = RefreshToken.query.filter(
                RefreshToken.is_revoked == True,
                RefreshToken.created_at < datetime.utcnow() - timedelta(hours=24)
            ).delete()
            
            # Clean up PasswordResetTokens
            expired_password_reset = PasswordResetToken.query.filter(
                PasswordResetToken.expires_at < datetime.utcnow()
            ).delete()
            
            used_password_reset = PasswordResetToken.query.filter(
                PasswordResetToken.used == True,
                PasswordResetToken.created_at < datetime.utcnow() - timedelta(hours=24)
            ).delete()
            
            db.session.commit()
            
            total_cleaned = expired_refresh + revoked_refresh + expired_password_reset + used_password_reset
            
            if total_cleaned > 0:
                logger.info(f"Scheduled token cleanup completed: {expired_refresh} expired refresh, {revoked_refresh} revoked refresh, {expired_password_reset} expired password reset, {used_password_reset} used password reset tokens removed")
                print(f"✅ Token cleanup completed:")
                print(f"   - {expired_refresh} expired refresh tokens")
                print(f"   - {revoked_refresh} revoked refresh tokens")
                print(f"   - {expired_password_reset} expired password reset tokens")
                print(f"   - {used_password_reset} used password reset tokens")
                print(f"   Total: {total_cleaned} tokens removed")
            else:
                print("✅ No tokens to clean up")
            
            return total_cleaned
            
        except Exception as e:
            logger.error(f"Scheduled token cleanup failed: {str(e)}")
            print(f"❌ Token cleanup failed: {str(e)}")
            db.session.rollback()
            return 0

if __name__ == "__main__":
    cleanup_tokens()
