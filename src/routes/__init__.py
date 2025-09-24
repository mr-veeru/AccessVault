"""
Routes Package

This package contains all API route modules organized by functionality.
"""

from .health import health_ns
from .auth import auth_ns
from .profile import profile_ns
from .admin import admin_ns

__all__ = ['health_ns', 'auth_ns', 'profile_ns', 'admin_ns']
