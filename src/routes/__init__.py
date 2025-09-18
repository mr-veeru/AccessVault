"""
Routes Package

This package contains all API route modules organized by functionality.
"""

from .auth import auth_ns
from .profile import profile_ns
from .admin import admin_ns
from .health import health_ns

__all__ = ['auth_ns', 'profile_ns', 'admin_ns', 'health_ns']
