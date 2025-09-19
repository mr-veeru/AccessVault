"""
Routes Package

This package contains all API route modules organized by functionality.
"""

from .health import health_bp

__all__ = ['health_bp']
