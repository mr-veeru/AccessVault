"""
Health Check Routes Module

Provides a single GET /api/health/ endpoint that checks database, Redis,
JWT config, and Flask config. Used by load balancers and monitoring.
Config is read via current_app.config only; storage URIs are redacted in responses.
"""
import sys
import flask
import redis
from datetime import datetime, timezone
from flask import current_app
from flask_restx import Namespace, Resource, fields
from sqlalchemy import text
from ..extensions import db, limiter
from ..redis_blocklist import blocklist_redis
from ..logger import logger


# Create health check namespace
health_ns = Namespace("health", description="Health check operations")

# Response models for Swagger documentation
health_check_model = health_ns.model(
    "HealthCheck",
    {
        "status": fields.String(description="Overall health status"),
        "timestamp": fields.String(description="Check timestamp"),
        "service": fields.String(description="Service name"),
        "version": fields.String(description="API version"),
        "checks": fields.Raw(description="Individual check results"),
        "system": fields.Raw(description="System information"),
    },
)


# Check helpers (each returns a dict for health_status["checks"][key])


def _check_database():
    """Check database connectivity."""
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "healthy", "message": "Database connection successful", "type": "PostgreSQL"}
    except Exception as e:
        logger.error(f"Database connection failed: {str(e)}")
        return {"status": "unhealthy", "message": str(e), "type": "PostgreSQL"}


def _redact_storage_uri(uri):
    """Return a safe, non-sensitive value for health response (never expose credentials)."""
    if not uri or uri == "memory://":
        return "memory://"
    if uri.startswith("redis://"):
        return "redis://***"
    return "***"


def _check_redis_connection(uri, client=None):
    """
    Check Redis connectivity. Returns dict with status, type, connected, uri (internal).
    If uri is not redis://, treats as memory (healthy, not connected).
    """
    if not uri.startswith("redis://"):
        return {"status": "healthy", "type": "Memory", "connected": False, "uri": uri}
    try:
        (client or redis.from_url(uri)).ping()
        return {"status": "healthy", "type": "Redis", "connected": True, "uri": uri}
    except Exception:
        return {
            "status": "degraded",
            "type": "Unavailable" if client else "Memory",
            "connected": False,
            "uri": uri,
        }


def _check_jwt_config(app):
    """Check JWT secret is configured."""
    try:
        secret = app.config.get("JWT_SECRET_KEY")
        if secret:
            return {"status": "healthy", "message": "JWT configuration valid"}
        return {"status": "unhealthy", "message": "JWT secret key not configured"}
    except Exception as e:
        logger.error(f"JWT configuration error: {str(e)}")
        return {"status": "unhealthy", "message": str(e)}


def _check_flask_secret(app):
    """Check Flask SECRET_KEY is configured."""
    try:
        secret = app.config.get("SECRET_KEY")
        if secret:
            return {"status": "healthy", "message": "Flask configuration valid"}
        return {"status": "unhealthy", "message": "Flask secret key not configured"}
    except Exception as e:
        logger.error(f"Flask configuration error: {str(e)}")
        return {"status": "unhealthy", "message": str(e)}


def _build_system_info():
    """Build system info dict (Python, Flask, env, debug)."""
    return {
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "flask_version": flask.__version__,
        "environment": current_app.config.get("ENV", "development"),
        "debug_mode": current_app.config.get("DEBUG", False),
    }


# Endpoint

@health_ns.route("/")
class HealthStatus(Resource):
    """GET /api/health/ — aggregate health for database, Redis, JWT, Flask."""

    @limiter.limit("10 per minute")
    @health_ns.marshal_with(health_check_model, code=200)
    def get(self):
        app = current_app
        checks = {}

        # Database
        checks["database"] = _check_database()

        # Redis: rate limiting and token blocklist (URLs from config; never expose raw URI)
        rate_limit_url = current_app.config.get("RATELIMIT_STORAGE_URL", "memory://")
        blocklist_url = current_app.config.get("BLOCKLIST_REDIS_URL", "memory://")
        for name, uri, client, msg_ok, msg_fallback in [
            ("rate_limiting", rate_limit_url, None, "Rate limiting active using Redis storage", "Rate limiting active using Memory storage"),
            ("token_blocklist", blocklist_url, blocklist_redis, "Token blocklist active using Redis storage", "Token blocklist using fallback (Redis not configured)"),
        ]:
            r = _check_redis_connection(uri, client)
            checks[name] = {
                "status": r["status"],
                "message": msg_ok if r["connected"] else msg_fallback,
                "storage_type": r["type"],
                "storage_uri": _redact_storage_uri(r["uri"]),
            }

        # JWT and Flask config
        checks["jwt"] = _check_jwt_config(app)
        checks["flask"] = _check_flask_secret(app)

        # Overall status: unhealthy if any check is unhealthy
        unhealthy = any(c.get("status") == "unhealthy" for c in checks.values())
        status = "unhealthy" if unhealthy else "healthy"
        status_code = 503 if unhealthy else 200

        health_status = {
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
            "service": "AccessVault API",
            "version": "1.0.0",
            "checks": checks,
            "system": _build_system_info(),
        }

        logger.info(f"Health status: {status}")
        return health_status, status_code
