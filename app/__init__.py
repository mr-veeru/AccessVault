"""
AccessVault Application Package

Flask application factory and app instance.
"""

from flask import Flask, jsonify, g, request

from .config import Config
from .extensions import db, jwt, bcrypt, limiter, cors, migrate, api
from .redis_blocklist import init_redis_blocklist
from .routes import health_ns, auth_ns, profile_ns, admin_ns
from .logger import logger
from .routes.auth import is_token_revoked
from .error_handlers import register_error_handlers

import uuid


_namespaces_registered = False


def create_app(config_overrides=None):
    """Create and configure the Flask application.

    Args:
        config_overrides: Optional dict merged into app.config (used by tests).
    """
    global _namespaces_registered

    app = Flask(__name__)
    app.config.from_object(Config)
    if config_overrides:
        app.config.update(config_overrides)

    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI") or ""
    if db_uri.startswith("sqlite"):
        from sqlalchemy.pool import StaticPool

        app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
            "connect_args": {"check_same_thread": False},
            "poolclass": StaticPool,
        }

    db.init_app(app)
    migrate.init_app(app, db)
    api.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)

    init_redis_blocklist(app.config.get("BLOCKLIST_REDIS_URL", Config.BLOCKLIST_REDIS_URL))

    cors.init_app(app, resources={
        r"/api/*": {
            "origins": app.config.get("CORS_ORIGINS", Config.CORS_ORIGINS),
            "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Request-ID"],
            "expose_headers": ["Content-Type", "X-Request-ID"],
            "supports_credentials": True
        }
    })

    jwt.token_in_blocklist_loader(is_token_revoked)

    if not _namespaces_registered:
        api.add_namespace(health_ns)
        api.add_namespace(auth_ns)
        api.add_namespace(profile_ns)
        api.add_namespace(admin_ns)
        _namespaces_registered = True

    register_error_handlers(app)

    @app.before_request
    def add_request_id():
        request_id = request.headers.get('X-Request-ID')
        if not request_id:
            request_id = str(uuid.uuid4())
        g.request_id = request_id

    @app.after_request
    def add_request_id_header(response):
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response

    @app.route('/')
    def home():
        logger.info("Home endpoint called")
        return jsonify({
            "message": "AccessVault API is running",
            "status": "healthy",
            "version": "1.0.0",
            "endpoints": {
                "health": "/api/health",
                "swagger": "/api/swagger-ui/"
            }
        })

    return app


app = create_app()
