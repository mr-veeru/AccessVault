"""Shared pytest fixtures for AccessVault API tests.

Uses SQLite in-memory — no PostgreSQL or Redis required.
"""

import os

# Must set env before importing the app (Config reads env at import time)
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["JWT_SECRET_KEY"] = "test-jwt-secret-key"
os.environ["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
os.environ["RATELIMIT_STORAGE_URL"] = "memory://"
os.environ["BLOCKLIST_REDIS_URL"] = "memory://"
os.environ["FLASK_ENV"] = "testing"
os.environ["FLASK_DEBUG"] = "false"
os.environ["LOG_LEVEL"] = "ERROR"

import pytest

# Import the single app instance created at package load (Flask-RESTX
# namespaces bind to that instance; a second create_app() would 404).
from app import app as flask_app
from app.extensions import db, bcrypt, limiter
from app.models import User

# Limiter is initialized at import; disable for the whole test process
limiter.enabled = False


@pytest.fixture()
def app():
    flask_app.config.update(
        {
            "TESTING": True,
            "RATELIMIT_ENABLED": False,
        }
    )
    limiter.enabled = False
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def password():
    return "SecurePass123!"


def _create_user(name, username, password, role="user", status="active"):
    user = User(
        name=name,
        username=username.lower(),
        password=bcrypt.generate_password_hash(password).decode("utf-8"),
        role=role,
        status=status,
    )
    db.session.add(user)
    db.session.commit()
    return user.id


@pytest.fixture()
def user(app, password):
    with app.app_context():
        user_id = _create_user("Test User", "user123", password, role="user")
        return {"id": user_id, "username": "user123"}


@pytest.fixture()
def admin(app, password):
    with app.app_context():
        user_id = _create_user("Admin User", "admin123", password, role="admin")
        return {"id": user_id, "username": "admin123"}


@pytest.fixture()
def auth_headers(client, user, password):
    response = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": password},
    )
    data = response.get_json()
    assert response.status_code == 200, data
    return {"Authorization": f"Bearer {data['access_token']}"}


@pytest.fixture()
def admin_headers(client, admin, password):
    response = client.post(
        "/api/auth/login",
        json={"username": "admin123", "password": password},
    )
    data = response.get_json()
    assert response.status_code == 200, data
    return {"Authorization": f"Bearer {data['access_token']}"}


@pytest.fixture()
def login_tokens(client, password):
    """Factory: log in as username and return (access, refresh) tokens."""

    def _login(username):
        response = client.post(
            "/api/auth/login",
            json={"username": username, "password": password},
        )
        data = response.get_json()
        assert response.status_code == 200, data
        return data["access_token"], data["refresh_token"]

    return _login
