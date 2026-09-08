"""Admin endpoint and password-reset tests."""

from datetime import datetime, timedelta

from app.extensions import db
from app.models import PasswordResetToken


def test_user_cannot_access_admin(client, auth_headers):
    response = client.get("/api/admin/users", headers=auth_headers)
    assert response.status_code == 403


def test_admin_list_users(client, admin_headers, user):
    response = client.get("/api/admin/users", headers=admin_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "success"
    usernames = {u["username"] for u in data["data"]}
    assert "user123" in usernames
    assert "admin123" in usernames


def test_admin_stats(client, admin_headers, user):
    response = client.get("/api/admin/stats", headers=admin_headers)
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["total_users"] >= 2
    assert data["admins"] >= 1


def test_admin_create_user(client, admin_headers):
    response = client.post(
        "/api/admin/users",
        headers=admin_headers,
        json={"name": "Created User", "username": "created1", "role": "user"},
    )
    assert response.status_code == 201
    data = response.get_json()["data"]
    assert data["username"] == "created1"
    # Current behavior: fixed default password (Phase 2 will change this)
    assert data["default_password"] == "User@123"

    login = client.post(
        "/api/auth/login",
        json={"username": "created1", "password": "User@123"},
    )
    assert login.status_code == 200


def test_admin_deactivate_user(client, admin_headers, user):
    response = client.patch(
        f"/api/admin/users/{user['id']}/deactivate",
        headers=admin_headers,
    )
    assert response.status_code == 200
    assert response.get_json()["data"]["status"] == "inactive"


def test_admin_generate_reset_token(client, admin_headers, user):
    response = client.get(
        f"/api/admin/users/{user['id']}/generate-reset-token",
        headers=admin_headers,
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert "token" in data
    assert len(data["token"]) > 10


def test_reset_password_with_valid_token(client, app, admin_headers, user, password):
    gen = client.get(
        f"/api/admin/users/{user['id']}/generate-reset-token",
        headers=admin_headers,
    )
    token = gen.get_json()["data"]["token"]
    new_password = "ResetPass123!"

    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": token,
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert response.status_code == 200

    old_login = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": password},
    )
    assert old_login.status_code == 400

    new_login = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": new_password},
    )
    assert new_login.status_code == 200


def test_reset_password_invalid_token(client):
    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": "not-a-real-token",
            "new_password": "ResetPass123!",
            "confirm_password": "ResetPass123!",
        },
    )
    assert response.status_code == 400


def test_reset_password_expired_token(client, app, user):
    with app.app_context():
        expired = PasswordResetToken(
            user_id=user["id"],
            token="expiredtoken123456789012345678",
            expires_at=datetime.utcnow() - timedelta(hours=1),
            used=False,
        )
        db.session.add(expired)
        db.session.commit()

    response = client.post(
        "/api/auth/reset-password",
        json={
            "token": "expiredtoken123456789012345678",
            "new_password": "ResetPass123!",
            "confirm_password": "ResetPass123!",
        },
    )
    assert response.status_code == 400


def test_reset_password_used_token(client, admin_headers, user):
    gen = client.get(
        f"/api/admin/users/{user['id']}/generate-reset-token",
        headers=admin_headers,
    )
    token = gen.get_json()["data"]["token"]

    first = client.post(
        "/api/auth/reset-password",
        json={
            "token": token,
            "new_password": "ResetPass123!",
            "confirm_password": "ResetPass123!",
        },
    )
    assert first.status_code == 200

    second = client.post(
        "/api/auth/reset-password",
        json={
            "token": token,
            "new_password": "AnotherPass123!",
            "confirm_password": "AnotherPass123!",
        },
    )
    assert second.status_code == 400
