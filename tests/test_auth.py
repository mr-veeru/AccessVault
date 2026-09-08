"""Authentication endpoint tests."""


VALID_PASSWORD = "SecurePass123!"


def test_register_success(client):
    response = client.post(
        "/api/auth/register",
        json={
            "name": "New User",
            "username": "newuser1",
            "password": VALID_PASSWORD,
            "confirm_password": VALID_PASSWORD,
        },
    )
    assert response.status_code == 201
    assert "registered" in response.get_json()["message"].lower()


def test_register_duplicate_username(client, user, password):
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Another",
            "username": "user123",
            "password": VALID_PASSWORD,
            "confirm_password": VALID_PASSWORD,
        },
    )
    assert response.status_code == 400
    assert "already exist" in response.get_json()["error"].lower()


def test_register_weak_password(client):
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Weak User",
            "username": "weakuser1",
            "password": "password",
            "confirm_password": "password",
        },
    )
    assert response.status_code == 400
    assert "password" in response.get_json()["error"].lower()


def test_register_password_mismatch(client):
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Mismatch User",
            "username": "mismatch1",
            "password": VALID_PASSWORD,
            "confirm_password": "OtherPass123!",
        },
    )
    assert response.status_code == 400
    assert "match" in response.get_json()["error"].lower()


def test_register_invalid_username(client):
    response = client.post(
        "/api/auth/register",
        json={
            "name": "Bad Username",
            "username": "ab",
            "password": VALID_PASSWORD,
            "confirm_password": VALID_PASSWORD,
        },
    )
    assert response.status_code == 400


def test_login_success(client, user, password):
    response = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": password},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_login_invalid_credentials(client, user):
    response = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": "WrongPass123!"},
    )
    assert response.status_code == 400
    assert "invalid" in response.get_json()["error"].lower()


def test_login_inactive_user(client, app, password):
    from app.extensions import db, bcrypt
    from app.models import User

    with app.app_context():
        inactive = User(
            name="Inactive",
            username="inactive1",
            password=bcrypt.generate_password_hash(password).decode("utf-8"),
            role="user",
            status="inactive",
        )
        db.session.add(inactive)
        db.session.commit()

    response = client.post(
        "/api/auth/login",
        json={"username": "inactive1", "password": password},
    )
    assert response.status_code == 403


def test_refresh_success(client, user, login_tokens):
    access, refresh = login_tokens("user123")
    response = client.post(
        "/api/auth/refresh",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert response.status_code == 200
    data = response.get_json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["access_token"] != access


def test_refresh_rejects_access_token(client, user, login_tokens):
    access, _ = login_tokens("user123")
    response = client.post(
        "/api/auth/refresh",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert response.status_code in (401, 422)


def test_logout_success(client, user, login_tokens):
    access, _ = login_tokens("user123")
    response = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert response.status_code == 200
    assert "logged out" in response.get_json()["message"].lower()


def test_logout_requires_auth(client):
    response = client.post("/api/auth/logout")
    assert response.status_code in (401, 422)
