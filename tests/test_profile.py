"""Profile endpoint tests."""


def test_get_profile(client, auth_headers):
    response = client.get("/api/profile/", headers=auth_headers)
    assert response.status_code == 200
    data = response.get_json()
    assert data["username"] == "user123"
    assert data["role"] == "user"
    assert data["status"] == "active"


def test_get_profile_requires_auth(client):
    response = client.get("/api/profile/")
    assert response.status_code in (401, 422)


def test_update_profile_name(client, auth_headers):
    response = client.patch(
        "/api/profile/",
        headers=auth_headers,
        json={"name": "Updated Name"},
    )
    assert response.status_code == 200
    assert response.get_json()["name"] == "Updated Name"


def test_change_password_success(client, auth_headers, password):
    new_password = "NewSecurePass123!"
    response = client.patch(
        "/api/profile/password",
        headers=auth_headers,
        json={
            "old_password": password,
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert response.status_code == 200

    # Old password should no longer work
    login = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": password},
    )
    assert login.status_code == 400

    # New password should work
    login = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": new_password},
    )
    assert login.status_code == 200


def test_change_password_wrong_old(client, auth_headers):
    response = client.patch(
        "/api/profile/password",
        headers=auth_headers,
        json={
            "old_password": "WrongPass123!",
            "new_password": "NewSecurePass123!",
            "confirm_password": "NewSecurePass123!",
        },
    )
    assert response.status_code == 400


def test_deactivate_account(client, auth_headers, password):
    response = client.patch("/api/profile/deactivate", headers=auth_headers)
    assert response.status_code == 200

    login = client.post(
        "/api/auth/login",
        json={"username": "user123", "password": password},
    )
    assert login.status_code == 403
