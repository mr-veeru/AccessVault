"""Health and root endpoint tests."""


def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_health(client):
    response = client.get("/api/health/")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] in ("healthy", "degraded", "unhealthy")
    assert "checks" in data
