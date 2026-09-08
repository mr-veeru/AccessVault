"""Authorization security tests.

These assert the *intended* secure behavior (DB-backed authz / token_version).
They are expected to fail on the current codebase until Phase 1 of ROADMAP.md.
"""

import pytest

from app.extensions import db
from app.models import User


pytestmark = pytest.mark.xfail(
    reason="Phase 1: JWT role/status claims trusted; no token_version yet",
    strict=False,
)


def test_demoted_admin_token_rejected_on_admin_route(client, app, admin, login_tokens):
    access, _ = login_tokens("admin123")

    with app.app_context():
        admin_user = User.query.filter_by(username="admin123").first()
        admin_user.role = "user"
        db.session.commit()

    response = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert response.status_code == 403


def test_deactivated_admin_token_rejected_on_admin_route(client, app, admin, login_tokens):
    access, _ = login_tokens("admin123")

    with app.app_context():
        admin_user = User.query.filter_by(username="admin123").first()
        admin_user.status = "inactive"
        db.session.commit()

    response = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert response.status_code in (401, 403)


def test_promoted_user_old_token_does_not_gain_admin(client, app, user, login_tokens):
    access, _ = login_tokens("user123")

    with app.app_context():
        regular = User.query.filter_by(username="user123").first()
        regular.role = "admin"
        db.session.commit()

    response = client.get(
        "/api/admin/users",
        headers={"Authorization": f"Bearer {access}"},
    )
    # Old token still has role=user in claims; with DB-backed authz + version,
    # promotion should require a fresh login (or version bump). Prefer rejecting
    # stale tokens entirely once token_version exists.
    assert response.status_code == 403


def test_password_change_invalidates_existing_tokens(client, app, user, password, login_tokens):
    access, refresh = login_tokens("user123")
    new_password = "BrandNewPass123!"

    change = client.patch(
        "/api/profile/password",
        headers={"Authorization": f"Bearer {access}"},
        json={
            "old_password": password,
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )
    assert change.status_code == 200

    profile = client.get(
        "/api/profile/",
        headers={"Authorization": f"Bearer {access}"},
    )
    assert profile.status_code in (401, 403, 422)

    refresh_resp = client.post(
        "/api/auth/refresh",
        headers={"Authorization": f"Bearer {refresh}"},
    )
    assert refresh_resp.status_code in (401, 403, 422)
