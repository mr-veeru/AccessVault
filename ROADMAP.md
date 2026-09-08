# AccessVault Roadmap

Prioritized plan based on a code review of the current repo. Items are ordered by security risk first, then correctness and operational hardening, then product depth.

Status legend: `todo` · `in progress` · `done` · `wontfix` / deferred

---

## Phase 0 — Docs honesty

| # | Item | Status |
|---|------|--------|
| 0.1 | Tone down README (no “enterprise / production-ready / comprehensive audit logging”) | done |
| 0.2 | Document password reset as **admin-assisted recovery**, not email forgot-password | todo |
| 0.3 | Document that Redis is required in production for rate limiting and token revocation | done |

---

## Phase 1 — Critical authorization (fix first)

**Problems:** JWT `role` / `status` claims are trusted without a server-side check. Admin routes do not use `active_required`, so a demoted or deactivated admin can keep using an old access token until it expires.

| # | Item | Fixes | Status |
|---|------|-------|--------|
| 1.1 | Validate current authorization state from a trusted server-side source; do not trust JWT `role` / `status` claims for authorization (DB and/or Redis/session state) | #19, #20 | todo |
| 1.2 | Single `admin_required` (or equivalent) on all admin routes | #19, #20 | todo |
| 1.3 | Add `token_version` on `User` and include it in JWTs | #19, #20 + Option B | todo |
| 1.4 | Bump `token_version` whenever role, status, or password changes, invalidating existing tokens | #19, #20 + Option C | todo |
| 1.5 | Production authentication requires Redis for distributed rate limiting and token revocation; fail closed if required Redis is unavailable | security boundary | todo |

**Acceptance:** After demotion or deactivation, existing access tokens must be rejected on admin (and other protected) routes immediately—not only after expiry.

---

## Phase 2 — Credential hygiene

| # | Item | Fixes | Status |
|---|------|-------|--------|
| 2.1 | Remove hardcoded default password `User@123`; use random one-time setup password or invite/reset token | #22 | todo |
| 2.2 | Store password-reset tokens as hashes (SHA-256/HMAC); return raw token once | #21 | todo |
| 2.3 | On password reset/change: bump `token_version` / revoke sessions | #21 related | todo |
| 2.4 | Update `API.md` and `DEPLOYMENT.md` for new create-user / setup and reset-token behavior | docs | todo |

---

## Phase 3 — Automated tests

| # | Item | Fixes | Status |
|---|------|-------|--------|
| 3.1 | Add `pytest` + app/DB fixtures | #36 | todo |
| 3.2 | Auth tests: register, login, refresh, revoke, weak password, duplicate username | #36 | todo |
| 3.3 | Authz demotion: admin logs in → demoted to user → old token → admin endpoint → 403 | #19, #20, #36 | todo |
| 3.4 | Authz promotion: user logs in → promoted to admin → old token must **not** gain admin access | #19, #36 | todo |
| 3.5 | Reset-token tests: valid / expired / used / hashed lookup | #21, #36 | todo |
| 3.6 | Password change/reset → existing access and refresh tokens rejected | #21, token_version | todo |
| 3.7 | Concurrent refresh race: same refresh token → only one success | #37, #38 | todo |

After Phase 3, update README Testing to describe pytest coverage (keep Postman for manual exploration).

---

## Phase 4 — Production defaults

| # | Item | Fixes | Status |
|---|------|-------|--------|
| 4.1 | Wire production Redis in `render.yaml` / deploy docs (implements Phase 1.5 in deployment config) | #39 | todo |
| 4.2 | Restrict CORS in production; avoid `*` with `supports_credentials=True` | #40, #41 | todo |
| 4.3 | Console/stdout JSON logging in production; file logs local-only | #43 | todo |
| 4.4 | Include `request_id` on error responses | #44 | todo |
| 4.5 | Use conventional HTTP status codes (e.g. login failure → 401) | #45 | todo |
| 4.6 | Commit Alembic `migrations/` | #48 | todo |
| 4.7 | DB constraints/enums for `role` and `status` | #49 | todo |

---

## Phase 5 — API hardening

| # | Item | Fixes | Status |
|---|------|-------|--------|
| 5.1 | Paginate admin user list (`page`/`limit` or cursor) | #30 | todo |
| 5.2 | Standardize response envelope across auth and admin | #46 | todo |
| 5.3 | Explicit log redaction (never log passwords, JWTs, reset tokens, Authorization) | #42 | todo |

---

## Phase 6 — Product depth (optional showcase)

Pick based on what you want the portfolio to demonstrate. Not required for a solid auth API.

For an **admin/user-management** focus, prefer audit logs early.

| # | Item | Fixes | Status |
|---|------|-------|--------|
| 6.1 | Audit log for sensitive admin actions (role/status/delete/reset) | #34 | todo |
| 6.2 | Session / device list + revoke one / revoke all | #27, #28 | todo |
| 6.3 | Email field + verification flow | #24 | todo |
| 6.4 | TOTP MFA (+ recovery codes) | #26 | todo |
| 6.5 | Fine-grained permissions only if two roles are no longer enough | #33 | todo |

---

## Deferred / low priority

These are valid observations, not urgent bugs for the current scale:

| # | Item | Why deferred |
|---|------|----------------|
| D.1 | Softer password policy / breach lists (#25) | Policy preference; current regex is acceptable |
| D.2 | Cache user lookups for authorization (#29) | Fine until high QPS |
| D.3 | Trigram / full-text indexes for admin search (#31) | Fine until large user tables |
| D.4 | Split routes into services/repositories (#47) | Do when Phase 6 features create pressure |
| D.5 | Optimistic locking on admin updates (#50) | Rare conflict case |
| D.6 | Password history (#51) | Enterprise policy nicety |
| D.7 | Account lockout / risk-based auth (#52) | Rate limiting covers part of this; MFA is higher value |

---

## Suggested order of work

1. **Phase 1** — trusted server-side authz + `token_version` + production Redis requirement (biggest security win)
2. **Phase 2** — default password + hashed reset tokens (then update `DEPLOYMENT.md` create-admin / setup notes)
3. **Phase 3** — tests that lock in Phase 1–2
4. **Phase 4–5** — production defaults and API polish
5. **Phase 6** — audit / sessions / MFA / email as portfolio depth

Next concrete step: implement Phase 1.1–1.4.
