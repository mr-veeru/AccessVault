# Deploy AccessVault (Render)

Live demo links are in [README.md](README.md). Config blueprint: [render.yaml](render.yaml). Env reference: [.env.example](.env.example).

**Free tier:** cold starts after idle; fine for demos, not high traffic.

---

## 1. Create the service

1. Push the repo to GitHub.
2. In [Render](https://render.com): **New → Web Service** → connect the repo.
3. Use Blueprint (`render.yaml`) or set manually:

| Setting | Value |
|---------|--------|
| Build | `pip install -r requirements.txt` |
| Start | `gunicorn app:app` |
| Branch | `main` |

4. Add a PostgreSQL database (**New → PostgreSQL**) and copy the **Internal Database URL**.

---

## 2. Environment variables

| Variable | Required | Notes |
|----------|----------|--------|
| `SECRET_KEY` | Yes | Random secret (Render can generate) |
| `JWT_SECRET_KEY` | Yes | Different random secret |
| `SQLALCHEMY_DATABASE_URI` | Yes | Postgres URL (Internal URL on Render) |
| `FLASK_ENV` | Recommended | `production` |
| `FLASK_DEBUG` | Recommended | `false` |
| `CORS_ORIGINS` | Recommended | Frontend origin(s); avoid `*` in production |
| `RATELIMIT_STORAGE_URL` | Recommended | Redis URL in production (`memory://` is per-process only) |
| `BLOCKLIST_REDIS_URL` | Recommended | Redis URL so logout/token rotation actually revoke |

---

## 3. Initialize the database

After the first successful deploy, open the service **Shell** and run:

```bash
python -m scripts.init_db
python -m scripts.create_admin
```

Change the default admin password after first login.

> **Note:** Admin-created users currently get a fixed default password (`User@123`). Phase 2 of [ROADMAP.md](ROADMAP.md) replaces that with a one-time setup/invite flow — update this section when that lands.

---

## 4. Verify

- Root: `https://<your-service>.onrender.com/`
- Health: `/api/health/`
- Swagger: `/api/swagger-ui/`

---

## Troubleshooting

| Issue | Check |
|-------|--------|
| Build fails | `requirements.txt` present; build command correct |
| Crash on start | Logs; start command is `gunicorn app:app` |
| DB / 503 errors | `SQLALCHEMY_DATABASE_URI`; run `init_db` |
| Auth 401/403 | `SECRET_KEY` / `JWT_SECRET_KEY` set |
| CORS errors | Set `CORS_ORIGINS` to your frontend origin |
