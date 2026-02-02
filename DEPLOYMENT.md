# AccessVault – Deployment Guide (Render)

> **Version:** v1.0.0  
> **Last Updated:** Feb 2026

This guide walks you through deploying AccessVault to [Render](https://render.com) by connecting your GitHub repository and configuring environment variables.

---

## Production Deployment Overview

This guide demonstrates how AccessVault is deployed in a **real production-like environment** using:

- **Gunicorn** WSGI server for production-grade request handling
- **Environment-based configuration** — no secrets in code
- **PostgreSQL** database with connection pooling and health checks
- **Secure secret management** via Render Environment (JWT, Flask secrets, DB URL)
- **CI/CD via GitHub → Render** — push to `main` triggers automatic deploy

This setup reflects how modern Flask APIs are deployed in industry.

| Link           | URL                                                                                                                    |
|----------------|------------------------------------------------------------------------------------------------------------------------|
| **Live API**   | [https://accessvault-api-8shv.onrender.com/](https://accessvault-api-8shv.onrender.com/)                               |
| **Health**     | [https://accessvault-api-8shv.onrender.com/api/health/](https://accessvault-api-8shv.onrender.com/api/health/)         |
| **Swagger UI** | [https://accessvault-api-8shv.onrender.com/api/swagger-ui/](https://accessvault-api-8shv.onrender.com/api/swagger-ui/) |

### Free-Tier Notes

- **Cold starts** after inactivity — first request may take several seconds to wake the service.
- **Limited RAM/CPU** — fine for demos and low traffic; not for sustained high load.
- **Not suitable for high traffic** — upgrade to a paid plan or move to a scalable setup for production workloads.

---

## Prerequisites

- A [GitHub](https://github.com) account with the AccessVault repository
- A [Render](https://render.com) account (free tier is fine)
- A PostgreSQL database (Render PostgreSQL, Supabase, or any hosted PostgreSQL)

---

## Deployment Architecture

```
GitHub Repo → Render Build → Gunicorn → Flask App → PostgreSQL
```

- **GitHub** holds the source; Render connects to the repo and builds on push.
- **Render** runs the **Build Command** (`pip install -r requirements.txt`), then starts the app with **Start Command** (`gunicorn app:app`).
- **Gunicorn** serves the Flask app with multiple workers (production WSGI).
- **Environment variables** (secrets, DB URL, CORS) are injected securely via the Render dashboard — **JWT secrets and DB credentials are never stored in code**.

```
┌─────────────┐     push      ┌─────────────┐     build/start      ┌──────────────┐     queries     ┌─────────────┐
│   GitHub    │ ───────────►  │   Render    │ ─────────────────►   │   Gunicorn   │ ◄─────────────► │ PostgreSQL  │
│   (repo)    │               │  (dashboard)│                      │  Flask app   │                 │  (database) │
└─────────────┘               └─────────────┘                      └──────────────┘                 └─────────────┘
                                     │
                                     │ env vars (SECRET_KEY, JWT_SECRET_KEY, DB URL, CORS)
                                     ▼
                             injected at runtime
```

---

## Step 1: Push Your Code to GitHub

Ensure your AccessVault project is in a GitHub repository and that the branch you want to deploy (e.g. `main`) is up to date.

```bash
git add .
git commit -m "Prepare for deployment"
git push origin main
```

---

## Step 2: Log In to Render

1. Go to [https://render.com](https://render.com).
2. Sign up or log in (e.g. **Log in with GitHub** for easier repo access).

---

## Step 3: Create a New Web Service

1. From the Render **Dashboard**, click **New** → **Web Service**.
2. If prompted, **connect your GitHub account** and authorize Render to access your repositories.
3. Find and **select the AccessVault repository** (e.g. `mr-veeru/AccessVault`).
4. Click **Connect** (or **Use this repository**).

---

## Step 4: Configure the Service

Render may detect the app from `render.yaml`. If not, or if you are creating the service manually, use:

| Setting           | Value                                      |
|-------------------|--------------------------------------------|
| **Name**          | `accessvault-api` (or any name you prefer) |
| **Region**        | Choose the region closest to your users    |
| **Branch**        | `main` (or your default branch)            |
| **Runtime**       | `Python 3`                                 |
| **Build Command** | `pip install -r requirements.txt`          |
| **Start Command** | `gunicorn app:app`                         |

If you use the repo’s **render.yaml**, these are already set; you can adjust the service name or region in the dashboard if needed.

---

## Step 5: Add Environment Variables

In the Render dashboard for your service:

1. Open your **Web Service**.
2. Go to the **Environment** tab (or **Environment** section).
3. Add the following variables (use **Add Environment Variable** for each):

| Key                       | Value                                                   | Required                |
|---------------------------|---------------------------------------------------------|-------------------------|
| `SECRET_KEY`              | A long random string (e.g., from a password generator)  | Yes                     |
| `JWT_SECRET_KEY`          | Another long random string (different from SECRET_KEY)  | Yes                     |
| `SQLALCHEMY_DATABASE_URI` | Your PostgreSQL connection URL                          | Yes                     |
| `RATELIMIT_STORAGE_URL`   | `memory://` (default) or Redis URL, e.g. `redis://...`  | No (defaults to memory) |
| `CORS_ORIGINS`            | `*` for all origins, or e.g. `https://yourdomain.com`   | No (defaults to `*`)    |
| `FLASK_ENV`               | `production`                                            | Recommended             |
| `FLASK_DEBUG`             | `false`                                                 | Recommended             |

**Example values (do not use these in production):**

- `SECRET_KEY`: generate a strong secret (e.g., 32+ random characters).
- `JWT_SECRET_KEY`: generate another strong secret.
- `SQLALCHEMY_DATABASE_URI`:  
  - **Render PostgreSQL:** use the **Internal Database URL** from your Render PostgreSQL service.  
  - **Supabase:**  
    `postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres?sslmode=require`

After adding variables, click **Save Changes**. Render will redeploy if needed.

---

## Step 6: Database Setup After First Deploy

Once the service is running and the database URL is set:

1. **Option A – Render Shell (recommended)**  
   - In your service, open **Shell** (or use a one-off job).  
   - Run:
     ```bash
     python -m scripts.init_db
     python -m scripts.create_admin
     ```
2. **Option B – Local with production DB URL**  
   - Set `SQLALCHEMY_DATABASE_URI` in your local `.env` to the same URL (temporarily).  
   - Run the same commands locally:
     ```bash
     python -m scripts.init_db
     python -m scripts.create_admin
     ```  
   - Remove or change the URL afterward.

This creates the tables and an initial admin user (default username/password as in the script; change them after first login in production).

---

## Step 7: Verify Deployment

1. Open your service URL (e.g. `https://accessvault-api-8shv.onrender.com/`).
2. You should see a JSON response similar to:
   ```json
   {
     "message": "AccessVault API is running",
     "status": "healthy",
     "version": "1.0.0",
     "endpoints": {
       "health": "/api/health",
       "swagger": "/api/swagger-ui/"
     }
   }
   ```
3. Check health: `https://your-service.onrender.com/api/health/`
4. Open Swagger UI: `https://your-service.onrender.com/api/swagger-ui/`

---

## Optional: Add a PostgreSQL Database on Render

1. In the Render dashboard: **New** → **PostgreSQL**.
2. Create the database and note the **Internal Database URL** (use this in `SQLALCHEMY_DATABASE_URI` for your web service).
3. Ensure the web service and the database are in the same Render account/team so the internal URL works.

---

## Security Notes

- **Secrets** are stored only in Render **Environment** variables — never in the repo or in code.
- **JWT and Flask secrets** should be strong, unique, and rotated periodically in production.
- **Database** uses SSL when supported (e.g. `sslmode=require` in Supabase URL).
- **Debug mode** is disabled in production (`FLASK_DEBUG=false`).
- **CORS** should be restricted in production to your frontend origin(s) via `CORS_ORIGINS`, not `*`.

This reflects production security practices for a backend API.

---

## Troubleshooting

| Issue                     | What to check                                                                                        |
|---------------------------|------------------------------------------------------------------------------------------------------|
| Build fails               | Ensure `requirements.txt` is in the repo and **Build Command** is `pip install -r requirements.txt`. |
| App crashes on start      | Check **Start Command** is `gunicorn app:app`. Check **Logs** for Python errors.                     |
| 503 or DB errors          | Confirm `SQLALCHEMY_DATABASE_URI` is set and correct. Run `scripts.init_db` as in Step 6.            |
| 401/403 on API            | Verify `SECRET_KEY` and `JWT_SECRET_KEY` are set and not empty.                                      |
| CORS errors from frontend | Set `CORS_ORIGINS` to your frontend origin(s), e.g. `https://your-app.vercel.app`.                   |

---

## What This Deployment Demonstrates

- **Cloud deployment** — Shipping a Flask API to a managed platform (Render) with GitHub integration.
- **Production configuration** — Gunicorn, env-based config, and health checks.
- **Secure environment management** — No secrets in code; use of platform-native env vars.
- **PostgreSQL in production** — Connection strings, migrations, and post-deploy DB setup.
- **Operational practices** — Logs, troubleshooting, and verification steps.

This reflects real-world backend engineering and deployment practices.

---

## Scaling & Future Improvements

For higher traffic, this setup can be extended with:

- **Redis** for rate-limit and token-blocklist storage (distributed, multi-instance).
- **Multiple Gunicorn workers** — increase workers in the start command for more concurrency.
- **Load balancer + multiple instances** — scale horizontally behind a load balancer.
- **Dedicated managed PostgreSQL** — e.g. Render PostgreSQL, Supabase, or RDS with connection pooling.
- **Monitoring** — Sentry for errors, Prometheus/Grafana or Render metrics for observability.

This reflects how AccessVault can evolve in production as requirements grow.

---

## Summary

1. Log in to Render and connect to GitHub.  
2. Create a Web Service from your AccessVault repo.  
3. Set **Build Command**: `pip install -r requirements.txt`, **Start Command**: `gunicorn app:app`.  
4. Add **Environment** variables (especially `SECRET_KEY`, `JWT_SECRET_KEY`, `SQLALCHEMY_DATABASE_URI`).  
5. Deploy, then run `scripts.init_db` and `scripts.create_admin` (via Shell or locally with prod DB URL).  
6. Test the root URL, `/api/health/`, and `/api/swagger-ui/`.

For local development and env reference, see [.env.example](.env.example) and [README.md](README.md).
