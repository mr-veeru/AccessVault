# AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management with JWT tokens, role-based access control, rate limiting, and comprehensive logging. Built with **Flask**, **PostgreSQL**, and **JWT Authentication**.

## Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/mr-veeru/AccessVault.git
cd AccessVault
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment
Copy the environment template and configure your settings:

```bash
# Copy the example file
copy .env.example .env
```

Edit `.env` file with your actual values:

**For Supabase users:**
```bash
SQLALCHEMY_DATABASE_URI=postgresql://postgres.xxxxx:your-password@aws-0-region.pooler.supabase.com:6543/postgres?sslmode=require
```

### 4. Initialize Database
Create the database tables:
```bash
python -m scripts.init_db
```
This creates the `users` table based on the models.

### 5. Run the Application
Start the Flask development server:
```bash
python app.py
```
The API will be available at:
- **API Base URL**: `http://127.0.0.1:5000`
- **Health Check**: `http://127.0.0.1:5000/health`

## Project Structure
```
AccessVault/
├── app.py                 # Main application entry point and Flask app factory
├── src/                   # Core application package
│   ├── models.py          # SQLAlchemy database models (User, PasswordResetToken)
│   ├── extensions.py      # Flask extensions (db, jwt, bcrypt, limiter, api)
│   ├── config.py          # Application configuration and database settings
│   └── routes/            # API routes organized by functionality
│       ├── __init__.py    # Route package initialization
│       └── health.py      # Health check namespace (Flask-RESTX)
├── scripts/               # Database and utility scripts
│   └── init_db.py         # Database initialization script
├── requirements.txt       # Python package dependencies
├── .env                   # Environment variables (git-ignored)
├── .env.example           # Environment variables template (git-tracked)
├── .gitignore             # Git ignore patterns
└── README.md              # Project documentation
```

## API Reference

### Health Check Endpoints

#### Basic Health Check
**GET** `/` 

**Response:**
```json
{
    "message": "AccessVault API is running",
    "status": "healthy",
    "version": "1.0.0"
}
```

#### Comprehensive Health Check
**GET** `/health`

**Description:** Detailed health check for monitoring and load balancers. Checks database connectivity, JWT configuration, and Flask setup.

**Response (Healthy):**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "AccessVault API",
  "version": "1.0.0",
  "checks": {
    "database": {
      "status": "healthy",
      "message": "Database connection successful"
    },
    "jwt": {
      "status": "healthy",
      "message": "JWT configuration valid"
    },
    "flask": {
      "status": "healthy",
      "message": "Flask configuration valid"
    }
  },
  "system": {
    "python_version": "3.10.0",
    "flask_version": "2.3.3",
    "environment": "development",
    "debug_mode": true
  }
}
```

**Response (Unhealthy):**
```json
{
  "status": "unhealthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "service": "AccessVault API",
  "version": "1.0.0",
  "checks": {
    "database": {
      "status": "unhealthy",
      "message": "Database connection failed: connection refused"
    }
  }
}
```

**Status Codes:**
- `200` - All systems healthy
- `503` - One or more systems unhealthy

## Troubleshooting

### Common Issues

**Database Connection Issues:**
- Ensure your PostgreSQL database is running and accessible
- Verify the connection string format matches your provider
- For Supabase, ensure `?sslmode=require` is included in the URL
