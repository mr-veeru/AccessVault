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
- **API Base URL**: `http://127.0.0.1:5000/`
- **Health Check**: `http://127.0.0.1:5000/api/health`
- **Swagger UI**: `http://127.0.0.1:5000/swagger-ui/`

## Project Structure
```
AccessVault/
├── app.py                 # Main application entry point and Flask app factory
├── src/                   # Core application package
│   ├── models.py          # SQLAlchemy database models (User)
│   ├── extensions.py      # Flask extensions (db, api, jwt, bcrypt)
│   ├── decorators.py      # Role-based access control decorators
│   ├── config.py          # Application configuration and database settings
│   └── routes/            # API routes organized by functionality
│       ├── __init__.py    # Route package initialization
│       ├── health.py      # Health check namespace (Flask-RESTX)
│       ├── admin.py       # Admin routes namespace (user management, statistics)
│       └── profile.py     # User profile routes namespace (profile, updates)
├── scripts/               # Database and utility scripts
│   └── init_db.py         # Database initialization script
├── logs/                  # Application logs (auto-generated, git-ignored)
│   └── accessvault.log    # Current log file with daily rotation
├── requirements.txt       # Python package dependencies
├── .env                   # Environment variables (git-ignored)
├── .env.example           # Environment variables template (git-tracked)
├── .gitignore             # Git ignore patterns
└── README.md              # Project documentation
```

## Architecture

AccessVault follows a modular architecture with clear separation of concerns:

### Core Components

- **`app.py`**: Main entry point and Flask application factory
- **`src/`**: Core application package containing all business logic
- **`src/extensions.py`**: Flask extensions initialization (db, jwt, bcrypt, limiter, api)
- **`src/config.py`**: Configuration management with environment variables
- **`src/models.py`**: SQLAlchemy database models
- **`src/logger.py`**: Logging configuration with rotation
- **`src/routes/`**: API routes organized by functionality using Flask-RESTX namespaces

### Route Organization

- **`health_ns`**: Health check endpoints for monitoring

## API Reference

### Health Check Endpoints

#### Basic Health Check
**GET** `/` 

**Response:**
```json
{
    "endpoints": {
        "health": "/health",
        "swagger": "/api/swagger-ui/"
    },
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
    "timestamp": "2025-09-19T10:39:51.341416+00:00Z",
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
        "python_version": "3.10.11",
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

### Authentication

#### Register User
**POST** `/api/auth/register`

Register a new user account.

**Request Body:**
```json
{
  "name": "Veerendra",
  "username": "veeru68",
  "password": "Veeru!123",
  "confirm_password": "Veeru!123"
}
```

**Username Requirements:**
- Minimum 3 characters
- At least one letter
- At least one number
- No special characters
- **Case-insensitive** - usernames are automatically converted to lowercase

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one number
- At least one special character: `@ # $ % & * ! ?`

**Responses:**
- `201 Created` - User registered successfully
- `400 Bad Request` - Validation errors or username already exists

**Error Response Examples:**
```json
{
  "error": "Missing required fields",
  "missing_fields": ["name", "username"],
  "required_fields": ["name", "username", "password", "confirm_password"]
}
```

```json
{
  "error": "Username already exist"
}
```

#### Login
**POST** `/api/auth/login`

Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "username": "veeru68",
  "password": "Veeru!123"
}
```

**Response:**
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
}
```

**Error Responses:**
- `400 Bad Request` - Missing fields or invalid credentials
- `403 Forbidden` - Account deactivated

```json
{
  "error": "Invalid username or password"
}
```

```json
{
  "error": "Account is deactivated. Please contact admin."
}
```

#### Logout
**POST** `/api/auth/logout`

Logout user by revoking all refresh tokens.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "message": "Logged out successfully"
}
```

## Troubleshooting

### Common Issues

**Database Connection Issues:**
- Ensure your PostgreSQL database is running and accessible
- Verify the connection string format matches your provider
- For Supabase, ensure `?sslmode=require` is included in the URL
