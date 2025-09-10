# AccessVault 

A secure role-based access control (RBAC) system built with **Flask**, **PostgreSQL**, and **JWT Authentication**. AccessVault provides a robust API for user management, authentication, and authorization with support for different roles(user and admin).

## Features
- **JWT Authentication** - Secure token-based authentication
- **Password Security** - bcrypt hashing with strong password policies
- **Modular Architecture** - Blueprinted REST API for scalability
- **Database Integration** - SQLAlchemy ORM with PostgreSQL support

## Requirements
- Python 3.10+
- PostgreSQL database (Supabase recommended)

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
Create a `config.py` file in the project root with your database credentials:

```python
import os
from datetime import timedelta

# Flask secret keys
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-here")
JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)

# Database connection (replace with your PostgreSQL URL)
SQLALCHEMY_DATABASE_URI = (
    "postgresql://username:password@host:port/database_name"
    "?sslmode=require"
)
SQLALCHEMY_TRACK_MODIFICATIONS = False
```

**For Supabase users:**
```python
SQLALCHEMY_DATABASE_URI = (
    "postgresql://postgres.xxxxx:your-password"
    "@aws-0-region.pooler.supabase.com:6543/postgres"
    "?sslmode=require"
)
```

### 4. Initialize Database
Create the database tables:
```bash
python init_db.py
```
This creates the `users` table based on the User model.

### 5. Run the Application
Start the Flask development server:
```bash
python app.py
```
The API will be available at `http://127.0.0.1:5000`

## Project Structure
```
AccessVault/
├── app.py              # Flask app factory and main entry point
├── config.py           # Application configuration and database settings
├── decorators.py       # Role-based access control decorators
├── extensions.py       # Flask extensions (db, jwt, bcrypt)
├── init_db.py          # Database initialization script
├── model.py            # SQLAlchemy database models
├── routes/
│   ├── auth.py         # Authentication routes (register, login)
│   └── profile.py      # User profile routes (profile, updates)
├── requirements.txt    # Python package dependencies
└── README.md           # Project documentation
```

## API Reference

### Health Check
**GET** `/` 

**Response:**
```json
{
  "message":"AccessVault API is running 🚀"
}
```

### Authentication

#### Register User
**POST** `/auth/register`

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

**Password Requirements:**
- Minimum 6 characters
- At least one uppercase letter
- At least one number
- At least one special character: `@ # $ % & * ! ?`

**Responses:**
- `201 Created` - User registered successfully
- `400 Bad Request` - Validation errors or username already exists

#### Login
**POST** `/auth/login`

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

## Troubleshooting

### Common Issues

**Database Connection Issues:**
- Ensure your PostgreSQL database is running and accessible
- Verify the connection string format matches your provider
- For Supabase, ensure `?sslmode=require` is included in the URL

**Token Issues:**
- JWT tokens expire after 1 hour (configurable in `config.py`)
- Include `Authorization: Bearer <token>` header for protected routes
- Get a new token via `/auth/login` when it expires
