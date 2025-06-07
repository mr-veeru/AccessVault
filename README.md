# AccessVault - User Management & Auth System

A microservice-based user management and authentication system built with Flask and PostgreSQL.

## Features

- Separate admin and user services
- JWT-based authentication
- Role-based access control (admin, user)
- PostgreSQL database integration
- Swagger API documentation
- Microservice architecture

## Project Structure

```
project/
│
├── admin_service/
│   ├── __init__.py
│   ├── app.py
│   ├── models.py
│   └── routes/
│       ├── admin_auth.py
│       └── admin_management.py
│
├── user_service/
│   ├── __init__.py
│   ├── app.py
│   ├── models.py
│   └── routes/
│       ├── user_auth.py
│       └── user_profile.py
│
├── shared/
│   ├── __init__.py
│   ├── config.py
│   ├── db.py
│   └── utils/
│       ├── auth_utils.py
│       └── validators.py
│
├── scripts/
│   └── init_db.py
│
└── requirements.txt
```

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment variables:
```bash
# Database configuration
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/accessvault"

# JWT configuration
export JWT_SECRET_KEY="your-secret-key-here"

# Service ports
export ADMIN_SERVICE_PORT=5001
export USER_SERVICE_PORT=5002
```

3. Initialize the database and create admin user:
```bash
python scripts/init_db.py admin admin@example.com "Admin@123"
```

4. Run the services:

Admin Service:
```bash
python admin_service/app.py
```

User Service:
```bash
python user_service/app.py
```

## API Endpoints

### Admin Service (Port 5001)

#### Authentication
- `POST /admin/auth/login` - Admin login
- `GET /admin/auth/verify` - Verify admin token

#### Management
- `GET /admin/users` - List all users
- `GET /admin/users/<user_id>` - Get user details
- `POST /admin/users/<user_id>/deactivate` - Deactivate user
- `GET /admin/settings` - Get system settings
- `PUT /admin/settings` - Update system settings

### User Service (Port 5002)

#### Authentication
- `POST /user/auth/register` - Register new user
- `POST /user/auth/login` - User login
- `GET /user/auth/verify` - Verify user token

#### Profile
- `GET /user/profile` - Get user profile
- `PUT /user/profile` - Update user profile
- `PUT /user/password` - Change password

## Security

- Password requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character

- JWT token expiration: 1 hour
- Role-based access control
- Secure password hashing

## Development

To run in development mode:
```bash
export FLASK_DEBUG=True
```

## API Documentation

Access Swagger documentation at:
- Admin Service: `http://localhost:5001/api/docs`
- User Service: `http://localhost:5002/api/docs` 