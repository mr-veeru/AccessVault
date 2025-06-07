# User Management & Auth System

A microservice-based user management and authentication system built with Flask and PostgreSQL.

## Features

- User authentication with JWT
- Role-based access control (admin, user)
- PostgreSQL database integration
- Swagger API documentation
- Microservice architecture

## Project Structure

```
project/
│
├── auth_service/
│   ├── app.py
│   ├── models.py
│   ├── routes.py
│   └── ...
│
├── shared/
│   ├── db.py
│   └── config.py
│
└── requirements.txt
```

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure the database:
- Update the database URI in `shared/config.py`
- Update the JWT secret key in `shared/config.py`

4. Run the auth service:
```bash
python auth_service/app.py
```

## API Endpoints

### Auth Service (Port 5000)

- `POST /auth/register` - Register a new user
- `POST /auth/login` - Login and get JWT token
- `GET /auth/verify` - Verify JWT token
- `GET /api/docs` - Swagger API documentation

## Example Usage

### Register a new user
```bash
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name": "testuser", "password": "password123", "age": 25}'
```

### Login
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"name": "testuser", "password": "password123"}'
```

### Verify Token
```bash
curl -X GET http://localhost:5000/auth/verify \
  -H "Authorization: Bearer <your_jwt_token>"
``` 