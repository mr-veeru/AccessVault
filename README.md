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
python scripts/init_db.py
```
This creates the `users` table based on the User model.

### 5. Create Admin User (Optional)
Create an admin user for testing:
```bash
python scripts/create_admin.py
```
**Default admin credentials:**
- name: `Administrator`
- Username: `admin66`
- Password: `Admin@123`
- Role: `admin`
- Status: `active`

### 6. Run the Application
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
├── models.py            # SQLAlchemy database models
├── routes/
│   ├── admin.py        # Admin routes (user management, statistics)
│   ├── auth.py         # Authentication routes (register, login)
│   └── profile.py      # User profile routes (profile, updates)
├── scripts/
│   ├── create_admin.py # Script to create initial admin user
│   └── init_db.py      # Database initialization script
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
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Refresh Token
**POST** `/auth/refresh`

Generate a new access token using a valid refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "message": "New access token generated",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Token Expiration:**
- **Access Token**: 15 minutes (configurable)
- **Refresh Token**: 7 days (configurable)

### Profile Management

#### Get Profile
**GET** `/profile/`

Get the current user's profile information.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
  "user_id": 1,
  "name": "Veerendra",
  "username": "veeru68",
  "role": "user",
  "status": "active"
}
```

#### Update Profile
**PATCH** `/profile/`

Update user's display name and/or username.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "name": "newName",
  "username": "newUsername"
}
```

**Note:** You can update either `name`, `username`, or both. At least one field is required.

#### Update Password
**PATCH** `/profile/password`

Update user's password.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "old_password": "OldPass@123",
  "new_password": "NewPass@456",
  "confirm_password": "NewPass@456"
}
```

#### Deactivate Account
**PATCH** `/profile/deactivate`

Deactivate own account (soft delete).

**Headers:**
```
Authorization: Bearer <access_token>
```

#### Delete Account
**DELETE** `/profile/`

Delete own account (hard delete).

**Headers:**
```
Authorization: Bearer <access_token>
```

### Admin Routes

All admin routes require `Authorization: Bearer <access_token>` header with admin role.

#### System Statistics
**GET** `/admin/stats`

Get comprehensive system statistics for admin dashboard.

**Response:**
```json
{
  "message": "System statistics retrieved successfully",
  "statistics": {
    "total_users": 25,
    "active_users": 20,
    "inactive_users": 5,
    "admins": 2,
    "regular_users": 23
  }
}
```

#### Get All Users
**GET** `/admin/users`

Retrieve the list of all users in the system.

**Response:**
```json
[
  {
    "id": 1,
    "name": "Veerendra",
    "username": "veeru68",
    "role": "user",
    "status": "active"
  },
  {
    "id": 2,
    "name": "Administrator",
    "username": "admin36",
    "role": "admin",
    "status": "active"
  }
]
```

#### Get Active Users
**GET** `/admin/users/active`

Retrieve all users with active status.

**Response:**
```json
{
  "message": "Active users found",
  "users": [
    {
      "id": 1,
      "name": "Veerendra",
      "username": "veeru68",
      "role": "user",
      "status": "active"
    }
  ]
}
```

#### Get Inactive Users
**GET** `/admin/users/inactive`

Retrieve all users with inactive status.

**Response:**
```json
{
  "message": "Inactive users found",
  "users": [
    {
      "id": 3,
      "name": "Inactive User",
      "username": "inactive1",
      "role": "user",
      "status": "inactive"
    }
  ]
}
```

#### Search Users by Username
**GET** `/admin/users/search/username/<username>`

Search for users by username (case-insensitive partial match).

**Example:** `/admin/users/search/username/veer`

**Response:**
```json
{
  "message": "Found 1 user(s) matching 'veer'",
  "users": [
    {
      "id": 1,
      "name": "Veerendra",
      "username": "veeru68",
      "role": "user",
      "status": "active"
    }
  ]
}
```

#### Search Users by Name
**GET** `/admin/users/search/name/<name>`

Search for users by full name (case-insensitive partial match).

**Example:** `/admin/users/search/name/Veerendra`

#### Get User by ID
**GET** `/admin/users/<user_id>`

Get specific user details by ID.

**Response:**
```json
{
  "id": 1,
  "name": "Veerendra",
  "username": "veeru68",
  "role": "user",
  "status": "active"
}
```

#### Create User
**POST** `/admin/users`

Create a new user with default password.

**Request Body:**
```json
{
  "name": "New User",
  "username": "newuser1",
  "role": "user"
}
```

**Response:**
```json
{
  "message": "New user created successfully",
  "default_password": "User@123",
  "user": {
    "id": 3,
    "name": "New User",
    "username": "newuser1",
    "role": "user",
    "status": "active"
  }
}
```

#### Update User
**PATCH** `/admin/users/<user_id>`

Update user details (name, username, role).

**Request Body:**
```json
{
  "name": "Updated Name",
  "username": "newusername",
  "role": "admin"
}
```

**Note:** You can update any combination of fields. At least one field is required.

#### Activate User
**PATCH** `/admin/users/<user_id>/activate`

Activate a user account (set status to 'active').

**Response:**
```json
{
  "message": "User activated successfully",
  "user": {
    "id": 3,
    "name": "User Name",
    "username": "username",
    "role": "user",
    "status": "active"
  }
}
```

#### Deactivate User
**PATCH** `/admin/users/<user_id>/deactivate`

Deactivate a user account (set status to 'inactive').

**Response:**
```json
{
  "message": "User username deactivated"
}
```

#### Delete User
**DELETE** `/admin/users/<user_id>`

Permanently delete a user account (hard delete).

**Edge Cases:**
- Prevents admin from deleting their own account
- Validates user exists before deletion

**Response:**
```json
{
  "message": "User username deleted successfully"
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
