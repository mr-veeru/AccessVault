# AccessVault 

A secure role-based access control (RBAC) system built with **Flask**, **PostgreSQL**, and **JWT Authentication**. AccessVault provides a robust API for user management, authentication, and authorization with support for different roles(user and admin).

## Features
- **JWT Authentication** - Secure token-based authentication
- **Password Security** - bcrypt hashing with strong password policies
- **Password Reset System** - Admin-generated secure reset tokens with expiration
- **Modular Architecture** - Blueprinted REST API for scalability
- **Database Integration** - SQLAlchemy ORM with PostgreSQL support
- **Rate Limiting** - Comprehensive protection against abuse and DDoS attacks
- **Health Monitoring** - Production-ready health check endpoints
- **Role-Based Access Control** - Admin and user role management
- **Refresh Token System** - Secure token refresh mechanism
- **Comprehensive Logging** - Enterprise-grade audit trails and security monitoring

## Rate Limiting

AccessVault implements comprehensive rate limiting to prevent abuse and ensure fair usage. Rate limits are applied per IP address and include both endpoint-specific and global fallback limits.

### Rate Limiting Strategy

| **Endpoint**                      | **Rate Limit** | **Purpose**                  |
|-----------------------------------|----------------|------------------------------|
| **User Registration**             | 5 per hour     | Prevent spam account creation|
| **User Login**                    | 5 per minute   | Prevent brute force attacks  |
| **Token Refresh**                 | 10 per minute  | Prevent token abuse          |
| **Password Change**               | 5 per hour     | Prevent password attacks     |
| **Account Deactivation**          | 3 per hour     | Prevent account abuse        |
| **User Creation (Admin)**         | 10 per hour    | Prevent admin abuse          |
| **User Activation/Deactivation**  | 20 per hour    | Allow admin operations       |
| **User Deletion (Admin)**         | 5 per hour     | Prevent destructive abuse    |

### Global Fallback Limits

All endpoints without specific rate limits are protected by global fallback limits:
- **100 requests per day** per IP
- **20 requests per hour** per IP  
- **5 requests per minute** per IP

### Rate Limit Headers

When rate limits are exceeded, the API returns:
- **HTTP Status**: `429 Too Many Requests`
- **Headers**: Rate limit information
- **Response**: Error message with retry information

### Example Rate Limit Response

```json
{
  "error": "Rate limit exceeded: 5 per minute",
  "retry_after": 60
}
```

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
├── models.py           # SQLAlchemy database models
├── logger.py           # Logging configuration and setup
├── routes/
│   ├── health.py       # Health check (Checks database connectivity, JWT configuration, and Flask setup)
│   ├── admin.py        # Admin routes (user management, statistics)
│   ├── auth.py         # Authentication routes (register, login)
│   └── profile.py      # User profile routes (profile, updates)
├── scripts/
│   ├── create_admin.py # Script to create initial admin user
│   └── init_db.py      # Database initialization script
├── logs/               # Application logs (auto-generated, git-ignored)
│   └── accessvault.log # Current log file with daily rotation
├── requirements.txt    # Python package dependencies
├── .env                # Environment variables (git-ignored)
├── .gitignore          # Git ignore patterns
└── README.md           # Project documentation
```

## API Reference

### Health Check Endpoints

#### Basic Health Check
**GET** `/` 

**Response:**
```json
{
  "message": "AccessVault API is running 🚀"
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

### Authentication

#### Register User
**POST** `/auth/register`

Register a new user account.

**Rate Limit**: 5 registrations per hour per IP

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

**Rate Limit**: 5 login attempts per minute per IP

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

**Rate Limit**: 10 refresh attempts per minute per IP

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

#### Password Reset
**POST** `/auth/reset-password`

Reset user password using a valid reset token (generated by admin).

**Request Body:**
```json
{
  "token": "reset_token_from_admin",
  "new_password": "NewSecurePassword123!",
  "confirm_password": "NewSecurePassword123!"
}
```

**Password Requirements:**
- Minimum 6 characters
- At least one uppercase letter
- At least one number
- At least one special character: `@ # $ % & * ! ?`

**Response:**
```json
{
  "message": "Password reset successful"
}
```

**Error Responses:**
- `400 Bad Request` - Invalid token, passwords don't match, or password doesn't meet requirements
- `404 Not Found` - User not found

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

**Rate Limit**: 5 password changes per hour per IP

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

**Rate Limit**: 3 deactivations per hour per IP

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

**Rate Limit**: 10 user creations per hour per IP

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

**Rate Limit**: 20 activations per hour per IP

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

**Rate Limit**: 20 deactivations per hour per IP

**Response:**
```json
{
  "message": "User username deactivated"
}
```

#### Delete User
**DELETE** `/admin/users/<user_id>`

Permanently delete a user account (hard delete).

**Rate Limit**: 5 deletions per hour per IP

**Edge Cases:**
- Prevents admin from deleting their own account
- Validates user exists before deletion

**Response:**
```json
{
  "message": "User username deleted successfully"
}
```

#### Create Password Reset Token
**GET** `/admin/create-reset-token/<user_id>`

Generate a password reset token for a specific user (admin-only).

**Rate Limit**: No specific limit (admin operation)

**Response:**
```json
{
  "message": "Password reset token generated for username",
  "reset_token": "secure_token_string",
  "expires_at": "2024-01-15T10:45:00Z"
}
```

**Token Details:**
- **Expiration**: 15 minutes from creation
- **Single Use**: Token becomes invalid after use
- **Secure**: 32-character URL-safe token

**Usage Flow:**
1. Admin generates reset token for user
2. Admin securely shares token with user
3. User calls `/auth/reset-password` with token and new password
4. Token is automatically invalidated after use

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

## Improvements to be done
1. swagger


## Project flow
1. Project setup (database, JWT), Health check
2. Logging setup (logger.py)
3. Global error handling
4. Authentication routes (login, registration, password reset)
5. User routes (profile management)
6. Admin routes (user management, password reset tokens)
7. Refresh token and rate limiting
8. Swagger documentation