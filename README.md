# AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management with JWT tokens, role-based access control, password reset functionality, token cleanup, and comprehensive logging. Built with **Flask**, **PostgreSQL**, and **JWT Authentication**.

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
This creates the following tables based on the models:
- `users` - User accounts and authentication data
- `revoked_tokens` - Revoked JWT tokens for security
- `password_reset_tokens` - Admin-generated password reset tokens

### 5. Create Admin User (Optional)
Create an admin user for testing:
```bash
python -m scripts.create_admin
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
The API will be available at:
- **API Base URL**: `http://127.0.0.1:5000/`
- **Health Check**: `http://127.0.0.1:5000/api/health`
- **Swagger UI**: `http://127.0.0.1:5000/api/swagger-ui/`

## Project Structure
```
AccessVault/
├── app.py                 # Main application entry point and Flask app factory
├── src/                   # Core application package
│   ├── models.py          # SQLAlchemy database models (User, RevokedToken, PasswordResetToken)
│   ├── extensions.py      # Flask extensions (db, api, jwt, bcrypt)
│   ├── decorators.py      # Role-based access control decorators
│   ├── config.py          # Application configuration and database settings
│   ├── logger.py          # Responsible for creating logs
│   └── routes/            # API routes organized by functionality
│       ├── __init__.py    # Route package initialization
│       ├── health.py      # Health check namespace (Flask-RESTX)
│       ├── auth.py        # Authentication routes namespace (register, login, logout, refresh, password reset)
│       ├── profile.py     # User profile routes namespace (profile, updates)
│       └── admin.py       # Admin routes namespace (user management, statistics, token generation, cleanup)
├── scripts/               # Database and utility scripts
│   ├── init_db.py         # Database initialization script
│   ├── create_admin.py    # Script to create initial admin user
│   └── cleanup_tokens.py  # Token cleanup script for maintenance
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
        "health": "/api/health",
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

Authenticate user and receive JWT access and refresh tokens.

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

**Token Information:**
- **Access Token**: Expires in 1 hour, used for API authentication
- **Refresh Token**: Expires in 7 days, used to get new access tokens

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

#### Refresh Tokens
**POST** `/api/auth/refresh`

Refresh JWT tokens using a valid refresh token. This implements **token rotation** for enhanced security.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "message": "Tokens refreshed successfully",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

**Security Features:**
- **Token Rotation**: Old refresh token is immediately revoked
- **One-time Use**: Each refresh token can only be used once
- **Automatic Expiry**: Access tokens expire in 1 hour, refresh tokens in 7 days
- **Database Tracking**: All revoked tokens are stored and validated

**Error Responses:**
- `401 Unauthorized` - Invalid or expired refresh token
- `403 Forbidden` - Account deactivated

```json
{
  "error": "Token has been revoked"
}
```

**Token Rotation Flow:**
1. Use refresh token to get new tokens
2. Old refresh token becomes invalid immediately
3. New tokens are generated with fresh expiration times
4. Only the new refresh token can be used for future refreshes

#### Logout
**POST** `/api/auth/logout`

Logout user by revoking the current access token.

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

**Security Features:**
- **Token Revocation**: Current access token is immediately revoked
- **Database Tracking**: Revoked token is stored in database
- **Immediate Effect**: Token becomes invalid instantly

#### Password Reset
**POST** `/api/auth/reset-password`

Reset user password using a valid reset token provided by an admin.

**Request Body:**
```json
{
  "token": "abc123def456",
  "new_password": "NewPassword123!",
  "confirm_password": "NewPassword123!"
}
```

**Response:**
```json
{
  "message": "Password reset successfully"
}
```

**Security Features:**
- **Admin-Controlled**: Only admins can generate reset tokens
- **Time-Limited**: Tokens expire in 24 hours
- **One-Time Use**: Tokens can only be used once
- **Strong Validation**: Enforces password strength requirements
- **Immediate Effect**: Old password becomes invalid instantly

**Error Responses:**
- `400 Bad Request` - Invalid token, expired token, or validation errors
- `404 Not Found` - Token not found or user inactive

```json
{
  "error": "Invalid or expired reset token"
}
```

```json
{
  "error": "Password must be at least 8 characters long, include one uppercase letter, one number, and one special character"
}
```

### Profile Management

#### Get Profile
**GET** `/api/profile/`

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
**PATCH** `/api/profile/`

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
**PATCH** `/api/profile/password`

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
**PATCH** `/api/profile/deactivate`

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
**GET** `/api/admin/stats`

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
**GET** `/api/admin/users`

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
**GET** `/api/admin/users/active`

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
**GET** `/api/admin/users/inactive`

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
**GET** `/api/admin/users/search/username/<username>`

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
**GET** `/api/admin/users/search/name/<name>`

Search for users by full name (case-insensitive partial match).

**Example:** `/admin/users/search/name/Veerendra`

#### Get User by ID
**GET** `/api/admin/users/<user_id>`

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
**POST** `/api/admin/users`

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
  "message": "User created successfully",
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
**PATCH** `/api/admin/users/<user_id>`

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
**PATCH** `/api/admin/users/<user_id>/activate`

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
**PATCH** `/api/admin/users/<user_id>/deactivate`

Deactivate a user account (set status to 'inactive').

**Rate Limit**: 20 deactivations per hour per IP

**Response:**
```json
{
  "message": "User username deactivated"
}
```

#### Delete User
**DELETE** `/api/admin/users/<user_id>`

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

#### Generate Password Reset Token
**GET** `/api/admin/users/<user_id>/generate-reset-token`

Generate a password reset token for a specific user (Admin only).

**Response:**
```json
{
  "message": "Password reset token generated successfully",
  "token": "abc123def456",
  "expires_at": "2025-09-25T12:00:00Z",
  "user": {
    "id": 6,
    "name": "Test User",
    "username": "testuser123"
  }
}
```

**Security Features:**
- **Admin Only**: Requires admin role authentication
- **24-Hour Expiry**: Tokens expire in 24 hours
- **One-Time Use**: Each token can only be used once
- **Secure Generation**: Uses cryptographically secure token generation

**Error Responses:**
- `404 Not Found` - User not found
- `400 Bad Request` - User is inactive

#### Cleanup Expired Tokens
**DELETE** `/api/admin/cleanup-expired-tokens`

Clean up expired tokens from the database to improve performance (Admin only).

**Response:**
```json
{
  "message": "Cleanup completed successfully. Removed 5 expired tokens (3 JWT tokens, 2 reset tokens)"
}
```

**What Gets Cleaned:**
- **Expired JWT Tokens**: Revoked tokens older than 7 days
- **Expired Reset Tokens**: Password reset tokens past expiration

**Benefits:**
- **Database Performance**: Fewer records = faster queries
- **Storage Efficiency**: Prevents unlimited growth
- **Security**: Removes old token data

## Token Management & Maintenance

### JWT Authentication System

AccessVault implements a comprehensive JWT authentication system with enhanced security features:

#### Token Types
- **Access Tokens**: Short-lived (1 hour) for API authentication
- **Refresh Tokens**: Long-lived (7 days) for obtaining new access tokens
- **Password Reset Tokens**: Admin-generated (24 hours) for password resets

#### Security Features
- **Token Rotation**: Refresh tokens are rotated on each use
- **Token Revocation**: Immediate invalidation on logout
- **Database Tracking**: All revoked tokens are stored and validated
- **Automatic Expiry**: Tokens expire based on configured timeframes

#### Token Cleanup

**Manual Cleanup (Admin API):**
```bash
# Clean up expired tokens via API
DELETE /api/admin/cleanup-expired-tokens
Authorization: Bearer <admin_token>
```

**Scheduled Cleanup (Script):**
```bash
# Run cleanup script manually
python -m scripts.cleanup_tokens

# Or schedule with cron (daily at 2 AM)
0 2 * * * cd /path/to/AccessVault && python -m scripts.cleanup_tokens
```

**Cleanup Schedule Recommendations:**
- **Development**: Weekly cleanup
- **Production**: Daily cleanup
- **High Traffic**: Twice daily cleanup

### Password Reset Flow

1. **User requests password reset** from admin
2. **Admin generates reset token** via API
3. **User receives token** (via secure channel)
4. **User resets password** using token
5. **Token becomes invalid** after use

### Example: Complete Password Reset Flow

```bash
# 1. Admin generates reset token for user ID 6
GET /api/admin/users/6/generate-reset-token
Authorization: Bearer <admin_token>

# Response:
{
  "message": "Password reset token generated successfully",
  "token": "abc123def456",
  "expires_at": "2025-09-25T12:00:00Z",
  "user": {
    "id": 6,
    "name": "Test User",
    "username": "testuser123"
  }
}

# 2. User resets password with the token
POST /api/auth/reset-password
{
  "token": "abc123def456",
  "new_password": "NewPassword123!",
  "confirm_password": "NewPassword123!"
}

# Response:
{
  "message": "Password reset successfully"
}

# 3. User can now login with new password
POST /api/auth/login
{
  "username": "testuser123",
  "password": "NewPassword123!"
}
```

## Troubleshooting

### Common Issues

**Database Connection Issues:**
- Ensure your PostgreSQL database is running and accessible
- Verify the connection string format matches your provider
- For Supabase, ensure `?sslmode=require` is included in the URL
