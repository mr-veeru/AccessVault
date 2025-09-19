# AccessVault - Secure User Management API

A comprehensive Flask-based API for user authentication, authorization, and management with JWT tokens, role-based access control, rate limiting, and comprehensive logging. Built with **Flask**, **PostgreSQL**, **JWT Authentication**, and **Flask-RESTX** for automatic API documentation.

## Features
- **JWT Authentication** - Secure token-based authentication with refresh token rotation
- **Password Security** - bcrypt hashing with strong password policies
- **Password Reset System** - Admin-generated secure reset tokens with expiration
- **Refresh Token Management** - Database-stored tokens with device/IP binding and automatic cleanup
- **Modular Architecture** - Professional package structure with organized modules for scalability
- **Database Integration** - SQLAlchemy ORM with PostgreSQL support
- **Rate Limiting** - Comprehensive protection against abuse and DDoS attacks
- **Health Monitoring** - Production-ready health check endpoints
- **Role-Based Access Control** - Admin and user role management
- **Token Cleanup** - Automatic removal of expired and used tokens
- **Comprehensive Logging** - Enterprise-grade audit trails and security monitoring
- **Flask-RESTX Integration** - Automatic Swagger UI documentation with interactive testing

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
This creates the `users` and `password_reset_tokens` tables based on the models.

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
- **API Base URL**: `http://127.0.0.1:5000`
- **Swagger UI**: `http://127.0.0.1:5000/swagger-ui/`
- **Health Check**: `http://127.0.0.1:5000/api/health`

## Project Structure
```
AccessVault/
├── app.py                 # Main application entry point and Flask app factory
├── src/                   # Core application package
│   ├── __init__.py        # Global error handlers and error handling registration
│   ├── models.py          # SQLAlchemy database models (User, PasswordResetToken)
│   ├── extensions.py      # Flask extensions (db, jwt, bcrypt, limiter, api)
│   ├── decorators.py      # Role-based access control decorators
│   ├── logger.py          # Logging configuration and setup
│   ├── config.py          # Application configuration and database settings
│   └── routes/            # API routes organized by functionality
│       ├── __init__.py    # Route package initialization
│       ├── health.py      # Health check namespace (Flask-RESTX)
│       ├── admin.py       # Admin routes namespace (user management, statistics)
│       ├── auth.py        # Authentication routes namespace (register, login, refresh)
│       └── profile.py     # User profile routes namespace (profile, updates)
├── scripts/               # Database and utility scripts
│   ├── create_admin.py    # Script to create initial admin user
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
- **`src/decorators.py`**: Custom decorators for access control
- **`src/logger.py`**: Logging configuration with rotation
- **`src/routes/`**: API routes organized by functionality using Flask-RESTX namespaces

### Route Organization

- **`health_ns`**: Health check endpoints for monitoring
- **`auth_ns`**: Authentication operations (register, login, refresh, password reset)
- **`profile_ns`**: User profile management (view, update, password change, deactivate)
- **`admin_ns`**: Administrative operations (user management, statistics, password reset tokens)

### Key Design Patterns

- **Application Factory**: Flask app creation with `create_app()` function
- **Namespace Organization**: Flask-RESTX namespaces for API documentation
- **Decorator Pattern**: Custom decorators for authentication and authorization
- **Error Handling**: Global error handlers with consistent JSON responses
- **Rate Limiting**: Endpoint-specific and global rate limiting with Redis support

## API Reference

### Health Check Endpoints

#### Basic Health Check
**GET** `/` 

**Response:**
```json
{
  "message": "AccessVault API is running 🚀",
  "status": "healthy",
  "version": "1.0.0",
  "endpoints": {
    "health": "/api/health",
    "swagger": "/swagger-ui/"
  }
}
```

#### Comprehensive Health Check
**GET** `/api/health`

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
**POST** `/api/auth/register`

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
- **Case-insensitive** - usernames are automatically converted to lowercase

**Password Requirements:**
- Minimum 6 characters
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

#### Refresh Token
**GET** `/api/auth/refresh`

Generate new access and refresh tokens using current refresh token (token rotation).

**Rate Limit**: 10 refresh attempts per minute per IP

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
  "message": "New access token and refresh token generated",
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "new_refresh_token_value"
}
```

**Token Rotation:**
- Old refresh token is automatically revoked
- New refresh token is generated and stored in database
- Device and IP information is tracked for security

**Token Expiration:**
- **Access Token**: 15 minutes (configurable)
- **Refresh Token**: 7 days (configurable)

#### Logout
**POST** `/api/auth/logout`

Logout user by revoking all refresh tokens.

**Rate Limit**: 10 logout attempts per minute per IP

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

#### Password Reset
**POST** `/api/auth/reset-password`

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

#### Create Password Reset Token
**GET** `/api/admin/create-reset-token/<user_id>`

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

#### Refresh Token Management

**GET** `/api/admin/refresh-tokens`

Get all refresh tokens with pagination and filtering.

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `per_page` (optional): Items per page (default: 20)
- `user_id` (optional): Filter by specific user ID

**Response:**
```json
{
  "tokens": [
    {
      "id": 1,
      "user_id": 2,
      "token": "abc12345...",
      "device_info": "Mozilla/5.0...",
      "ip_address": "192.168.1.100",
      "created_at": "2024-01-15T10:30:00Z",
      "expires_at": "2024-01-22T10:30:00Z",
      "is_revoked": false,
      "is_expired": false
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 5,
    "pages": 1,
    "has_next": false,
    "has_prev": false
  }
}
```

**PATCH** `/api/admin/refresh-tokens/<token_id>/revoke`

Revoke a specific refresh token.

**Response:**
```json
{
  "message": "Refresh token revoked successfully",
  "token_id": 1,
  "user_id": 2
}
```

**POST** `/api/admin/refresh-tokens/cleanup`

Clean up expired and revoked refresh tokens.

**Response:**
```json
{
  "message": "Token cleanup completed successfully",
  "expired_tokens_removed": 3,
  "revoked_tokens_removed": 2,
  "total_cleaned": 5
}
```

**GET** `/api/admin/users/<user_id>/refresh-tokens`

Get all refresh tokens for a specific user.

**Response:**
```json
{
  "user": {
    "id": 2,
    "name": "John Doe",
    "username": "johndoe"
  },
  "tokens": [...],
  "total_tokens": 3,
  "active_tokens": 2
}
```

**PATCH** `/api/admin/users/<user_id>/revoke-all-tokens`

Revoke all refresh tokens for a specific user.

**Response:**
```json
{
  "message": "All refresh tokens revoked for user johndoe",
  "user_id": 2,
  "tokens_revoked": 3
}
```

## Token Cleanup

### Automatic Cleanup

The system includes automatic token cleanup to maintain database hygiene:

**What Gets Cleaned:**
- Expired refresh tokens (7+ days old)
- Revoked refresh tokens (24+ hours old)
- Expired password reset tokens (1+ hour old)
- Used password reset tokens (24+ hours old)

**Manual Cleanup:**
```bash
python scripts/cleanup_tokens.py
```

**Scheduled Cleanup:**
Set up a cron job to run cleanup automatically:
```bash
# Every 6 hours
0 */6 * * * cd /path/to/AccessVault && python scripts/cleanup_tokens.py
```

## Troubleshooting

### Common Issues

**Database Connection Issues:**
- Ensure your PostgreSQL database is running and accessible
- Verify the connection string format matches your provider
- For Supabase, ensure `?sslmode=require` is included in the URL

**Token Issues:**
- Access tokens expire after 15 minutes (configurable in `src/config.py`)
- Refresh tokens expire after 7 days (configurable in `src/config.py`)
- Include `Authorization: Bearer <token>` header for protected routes
- Use refresh token to get new access token via `/auth/refresh`
- Old refresh tokens are automatically revoked (token rotation)
- Use `/auth/logout` to revoke all tokens for a user

**Environment Configuration Issues:**
- Ensure `.env` file exists (copy from `.env.example`)
- Check that all required environment variables are set
- Verify database connection string format is correct
- Make sure `.env` file is in the project root directory
- For Supabase, ensure `?sslmode=require` is included in the URL

## API Documentation

### Swagger UI
Interactive API documentation is available at:
- **Swagger UI**: `http://127.0.0.1:5000/swagger-ui/`

The Swagger documentation provides:
- Interactive API testing
- Request/response examples
- Authentication testing with JWT tokens
- Model schemas and validation
- Error code documentation

## Error Handling

AccessVault implements comprehensive error handling with detailed error messages and proper HTTP status codes:

### Error Response Format
All error responses follow a consistent JSON format:
```json
{
  "error": "Error message description"
}
```

### Common Error Types

#### Validation Errors (400 Bad Request)
```json
{
  "error": "Missing required fields",
  "missing_fields": ["username", "password"],
  "required_fields": ["username", "password"]
}
```

#### Authentication Errors (401 Unauthorized)
```json
{
  "error": "Invalid username or password"
}
```

#### Authorization Errors (403 Forbidden)
```json
{
  "error": "Account is deactivated. Please contact admin."
}
```

#### Not Found Errors (404 Not Found)
```json
{
  "error": "User not found"
}
```

#### Rate Limit Errors (429 Too Many Requests)
```json
{
  "error": "Rate limit exceeded. Try again later."
}
```

## Project flow
1. Initialize Flask app, DB (SQLAlchemy), JWT, health check
2. logging: add centralized logging with logger.py
3. errors: implement global error handling middleware
4. auth: add registration route and login route with JWT
5. auth: add refresh token flow
6. security: add rate limiting to auth routes
7. user: add profile management APIs (view/update)
8. admin: add user management APIs
9. admin: add password reset token generation
10. swagger: document all models & responses