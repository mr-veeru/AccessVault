# AccessVault API Documentation

Complete API reference for AccessVault User Management API.

**Base URL:** `http://127.0.0.1:5000/api`  
**Swagger UI:** `http://127.0.0.1:5000/api/swagger-ui/`

---

## Authentication

Protected endpoints require a JWT token in the header:

```
Authorization: Bearer <access_token>
```

**Token Types:**
- **Access Token** - Valid for 1 hour (use for API calls)
- **Refresh Token** - Valid for 7 days (use to get new tokens)

---

## Endpoints

### Health Check

**GET** `/api/health/`

Check if the API is running and healthy.

**Response:**
```json
{
  "status": "healthy",
  "checks": {
    "database": {"status": "healthy"},
    "jwt": {"status": "healthy"}
  }
}
```

---

## Authentication

### Register

**POST** `/api/auth/register`

Create a new user account.

**Request:**
```json
{
  "name": "Veerendra",
  "username": "veeru123",
  "password": "SecurePass123!",
  "confirm_password": "SecurePass123!"
}
```

**Response:** `201 Created`
```json
{
  "message": "User registered successfully"
}
```

**Rules:**
- Username: 3+ chars, alphanumeric, must have letter + number
- Password: 8+ chars, must have uppercase, number, and special char (@#$%&*!?)

---

### Login

**POST** `/api/auth/login`

Get access and refresh tokens.

**Request:**
```json
{
  "username": "veeru123",
  "password": "SecurePass123!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Login successful",
  "access_token": "eyJ0eXAi...",
  "refresh_token": "eyJ0eXAi..."
}
```

---

### Logout

**POST** `/api/auth/logout`  
**Auth Required:** Yes

Revoke current access token.

**Response:** `200 OK`
```json
{
  "message": "Logged out successfully"
}
```

---

### Refresh Tokens

**POST** `/api/auth/refresh`  
**Auth Required:** Yes (refresh token)

Get new access and refresh tokens.

**Response:** `200 OK`
```json
{
  "message": "Tokens refreshed successfully",
  "access_token": "eyJ0eXAi...",
  "refresh_token": "eyJ0eXAi..."
}
```

**Note:** Old refresh token is automatically revoked.

---

### Reset Password

**POST** `/api/auth/reset-password`

Reset password using admin-generated token.

**Request:**
```json
{
  "token": "reset-token-from-admin",
  "new_password": "NewSecurePass123!",
  "confirm_password": "NewSecurePass123!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset successfully"
}
```

---

## Profile Management

### Get Profile

**GET** `/api/profile/`  
**Auth Required:** Yes

Get current user's profile information.

**Response:** `200 OK`
```json
{
  "user_id": 1,
  "name": "Veerendra",
  "username": "veeru123",
  "role": "user",
  "status": "active"
}
```

---

### Update Profile

**PATCH** `/api/profile/`  
**Auth Required:** Yes

Update name or username.

**Request:**
```json
{
  "name": "Veerendra Bannuru",
  "username": "veeru123"
}
```

**Response:** `200 OK` (returns updated profile)

---

### Change Password

**PATCH** `/api/profile/password`  
**Auth Required:** Yes

Change your password.

**Request:**
```json
{
  "old_password": "OldPassword123!",
  "new_password": "NewPassword123!",
  "confirm_password": "NewPassword123!"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password updated successfully"
}
```

---

### Deactivate Account

**PATCH** `/api/profile/deactivate`  
**Auth Required:** Yes

Deactivate your account (can be reactivated by admin).

**Response:** `200 OK`
```json
{
  "message": "Account deactivated successfully"
}
```

---

### Delete Account

**DELETE** `/api/profile/delete`  
**Auth Required:** Yes

Permanently delete your account.

**Response:** `200 OK`
```json
{
  "message": "Account {username} deleted successfully"
}
```

**Warning:** This action cannot be undone.

---

## Admin Operations

All admin endpoints require admin role.

### System Statistics

**GET** `/api/admin/stats`  
**Auth Required:** Yes (Admin)

Get system statistics.

**Response:** `200 OK`
```json
{
  "status": "success",
  "data": {
    "total_users": 100,
    "active_users": 85,
    "inactive_users": 15,
    "admins": 5,
    "regular_users": 95
  }
}
```

---

### Get All Users

**GET** `/api/admin/users`  
**Auth Required:** Yes (Admin)

Get list of all users.

**Response:** `200 OK`
```json
{
  "status": "success",
  "count": 100,
  "data": [
    {
      "id": 1,
      "name": "Veerendra",
      "username": "veeru123",
      "role": "user",
      "status": "active"
    }
  ]
}
```

---

### Get Active Users

**GET** `/api/admin/users/active`  
**Auth Required:** Yes (Admin)

Get only active users.

---

### Get Inactive Users

**GET** `/api/admin/users/inactive`  
**Auth Required:** Yes (Admin)

Get only inactive users.

---

### Search Users by Username

**GET** `/api/admin/users/search/username/{username}`  
**Auth Required:** Yes (Admin)

Search users by username (partial match, case-insensitive).

**Example:** `GET /api/admin/users/search/username/veeru`

---

### Search Users by Name

**GET** `/api/admin/users/search/name/{name}`  
**Auth Required:** Yes (Admin)

Search users by full name (partial match, case-insensitive).

**Example:** `GET /api/admin/users/search/name/Veerendra`

---

### Get User by ID

**GET** `/api/admin/users/{user_id}`  
**Auth Required:** Yes (Admin)

Get specific user details.

**Response:** `200 OK`
```json
{
  "status": "success",
  "data": {
    "id": 1,
    "name": "Veerendra",
    "username": "veeru123",
    "role": "user",
    "status": "active"
  }
}
```

---

### Create User

**POST** `/api/admin/users`  
**Auth Required:** Yes (Admin)

Create a new user (with default password).

**Request:**
```json
{
  "name": "Veerendra Bannuru",
  "username": "veeru123",
  "role": "user"
}
```

**Response:** `201 Created`
```json
{
  "status": "success",
  "data": {
    "id": 101,
    "name": "Veerendra Bannuru",
    "username": "veeru123",
    "role": "user",
    "status": "active",
    "default_password": "User@123"
  }
}
```

**Note:** Default password is `User@123` - user should reset on first login.

---

### Update User

**PATCH** `/api/admin/users/{user_id}`  
**Auth Required:** Yes (Admin)

Update user information.

**Request:**
```json
{
  "name": "Veerendra",
  "username": "veeru123",
  "role": "admin"
}
```

**Response:** `200 OK` (returns updated user)

---

### Delete User

**DELETE** `/api/admin/users/{user_id}`  
**Auth Required:** Yes (Admin)

Delete a user permanently.

**Response:** `200 OK`
```json
{
  "status": "success",
  "message": "User {username} deleted successfully"
}
```

**Note:** Cannot delete your own account.

---

### Activate User

**PATCH** `/api/admin/users/{user_id}/activate`  
**Auth Required:** Yes (Admin)

Activate a user account.

**Response:** `200 OK` (returns activated user)

---

### Deactivate User

**PATCH** `/api/admin/users/{user_id}/deactivate`  
**Auth Required:** Yes (Admin)

Deactivate a user account.

**Response:** `200 OK` (returns deactivated user)

---

### Generate Password Reset Token

**GET** `/api/admin/users/{user_id}/generate-reset-token`  
**Auth Required:** Yes (Admin)

Generate a password reset token for a user.

**Response:** `200 OK`
```json
{
  "status": "success",
  "data": {
    "token": "abc123def456...",
    "expires_at": "2024-01-02T12:00:00Z",
    "user": {
      "id": 1,
      "name": "Veerendra",
      "username": "veeru123"
    }
  }
}
```

**Note:** Token expires in 24 hours. User can use it at `/api/auth/reset-password`.


---

## Rate Limiting

All endpoints have rate limits to prevent abuse:

| Endpoint           | Rate Limit       |
|--------------------|------------------|
| Register           | 5 per minute     |
| Login              | 3 per minute     |
| Password Reset     | 5 per minute     |
| Profile Update     | 20 per minute    |
| Change Password    | 5 per hour       |
| Deactivate Account | 3 per hour       |
| Delete Account     | 1 per hour       |
| Admin Operations   | 10-60 per hour   |
| Health Check       | 10 per minute    |

**Rate Limit Exceeded:** Returns `429 Too Many Requests`

---

## Error Responses

- **400 Bad Request** - Invalid input data
- **401 Unauthorized** - Missing or invalid authentication token
- **403 Forbidden** - Insufficient permissions or account deactivated
- **404 Not Found** - Requested resource doesn't exist
- **422 Unprocessable Entity** - Token expired or invalid
- **429 Too Many Requests** - Rate limit exceeded
- **500 Internal Server Error** - Server error occurred

**Example Error Response:**
```json
{
  "error": "Bad Request"
}
```

---

## Interactive Documentation

Use **Swagger UI** for interactive API testing:

```
http://127.0.0.1:5000/api/swagger-ui/
```

Features:
- Try all endpoints directly
- See request/response schemas
- Test with authentication
- View examples

---

## Notes

- All timestamps are in UTC (ISO 8601 format)
- Usernames are case-insensitive
- Passwords must be 8+ characters with uppercase, number, and special character
- Access tokens expire after 1 hour
- Refresh tokens expire after 7 days
- Rate limits are per IP address
- Admin endpoints require admin role in JWT token
