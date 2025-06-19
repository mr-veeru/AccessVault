# AccessVault API Testing Guide

This guide provides `curl` commands for quick and effective testing of the Admin and User services. It's an essential tool for verifying API functionality during development and troubleshooting.

**Before you start:**
1.  Ensure your `.env` file in the project root is correctly configured with your PostgreSQL `DATABASE_URL` and `JWT_SECRET_KEY`.
2.  Initialize the database and create the initial admin user:
    ```bash
    python backend/shared/init_db.py <username> <email> <password> <name>
    # Example: python backend/shared/init_db.py superadmin super@example.com StrongPass!123 Super Admin
    ```
3.  Start both backend services in separate terminal windows:
    *   Admin Service: `python backend/admin_service/app.py`
    *   User Service: `python backend/user_service/app.py`

## 1. Admin Service (Port 5001)

### A. Admin Login

-   **Description**: Authenticate an administrator to obtain a JWT access token. This token is required for all other admin-specific endpoints. Supports both dedicated admin accounts and users with admin role.
-   **Sample Input**:
    ```json
    {
        "username_or_email": "superadmin",
        "password": "StrongPass!123"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X POST http://localhost:5001/admin/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username_or_email": "superadmin", "password": "StrongPass!123"}'
    ```
-   **Expected Output**: A JSON object containing an `access_token` and `admin` details. **Copy the `access_token`** for subsequent admin requests.
    ```json
    {
        "access_token": "<your_jwt_token_here>",
        "admin": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "super@example.com",
            "id": 1,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "Super Admin",
            "role": "admin",
            "username": "superadmin"
        }
    }
    ```

### B. Get All Users

-   **Description**: Retrieve a list of all registered users in the system. (Admin role required)
-   **cURL Command**:
    ```bash
    curl -X GET http://localhost:5001/admin/users \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON array of user objects.
    ```json
    [
        {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "testuser@example.com",
            "id": 2,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "Test User",
            "role": "user",
            "updated_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "username": "testuser"
        }
    ]
    ```

### C. Get User Details

-   **Description**: Fetch detailed information for a specific user by their ID. (Admin role required)
-   **cURL Command**:
    ```bash
    curl -X GET http://localhost:5001/admin/users/<USER_ID> \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON object containing the specified user's details.
    ```json
    {
        "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
        "email": "testuser@example.com",
        "id": 2,
        "is_active": true,
        "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
        "name": "Test User",
        "role": "user",
        "updated_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
        "username": "testuser"
    }
    ```

### D. Update User Details (including Role Change)

-   **Description**: Modify a user's details, including their username, email, name, role, or account status (`is_active`). (Admin role required)
-   **Sample Input (to change role to admin)**:
    ```json
    {
        "role": "admin"
    }
    ```
-   **Sample Input (to update name/email)**:
    ```json
    {
        "name": "New Name",
        "email": "newemail@example.com"
    }
    ```
-   **Sample Input (to activate/deactivate)**:
    ```json
    {
        "is_active": false
    }
    ```
-   **cURL Command (Example for role change)**:
    ```bash
    curl -X PUT http://localhost:5001/admin/users/<USER_ID> \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>" \
      -d '{"role": "admin"}'
    ```
-   **Expected Output**: A JSON object confirming the update and showing the modified user details.
    ```json
    {
        "message": "User updated successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "testuser@example.com",
            "id": 2,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "Test User",
            "role": "admin", # Role has been changed to admin
            "updated_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "username": "testuser"
        }
    }
    ```
-   **Important Note**: When a user's role is changed to admin, they will need to log out and log back in through the admin login endpoint to get admin privileges.

### E. Delete User

-   **Description**: Permanently delete a user account from the system. (Admin role required)
-   **cURL Command**:
    ```bash
    curl -X DELETE http://localhost:5001/admin/users/<USER_ID> \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON object confirming successful deletion.
    ```json
    {
        "message": "User deleted successfully"
    }
    ```

### F. Update Admin Profile

-   **Description**: Update the currently logged-in admin's profile information.
-   **Sample Input**:
    ```json
    {
        "name": "Updated Admin Name",
        "email": "updated_admin@example.com"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X PUT http://localhost:5001/admin/profile \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>" \
      -d '{"name": "Updated Admin Name", "email": "updated_admin@example.com"}'
    ```
-   **Expected Output**: A JSON object confirming the update and showing the modified admin details.
    ```json
    {
        "message": "Admin profile updated successfully!",
        "admin": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "updated_admin@example.com",
            "id": 1,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "Updated Admin Name",
            "role": "admin",
            "username": "superadmin"
        }
    }
    ```

### G. Change Admin Password

-   **Description**: Allow the currently authenticated admin to change their password.
-   **Sample Input**:
    ```json
    {
        "old_password": "StrongPass!123",
        "new_password": "NewStrongPass!456"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X PUT http://localhost:5001/admin/auth/change-password \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>" \
      -d '{"old_password": "StrongPass!123", "new_password": "NewStrongPass!456"}'
    ```
-   **Expected Output**: A JSON object confirming the password change.
    ```json
    {
        "message": "Password updated successfully"
    }
    ```

## 2. User Service (Port 5002)

### A. User Registration

-   **Description**: Create a new user account in the system.
-   **Sample Input**:
    ```json
    {
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "UserPass!123",
        "name": "New User"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X POST http://localhost:5002/user/auth/register \
      -H "Content-Type: application/json" \
      -d '{"username": "newuser", "email": "newuser@example.com", "password": "UserPass!123", "confirmPassword": "UserPass!123", "name": "New User"}'
    ```
-   **Expected Output**: A JSON object confirming successful registration and the new user's details.
    ```json
    {
        "message": "User registered successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "newuser@example.com",
            "id": 2, # Example ID
            "is_active": true,
            "last_login": null,
            "name": "New User",
            "role": "user",
            "username": "newuser"
        }
    }
    ```

### B. User Login

-   **Description**: Authenticate a user to obtain a JWT access token. This token is required for all other user-specific endpoints.
-   **Sample Input**:
    ```json
    {
        "username_or_email": "newuser",
        "password": "UserPass!123"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X POST http://localhost:5002/user/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username_or_email": "newuser", "password": "UserPass!123"}'
    ```
-   **Expected Output**: A JSON object containing an `access_token` and `user` details. **Copy the `access_token`** for subsequent user requests.
    ```json
    {
        "access_token": "<your_jwt_token_here>",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "newuser@example.com",
            "id": 2,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "New User",
            "role": "user",
            "username": "newuser"
        }
    }
    ```

### C. Get User Profile

-   **Description**: Retrieve the profile information for the currently authenticated user.
-   **cURL Command**:
    ```bash
    curl -X GET http://localhost:5002/user/profile \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON object containing the current user's profile details.
    ```json
    {
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "newuser@example.com",
            "id": 2,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "New User",
            "role": "user",
            "updated_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "username": "newuser"
        }
    }
    ```

### D. Update User Profile

-   **Description**: Modify the profile information for the currently authenticated user (e.g., email, name).
-   **Sample Input**:
    ```json
    {
        "email": "updated.user@example.com",
        "name": "Updated User"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X PUT http://localhost:5002/user/profile \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>" \
      -d '{"email": "updated.user@example.com", "name": "Updated User"}'
    ```
-   **Expected Output**: A JSON object confirming the profile update and showing the new user details.
    ```json
    {
        "message": "Profile updated successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "updated.user@example.com",
            "id": 2,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "Updated User",
            "role": "user",
            "username": "newuser"
        }
    }
    ```

### E. Change User Password

-   **Description**: Allow the currently authenticated user to change their password.
-   **Sample Input**:
    ```json
    {
        "old_password": "UserPass!123",
        "new_password": "UserNewPass!456",
        "confirm_new_password": "UserNewPass!456"
    }
    ```
-   **cURL Command**:
    ```bash
    curl -X POST http://localhost:5002/user/profile/change-password \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>" \
      -d '{"old_password": "UserPass!123", "new_password": "UserNewPass!456", "confirm_new_password": "UserNewPass!456"}'
    ```
-   **Expected Output**: A JSON object confirming the password change.
    ```json
    {
        "message": "Password updated successfully"
    }
    ```

### F. Deactivate User Account

-   **Description**: Allow the currently authenticated user to deactivate their own account. This action is irreversible.
-   **cURL Command**:
    ```bash
    curl -X POST http://localhost:5002/user/profile/deactivate \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON object confirming account deactivation and showing the user's updated status.
    ```json
    {
        "message": "Account deactivated successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "newuser@example.com",
            "id": 2,
            "is_active": false,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "New User",
            "role": "user",
            "username": "newuser"
        }
    }
    ```

## 3. Testing Role Change Scenarios

### A. Promoting a User to Admin

1. **Register a new user** (if not already done):
   ```bash
   curl -X POST http://localhost:5002/user/auth/register \
     -H "Content-Type: application/json" \
     -d '{"username": "promoteuser", "email": "promote@example.com", "password": "UserPass!123", "name": "Promote User"}'
   ```

2. **Login as admin** and get admin token:
   ```bash
   curl -X POST http://localhost:5001/admin/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username_or_email": "superadmin", "password": "StrongPass!123"}'
   ```

3. **Change user role to admin**:
   ```bash
   curl -X PUT http://localhost:5001/admin/users/<USER_ID> \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>" \
     -d '{"role": "admin"}'
   ```

4. **Login as the promoted user** through admin login:
   ```bash
   curl -X POST http://localhost:5001/admin/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username_or_email": "promoteuser", "password": "UserPass!123"}'
   ```

5. **Verify admin access** using the new admin token:
   ```bash
   curl -X GET http://localhost:5001/admin/users \
     -H "Authorization: Bearer <NEW_ADMIN_ACCESS_TOKEN>"
   ```

### B. Testing Role Change Edge Cases

1. **Try to access admin endpoints with user token**:
   ```bash
   curl -X GET http://localhost:5001/admin/users \
     -H "Authorization: Bearer <USER_ACCESS_TOKEN>"
   ```
   Expected: 401 Unauthorized

2. **Try to change role without admin privileges**:
   ```bash
   curl -X PUT http://localhost:5001/admin/users/<USER_ID> \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <USER_ACCESS_TOKEN>" \
     -d '{"role": "admin"}'
   ```
   Expected: 401 Unauthorized

3. **Try to login to admin service with non-admin user**:
   ```bash
   curl -X POST http://localhost:5001/admin/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username_or_email": "regularuser", "password": "UserPass!123"}'
   ```
   Expected: 401 Unauthorized

## 4. Common Testing Scenarios

### A. Password Requirements

Test password validation with various combinations:
```bash
# Too short
curl -X POST http://localhost:5002/user/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "short", "name": "Test User"}'

# No uppercase
curl -X POST http://localhost:5002/user/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "lowercase123!", "name": "Test User"}'

# No special character
curl -X POST http://localhost:5002/user/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "NoSpecial123", "name": "Test User"}'

# Valid password
curl -X POST http://localhost:5002/user/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "email": "test@example.com", "password": "ValidPass123!", "name": "Test User"}'
```

### B. Token Expiration

1. Wait for token to expire (1 hour)
2. Try to access protected endpoint:
```bash
curl -X GET http://localhost:5001/admin/users \
  -H "Authorization: Bearer <EXPIRED_TOKEN>"
```
Expected: 401 Unauthorized

### C. Account Deactivation

1. Deactivate a user:
```bash
curl -X PUT http://localhost:5001/admin/users/<USER_ID> \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <ADMIN_ACCESS_TOKEN>" \
  -d '{"is_active": false}'
```

2. Try to login with deactivated account:
```bash
curl -X POST http://localhost:5002/user/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username_or_email": "deactivateduser", "password": "UserPass!123"}'
```
Expected: 403 Forbidden

## 5. Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check if the token is valid and not expired
   - Verify the token is being sent in the correct format
   - Ensure the user has the required role

2. **403 Forbidden**
   - Check if the account is active
   - Verify the user has the correct role for the endpoint

3. **404 Not Found**
   - Verify the user ID exists
   - Check if the endpoint URL is correct

4. **500 Internal Server Error**
   - Check server logs for detailed error messages
   - Verify database connection
   - Ensure all required environment variables are set

### Debugging Tips

1. Use verbose mode with curl to see detailed request/response:
```bash
curl -v -X POST http://localhost:5001/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username_or_email": "superadmin", "password": "StrongPass!123"}'
```

2. Check server logs for detailed error messages:
```bash
tail -f logs/admin_service.log
tail -f logs/user_service.log
```

3. Verify database connection:
```bash
psql $DATABASE_URL -c "\dt"
```

4. Test database queries directly:
```bash
psql $DATABASE_URL -c "SELECT * FROM users;"
psql $DATABASE_URL -c "SELECT * FROM admins;"
``` 