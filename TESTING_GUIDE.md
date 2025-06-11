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

-   **Description**: Authenticate an administrator to obtain a JWT access token. This token is required for all other admin-specific endpoints.
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

### D. Update User Details (including Activate/Deactivate)

-   **Description**: Modify a user's details, including their username, email, name, or account status (`is_active`). (Admin role required)
-   **Sample Input (to activate/deactivate)**:
    ```json
    {
        "is_active": false
    }
    ```
-   **Sample Input (to update name/email)**:
    ```json
    {
        "name": "New Name",
        "email": "newemail@example.com"
    }
    ```
-   **cURL Command (Example for deactivation)**:
    ```bash
    curl -X PUT http://localhost:5001/admin/users/<USER_ID> \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>" \
      -d '{"is_active": false}'
    ```
-   **Expected Output**: A JSON object confirming the update and showing the modified user details.
    ```json
    {
        "message": "User updated successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "testuser@example.com",
            "id": 2,
            "is_active": false, # Will reflect the new status
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "name": "Test User",
            "role": "user",
            "updated_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "username": "testuser"
        }
    }
    ```

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
      -d '{"username": "newuser", "email": "newuser@example.com", "password": "UserPass!123", "name": "New User"}'
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

-   **Description**: Authenticate a user to obtain an access token. This token is required for all other user-specific endpoints.
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
        "access_token": "<your_user_jwt_token_here>",
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