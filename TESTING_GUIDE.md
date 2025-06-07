# API Testing Guide

This guide provides `curl` commands for testing the Admin and User services.

**Before you start:**
1. Ensure your `.env` file is correctly configured with your Supabase `DATABASE_URL` and `JWT_SECRET_KEY`.
2. Run `python scripts/init_db.py admin admin@example.com "Admin@123"` to initialize the database and create the initial admin user.
3. Start both services in separate terminals:
   - Admin Service: `python admin_service/app.py`
   - User Service: `python user_service/app.py`

## 1. Admin Service (Port 5001)

### A. Admin Login

-   **What we are doing**: Authenticating an administrator to obtain an access token. This token is required for all other admin-specific endpoints.
-   **Sample Input**:
    ```json
    {
        "username": "admin",
        "password": "Admin@123"
    }
    ```
-   **How to Run (cURL)**:
    ```bash
    curl -X POST http://localhost:5001/admin/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username": "admin", "password": "Admin@123"}'
    ```
-   **Expected Output**: A JSON object containing an `access_token` and `admin` details. Copy the `access_token` for subsequent admin requests.
    ```json
    {
        "access_token": "<your_jwt_token_here>",
        "admin": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "admin@example.com",
            "id": 1,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "role": "admin",
            "username": "admin"
        }
    }
    ```

### B. Get All Users (Admin Required)

-   **What we are doing**: Retrieving a list of all registered users. This endpoint demonstrates role-based access control (only accessible by admins).
-   **Sample Input**: None (uses Authorization header)
-   **How to Run (cURL)**:
    ```bash
    curl -X GET http://localhost:5001/admin/users \
      -H "Authorization: Bearer <YOUR_ADMIN_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON object indicating that the list of users would be returned (currently a placeholder).
    ```json
    {
        "message": "List of users would be returned here",
        "users": []
    }
    ```

## 2. User Service (Port 5002)

### A. User Registration

-   **What we are doing**: Creating a new user account in the system.
-   **Sample Input**:
    ```json
    {
        "username": "testuser",
        "email": "test@example.com",
        "password": "User@123",
        "first_name": "Test",
        "last_name": "User"
    }
    ```
-   **How to Run (cURL)**:
    ```bash
    curl -X POST http://localhost:5002/user/auth/register \
      -H "Content-Type: application/json" \
      -d '{\"username\": \"testuser\", \"email\": \"test@example.com\", \"password\": \"User@123\", \"first_name\": \"Test\", \"last_name\": \"User\"}'
    ```
-   **Expected Output**: A JSON object confirming successful registration and the new user's details.
    ```json
    {
        "message": "User registered successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "test@example.com",
            "first_name": "Test",
            "id": 1,
            "is_active": true,
            "last_login": null,
            "last_name": "User",
            "profile_data": null,
            "role": "user",
            "username": "testuser"
        }
    }
    ```

### B. User Login

-   **What we are doing**: Authenticating a user to obtain an access token. This token is required for all other user-specific endpoints.
-   **Sample Input**:
    ```json
    {
        "username": "testuser",
        "password": "User@123"
    }
    ```
-   **How to Run (cURL)**:
    ```bash
    curl -X POST http://localhost:5002/user/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username": "testuser", "password": "User@123"}'
    ```
-   **Expected Output**: A JSON object containing an `access_token` and `user` details. Copy the `access_token` for subsequent user requests.
    ```json
    {
        "access_token": "<your_user_jwt_token_here>",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "test@example.com",
            "first_name": "Test",
            "id": 1,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "last_name": "User",
            "profile_data": null,
            "role": "user",
            "username": "testuser"
        }
    }
    ```

### C. Get User Profile (User Required)

-   **What we are doing**: Retrieving the profile information for the currently authenticated user.
-   **Sample Input**: None (uses Authorization header)
-   **How to Run (cURL)**:
    ```bash
    curl -X GET http://localhost:5002/user/profile \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>"
    ```
-   **Expected Output**: A JSON object containing the current user's profile details.
    ```json
    {
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "test@example.com",
            "first_name": "Test",
            "id": 1,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "last_name": "User",
            "profile_data": null,
            "role": "user",
            "username": "testuser"
        }
    }
    ```

### D. Update User Profile

-   **What we are doing**: Modifying the profile information for the currently authenticated user (e.g., email, first name).
-   **Sample Input**:
    ```json
    {
        "email": "new.email@example.com",
        "first_name": "Updated"
    }
    ```
-   **How to Run (cURL)**:
    ```bash
    curl -X PUT http://localhost:5002/user/profile \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>" \
      -d '{\"email\": \"new.email@example.com\", \"first_name\": \"Updated\"}'
    ```
-   **Expected Output**: A JSON object confirming the profile update and showing the new user details.
    ```json
    {
        "message": "Profile updated successfully",
        "user": {
            "created_at": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "email": "new.email@example.com",
            "first_name": "Updated",
            "id": 1,
            "is_active": true,
            "last_login": "YYYY-MM-DDTHH:MM:SS.ffffff",
            "last_name": "User",
            "profile_data": null,
            "role": "user",
            "username": "testuser"
        }
    }
    ```

### E. Change User Password

-   **What we are doing**: Allowing the currently authenticated user to change their password.
-   **Sample Input**:
    ```json
    {
        "current_password": "User@123",
        "new_password": "NewPass@456"
    }
    ```
-   **How to Run (cURL)**:
    ```bash
    curl -X PUT http://localhost:5002/user/password \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer <YOUR_USER_ACCESS_TOKEN>" \
      -d '{\"current_password\": \"User@123\", \"new_password\": \"NewPass@456\"}'
    ```
-   **Expected Output**: A JSON object confirming the password change.
    ```json
    {
        "message": "Password changed successfully"
    }
    ``` 