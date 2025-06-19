# AccessVault: Secure User Management & Authentication System 🔐

AccessVault is a robust, microservice-based solution designed for comprehensive user management and authentication. Built with a powerful Flask backend (featuring distinct admin and user services) and a modern ReactJS frontend, it offers secure, scalable, and intuitive control over user data.

## ✨ Key Features

*   **Microservice Architecture:** Separate Flask services for `Admin` and `User` operations, ensuring scalability and maintainability.
*   **Role-Based Access Control (RBAC):** Granular permissions for `admin` and `user` roles to secure functionality.
*   **JWT-Based Authentication:** Industry-standard JSON Web Tokens for secure and stateless API authentication.
*   **PostgreSQL Database:** A reliable and high-performance data storage solution with optimized single-table design.
*   **Comprehensive API Documentation:** An interactive Swagger UI is available for both Admin and User services, making API exploration effortless.
*   **Modern ReactJS Frontend:** A sleek and responsive user interface built with TypeScript and styled using Tailwind CSS.
*   **Secure Password Handling:** Robust password policies including minimum length, uppercase, lowercase, digit, and special character requirements.
*   **Dynamic Account Status:** Admins can easily activate or deactivate user accounts via the dashboard.
*   **Flexible Role Management:** Users can be promoted to the admin role with automatic session handling.

## 🚀 Getting Started

Follow these steps to set up and run AccessVault on your local machine.

### Prerequisites

*   Python 3.8+
*   Node.js & npm (or yarn)
*   PostgreSQL (or a PostgreSQL-compatible database, e.g., Supabase)

### Backend Setup (Flask & PostgreSQL)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mr-veeru/AccessVault.git
    cd AccessVault
    ```

2.  **Install Python dependencies:**
```bash
pip install -r backend/requirements.txt
```

3.  **Configure environment variables:**
    *   Create a `.env` file in the project root (`AccessVault/.env`).
    *   Populate it with your database URI, JWT secret key, and frontend origin.
    *   **Important:** Replace placeholders with your actual values.

    ```dotenv
    DATABASE_URL="postgresql://postgres:postgres@localhost:5432/accessvault"
    JWT_SECRET_KEY="a_very_strong_and_secret_key_for_jwt_tokens" # **CHANGE THIS IN PRODUCTION**
    ADMIN_SERVICE_PORT=5001
    USER_SERVICE_PORT=5002
    FLASK_DEBUG=False
    REACT_APP_ORIGIN=http://localhost:3000
    ```

4.  **Initialize the database and create a default admin user:**
    (Ensure your PostgreSQL database is running and accessible)
    ```bash
    python backend/shared/init_db.py <username> <email> <password> <name>
    # Example: python backend/shared/init_db.py adminuser admin@example.com StrongPass!123 AdminName
    ```
    **Troubleshooting:** If you see database connection errors, make sure PostgreSQL is running and the credentials in your `.env` file are correct.

5.  **Run the backend services (in separate terminal windows):**

    *   **Admin Service:**
    ```bash
    python backend/admin_service/app.py
    ```
    *   **User Service:**
    ```bash
    python backend/user_service/app.py
    ```

### Frontend Setup (ReactJS)

1.  **Navigate to the frontend directory:**
    ```bash
    cd frontend
    ```

2.  **Install Node.js dependencies:**
    ```bash
    npm install
    # or yarn install
    ```

3.  **Start the React development server:**
    ```bash
    npm start
    # or yarn start
    ```
    This will typically open the application in your web browser at `http://localhost:3000`.

## 📂 Project Structure

```
project/
│
├── backend/                              # Flask microservices
│   ├── admin_service/                    # Admin-specific logic & API
│   │   ├── app.py                        # Admin service Flask app
│   │   ├── routes/                       # Admin API endpoints (auth, management)
│   │   │   ├── admin_auth.py             # Admin authentication endpoints
│   │   │   ├── admin_management.py       # Admin profile/settings endpoints
│   │   │   └── user_management.py        # Endpoints for managing user accounts
│   │   └── static/
│   │       └── swagger.json              # OpenAPI/Swagger documentation for admin service
│   │
│   ├── user_service/                     # User-specific logic & API
│   │   ├── app.py                        # User service Flask app
│   │   ├── routes/                       # User API endpoints (auth, profile)
│   │   │   ├── user_auth.py              # User authentication endpoints
│   │   │   └── user_profile.py           # User profile management endpoints
│   │   └── static/
│   │       └── swagger.json              # OpenAPI/Swagger documentation for user service
│   │
│   ├── shared/                           # Shared utilities, DB config, validators
│   │   ├── config.py                     # Centralized application configuration
│   │   ├── db.py                         # Database initialization and SQLAlchemy instance
│   │   ├── models.py                     # Single Account model for all users/admins
│   │   ├── init_db.py                    # Script to initialize database and create first admin
│   │   ├── logger.py                     # Logging setup and log rotation
│   │   └── utils/                        # Common utility functions
│   │       ├── auth_utils.py             # Authentication helper decorators
│   │       ├── validators.py             # Input validation functions
│   │       └── rate_limiter.py           # API rate limiting logic
│   │
│   ├── .env                              # Backend environment variables
│   └── requirements.txt                  # Python dependencies
│
├── frontend/                             # ReactJS single-page application
│   ├── public/                           # Static assets
│   ├── src/                              # React source code
│   │   ├── App.tsx                       # Main application component & routing
│   │   ├── index.tsx                     # React app entry point
│   │   ├── components/                   # Reusable UI components (AuthForm, Dashboards, Profiles)
│   │   ├── services/                     # Centralized API service for frontend
│   │   ├── context/                      # React Context providers (e.g., notifications)
│   │   └── types/                        # TypeScript type definitions (interfaces)
│   │
│   ├── package.json                      # Frontend dependencies & scripts
│   ├── tailwind.config.js                # Tailwind CSS configuration
│   ├── postcss.config.js                 # PostCSS configuration
│   └── ... (other React project files)
│
├── tests/                                # Automated test scripts (backend & frontend)
│   ├── test_user_auth.py                 # Account registration/login test
│   ├── test_rate_limiting.py             # Backend rate limiting/log rotation test
│   └── test_frontend_rate_limit.js       # Frontend rate limit test
│
├── README.md                             # Project overview and setup guide
├── TESTING_GUIDE.md                      # Guide for running tests and manual testing steps
├── .gitignore                            # Git ignore configurations
```

## 🛠️ Backend Utilities & Documentation

- **logger.py**: Centralized logging setup for all backend services. Handles log formatting, file output, and aggressive log rotation (size and age-based). All security events and errors are logged for monitoring and analysis.
- **rate_limiter.py**: Implements API rate limiting for both user and admin services. Protects against brute force, DDoS, and API abuse with configurable limits per endpoint and user type.
- **Swagger/OpenAPI Docs**: Each service exposes interactive API documentation:
  - **Admin Service:** `backend/admin_service/static/swagger.json` (view at `http://localhost:5001/api/docs/`)
  - **User Service:** `backend/user_service/static/swagger.json` (view at `http://localhost:5002/api/docs/`)

## 🔒 Security Highlights

*   **Strong Password Policy:** Enforces minimum length, uppercase, lowercase, digit, and special character requirements.
*   **JWT Token Management:** Tokens expire after 1 hour, enhancing security.
*   **Role-Based Access Control:** Ensures users can only access resources permitted by their assigned roles (`admin` or `user`).
*   **Secure Password Hashing:** Utilizes `werkzeug.security` for robust password storage.
*   **Flexible Role Management:** Users can be promoted to the admin role with automatic session handling and token refresh.
*   **🛡️ Rate Limiting:** Comprehensive API rate limiting protects against brute force attacks, DDoS, and API abuse with different limits for different endpoints and user types. See `backend/shared/utils/rate_limiter.py` for details.
*   **🔄 Aggressive Log Rotation:** Size-based log rotation with automatic cleanup prevents disk space issues and reduces exposure of sensitive information in old logs. See `backend/shared/logger.py` for details.
*   **Security Monitoring:** All security events (rate limit violations, authentication attempts, etc.) are logged for monitoring and analysis.

## 🧪 Running Tests

All automated test scripts are located in the `tests/` directory.

- **Account registration/login test:**
  ```bash
  python tests/test_user_auth.py
  ```
- **Backend rate limiting/log rotation test:**
  ```bash
  python tests/test_rate_limiting.py
  ```
- **Frontend rate limit test:**
  ```bash
  node tests/test_frontend_rate_limit.js
  ```

See [`TESTING_GUIDE.md`](TESTING_GUIDE.md) for detailed API and manual testing instructions, including sample curl commands and troubleshooting tips.