# AccessVault: Secure User Management & Authentication System 🔐

![AccessVault Banner](https://img.shields.io/badge/Status-Active-brightgreen)
![Backend](https://img.shields.io/badge/Backend-Flask%20%7C%20PostgreSQL-blueviolet)
![Frontend](https://img.shields.io/badge/Frontend-ReactJS%20%7C%20TypeScript%20%7C%20TailwindCSS-blue)
![Auth](https://img.shields.io/badge/Authentication-JWT-orange)

AccessVault is a robust, microservice-based solution designed for comprehensive user management and authentication. Built with a powerful Flask backend (featuring distinct admin and user services) and a modern ReactJS frontend, it offers secure, scalable, and intuitive control over user data.

## ✨ Key Features

*   **Microservice Architecture:** Separate Flask services for `Admin` and `User` operations, ensuring scalability and maintainability.
*   **Role-Based Access Control (RBAC):** Granular permissions for `admin` and `user` roles to secure functionality.
*   **JWT-Based Authentication:** Industry-standard JSON Web Tokens for secure and stateless API authentication.
*   **PostgreSQL Database:** Reliable and high-performance data storage, integrated seamlessly with Supabase.
*   **Comprehensive API Documentation:** Interactive Swagger UI for both Admin and User services, making API exploration a breeze.
*   **Modern ReactJS Frontend:** A sleek and responsive user interface built with TypeScript and styled using Tailwind CSS.
*   **Secure Password Handling:** Robust password policies including minimum length, uppercase, lowercase, digit, and special character requirements.
*   **Dynamic Account Status:** Admins can easily activate or deactivate user accounts via the dashboard.

## 🚀 Getting Started

Follow these steps to set up and run AccessVault on your local machine.

### Prerequisites

*   Python 3.8+
*   Node.js & npm (or yarn)
*   PostgreSQL (or a PostgreSQL-compatible database, e.g., Supabase)

### Backend Setup (Flask & PostgreSQL)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/AccessVault.git
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
│   │   ├── models.py                     # Admin database models
│   │   └── routes/                       # Admin API endpoints (auth, management)
│   │
│   ├── user_service/                     # User-specific logic & API
│   │   ├── app.py                        # User service Flask app
│   │   ├── models.py                     # User database models
│   │   └── routes/                       # User API endpoints (auth, profile)
│   │
│   ├── shared/                           # Shared utilities, DB config, validators
│   │   ├── config.py                     # Centralized application configuration
│   │   ├── db.py                         # Database initialization and SQLAlchemy instance
│   │   ├── init_db.py                    # Script to initialize database and create first admin
│   │   └── utils/                        # Common utility functions
│   │       ├── auth_utils.py             # Authentication helper decorators
│   │       └── validators.py             # Input validation functions
│   │
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
│   ├── .env.development                  # Frontend environment variables (optional, for specific environments)
│   └── ... (other React project files)
│
├── .env                                  # Backend environment variables
├── README.md                             # Project overview and setup guide
├── TESTING_GUIDE.md                      # Guide for running tests and manual testing steps
├── .gitignore                            # Git ignore configurations
└── package-lock.json                     # Node.js dependency lock file
```

## 🌐 API Endpoints

Access the interactive Swagger UI for detailed API specifications:
*   **Admin Service API Docs:** `http://localhost:5001/apidocs/`
*   **User Service API Docs:** `http://localhost:5002/apidocs/`

### Admin Service (Port 5001)

#### Authentication
*   `POST /admin/auth/login` - Admin login
*   `GET /admin/auth/verify` - Verify admin token

#### User Management
*   `GET /admin/users` - List all users
*   `GET /admin/users/<user_id>` - Get user details
*   `PUT /admin/users/<user_id>` - Update user details (includes status change)
*   `DELETE /admin/users/<user_id>` - Delete user

#### System & Profile Management
*   `GET /admin/settings` - Get system settings
*   `PUT /admin/settings` - Update system settings
*   `PUT /admin/profile` - Update admin's own profile (username, email, name)
*   `PUT /admin/auth/change-password` - Change admin's own password

### User Service (Port 5002)

#### Authentication
*   `POST /user/auth/register` - Register new user
*   `POST /user/auth/login` - User login
*   `GET /user/auth/verify` - Verify user token

#### Profile Management
*   `GET /user/profile` - Get user's own profile
*   `PUT /user/profile` - Update user's own profile (username, email, name)
*   `POST /user/profile/change-password` - Change user's own password
*   `POST /user/profile/deactivate` - Deactivate user's own account

## 🔒 Security Highlights

*   **Strong Password Policy:** Enforces minimum length, uppercase, lowercase, digit, and special character requirements.
*   **JWT Token Management:** Tokens expire after 1 hour, enhancing security.
*   **Role-Based Access Control:** Ensures users can only access resources permitted by their assigned roles (`admin` or `user`).
*   **Secure Password Hashing:** Utilizes `werkzeug.security` for robust password storage.

## 🙏 Contributing

Contributions are welcome! If you have suggestions or find issues, please open an issue or submit a pull request.

---

**Developed with ❤️ by Veeru**
