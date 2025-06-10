# AccessVault - User Management & Auth System

A microservice-based user management and authentication system built with Flask and PostgreSQL, with a ReactJS frontend.

## Features

- Separate admin and user services
- JWT-based authentication
- Role-based access control (admin, user)
- PostgreSQL database integration (Supabase hosted)
- Comprehensive Swagger API documentation using Flasgger
- Microservice architecture
- ReactJS frontend for a modern user interface

## Project Structure

```
project/
│
├── backend/
│   ├── admin_service/
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── models.py
│   │   └── routes/
│   │       ├── admin_auth.py
│   │       └── admin_management.py
│   │
│   ├── user_service/
│   │   ├── __init__.py
│   │   ├── app.py
│   │   ├── models.py
│   │   └── routes/
│   │       ├── user_auth.py
│   │       └── user_profile.py
│   │
│   ├── shared/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── db.py
│   │   ├── init_db.py
│   │   └── utils/
│   │       ├── auth_utils.py
│   │       └── validators.py
│   │
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── index.tsx
│   │   ├── AuthForm.tsx
│   │   ├── UserProfile.tsx
│   │   ├── AdminDashboard.tsx
│   │   ├── index.css
│   │   └── ... (other React components and assets)
│   ├── package.json
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── .env (for React app environment variables)
│   └── ... (other React project files)
│
├── .env (for Backend environment variables)
├── README.md
├── TESTING_GUIDE.md
└── .gitignore
```

## Setup

### Backend Setup

1. Install Python dependencies:
```bash
pip install -r backend/requirements.txt
```

2. Configure backend environment variables:
   Rename `config.env` to `.env` in the project root.
   Update the `.env` file with your database URI and JWT secret key. Also ensure `REACT_APP_ORIGIN` is set to your React development server URL (e.g., `http://localhost:3000`).

   Example `.env` content:
   ```
   DATABASE_URL="postgresql://postgres:postgres@localhost:5432/accessvault"
   JWT_SECRET_KEY="your-secret-key-here"
   ADMIN_SERVICE_PORT=5001
   USER_SERVICE_PORT=5002
   FLASK_DEBUG=False # Debug mode is now set to False by default
   REACT_APP_ORIGIN=http://localhost:3000
   ```

3. Initialize the database and create admin user:
   (Ensure your PostgreSQL database, e.g., Supabase, is running and accessible)
   ```bash
   python backend/shared/init_db.py admin68 admin@example.com "Admin@123" Admin
   ```

4. Run the backend services in separate terminals:

   Admin Service:
   ```bash
   python backend/admin_service/app.py
   ```

   User Service:
   ```bash
   python backend/user_service/app.py
   ```

### Frontend Setup (ReactJS)

1. Navigate to the React app directory:
   ```bash
   cd frontend
   ```

2. Install Node.js dependencies (if not already installed during `create-react-app`):
   ```bash
   npm install
   ```

3. Start the React development server:
   ```bash
   npm start
   ```
   This will usually open your application in your web browser at `http://localhost:3000`.

## API Endpoints

### Admin Service (Port 5001)

#### Authentication
- `POST /admin/auth/login` - Admin login
- `GET /admin/auth/verify` - Verify admin token

#### Management
- `GET /admin/users` - List all users
- `GET /admin/users/<user_id>` - Get user details
- `POST /admin/users/<user_id>/deactivate` - Deactivate user
- `GET /admin/settings` - Get system settings
- `PUT /admin/settings` - Update system settings

### User Service (Port 5002)

#### Authentication
- `POST /user/auth/register` - Register new user
- `POST /user/auth/login` - User login
- `GET /user/auth/verify` - Verify user token

#### Profile
- `GET /user/profile` - Get user profile
- `PUT /user/profile` - Update user profile
- `PUT /user/password` - Change password

## Security

- Password requirements:
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one digit
  - At least one special character

- JWT token expiration: 1 hour
- Role-based access control
- Secure password hashing

## API Documentation

Access Swagger documentation at:
- Admin Service: `http://localhost:5001/apidocs/`
- User Service: `http://localhost:5002/apidocs/`

## Recent Updates

- Migrated Swagger UI from `flask_swagger_ui` to `Flasgger` for better compatibility and documentation generation.
- Added OpenAPI specifications (docstrings) to various API endpoints for improved documentation.
- Removed unused imports and debug flags from backend services.
- Updated README.md to reflect the latest changes and improvements. 