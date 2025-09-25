# AccessVault - Enterprise User Management API

AccessVault is a **production-ready REST API** that provides secure user management capabilities for modern web applications. It's designed with enterprise security standards and includes features like JWT authentication, role-based access control, rate limiting, and comprehensive audit logging.

### **Key Features**

- **JWT Authentication** - Secure token-based authentication
- **Role-Based Access Control** - User and Admin roles
- **Rate Limiting** - Redis-backed protection against abuse
- **Token Management** - Automatic token rotation and revocation
- **Password Security** - Bcrypt hashing with strength validation
- **Admin Dashboard** - Complete user management interface
- **Comprehensive Logging** - Security audit trail
- **Health Monitoring** - System status and diagnostics
- **Auto Documentation** - Interactive Swagger UI

---

## **Project Architecture**

```
AccessVault/
├── 📁 src/                   # Core application package
│   ├── 📄 __init__.py        # Package initialization & global error handlers
│   ├── 📄 models.py          # Database models (User, RevokedToken, PasswordResetToken)
│   ├── 📄 extensions.py      # Flask extensions (db, jwt, bcrypt, limiter, api)
│   ├── 📄 decorators.py      # Access control decorators
│   ├── 📄 config.py          # Configuration management
│   ├── 📄 logger.py          # Logging configuration
│   └── 📁 routes/            # API routes organized by functionality
│       ├── 📄 __init__.py    # Routes package initialization
│       ├── 📄 health.py      # Health check endpoints
│       ├── 📄 auth.py        # Authentication (register, login, logout, refresh)
│       ├── 📄 profile.py     # User profile management
│       └── 📄 admin.py       # Admin operations
├── 📁 scripts/               # Utility scripts
│   ├── 📄 init_db.py         # Database initialization
│   ├── 📄 create_admin.py    # Admin user creation
│   └── 📄 cleanup_tokens.py  # Token cleanup
├── 📁 logs/                  # Application logs (auto-generated)
│   └── 📄 accessvault.log    # Current log file with daily rotation
├── 📄 app.py                 # Main application entry point
├── 📄 requirements.txt       # Python dependencies
├── 📄 .env                   # Environment variables (git-ignored)
├── 📄 .env.example           # Environment variables template
├── 📄 .gitignore             # Git ignore patterns
└── 📄 README.md              # This file
```

---

## **Quick Start Guide**

### **Step 1: Clone the Repository**
```bash
git clone https://github.com/mr-veeru/AccessVault.git
cd AccessVault
```

### **Step 2: Install Dependencies**
```bash
pip install -r requirements.txt
```

**Key Dependencies:**
- `Flask` - Web framework
- `Flask-JWT-Extended` - JWT token management
- `Flask-Bcrypt` - Password hashing
- `Flask-Limiter` - Rate limiting
- `PostgreSQL` - Database
- `Redis` - Rate limiting storage (optional)

### **Step 3: Set Up Environment Variables**
Create a `.env` file in the project root:

```bash
# Database Configuration
SQLALCHEMY_DATABASE_URI=postgresql://username:password@localhost:5432/accessvault

# Security Keys (Generate strong keys for production)
SECRET_KEY=your-super-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# Rate Limiting (Optional - defaults to memory storage)
RATELIMIT_STORAGE_URL=redis://localhost:6379/0
```

**For Supabase users:**
```bash
SQLALCHEMY_DATABASE_URI=postgresql://postgres.xxxxx:your-password@aws-0-region.pooler.supabase.com:6543/postgres?sslmode=require
```

### **Step 4: Initialize Database**
```bash
python -m scripts.init_db
```

This creates the following tables:
- `users` - User accounts and authentication data
- `revoked_tokens` - Revoked JWT tokens for security
- `password_reset_tokens` - Admin-generated password reset tokens

### **Step 5: Create Admin User (Optional)**
```bash
python -m scripts.create_admin
```

**Default admin credentials:**
- **Username:** `admin66`
- **Password:** `Admin@123`
- **Role:** `admin`

### **Step 6: Run the Application**
```bash
python app.py
```

**Access Points:**
- **API Base URL:** `http://127.0.0.1:5000/`
- **Health Check:** `http://127.0.0.1:5000/api/health/`
- **Swagger UI:** `http://127.0.0.1:5000/api/swagger-ui/`

### **Step 7: Token Cleanup (Optional)**
For production environments, you can set up automated token cleanup:
```bash
python -m scripts.cleanup_tokens
```

**What it does:**
- Removes expired JWT tokens (older than 7 days)
- Removes expired password reset tokens
- Improves database performance
- Can be run as a scheduled task (cron job)

---

## **API Documentation**

### **Health Check**
```http
GET /api/health/
```
**Purpose:** Monitor system health and connectivity
**Response:** System status, database connectivity, JWT configuration, rate limiting status

### **Authentication Endpoints**

#### **Register User**
```http
POST /api/auth/register
Content-Type: application/json

{
  "name": "Veerendra",
  "username": "veeru123",
  "password": "SecurePass123!",
  "confirm_password": "SecurePass123!"
}
```

#### **Login**
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "veeru123",
  "password": "SecurePass123!"
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

#### **Logout**
```http
POST /api/auth/logout
Authorization: Bearer <access_token>
```

#### **Refresh Tokens**
```http
POST /api/auth/refresh
Authorization: Bearer <refresh_token>
```

#### **Reset Password**
```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "token": "reset-token-from-admin",
  "new_password": "NewSecurePass123!",
  "confirm_password": "NewSecurePass123!"
}
```

### **Profile Management**

#### **Get Profile**
```http
GET /api/profile/
Authorization: Bearer <access_token>
```

#### **Update Profile**
```http
PATCH /api/profile/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "name": "Veerendra",
  "username": "veeru66"
}
```

#### **Change Password**
```http
PATCH /api/profile/password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "old_password": "OldPassword123!",
  "new_password": "NewPassword123!",
  "confirm_password": "NewPassword123!"
}
```

#### **Deactivate Account**
```http
PATCH /api/profile/deactivate
Authorization: Bearer <access_token>
```

#### **Delete Account**
```http
DELETE /api/profile/delete
Authorization: Bearer <access_token>
```

### **Admin Operations**

#### **System Statistics**
```http
GET /api/admin/stats
Authorization: Bearer <admin_token>
```

#### **User Management**
```http
# Get all users
GET /api/admin/users
Authorization: Bearer <admin_token>

# Get active users
GET /api/admin/users/active
Authorization: Bearer <admin_token>

# Get inactive users
GET /api/admin/users/inactive
Authorization: Bearer <admin_token>

# Search users by username
GET /api/admin/users/search/username/{username}
Authorization: Bearer <admin_token>

# Search users by name
GET /api/admin/users/search/name/{name}
Authorization: Bearer <admin_token>

# Get specific user
GET /api/admin/users/{user_id}
Authorization: Bearer <admin_token>
```

#### **Create User**
```http
POST /api/admin/users
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "Jane Doe",
  "username": "janedoe123",
  "role": "user"
}
```

#### **Update User**
```http
PATCH /api/admin/users/{user_id}
Authorization: Bearer <admin_token>
Content-Type: application/json

{
  "name": "Jane Smith",
  "username": "janesmith123",
  "role": "admin"
}
```

#### **Delete User**
```http
DELETE /api/admin/users/{user_id}
Authorization: Bearer <admin_token>
```

#### **User Status Management**
```http
# Activate user
PATCH /api/admin/users/{user_id}/activate
Authorization: Bearer <admin_token>

# Deactivate user
PATCH /api/admin/users/{user_id}/deactivate
Authorization: Bearer <admin_token>
```

#### **Password Reset Management**
```http
# Generate password reset token
GET /api/admin/users/{user_id}/generate-reset-token
Authorization: Bearer <admin_token>
```

#### **System Maintenance**
```http
# Clean up expired tokens
DELETE /api/admin/cleanup-expired-tokens
Authorization: Bearer <admin_token>
```

---

## **Security Features**

### **Authentication & Authorization**
- **JWT Tokens** - Secure, stateless authentication
- **Token Rotation** - Automatic refresh token rotation
- **Token Revocation** - Database-backed token blacklist
- **Role-Based Access** - User and Admin role separation

### **Password Security**
- **Bcrypt Hashing** - Industry-standard password hashing
- **Strength Validation** - Enforced password complexity
- **Password History** - Prevents password reuse

### **Rate Limiting**
- **Redis-Backed** - Distributed rate limiting
- **Endpoint-Specific** - Custom limits per endpoint
- **IP-Based Tracking** - Per-client rate limiting

### **Input Validation**
- **Field Validation** - Required field checking
- **Format Validation** - Username and password patterns
- **Length Limits** - DoS attack prevention
- **SQL Injection Protection** - Parameterized queries

---

## **Rate Limiting Configuration**

| Endpoint              | Rate Limit    | Purpose                     |
|-----------------------|---------------|-----------------------------|
| **Register**          | 5 per minute  | Prevent spam registrations  |
| **Login**             | 3 per minute  | Prevent brute force attacks |
| **Password Reset**    | 5 per minute  | Prevent token abuse         |
| **Profile Update**    | 20 per minute | Normal usage patterns       |
| **Admin Operations**  | 10-60 per hour| Administrative controls     |
| **Health Check**      | 10 per minute | Monitoring endpoints        |

---

## **Configuration Options**

### **Environment Variables**
```bash
# Required
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
SQLALCHEMY_DATABASE_URI=postgresql://...

# Optional
RATELIMIT_STORAGE_URL=redis://localhost:6379/0
```

### **Database Configuration**
- **PostgreSQL** - Primary database
- **Redis** - Rate limiting storage (optional)
- **Connection Pooling** - Optimized for production

---

## **Production Deployment**

### **Prerequisites**
- Python 3.10+
- PostgreSQL 12+
- Redis 6+ (optional)
- Nginx (recommended)

### **Deployment Steps**
1. **Set up production database**
2. **Configure environment variables**
3. **Run database migrations**
4. **Set up Redis (optional)**
5. **Deploy with Gunicorn**
6. **Configure Nginx reverse proxy**

---

## **Monitoring & Logging**

### **Health Monitoring**
- **System Health** - Database, JWT, Flask status
- **Performance Metrics** - Response times, error rates
- **Security Events** - Failed logins, rate limit hits

### **Logging**
- **Structured Logging** - JSON format for easy parsing
- **Log Rotation** - Daily rotation with retention
- **Security Audit** - All authentication events logged

---

## **Testing**

### **Manual Testing**
1. **Start the application**
2. **Access Swagger UI** at `/api/swagger-ui/`
3. **Test endpoints** using the interactive interface
4. **Verify rate limiting** by making multiple requests

### **API Testing with curl**
```bash
# Register a user
curl -X POST http://127.0.0.1:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","username":"testuser123","password":"TestPass123!","confirm_password":"TestPass123!"}'

# Login
curl -X POST http://127.0.0.1:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser123","password":"TestPass123!"}'
```

---

## **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

## **Author**

**Veerendra** - *Full Stack Developer*
- GitHub: [@mr-veeru](https://github.com/mr-veeru)
- LinkedIn: [Veerendra](https://www.linkedin.com/in/veerendra-bannuru-900934215)

---

## **Acknowledgments**

- Flask community for the excellent framework
- PostgreSQL team for the robust database
- JWT.io for the authentication standard
- All contributors and testers

---
