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

### **Step 4: Set Up Redis with Docker (Optional)**

Redis is used for distributed rate limiting. The app works without Redis using in-memory storage.

**To use Redis (recommended for production):**
```bash
# Start Redis container
docker run -d --name redis-server -p 6379:6379 redis:latest

# Check if Redis is running
docker ps
```

**Environment Configuration:**
Add to your `.env` file:
```bash
RATELIMIT_STORAGE_URL=redis://localhost:6379/0
```

**Note:** If Redis is not available or not configured, the application automatically uses in-memory storage.

### **Step 5: Initialize Database**
```bash
python -m scripts.init_db
```

This creates the following tables:
- `users` - User accounts and authentication data
- `revoked_tokens` - Revoked JWT tokens for security
- `password_reset_tokens` - Admin-generated password reset tokens

### **Step 6: Create Admin User (Optional)**
```bash
python -m scripts.create_admin
```

**Default admin credentials:**
- **Username:** `admin66`
- **Password:** `Admin@123`
- **Role:** `admin`

### **Step 7: Run the Application**
```bash
python app.py
```

**Access Points:**
- **API Base URL:** `http://127.0.0.1:5000/`
- **Health Check:** `http://127.0.0.1:5000/api/health/`
- **Swagger UI:** `http://127.0.0.1:5000/api/swagger-ui/`

### **Step 8: Token Cleanup (Optional)**
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

Complete API documentation is available in **[API.md](API.md)**.
**API Base URL:** `http://127.0.0.1:5000/api`

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

## **Rate Limiting**

Rate limiting is configured for all endpoints to prevent abuse. See [API.md](API.md) for detailed rate limit information.

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
- **Redis** - Rate limiting storage (Docker: `redis://localhost:6379/0`)

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

---

## **Contributing**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

---

<div align="center">

## 📞 Contact

**Bannuru Veerendra**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/mr-veeru)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/veerendra-bannuru-900934215)
[![Gmail](https://img.shields.io/badge/Gmail-D14836?style=for-the-badge&logo=gmail&logoColor=white)](mailto:mr.veeru68@gmail.com)

---

</div>
