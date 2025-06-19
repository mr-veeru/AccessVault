# Security Features Documentation

## Overview

AccessVault now includes enhanced security features with aggressive log rotation and comprehensive rate limiting to protect against common security threats and ensure optimal system performance.

## 🔄 Log Rotation

### Features
- **Size-based rotation**: Log files rotate when they reach 5MB (configurable)
- **Aggressive retention**: Logs are kept for only 3 days (configurable)
- **Total size limits**: Maximum 100MB total log storage (configurable)
- **Automatic cleanup**: Old logs are automatically deleted
- **UTF-8 encoding**: Proper character encoding for international support

### Configuration
Log rotation settings can be configured via environment variables:

```bash
# Log file size before rotation (default: 5MB)
LOG_MAX_FILE_SIZE_MB=5

# Number of backup files to keep (default: 3)
LOG_BACKUP_COUNT=3

# Days to retain logs (default: 3 days)
LOG_RETENTION_DAYS=3

# Maximum total log size (default: 100MB)
LOG_MAX_TOTAL_SIZE_MB=100
```

### Benefits
- **Prevents disk space issues**: Automatic cleanup prevents log files from consuming excessive disk space
- **Improved performance**: Smaller log files are faster to read and process
- **Security**: Reduces exposure of sensitive information in old logs
- **Compliance**: Helps meet data retention requirements

## 🛡️ Rate Limiting

### Overview
Rate limiting protects against brute force attacks, DDoS, and API abuse by limiting the number of requests a client can make within a specified time period.

### Rate Limits by Endpoint Type

#### Authentication Endpoints
- **User Login/Register**: 5 requests per minute, 50 per hour
- **Admin Login**: 10 requests per minute, 100 per hour
- **Password Changes**: 3 requests per hour (very strict)

#### User Management Endpoints
- **Admin Operations**: 30 requests per minute, 1000 per hour
- **Profile Operations**: 60 requests per minute, 2000 per hour

#### Default Limits
- **General API**: 200 requests per day, 50 per hour

### Configuration
Rate limits can be configured via environment variables in `shared/config.py`:

```python
# Rate limiting configuration
RATE_LIMIT_DEFAULT = "200 per day, 50 per hour"
RATE_LIMIT_AUTH = "5 per minute, 50 per hour"
RATE_LIMIT_AUTH_ADMIN = "10 per minute, 100 per hour"
RATE_LIMIT_PASSWORD_CHANGE = "3 per hour"
RATE_LIMIT_USER_MANAGEMENT = "30 per minute, 1000 per hour"
RATE_LIMIT_PROFILE = "60 per minute, 2000 per hour"
```

### Implementation Details

#### Rate Limiting Decorators
The system provides several decorators for easy application:

```python
from shared.utils.rate_limiter import (
    auth_rate_limit,
    password_change_rate_limit,
    user_management_rate_limit,
    profile_rate_limit
)

@auth_rate_limit
def login():
    # Login logic here
    pass

@password_change_rate_limit
def change_password():
    # Password change logic here
    pass
```

#### User Type Detection
Rate limits automatically adjust based on user type:
- **Admin users**: Higher limits for administrative operations
- **Regular users**: Standard limits for normal operations
- **Unauthenticated users**: Strictest limits

#### Response Format
When rate limits are exceeded, the API returns:

```json
{
    "error": "Rate limit exceeded",
    "message": "Too many requests. Limit: 5 per minute, 50 per hour"
}
```

With HTTP status code `429 (Too Many Requests)`.

### Benefits
- **Brute Force Protection**: Prevents password guessing attacks
- **DDoS Mitigation**: Limits the impact of distributed attacks
- **Resource Protection**: Prevents API abuse and server overload
- **Security Monitoring**: All rate limit violations are logged
- **Flexible Configuration**: Different limits for different user types and endpoints

## 🔍 Monitoring and Logging

### Rate Limit Violations
All rate limit violations are logged with:
- Timestamp
- User type (admin/user/unauthenticated)
- Endpoint accessed
- IP address
- Request details

### Log Rotation Events
Log rotation events are logged with:
- File sizes before and after rotation
- Number of files deleted
- Total disk space freed
- Age of deleted files

## 🚀 Installation and Setup

### 1. Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment Variables (Optional)
Create a `.env` file in the backend directory:

```bash
# Logging Configuration
LOG_MAX_FILE_SIZE_MB=5
LOG_BACKUP_COUNT=3
LOG_RETENTION_DAYS=3
LOG_MAX_TOTAL_SIZE_MB=100

# Rate Limiting (optional - uses defaults if not set)
# These are already configured in shared/config.py
```

### 3. Start Services
```bash
# Start admin service
cd backend/admin_service
python app.py

# Start user service
cd backend/user_service
python app.py
```

## 🧪 Testing

### Test Rate Limiting
```bash
# Test authentication rate limiting
curl -X POST http://localhost:5002/user/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"test"}' \
  -w "\nHTTP Status: %{http_code}\n"

# Repeat multiple times to trigger rate limit
```

### Test Log Rotation
```bash
# Monitor log files
ls -la logs/
tail -f logs/application.log

# Check log rotation
# Logs will automatically rotate when they reach 5MB
```

## 🔧 Troubleshooting

### Common Issues

#### Rate Limiting Not Working
1. Check that `flask-limiter` is installed
2. Verify rate limiting is applied in app initialization
3. Check logs for any import errors

#### Log Rotation Not Working
1. Verify log directory permissions
2. Check that log files are being written
3. Monitor disk space availability

#### High Memory Usage
1. Check rate limiting storage (currently using memory)
2. Consider switching to Redis for production
3. Monitor log file sizes and rotation frequency

### Performance Considerations

#### Production Recommendations
- **Use Redis for rate limiting**: Replace `storage_uri="memory://"` with Redis
- **Monitor log growth**: Adjust retention periods based on usage
- **Set appropriate limits**: Adjust rate limits based on expected traffic
- **Enable compression**: Consider compressing old log files

## 📊 Metrics and Monitoring

### Key Metrics to Monitor
- Rate limit violations per endpoint
- Log file sizes and rotation frequency
- Total log storage usage
- API response times under rate limiting

### Alerts to Set Up
- Rate limit violations exceeding threshold
- Log storage usage above 80%
- Failed log rotation attempts
- Memory usage for rate limiting storage

---

**Note**: These security features are designed to work together to provide comprehensive protection while maintaining system performance. Regular monitoring and adjustment of settings based on usage patterns is recommended. 