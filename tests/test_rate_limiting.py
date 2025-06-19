#!/usr/bin/env python3
"""
Rate Limiting Test Script for AccessVault

This script demonstrates the rate limiting functionality by making multiple
requests to protected endpoints and showing how rate limits are enforced.
"""

import requests
import time
import json
from typing import Dict, Any

# Configuration
USER_SERVICE_URL = "http://localhost:5002"
ADMIN_SERVICE_URL = "http://localhost:5001"

def make_request(url: str, method: str = "POST", data: Dict[str, Any] = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
    """Make an HTTP request and return the response."""
    try:
        if method.upper() == "POST":
            response = requests.post(url, json=data, headers=headers)
        elif method.upper() == "GET":
            response = requests.get(url, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "body": response.json() if response.content else None
        }
    except requests.exceptions.RequestException as e:
        return {
            "status_code": None,
            "error": str(e)
        }

def test_authentication_rate_limiting():
    """Test rate limiting on authentication endpoints."""
    print("🔐 Testing Authentication Rate Limiting")
    print("=" * 50)
    
    # Test user login rate limiting
    print("\n1. Testing User Login Rate Limiting (5 per minute, 50 per hour)")
    print("-" * 60)
    
    login_data = {
        "username": "testuser",
        "password": "wrongpassword"
    }
    
    for i in range(7):  # Try 7 times to trigger rate limit
        print(f"Request {i+1}: ", end="")
        response = make_request(f"{USER_SERVICE_URL}/user/auth/login", data=login_data)
        
        if response.get("status_code") == 429:
            print(f"✅ Rate limit triggered! Status: {response['status_code']}")
            print(f"   Message: {response.get('body', {}).get('message', 'No message')}")
            break
        elif response.get("status_code") == 401:
            print(f"❌ Authentication failed (expected) - Status: {response['status_code']}")
        else:
            print(f"⚠️  Unexpected response - Status: {response.get('status_code')}")
        
        time.sleep(0.1)  # Small delay between requests
    
    print("\n2. Testing Admin Login Rate Limiting (10 per minute, 100 per hour)")
    print("-" * 60)
    
    admin_login_data = {
        "username": "adminuser",
        "password": "wrongpassword"
    }
    
    for i in range(12):  # Try 12 times to trigger rate limit
        print(f"Request {i+1}: ", end="")
        response = make_request(f"{ADMIN_SERVICE_URL}/admin/auth/login", data=admin_login_data)
        
        if response.get("status_code") == 429:
            print(f"✅ Rate limit triggered! Status: {response['status_code']}")
            print(f"   Message: {response.get('body', {}).get('message', 'No message')}")
            break
        elif response.get("status_code") == 401:
            print(f"❌ Authentication failed (expected) - Status: {response['status_code']}")
        else:
            print(f"⚠️  Unexpected response - Status: {response.get('status_code')}")
        
        time.sleep(0.1)  # Small delay between requests

def test_password_change_rate_limiting():
    """Test rate limiting on password change endpoints."""
    print("\n🔑 Testing Password Change Rate Limiting (3 per hour)")
    print("=" * 50)
    
    # First, we need to get a valid token (this would normally be done after successful login)
    print("Note: This test requires a valid JWT token.")
    print("To test password change rate limiting:")
    print("1. Login successfully to get a token")
    print("2. Use the token to make password change requests")
    print("3. After 3 attempts, you should hit the rate limit")
    print("\nExample curl command:")
    print(f'curl -X PUT {USER_SERVICE_URL}/user/auth/change-password \\')
    print('  -H "Authorization: Bearer YOUR_JWT_TOKEN" \\')
    print('  -H "Content-Type: application/json" \\')
    print('  -d \'{"old_password":"current","new_password":"newpassword123!"}\'')

def test_log_rotation():
    """Test log rotation functionality."""
    print("\n📝 Testing Log Rotation")
    print("=" * 50)
    
    print("Log rotation is automatic and happens when:")
    print("1. Log files reach 5MB in size")
    print("2. Logs are older than 3 days")
    print("3. Total log storage exceeds 100MB")
    print("\nTo monitor log rotation:")
    print("1. Check the logs directory: ls -la logs/")
    print("2. Monitor log file sizes: du -h logs/*")
    print("3. Watch for rotation events in the application logs")
    print("\nLog files are automatically cleaned up to prevent disk space issues.")

def main():
    """Main test function."""
    print("🚀 AccessVault Security Features Test")
    print("=" * 60)
    print("This script tests the rate limiting and log rotation features.")
    print("Make sure both services are running:")
    print("- Admin Service: http://localhost:5001")
    print("- User Service: http://localhost:5002")
    print()
    
    # Test authentication rate limiting
    test_authentication_rate_limiting()
    
    # Test password change rate limiting (informational)
    test_password_change_rate_limiting()
    
    # Test log rotation (informational)
    test_log_rotation()
    
    print("\n✅ Rate limiting tests completed!")
    print("\n📖 For more information, see SECURITY_FEATURES.md")
    print("\n💡 Tips:")
    print("- Rate limits are per IP address")
    print("- Different endpoints have different limits")
    print("- Admin users have higher limits than regular users")
    print("- All rate limit violations are logged")

if __name__ == "__main__":
    main() 