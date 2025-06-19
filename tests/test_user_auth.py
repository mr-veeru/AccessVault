import requests

BASE_URL = "http://localhost:5002"

# Test user registration

def test_register():
    data = {
        "username": "testuser1",
        "email": "testuser1@example.com",
        "password": "TestPass!123",
        "confirmPassword": "TestPass!123",
        "name": "Test User 1"
    }
    resp = requests.post(f"{BASE_URL}/user/auth/register", json=data)
    print("Register status:", resp.status_code)
    try:
        print("Register response:", resp.json())
    except Exception:
        print("Register response (non-JSON):", resp.text)
    if resp.status_code == 201:
        print("Registration successful.")
    elif resp.status_code == 400:
        print("User already exists or bad request.")
    elif resp.status_code == 500:
        print("Server error. Check database connection and backend logs.")
    else:
        print(f"Unexpected status code: {resp.status_code}")

# Test user login

def test_login():
    data = {
        "username_or_email": "testuser1",
        "password": "TestPass!123"
    }
    resp = requests.post(f"{BASE_URL}/user/auth/login", json=data)
    print("Login status:", resp.status_code)
    try:
        print("Login response:", resp.json())
    except Exception:
        print("Login response (non-JSON):", resp.text)
    if resp.status_code == 200:
        print("Login successful.")
    elif resp.status_code == 401:
        print("Invalid credentials.")
    elif resp.status_code == 403:
        print("Account is deactivated.")
    elif resp.status_code == 500:
        print("Server error. Check database connection and backend logs.")
    else:
        print(f"Unexpected status code: {resp.status_code}")

if __name__ == "__main__":
    test_register()
    test_login() 