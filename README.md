# AccessVault 

A secure role-based access control system built with **Flask**, **PostgreSQL (Supabase)**, and **JWT Authentication**.

## Features
- User & Admin roles
- JWT login & register
- Password hashing (bcrypt)
- REST API with Flask Blueprints
- PostgreSQL via SQLAlchemy

## Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mr-veeru/AccessVault.git
    cd AccessVault
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure database variables:**
    *   Create a `config.py` file in the project root (`AccessVault/config.py`).
    *   Populate it with your database URI and JWT secret key.
    *   **Important:** Replace placeholders with your actual values.

    ```dotenv
    # IMPORTANT: Replace these with your actual values
    # Flask secret keys
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "jwt-secret-key")
    # Database connection (paste your Supabase URL here)
    SQLALCHEMY_DATABASE_URI = (SUPABASE url)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ```

4.  **Initialize the database**
    (Ensure your PostgreSQL database is running and accessible)
    ```bash
    python init_db.py
    ```
    **Troubleshooting:** If you see database connection errors, make sure PostgreSQL is running and the credentials in your `config.py` file are correct.

5.  **Run the services**
    ```bash
    python app.py
    ```

## Project Structure
```
AccessVault/
├── app.py              # Admin service Flask app
├── extensions.py       # Admin profile/settings endpoints
├── init_db.py          # initialize database
├── model.py            # Structure of the database table
├── routes/             # API endpoints
│   └── auth.py         # Register, Login end points
├── config.py           # Database configarations
├── README.md           # This comprehensive guide
└── requirements.txt    # Python dependencies
```

## API Endpoints

### Auth
- `POST /auth/register` → Register new user (role = user by default)
- `POST /auth/login` → Login and receive JWT token

### Root
- `GET /` → Health check: returns `{"message": "AccessVault API is running 🚀"}`
