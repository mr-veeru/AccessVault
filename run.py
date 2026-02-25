"""
AccessVault - Run script for local development.

Usage: python run.py

Production: gunicorn app:app
"""
from app import app
from app.config import Config

if __name__ == "__main__":
    app.run(debug=Config.DEBUG)
