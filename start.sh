#!/bin/bash

# Production startup script for AccessVault API
echo "Starting AccessVault API..."

# Initialize database tables
echo "Initializing database..."
python -m scripts.init_db

# Start the application with Gunicorn
echo "Starting Gunicorn server..."
gunicorn --bind 0.0.0.0:$PORT --workers 4 --timeout 120 --keep-alive 2 --max-requests 1000 --max-requests-jitter 100 app:app
