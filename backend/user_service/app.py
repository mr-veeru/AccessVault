import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
sys.path.append(project_root)

from flask import Flask
from flask_jwt_extended import JWTManager
from flask_swagger_ui import get_swaggerui_blueprint
from shared.config import Config
from shared.db import db
from dotenv import load_dotenv
from flask_cors import CORS
from shared.logger import setup_logging

# Load environment variables
load_dotenv(os.path.join(project_root, '.env'))

# Set up logging for the user service
user_service_logger = setup_logging('user_service')

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    CORS(app, resources={r"/*": {"origins": Config.REACT_APP_ORIGIN}})
    
    # Swagger configuration
    SWAGGER_URL = '/api/docs'
    API_URL = '/static/swagger.json'
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={'app_name': "User Service API"}
    )
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
    
    # Register blueprints
    from user_service.routes.user_auth import user_auth_bp
    from user_service.routes.user_profile import user_profile_bp
    
    app.register_blueprint(user_auth_bp, url_prefix='/user/auth')
    app.register_blueprint(user_profile_bp, url_prefix='/user')
    
    return app

if __name__ == '__main__':
    app = create_app()
    user_service_logger.info(f"User Service running on port {os.getenv('USER_SERVICE_PORT', 5002)}")
    app.run(port=int(os.getenv('USER_SERVICE_PORT', 5002)), debug=True) 