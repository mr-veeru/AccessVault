from flask import Flask, jsonify
from extensions import db, jwt, bcrypt
from config import *
from routes.auth import auth_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object("config")
    
    db.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    
    app.register_blueprint(auth_bp, url_prefix="/auth")


    # Simple route (GET request to "/")
    @app.route("/")
    def home():
        return jsonify({"message": "AccessVault API is running 🚀"})

    return app

# Run the server only if this file is executed directly
if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)
    