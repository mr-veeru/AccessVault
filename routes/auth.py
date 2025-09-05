from flask import Blueprint, request, jsonify
from extensions import db, bcrypt
from model import User
from flask_jwt_extended import create_access_token


auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    """User Registeration"""
    required_fields = {"username", "password"}
    data = request.get_json()
    
    # check for missing fields
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Both username and password are required"}), 400
    
    # reject unknown fields
    if any(key not in required_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    username = data.get("username")
    password = data.get("password")
    
    # check if user already exist
    if User.query.filter_by(username=username).first():
        return jsonify({"Error": "Username already exist"}), 400
    
    # hashed password
    hashed_pwd = bcrypt.generate_password_hash(password).decode("utf-8")
    
    # create user
    new_user = User(username = username, password=hashed_pwd)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """User login route"""
    required_fields = {"username", "password"}
    data = request.get_json()
    
    # check for missing fields
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Both username and password are required"}), 400
    
    # reject unknown fields
    if any(key not in required_fields for key in data.keys()):
        return jsonify({"error": "Unexpected fields in request"}), 400
    
    username = data.get("username")
    password = data.get("password")

    # Find the user by username
    user = User.query.filter_by(username=username).first()
    
    # Check if user exists
    if not user:
        return jsonify({"Error": "Invalid username or password"}), 400
    
    # Check if password is correct
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"Error": "Invalid username or password"}), 400
    
    # Create access token with user's actual data
    access_token = create_access_token(identity={"id": user.id, "role": user.role})
    
    return jsonify({
        "message": "Login successful",
        "access_token": access_token
    }), 200
    