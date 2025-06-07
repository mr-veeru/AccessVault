from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt
from auth_service.models import UserAuth
from shared.db import db
from functools import wraps

auth_bp = Blueprint('auth', __name__)

# Role-based access control decorator
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            jwt = get_jwt()
            if jwt.get("role") != "admin":
                return jsonify({"error": "Admin privileges required"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json
    name = data.get("name")
    password = data.get("password")
    age = data.get("age")
    role = data.get("role", "user")

    if not name or not password:
        return jsonify({"error": "Name and password are required"}), 400

    if UserAuth.query.filter_by(name=name).first():
        return jsonify({"error": "User already exists"}), 400

    user = UserAuth(name=name, age=age, role=role)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    name = data.get("name")
    password = data.get("password")

    user = UserAuth.query.filter_by(name=name).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(
        identity=user.name,
        additional_claims={"role": user.role}
    )
    return jsonify({
        "access_token": access_token,
        "user": user.to_dict()
    })

@auth_bp.route("/verify", methods=["GET"])
@jwt_required()
def verify_token():
    current_user = get_jwt_identity()
    return jsonify({"logged_in_as": current_user}), 200

@auth_bp.route("/profile", methods=["GET"])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    user = UserAuth.query.filter_by(name=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user.to_dict())

@auth_bp.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    current_user = get_jwt_identity()
    user = UserAuth.query.filter_by(name=current_user).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.json
    if "age" in data:
        user.age = data["age"]
    if "password" in data:
        user.set_password(data["password"])

    db.session.commit()
    return jsonify({"message": "Profile updated successfully", "user": user.to_dict()})

@auth_bp.route("/users", methods=["GET"])
@jwt_required()
@admin_required()
def list_users():
    users = UserAuth.query.all()
    return jsonify({"users": [user.to_dict() for user in users]})

@auth_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
@admin_required()
def delete_user(user_id):
    user = UserAuth.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}) 