"""
Profile Routes Module

This module handles user profile management operations including viewing,
updating profile information, changing passwords, and account management.
Uses Flask-RESTX for automatic Swagger documentation.
"""

from flask import request
from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.models import User
from src.decorators import active_required
from src.extensions import api
from src.logger import logger

# Create profile namespace
profile_ns = Namespace('profile', description='Profile management operations')

# Request/Response models for Swagger documentation
profile_model = api.model('Profile', {
    'user_id': fields.Integer(description='User ID'),
    'name': fields.String(description='Full name'),
    'username': fields.String(description='Username'),
    'role': fields.String(description='User role'),
    'status': fields.String(description='Account status')
})

@profile_ns.route('/')
class Profile(Resource):
    @profile_ns.marshal_with(profile_model, code=200)
    @jwt_required()
    @active_required
    def get(self):
        """Get current user's profile information"""
        user_id = get_jwt_identity()  # JWT identity is now a string
        user = User.query.get(int(user_id))
        logger.info(f"User profile fetched successfully: {user.username} (ID: {user.id}) from IP: {request.remote_addr}")
        return {
            "user_id": user.id,
            "name": user.name,
            "username": user.username,
            "role": user.role,
            "status": user.status
        }, 200