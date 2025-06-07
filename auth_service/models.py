from shared.db import db
from werkzeug.security import generate_password_hash, check_password_hash

class UserAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    age = db.Column(db.Integer)
    role = db.Column(db.String(20), default='user')  # Added role field

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "age": self.age,
            "role": self.role
        }

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password) 