from extensions import db 

class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(20), default="user")
    
    def __repr__(self):
        return f"<User {self.username}>"
    