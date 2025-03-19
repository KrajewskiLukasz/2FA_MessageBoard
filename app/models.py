from app import db
from flask_login import UserMixin
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=False)
    private_key = db.Column(db.Text, nullable=False)  
    public_key = db.Column(db.Text, nullable=False)   
    messages = db.relationship('Message', backref='author', lazy=True)

    def generate_keys(self):
        """Generuje parę kluczy RSA i zapisuje je w bazie danych"""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        
        self.private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        self.public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)  
    title = db.Column(db.String(100), nullable=False)  
    content = db.Column(db.Text, nullable=False)  
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)  
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    signature = db.Column(db.Text, nullable=True)  

    def __repr__(self):
        return f"Message('{self.title}', '{self.date_posted}')"

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)  
    attempts = db.Column(db.Integer, default=0, nullable=False)  
    last_attempt = db.Column(db.DateTime, default=datetime.utcnow)  
    blocked_until = db.Column(db.DateTime, nullable=True)  
