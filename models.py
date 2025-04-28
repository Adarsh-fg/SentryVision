# models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    # Add more fields if needed, e.g., email_alerts_enabled = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

# You might add an Alert model later if you want to persist alerts in the DB
# class Alert(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
#     alert_type = db.Column(db.String(64))
#     detected_class = db.Column(db.String(64))
#     confidence = db.Column(db.Float)
#     camera_id = db.Column(db.String(64))
#     snapshot_file = db.Column(db.String(128))
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Optional link to user?



"""
models.py

This module defines the database models used in the Flask Security Monitoring App.
It uses SQLAlchemy as the ORM and integrates with Flask-Login for user authentication.

Models:
--------
1. User:
    - Represents a registered user in the system.
    - Fields: id, email (unique), password_hash.
    - Includes methods to securely set and verify passwords.
    - Inherits from UserMixin to support Flask-Login functionality.

2. Alert (Optional, currently commented out):
    - Represents a security alert (e.g., motion or threat detection).
    - Can be used to persist alerts in the database for logging and analytics.
    - Fields include timestamp, alert type, detected object class, confidence, camera ID, and snapshot file.
    - Can optionally link each alert to a specific user (via foreign key).

Usage:
--------
- Import `db` in your app and call `db.init_app(app)` during setup.
- Run `db.create_all()` once to create the tables in your database.
- The `User` model is used for user registration, login, and session management.
- Uncomment and use the `Alert` model if you want to store alert data persistently.

Security:
--------
- Passwords are hashed using Werkzeug's secure hashing functions.
- Never store plain-text passwords in the database.
"""
