# config.py
import os

# Base directory of the application
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # --- Security ---
    # Generate a strong secret key! You can use: python -c 'import secrets; print(secrets.token_hex())'
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-hard-to-guess-secret-key'

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'instance', 'site.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- MQTT (Added if missing) ---
    MQTT_BROKER = os.environ.get('MQTT_BROKER') # Ensure this line exists and is inside the class
    MQTT_PORT = int(os.environ.get('MQTT_PORT') or 1883)

    # --- Camera & Detection ---
    MODEL_PATH = "yolov8m.pt"
    CONFIDENCE_THRESHOLD = 0.5
    PRIMARY_THREAT_CLASSES = ["bottle","gun", "knife", "weapon", "explosive", "bomb", "bat", "machete", "sword", "axe", "spear" ,
                              "wood", "stick", "bludgeon", "club", "brass knuckles", "nunchaku", "katana", "scimitar", "swordfish"
                              ,"machete", "crossbow", "slingshot", "boomerang",  "scimitar"]
    PERSON_CLASS_NAME = "person"
    ALERT_INTERVAL_SECONDS = 2.0 # Min seconds between alerts (for display/MQTT)
    SNAPSHOT_DIR = os.path.join(basedir, 'static', 'snapshots')
    MAX_ALERT_HISTORY = 50
    # Define camera sources (indices, RTSP URLs, video files, etc.)
    # Example: CAMERA_SOURCES = [0, 'rtsp://user:pass@ip:port/stream', '/dev/video1']
    CAMERA_SOURCES = [0] # Start with one camera

    # --- Email Alerts ---
    # Get these from environment variables for security!
    MAIL_ENABLED = os.environ.get('MAIL_ENABLED', 'False').lower() in ('true', '1', 't') # Enable email alerts
    MAIL_SERVER = os.environ.get('MAIL_SERVER') or 'smtp.googlemail.com'
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') # Your email address
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') # Your email APP PASSWORD (not main password)
    MAIL_SENDER = os.environ.get('MAIL_SENDER') or MAIL_USERNAME # Email address alerts come from
    MAIL_ALERT_INTERVAL_SECONDS = 60 # Min seconds between emails for the *same* threat type
    
    # --- Other ---
    FLASK_HOST = '0.0.0.0'
    FLASK_PORT = 5000


"""
config.py

This module defines the configuration settings for the Flask Security Monitoring App.
It centralizes all configurable parameters for the application, such as database, security, email, MQTT, and detection system settings.

Class:
--------
Config:
    - Serves as the base configuration class loaded into the Flask app via `app.config.from_object(Config)`.
    - Contains all the settings grouped logically (Security, Database, MQTT, Camera, Email, etc.).

Main Configuration Sections:
--------
1. Security:
    - `SECRET_KEY`: Used by Flask and Flask-WTF for securely signing session cookies and CSRF protection.

2. Database:
    - `SQLALCHEMY_DATABASE_URI`: Path to the app's SQLite database (or can be overridden via `DATABASE_URL` environment variable).
    - `SQLALCHEMY_TRACK_MODIFICATIONS`: Disables a feature that unnecessarily uses memory.

3. MQTT Settings:
    - Used for real-time alert publishing to MQTT topics.
    - Configurable via environment variables like `MQTT_BROKER`, `MQTT_PORT`.

4. Camera & Detection:
    - `MODEL_PATH`: YOLOv8 model used for detection.
    - `CONFIDENCE_THRESHOLD`: Minimum confidence to consider a detection valid.
    - `PRIMARY_THREAT_CLASSES`: List of objects considered a primary threat (triggers alerts even in normal mode).
    - `CAMERA_SOURCES`: Defines which camera feeds are used (webcam index, RTSP stream, etc.).

5. Email Alerts:
    - Settings for SMTP-based email alerts.
    - Use environment variables to store sensitive credentials securely.
    - `MAIL_ALERT_INTERVAL_SECONDS`: Minimum interval between similar alert emails to avoid spam.

6. Other:
    - `FLASK_HOST` and `FLASK_PORT`: Used when running the app directly via `app.run()`.

Usage:
--------
- These settings are loaded into the Flask app like this:
    ```python
    from config import Config
    app.config.from_object(Config)
    ```
- Sensitive data (e.g., `SECRET_KEY`, email credentials, MQTT credentials) should be stored in environment variables for security.
"""
