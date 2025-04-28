# main.py
import os
import threading
import queue
import time
import json
import smtplib
from email.message import EmailMessage
from flask import Flask, render_template, Response, request, flash, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from flask_migrate import Migrate
import paho.mqtt.client as mqtt
import cv2 # Still needed for encoding frames for streaming

# Import local modules
from config import Config
from models import db, User
from forms import LoginForm, RegistrationForm
from camera_processor import CameraProcessor

from ultralytics import YOLO

# Load the medium model (YOLOv8m)
# model = YOLO('yolov8m.pt')  


# from dotenv import load_dotenv
# load_dotenv()

# --- Global Variables & Setup ---
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db) # Initialize Flask-Migrate
login = LoginManager(app)
login.login_view = 'login' # Redirect to 'login' view if user not logged in

# Shared data structures (thread-safe access needed)
alert_queue = queue.Queue(maxsize=100) # Queue for detections from cameras
latest_frames = {} # Dictionary to hold latest frames {camera_id: frame}
frame_lock = threading.Lock() # Lock for accessing latest_frames
alert_history = [] # In-memory history of processed alerts
alert_history_lock = threading.Lock() # Lock for accessing alert_history
camera_threads = {} # Dictionary to hold camera processor threads {camera_id: thread}
app_shutdown_event = threading.Event() # Event to signal threads to stop

# Security mode state (protected by lock)
is_full_security_mode = False
mode_lock = threading.Lock()

# Email alert throttling state (needs lock)
last_email_sent_time = {} # { (camera_id, class_name): timestamp }
email_lock = threading.Lock()

# Currently logged-in user's email for alerts (simple approach, needs lock)
# WARNING: This assumes only one user's preference matters system-wide.
# A better system would store preferences per user in the DB.
alert_recipient_email = None
recipient_lock = threading.Lock()

# MQTT Client (optional)
mqtt_client = None

# --- Flask-Login User Loader ---
@login.user_loader
def load_user(id):
    return User.query.get(int(id))

# --- MQTT Callbacks (If using MQTT) ---
def setup_mqtt():
    global mqtt_client
    if not Config.MQTT_BROKER:
        print("[MQTT] Broker not configured. Skipping MQTT setup.")
        return None

    client = mqtt.Client(client_id=f"threat_detector_main_{os.getpid()}", clean_session=True)

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print(f"[MQTT] Connected to broker at {Config.MQTT_BROKER}")
            # client.subscribe("some/topic") # Add subscriptions if needed
        else:
            print(f"[MQTT] Failed to connect, return code {rc}")

    def on_message(client, userdata, msg):
        print(f"[MQTT] Received message: {msg.topic} - {msg.payload.decode()}")
        # Add message handling logic if needed

    client.on_connect = on_connect
    client.on_message = on_message

    try:
        print(f"[MQTT] Connecting to {Config.MQTT_BROKER}:{Config.MQTT_PORT}...")
        # Add username/password if required: client.username_pw_set(user, pass)
        client.connect(Config.MQTT_BROKER, Config.MQTT_PORT, 60)
        client.loop_start() # Start background thread for MQTT
        return client
    except Exception as e:
        print(f"[MQTT] CRITICAL: Error connecting: {e}. MQTT disabled.")
        return None

# --- Email Sending Function ---
def send_alert_email(alert_data):
    global alert_recipient_email, recipient_lock

    with recipient_lock:
        recipient = alert_recipient_email # Get current recipient

    if not Config.MAIL_ENABLED or not recipient:
        # print("[Email] Disabled or no recipient set.") # Debug
        return False
    if not Config.MAIL_USERNAME or not Config.MAIL_PASSWORD:
        print("[Email] Error: Username or Password not configured.")
        return False

    print(f"[Email] Attempting to send alert email to {recipient}")

    subject = f"Security Alert: {alert_data['alert_type']} - {alert_data['class']} Detected"
    body = f"""
    Security Alert Details:
    -----------------------
    Timestamp: {alert_data['timestamp_str']}
    Camera:    {alert_data['camera_id']}
    Type:      {alert_data['alert_type']}
    Class:     {alert_data['class']}
    Confidence:{alert_data['confidence']:.2f}

    Check the dashboard for more details and snapshot (if available).
    """
    # Note: Attaching snapshots would add complexity (reading file, MIME types)

    msg = EmailMessage()
    msg.set_content(body)
    msg['Subject'] = subject
    msg['From'] = Config.MAIL_SENDER
    msg['To'] = recipient

    try:
        server = None
        if Config.MAIL_USE_TLS:
            server = smtplib.SMTP(Config.MAIL_SERVER, Config.MAIL_PORT)
            server.starttls()
        else: # Assuming SSL if not TLS
             # Use SMTP_SSL for implicit SSL (usually port 465)
            server = smtplib.SMTP_SSL(Config.MAIL_SERVER, Config.MAIL_PORT)

        server.login(Config.MAIL_USERNAME, Config.MAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[Email] Alert email sent successfully to {recipient}.")
        return True
    except smtplib.SMTPAuthenticationError:
        print("[Email] Error: Authentication failed. Check MAIL_USERNAME/MAIL_PASSWORD (App Password?).")
    except smtplib.SMTPServerDisconnected:
        print("[Email] Error: Server disconnected unexpectedly.")
    except smtplib.SMTPException as e:
        print(f"[Email] Error sending email: {e}")
    except Exception as e:
         print(f"[Email] Unexpected error during email sending: {e}")
    return False


# --- Background Alert Processor Thread ---
# main.py

# --- Background Alert Processor Thread ---
def alert_processor_thread():
    # ... (setup remains the same) ...
    global alert_history, last_email_sent_time, is_full_security_mode
    print("[AlertProc] Starting alert processing thread.")
    last_alert_time_local = {}

    while not app_shutdown_event.is_set():
        try:
            detection_data = alert_queue.get(timeout=1.0)

            current_time = detection_data['timestamp']
            cam_id = detection_data['camera_id']
            det_class = detection_data['class']
            alert_key = (cam_id, det_class)

            # --- Security Mode Check (remains the same) ---
            with mode_lock:
                current_mode_is_full = is_full_security_mode

            # --- Determine Alert Condition (remains the same) ---
            is_alert_condition_met = False
            alert_type = "Unknown"
            if detection_data["is_primary_threat"]:
                is_alert_condition_met = True
                alert_type = "Threat Detected"
            elif current_mode_is_full and det_class == Config.PERSON_CLASS_NAME:
                is_alert_condition_met = True
                alert_type = "Motion Detected (Person)"

            if not is_alert_condition_met:
                alert_queue.task_done()
                continue

            # --- Throttling for Display/MQTT (remains the same) ---
            last_occurrence = last_alert_time_local.get(alert_key, 0)
            if (current_time - last_occurrence) < Config.ALERT_INTERVAL_SECONDS:
                alert_queue.task_done()
                continue

            # --- Process the Alert ---
            print(f"[AlertProc] Processing Alert - Type: {alert_type}, Class: {det_class}, Cam: {cam_id}, Conf: {detection_data['confidence']:.2f}")
            last_alert_time_local[alert_key] = current_time

            timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(current_time))

            # --- Use the snapshot filename received from the queue ---
            snapshot_filename = detection_data.get('snapshot_file') # Get filename (could be None)
            # ---------------------------------------------------------

            alert_data = {
                "alert_type": alert_type,
                "class": det_class,
                "confidence": detection_data["confidence"],
                "timestamp": current_time,
                "timestamp_str": timestamp_str,
                "camera_id": cam_id,
                "bbox": detection_data["bbox"],
                "snapshot_file": snapshot_filename # Use the value from queue
            }

            # --- Add to history (remains the same) ---
            with alert_history_lock:
                alert_history.insert(0, alert_data)
                alert_history = alert_history[:Config.MAX_ALERT_HISTORY]

            # --- MQTT Publish (remains the same) ---
            if mqtt_client and mqtt_client.is_connected():
                # ... (MQTT logic) ...
                try:
                    mqtt_payload = alert_data.copy()
                    del mqtt_payload['timestamp']
                    mqtt_client.publish("iot/alerts", json.dumps(mqtt_payload))
                except Exception as e:
                    print(f"[AlertProc] Error publishing to MQTT: {e}")

            # --- Email Throttling & Sending (remains the same) ---
            send_email_now = False
            # ... (Email logic) ...
            with email_lock:
                last_email_time = last_email_sent_time.get(alert_key, 0)
                if (current_time - last_email_time) >= Config.MAIL_ALERT_INTERVAL_SECONDS:
                    send_email_now = True
                    last_email_sent_time[alert_key] = current_time

            if send_email_now:
                 email_thread = threading.Thread(target=send_alert_email, args=(alert_data,), daemon=True)
                 email_thread.start()

            alert_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            print(f"[AlertProc] Error processing alert: {e}")
            try: alert_queue.task_done()
            except ValueError: pass

    print("[AlertProc] Alert processing thread stopped.")

# --- Flask Routes ---

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        # --- Store email for alerts (simple approach) ---
        with recipient_lock:
            global alert_recipient_email
            alert_recipient_email = user.email
            print(f"[Auth] Set alert recipient: {alert_recipient_email}")
        # ---
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    # --- Clear alert recipient ---
    with recipient_lock:
        global alert_recipient_email
        print(f"[Auth] Clearing alert recipient: {alert_recipient_email}")
        alert_recipient_email = None
    # ---
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        # Log user in immediately after registration
        login_user(user)
        # --- Store email for alerts ---
        with recipient_lock:
            global alert_recipient_email
            alert_recipient_email = user.email
            print(f"[Auth] Set alert recipient: {alert_recipient_email}")
        # ---
        return redirect(url_for('index'))
    return render_template('register.html', title='Register', form=form)

# --- Main Application Routes ---
@app.route('/')
@login_required # Require login to see the dashboard
def index():
    """ Serves the main dashboard page. """
    # Pass camera IDs to the template for generating video feed URLs/elements
    camera_ids = list(Config.CAMERA_SOURCES) # Or use keys if CAMERA_SOURCES is a dict
    return render_template('index.html', camera_ids=camera_ids)

@app.route('/video_feed/<camera_id>')
@login_required
def video_feed(camera_id):
    """ Streams the processed video feed for a specific camera. """
    # Convert camera_id from URL string if necessary (e.g., if it's an index)
    try:
        # Attempt to find the camera_id as configured (could be int or str)
        # This logic might need adjustment based on how CAMERA_SOURCES stores IDs
        req_cam_id = camera_id
        found = False
        for idx, source in enumerate(Config.CAMERA_SOURCES):
             current_cam_id = idx # Assuming simple index for now
             if str(current_cam_id) == str(req_cam_id):
                 req_cam_id = current_cam_id
                 found = True
                 break
        if not found:
             print(f"Warning: Requested camera_id '{camera_id}' not found in configured sources.")
             # Return a placeholder image or 404?
             return "Camera not found", 404

    except ValueError:
        return "Invalid camera ID format", 400

    return Response(generate_frames(req_cam_id), mimetype='multipart/x-mixed-replace; boundary=frame')

def generate_frames(camera_id):
    """ Generator function to yield annotated frames for a specific camera stream. """
    global latest_frames, frame_lock
    while True:
        frame_to_yield = None
        with frame_lock:
            frame_to_yield = latest_frames.get(camera_id) # Get frame for specific camera

        if frame_to_yield is None:
            # If no frame ready, send placeholder or wait? Sending wait message for now.
            # Placeholder could be a static image: cv2.imread('static/loading.jpg')
            placeholder = b"Waiting for camera feed..."
            yield (b'--frame\r\n'
                   b'Content-Type: text/plain\r\n\r\n' + placeholder + b'\r\n')
            time.sleep(0.5) # Wait before checking again
            continue

        try:
            ret, buffer = cv2.imencode('.jpg', frame_to_yield, [int(cv2.IMWRITE_JPEG_QUALITY), 80])
            if not ret:
                print(f"Error encoding frame for stream (Cam {camera_id})")
                time.sleep(0.1)
                continue
            frame_bytes = buffer.tobytes()
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')
        except Exception as e:
            print(f"Error in generate_frames (Cam {camera_id}): {e}")
            time.sleep(0.5)

        # Control the streaming rate (adjust as needed)
        time.sleep(0.03)


@app.route('/api/alerts')
@login_required
def api_alerts():
    """ Returns the current alert history as JSON. """
    with alert_history_lock:
        # Return a copy of the current history
        current_alerts = list(alert_history)
    return jsonify(current_alerts)

@app.route('/api/security_mode', methods=['GET', 'POST'])
@login_required
def security_mode_api(): # Renamed to avoid conflict with variable
    global is_full_security_mode, mode_lock
    if request.method == 'POST':
        # (Logic from previous version - uses mode_lock)
        try:
            data = request.get_json()
            if data is None or 'enable' not in data:
                return jsonify({"status": "error", "message": "Missing 'enable' field"}), 400
            new_mode_state = bool(data['enable'])
            with mode_lock:
                is_full_security_mode = new_mode_state
            print(f"[Mode] Security mode changed via API to: {'Full' if is_full_security_mode else 'Standard'}")
            return jsonify({"status": "success", "mode_enabled": is_full_security_mode})
        except Exception as e:
             print(f"Error processing /api/security_mode POST: {e}")
             return jsonify({"status": "error", "message": "Invalid request"}), 400
    else: # GET request
        with mode_lock:
            current_mode = is_full_security_mode
        return jsonify({"status": "success", "mode_enabled": current_mode})

# --- Utility for Redirects (needed by Flask-Login) ---
from urllib.parse import urlparse, urljoin
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc

# --- Startup and Shutdown ---
def start_camera_processors():
    if not Config.CAMERA_SOURCES:
        print("Warning: No camera sources defined in config.CAMERA_SOURCES.")
        return

    print("Starting camera processor threads...")
    for i, source in enumerate(Config.CAMERA_SOURCES):
        camera_id = i # Using index as ID for simplicity
        print(f"  - Creating thread for Camera {camera_id} (Source: {source})")
        thread = CameraProcessor(
            camera_id=camera_id,
            camera_source=source,
            config=Config,
            alert_queue=alert_queue,
            frame_dict=latest_frames,
            frame_lock=frame_lock
        )
        camera_threads[camera_id] = thread
        thread.start()
    print(f"Started {len(camera_threads)} camera threads.")

def stop_camera_processors():
    print("Stopping camera processor threads...")
    for cam_id, thread in camera_threads.items():
        if thread.is_alive():
            print(f"  - Stopping thread for Camera {cam_id}...")
            thread.stop() # Signal the thread's loop to exit

    # Wait briefly for threads to finish cleanup
    for cam_id, thread in camera_threads.items():
         if thread.is_alive():
              thread.join(timeout=5.0) # Wait max 5 seconds per thread
              if thread.is_alive():
                   print(f"  - Warning: Thread for Camera {cam_id} did not stop gracefully.")
    print("Camera processor threads stopped.")

def shutdown_app():
    print("Initiating application shutdown...")
    app_shutdown_event.set() # Signal background threads to stop

    # Stop MQTT client
    if mqtt_client:
        print("Stopping MQTT client...")
        mqtt_client.loop_stop()
        if mqtt_client.is_connected():
            mqtt_client.disconnect()
        print("MQTT client stopped.")

    # Stop camera processors
    stop_camera_processors()

    # Wait for alert processor
    # (It checks app_shutdown_event, let it finish naturally or join it)
    print("Waiting for alert processor to finish...")
    # Add a join here if the alert thread isn't a daemon or needs guaranteed finish

    print("Shutdown complete.")


# --- Main Execution ---
if __name__ == "__main__":
    # Ensure instance folder exists for SQLite DB
    instance_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)

    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        print("Database tables checked/created.")

    # Setup MQTT
    mqtt_client = setup_mqtt()

    # Start background alert processor thread
    alert_thread = threading.Thread(target=alert_processor_thread, daemon=True)
    alert_thread.start()

    # Start camera processing threads
    start_camera_processors()

    print(f"Starting Flask server on http://{Config.FLASK_HOST}:{Config.FLASK_PORT}")

    # Register shutdown handler
    import atexit
    atexit.register(shutdown_app)

    try:
        # Run Flask app (disable reloader in production or when managing threads manually)
        app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT, threaded=True, use_reloader=False, debug=False)
    except KeyboardInterrupt:
         print("\nCtrl+C received. Initiating shutdown...")
         # atexit handler will call shutdown_app()
    finally:
         # Ensure shutdown runs even if app.run exits unexpectedly
         if not app_shutdown_event.is_set(): # Avoid running twice if already called by atexit
              shutdown_app()