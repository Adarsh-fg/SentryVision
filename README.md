# Flask Security Monitoring App

## Overview

The **Flask Security Monitoring App** is a real-time surveillance system using YOLOv8 for threat detection. It streams live video from multiple cameras, detects threats, and provides an interactive dashboard with email alerts and MQTT notifications.

---

## Features

- **Real-Time Threat Detection**: Detects threats like weapons and motion (e.g., person detection) using YOLOv8.
- **Live Video Streaming**: View multiple camera feeds with threat annotations.
- **User Authentication**: Secure login and registration system.
- **Dynamic Alerts**: Real-time alert updates with snapshots of detected threats.
- **Security Modes**:
  - **Standard Mode**: Detects primary threats (weapons).
  - **Full Mode**: Detects both threats and motion (people).
- **Email & MQTT Notifications**: Real-time alerts via email and MQTT for IoT integration.
- **Responsive UI**: Mobile-friendly dashboard with interactive controls.

---

## Project Structure

```
├── instance/                  # SQLite database and other instance-specific files
├── static/                    # Static files (CSS, JS, images, snapshots)
│   ├── snapshots/             # Directory for storing detection snapshots
│   ├── bg.jpg                # Background image for UI
│   └── alert.mp3             # Sound for alert notifications
├── templates/                 # HTML templates for Flask
│   ├── index.html            # Main dashboard
│   ├── login.html            # Login page
│   ├── register.html         # Registration page
│   └── alerts.html           # Standalone alerts page
├── camera_processor.py       # Handles camera processing and YOLO detection
├── config.py                 # Configuration settings
├── forms.py                  # Flask-WTF forms for authentication
├── main.py                   # Main Flask application
├── models.py                 # SQLAlchemy database models
├── requirements.txt          # Python dependencies
└── README.md                 # This file
```

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/flask-security-monitoring.git
   cd flask-security-monitoring
   ```

2. **Set Up a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables** (create `.env` file):
   ```ini
   SECRET_KEY=your-secret-key
   DATABASE_URL=sqlite:////path/to/site.db
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   ```

5. **Initialize the Database**:
   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

---

## Running the Application

1. **Start the Flask Server**:
   ```bash
   python main.py
   ```
   Access the dashboard at [http://localhost:5000](http://localhost:5000).

2. **Toggle Security Modes** and view live feeds and alerts.

---

## Configuration

- **Camera Sources**: Add webcam indices or RTSP URLs in `config.py`.
- **Threat Classes**: Modify `PRIMARY_THREAT_CLASSES` for detection.
- **Alert Settings**: Adjust alert intervals for email and real-time updates.
- **MQTT Settings**: Configure MQTT broker for IoT integration.

---

## Contributing

1. Fork the repository.
2. Create a branch (`git checkout -b feature/your-feature`).
3. Commit changes (`git commit -m 'Add feature'`).
4. Push to the branch (`git push origin feature/your-feature`).
5. Open a Pull Request.

---

## License

This project is licensed under the MIT License.

---

## Acknowledgments

- **YOLOv8**: For object detection.
- **Flask**: For the web framework.
- **OpenCV**: For video processing.
- **Paho MQTT**: For MQTT integration.
