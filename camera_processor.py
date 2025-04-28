# camera_processor.py
import cv2
import time
import os
import threading
from ultralytics import YOLO
import queue # For thread-safe communication

class ThreatDetector:
    """ Handles YOLO model loading and object detection. """
    def __init__(self, model_path, confidence_threshold, primary_threat_classes, person_class_name):
        try:
            self.model = YOLO(model_path)
            self.confidence_threshold = confidence_threshold
            self.primary_threat_classes = set(primary_threat_classes)
            self.person_class_name = person_class_name
            self.all_class_names = self.model.names
            print(f"  [Detector] YOLO model '{model_path}' loaded successfully.")
            # Check if the model loaded has the person class if specified
            if self.person_class_name not in self.all_class_names.values():
                 print(f"  [Detector] Warning: Person class '{self.person_class_name}' not found in model classes: {list(self.all_class_names.values())}")
        except Exception as e:
            print(f"  [Detector] CRITICAL: Error loading YOLO model '{model_path}': {e}")
            raise # Stop initialization if model fails

    def detect(self, frame):
        """ Performs detection on a single frame. """
        detections = []
        annotated_frame = frame # Default to original if detection fails

        try:
            results = self.model(frame, conf=self.confidence_threshold, verbose=False) # verbose=False reduces console spam

            if results and results[0].boxes:
                # Use YOLO's plotting function to get the annotated frame
                annotated_frame = results[0].plot()
                # Extract detection details
                for box in results[0].boxes:
                    try:
                        class_id = int(box.cls[0])
                        class_name = self.all_class_names[class_id]
                        confidence = float(box.conf[0])
                        # Check if it's a primary threat (gun, knife, etc.)
                        is_primary_threat = class_name in self.primary_threat_classes

                        detections.append({
                            "class": class_name,
                            "confidence": confidence,
                            "is_primary_threat": is_primary_threat,
                            "bbox": box.xyxy[0].tolist() # [xmin, ymin, xmax, ymax]
                        })
                    except Exception as e:
                        # Log error processing a specific box but continue with others
                        print(f"  [Detector] Error processing detection box: {e}")
                        continue
            # If no boxes found, detections remains empty, annotated_frame is original frame plotted (if plot() handles empty) or just original frame.
            # Ensure annotated_frame is always assigned. `results[0].plot()` might return the original if no boxes? Test this.
            # Safer: annotated_frame = results[0].plot() if results[0].boxes else frame.copy()

        except Exception as e:
             # Log error during the main prediction step
             print(f"  [Detector] Error during model prediction: {e}")
             # Return empty detections and the original (non-annotated) frame
             return [], frame

        return detections, annotated_frame

class CameraProcessor(threading.Thread):
    """
    Handles video capture, processing, detection, snapshot saving,
    and communication for a single camera source in a separate thread.
    """
    def __init__(self, camera_id, camera_source, config, alert_queue, frame_dict, frame_lock):
        super().__init__()
        self.camera_id = camera_id
        self.camera_source = camera_source
        self.config = config # Access config object directly
        self.alert_queue = alert_queue
        self.frame_dict = frame_dict # Shared dictionary for latest frames
        self.frame_lock = frame_lock # Lock protecting frame_dict

        # --- Configuration for this processor ---
        self.snapshot_dir = config.SNAPSHOT_DIR
        # Performance Tuning (set values directly or get from config)
        self.enable_resizing = True # <<< Set to False to disable resizing
        self.detect_w = 640         # <<< Width for detection if resizing enabled
        self.detect_h = 480         # <<< Height for detection if resizing enabled
        self.enable_frame_skipping = True # <<< Set to False to detect every frame
        self.detect_every_n_frames = 3   # <<< Process every Nth frame if skipping enabled

        self.detector = ThreatDetector(
            model_path=config.MODEL_PATH,
            confidence_threshold=config.CONFIDENCE_THRESHOLD,
            primary_threat_classes=config.PRIMARY_THREAT_CLASSES,
            person_class_name=config.PERSON_CLASS_NAME
        )
        self.cap = None
        self.running = False
        self.frame_count = 0
        self.daemon = True # Allows main program to exit even if this thread is running

        # Ensure snapshot directory exists for this camera processor
        try:
            os.makedirs(self.snapshot_dir, exist_ok=True)
        except OSError as e:
            print(f"[Cam {self.camera_id}] Error creating snapshot directory '{self.snapshot_dir}': {e}")
            # Decide if this is fatal or if snapshots should just be disabled


    def run(self):
        """ Main processing loop for the camera thread. """
        print(f"[Cam {self.camera_id}] Starting processor thread (Source: {self.camera_source})")
        self.running = True
        retry_delay = 5 # Seconds between camera open retries

        while self.running:
            try:
                # --- Camera Handling ---
                if self.cap is None or not self.cap.isOpened():
                    # print(f"[Cam {self.camera_id}] Opening camera...") # Reduce verbosity
                    self.cap = cv2.VideoCapture(self.camera_source)
                    # Optional: Set camera properties (e.g., resolution, FPS) - may fail
                    # self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
                    # self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
                    if not self.cap.isOpened():
                        # print(f"[Cam {self.camera_id}] Error: Could not open camera. Retrying in {retry_delay}s...")
                        self.cap = None
                        time.sleep(retry_delay)
                        continue
                    else:
                         print(f"[Cam {self.camera_id}] Camera opened successfully.")

                # --- Frame Capture ---
                ret, frame = self.cap.read()
                if not ret or frame is None:
                    print(f"[Cam {self.camera_id}] Warning: Failed to capture frame. Releasing and retrying...")
                    if self.cap: self.cap.release()
                    self.cap = None
                    time.sleep(retry_delay) # Wait before trying to reopen
                    continue

                # --- Frame Skipping Logic ---
                self.frame_count += 1
                run_detection_this_frame = (not self.enable_frame_skipping or
                                            self.frame_count % self.detect_every_n_frames == 0)

                annotated_frame_for_stream = frame.copy() # Default to original frame for stream
                detected_objects_this_frame = []

                # --- Detection & Annotation (only if not skipped) ---
                if run_detection_this_frame:
                    frame_to_detect = frame # Default to original frame

                    # --- Optional Resizing ---
                    if self.enable_resizing:
                        try:
                            # Resize before detection for performance
                            frame_to_detect = cv2.resize(frame, (self.detect_w, self.detect_h), interpolation=cv2.INTER_LINEAR)
                        except Exception as resize_e:
                            print(f"[Cam {self.camera_id}] Error resizing frame: {resize_e}. Using original.")
                            frame_to_detect = frame # Fallback

                    # --- Run Detection ---
                    detections, annotated_detection_frame = self.detector.detect(frame_to_detect)
                    detected_objects_this_frame = detections # Store detections from this frame

                    # Use the annotated frame (potentially resized) for the stream when detection runs
                    annotated_frame_for_stream = annotated_detection_frame


                    # --- Process Detections: Snapshot & Queueing (only when detection runs) ---
                    current_detection_time = time.time() # Timestamp for detections in this batch
                    for detection in detected_objects_this_frame:
                        # Check if object is interesting enough to *potentially* warrant a snapshot
                        is_interesting = (detection["is_primary_threat"] or
                                          detection["class"] == self.config.PERSON_CLASS_NAME)

                        snapshot_filename_for_queue = None # Default to no snapshot

                        if is_interesting:
                            timestamp_str = time.strftime("%Y%m%d_%H%M%S", time.localtime(current_detection_time))
                            # Create a unique filename
                            snapshot_filename = f"cam{self.camera_id}_{timestamp_str}_{detection['class']}.jpg"
                            snapshot_save_path = os.path.join(self.snapshot_dir, snapshot_filename)

                            try:
                                # Save the frame that detection ran on (annotated_detection_frame)
                                cv2.imwrite(snapshot_save_path, annotated_detection_frame)
                                snapshot_filename_for_queue = snapshot_filename # Store filename if saved
                            except Exception as e:
                                 print(f"[Cam {self.camera_id}] Error saving snapshot '{snapshot_filename}': {e}")
                                 # snapshot_filename_for_queue remains None

                        # --- Prepare data for the central alert queue ---
                        detection_data = detection.copy()
                        detection_data['camera_id'] = self.camera_id
                        detection_data['timestamp'] = current_detection_time
                        detection_data['snapshot_file'] = snapshot_filename_for_queue # Add filename (or None)

                        # Put onto the queue for central processing
                        try:
                            self.alert_queue.put(detection_data, block=False) # Non-blocking
                        except queue.Full:
                            # This is okay if the central processor is busy, alerts just get dropped
                            # print(f"[Cam {self.camera_id}] Warning: Alert queue full. Dropping detection.") # Reduce noise
                            pass # Silently drop if queue is full


                # --- Update Shared Frame Dictionary for Streaming ---
                # This should happen relatively frequently, even if detection is skipped,
                # using either the newly annotated frame or the original frame.
                with self.frame_lock:
                    self.frame_dict[self.camera_id] = annotated_frame_for_stream # Store the frame designated for streaming

                # Small delay to prevent busy-waiting and yield CPU time
                time.sleep(0.01) # Adjust if needed

            except KeyboardInterrupt:
                # Allow thread to exit cleanly on Ctrl+C if running script directly
                print(f"[Cam {self.camera_id}] KeyboardInterrupt received, stopping.")
                self.running = False
                break
            except Exception as e:
                print(f"[Cam {self.camera_id}] CRITICAL Error in processing loop: {e}")
                import traceback
                traceback.print_exc() # Print full traceback for debugging
                # Attempt recovery by releasing camera and delaying
                if self.cap:
                    try: self.cap.release()
                    except Exception: pass
                self.cap = None
                time.sleep(retry_delay * 2) # Longer delay after a major error


        # --- Cleanup when loop finishes ---
        if self.cap and self.cap.isOpened():
            try: self.cap.release()
            except Exception as e: print(f"[Cam {self.camera_id}] Error releasing camera on stop: {e}")
        print(f"[Cam {self.camera_id}] Processor thread stopped.")

    def stop(self):
        """ Signals the thread to stop processing. """
        print(f"[Cam {self.camera_id}] Stop signal received.")
        self.running = False


"""
camera_processor.py

This module defines two core classes:
1. `ThreatDetector`: Encapsulates object detection using the YOLO model.

class ThreatDetector:

    Encapsulates YOLO model loading and threat detection logic.
    
    Args:
        model_path (str): Path to the YOLO model.
        confidence_threshold (float): Minimum confidence for detection filtering.
        primary_threat_classes (list[str]): Class names considered high-threat (e.g., weapons).
        person_class_name (str): Class name used to identify people (e.g., 'person').

    Methods:
        detect(frame): Detects objects in the input frame and returns detection info and annotated frame.


2. `CameraProcessor`: A threaded video processor for a single camera source, which handles:
    - Capturing frames from a camera or video stream
    - Performing object detection using YOLO
    - Annotating frames
    - Saving snapshots of detected threats
    - Sending detection data to a shared alert queue
    - Updating frames for live video streaming

class CameraProcessor(threading.Thread):
    
    A threaded camera processor that captures video frames, runs object detection,
    saves snapshots, and updates shared data structures for streaming and alerting.

    Args:
        camera_id (int): Unique ID for this camera.
        camera_source (str): Camera input source (index, RTSP stream, or file path).
        config (object): Configuration object with model path, threshold, classes, etc.
        alert_queue (Queue): Shared queue for detection results.
        frame_dict (dict): Shared dictionary storing the latest frame for each camera.
        frame_lock (threading.Lock): Lock to protect access to frame_dict.

    Methods:
        run(): Main loop capturing frames, detecting threats, and updating shared data.
        stop(): Gracefully stops the processing thread.



The processor is designed to be lightweight, scalable, and suitable for real-time applications
such as surveillance systems.

Dependencies:
- OpenCV (cv2)
- ultralytics (YOLO model)
- threading, time, queue, os

Typical Usage:
    processor = CameraProcessor(
        camera_id=0,
        camera_source="rtsp://example.com/stream",
        config=config,
        alert_queue=alert_queue,
        frame_dict=shared_frame_dict,
        frame_lock=shared_lock
    )
    processor.start()
"""

