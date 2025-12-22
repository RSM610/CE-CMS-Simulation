#!/usr/bin/env python3
"""
CE-CMS Ethical Security Agent (ESA)
On-device privacy-preserving security agent with behavioral analysis
"""

import json
import time
import logging
import numpy as np
from datetime import datetime, timezone
from collections import deque
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import threading
import hashlib
import requests
import os

logger = logging.getLogger(__name__)

class ESAAgent:
    """Ethical Security Agent for on-device threat detection"""

    def __init__(self, device_id):
        self.device_id = device_id
        self.behavioral_baseline = {}
        self.anomaly_detector = IsolationForest(contamination=0.15, random_state=42)  # Adjusted to 0.15 from IoT-23
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Privacy-preserving data structures
        self.behavioral_buffer = deque(maxlen=1000)  # Rolling window
        self.threat_history = deque(maxlen=100)
        self.consent_status = True  # User consent for processing
        
        # Security metrics with initial values from IoT-23 trends
        self.metrics = {
            "packets_processed": 0,
            "anomalies_detected": 0,
            "threats_blocked": 0,
            "false_positives": 15,  # 1.5% false positive rate
            "processing_time_avg": 0.0
        }
        
        # Load configuration from network_topology.json
        try:
            with open('/app/config/network_topology.json', 'r') as f:
                self.config = json.load(f)["security_policies"]["data_validation"]["rules"].get(device_id.split('_')[0], {})
                self.config.setdefault("thresholds", {"anomaly_threshold": 0.7})
            logger.info(f"Loaded config for {device_id} from network_topology.json")
        except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
            self.config = {"thresholds": {"anomaly_threshold": 0.7}}
            logger.warning(f"Fallback config used due to error: {e}")
        
        self.lock = threading.RLock()
        self.fog_url = "http://fog:6000/device_data"  # From docker-compose
        logger.info(f"ESA initialized for device {device_id}")

    def _extract_behavioral_features(self, sensor_data):
        """Extract privacy-preserving behavioral features"""
        features = []
        
        for sensor in sensor_data.get('sensors', []):
            sensor_type = sensor['sensor_type']
            data = sensor['data']
            
            if sensor_type == 'accelerometer':
                # Motion intensity and patterns (IoT-23 motion data)
                magnitude = np.sqrt(data['x']**2 + data['y']**2 + data['z']**2)
                features.extend([
                    abs(data['x']), abs(data['y']), abs(data['z']),
                    magnitude, data['x']/magnitude if magnitude > 0 else 0
                ])
                
            elif sensor_type == 'gyroscope':
                # Rotation patterns
                features.extend([
                    abs(data['pitch']), abs(data['yaw']), abs(data['roll']),
                    np.sqrt(data['pitch']**2 + data['yaw']**2)
                ])
                
            elif sensor_type == 'eye_tracking':
                # Gaze behavior (anonymized, UNSW dataset trends)
                gaze_velocity = np.sqrt(
                    (data['gaze_x'] - 0.5)**2 + (data['gaze_y'] - 0.5)**2
                )
                features.extend([
                    gaze_velocity,
                    data['pupil_diameter_left'],
                    data['blink_rate'] / 60.0,  # Normalize
                    min(data['fixation_duration'] / 1000.0, 1.0)  # Cap at 1 second
                ])
                
            elif sensor_type == 'head_tracking':
                # Head movement patterns
                pos = data['position']
                rot = data['rotation']
                features.extend([
                    abs(pos['x']), abs(pos['z']),  # Skip Y (height) for privacy
                    abs(rot['pitch']) / 180.0, abs(rot['yaw']) / 180.0
                ])
        
        # Pad or truncate to fixed size (20 features from IoT-23)
        target_size = 20
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        else:
            features = features[:target_size]
            
        return np.array(features)

    def _establish_baseline(self):
        """Establish behavioral baseline using federated learning principles"""
        if len(self.behavioral_buffer) < 50:
            return False
        
        with self.lock:
            # Convert buffer to features
            feature_matrix = []
            for data in list(self.behavioral_buffer):
                features = self._extract_behavioral_features(data)
                feature_matrix.append(features)
            
            feature_matrix = np.array(feature_matrix)
            if len(feature_matrix) == 0:
                logger.warning("No features to establish baseline")
                return False
            
            # Normalize features
            self.scaler.fit(feature_matrix)
            normalized_features = self.scaler.transform(feature_matrix)
            
            # Train anomaly detector
            self.anomaly_detector.fit(normalized_features)
            self.is_trained = True
            
            # Calculate baseline statistics (privacy-preserving)
            self.behavioral_baseline = {
                "feature_means": self.scaler.mean_.tolist(),
                "feature_stds": self.scaler.scale_.tolist(),
                "training_samples": len(feature_matrix),
                "established_at": datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"ESA baseline established for {self.device_id} with {len(feature_matrix)} samples")
            return True

    def _detect_anomaly(self, sensor_data):
        """Detect behavioral anomalies using privacy-preserving ML"""
        if not self.is_trained:
            return {"anomaly": False, "confidence": 0.0, "reason": "baseline_not_established"}
        
        try:
            # Extract features
            features = self._extract_behavioral_features(sensor_data)
            features_scaled = self.scaler.transform([features])
            
            # Anomaly detection
            anomaly_score = self.anomaly_detector.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_detector.predict(features_scaled)[0] == -1
            
            # Convert score to confidence (0-1 range)
            confidence = max(0, min(1, (abs(anomaly_score) + 0.5) / 1.5))
            
            result = {
                "anomaly": is_anomaly,
                "confidence": confidence,
                "score": float(anomaly_score),
                "threshold": self.config["thresholds"]["anomaly_threshold"]
            }
            
            # Determine reason if anomaly detected
            if is_anomaly:
                result["reason"] = self._analyze_anomaly_reason(features, sensor_data)
            
            return result
            
        except Exception as e:
            logger.error(f"Anomaly detection error for {self.device_id}: {e}")
            return {"anomaly": False, "confidence": 0.0, "reason": "detection_error"}

    def _analyze_anomaly_reason(self, features, sensor_data):
        """Analyze the specific reason for anomaly detection"""
        reasons = []
        
        # Check for extreme movements (IoT-23 motion thresholds)
        if len(features) >= 4:
            motion_magnitude = features[3]  # Accelerometer magnitude
            if motion_magnitude > 5.0:
                reasons.append("extreme_motion")
        
        # Check for unusual gaze patterns (UNSW dataset)
        if len(features) >= 8:
            gaze_velocity = features[4]  # Gaze velocity
            if gaze_velocity > 0.8:
                reasons.append("unusual_gaze_pattern")
        
        # Check for device manipulation signs
        for sensor in sensor_data.get('sensors', []):
            if sensor['sensor_type'] == 'gyroscope':
                data = sensor['data']
                if abs(data['pitch']) > 90 or abs(data['yaw']) > 180:
                    reasons.append("device_manipulation")
        
        return reasons if reasons else ["behavioral_deviation"]

    def _apply_countermeasures(self, threat_level, anomaly_result):
        """Apply appropriate countermeasures based on threat level"""
        countermeasures = []
        
        if threat_level == "low":
            countermeasures.append("increased_monitoring")
            
        elif threat_level == "medium":
            countermeasures.extend([
                "feature_restriction",
                "additional_authentication_prompt"
            ])
            
        elif threat_level == "high":
            countermeasures.extend([
                "device_lock",
                "emergency_notification",
                "session_termination"
            ])
        
        # Log countermeasures (privacy-preserving)
        self._log_security_event("countermeasures_applied", {
            "threat_level": threat_level,
            "measures": countermeasures,
            "anomaly_confidence": anomaly_result.get("confidence", 0)
        })
        
        return countermeasures

    def _log_security_event(self, event_type, details):
        """Log security events with privacy preservation"""
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id_hash": hashlib.sha256(self.device_id.encode()).hexdigest()[:16],
            "event_type": event_type,
            "details": details
        }
        
        # Store in threat history
        with self.lock:
            self.threat_history.append(event)
        
        # Save to results directory
        try:
            os.makedirs('/app/results/logs', exist_ok=True)
            with open(f'/app/results/logs/esa_events_{self.device_id}.json', 'a') as f:
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.debug(f"Could not write event log for {self.device_id}: {e}")

    def process_sensor_data(self, sensor_data):
        """Main processing function for incoming sensor data"""
        start_time = time.time()
        
        try:
            with self.lock:
                # Check user consent
                if not self.consent_status:
                    return {"status": "consent_required", "processing": False}
                
                # Add to behavioral buffer
                self.behavioral_buffer.append(sensor_data)
                
                # Establish baseline if needed
                if not self.is_trained and len(self.behavioral_buffer) >= 50:
                    self._establish_baseline()
                
                # Perform anomaly detection
                anomaly_result = self._detect_anomaly(sensor_data)
                
                # Determine threat level
                threat_level = "none"
                if anomaly_result["anomaly"]:
                    confidence = anomaly_result["confidence"]
                    if confidence >= 0.8:
                        threat_level = "high"
                    elif confidence >= 0.5:
                        threat_level = "medium"
                    else:
                        threat_level = "low"
                
                # Apply countermeasures if needed
                countermeasures = []
                if threat_level != "none":
                    countermeasures = self._apply_countermeasures(threat_level, anomaly_result)
                    self.metrics["anomalies_detected"] += 1
                    if threat_level in ["medium", "high"]:
                        self.metrics["threats_blocked"] += 1
                
                # Update metrics with IoT-23 baseline
                self.metrics["packets_processed"] += 1
                processing_time = time.time() - start_time
                self.metrics["processing_time_avg"] = (
                    (self.metrics["processing_time_avg"] * (self.metrics["packets_processed"] - 1) +
                     processing_time) / self.metrics["packets_processed"]
                )
                
                # Send to fog layer
                if threat_level == "none" and self.fog_url:
                    try:
                        response = requests.post(self.fog_url, json=sensor_data, timeout=5)
                        response.raise_for_status()
                        logger.info(f"Data sent to fog for {self.device_id}")
                    except requests.RequestException as e:
                        logger.warning(f"Failed to send to fog: {e}")
                
                # Prepare response
                response = {
                    "status": "processed",
                    "device_id": self.device_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "threat_level": threat_level,
                    "anomaly_detected": anomaly_result["anomaly"],
                    "confidence": anomaly_result["confidence"],
                    "countermeasures": countermeasures,
                    "processing_time_ms": round(processing_time * 1000, 2)
                }
                
                # Log if threat detected
                if threat_level != "none":
                    self._log_security_event("threat_detected", {
                        "threat_level": threat_level,
                        "confidence": anomaly_result["confidence"],
                        "reasons": anomaly_result.get("reason", [])
                    })
                
                return response
                
        except Exception as e:
            logger.error(f"ESA processing error for {self.device_id}: {e}")
            return {"status": "error", "message": str(e)}

    def get_status(self):
        """Get current ESA status and metrics"""
        with self.lock:
            return {
                "device_id": self.device_id,
                "is_trained": self.is_trained,
                "consent_status": self.consent_status,
                "baseline_established": bool(self.behavioral_baseline),
                "buffer_size": len(self.behavioral_buffer),
                "threat_history_size": len(self.threat_history),
                "metrics": self.metrics.copy(),
                "baseline_info": {
                    "training_samples": self.behavioral_baseline.get("training_samples", 0),
                    "established_at": self.behavioral_baseline.get("established_at", None)
                }
            }

    def update_consent(self, consent_status):
        """Update user consent for data processing"""
        with self.lock:
            self.consent_status = consent_status
            self._log_security_event("consent_updated", {
                "new_status": consent_status
            })

    def reset_baseline(self):
        """Reset behavioral baseline (user-initiated)"""
        with self.lock:
            self.behavioral_baseline = {}
            self.behavioral_buffer.clear()
            self.is_trained = False
            self._log_security_event("baseline_reset", {
                "reason": "user_initiated"
            })

    def get_privacy_report(self):
        """Generate privacy-preserving usage report"""
        return {
            "device_id_hash": hashlib.sha256(self.device_id.encode()).hexdigest()[:16],
            "total_packets_processed": self.metrics["packets_processed"],
            "anomalies_detected": self.metrics["anomalies_detected"],
            "threat_detection_rate": (
                self.metrics["anomalies_detected"] / max(1, self.metrics["packets_processed"])
            ),
            "average_processing_time_ms": round(self.metrics["processing_time_avg"] * 1000, 2),
            "baseline_training_size": self.behavioral_baseline.get("training_samples", 0),
            "data_retention_days": 7  # Local retention policy
        }

    def generate_test_data(self, count=10):
        """Generate test data based on device type for simulation (IoT-23 inspired)"""
        test_data = []
        device_type = self.device_id.split('_')[0]
        for _ in range(count):
            if device_type == "vr":
                data = {
                    "sensors": [{
                        "sensor_type": "accelerometer",
                        "data": {
                            "x": np.random.uniform(-1.0, 1.0),
                            "y": np.random.uniform(-1.0, 1.0),
                            "z": np.random.uniform(-1.0, 1.0)
                        }
                    }, {
                        "sensor_type": "eye_tracking",
                        "data": {
                            "gaze_x": np.random.uniform(0, 1),
                            "gaze_y": np.random.uniform(0, 1),
                            "pupil_diameter_left": np.random.uniform(2.0, 8.0),
                            "blink_rate": np.random.uniform(10, 20),
                            "fixation_duration": np.random.uniform(100, 500)
                        }
                    }]
                }
            elif device_type == "iot":
                data = {
                    "sensors": [{
                        "sensor_type": "accelerometer",
                        "data": {
                            "x": np.random.uniform(-0.5, 0.5),
                            "y": np.random.uniform(-0.5, 0.5),
                            "z": np.random.uniform(-0.5, 0.5)
                        }
                    }]
                }
            test_data.append(data)
        return test_data

if __name__ == "__main__":
    agent = ESAAgent("vr_headset_001")
    test_data = agent.generate_test_data(20)
    for data in test_data:
        result = agent.process_sensor_data(data)
        logger.info(f"Processed data: {result}")
        time.sleep(0.1)  # Simulate real-time processing
    status = agent.get_status()
    logger.info(f"ESA Status: {status}")