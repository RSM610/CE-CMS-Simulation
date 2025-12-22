#!/usr/bin/env python3
"""
CE-CMS Device Layer: Sensor Simulation
Simulates various consumer electronics sensors including VR/AR devices
"""

import json
import time
import threading
import random
import math
import requests
from flask import Flask, jsonify, request
import numpy as np
from datetime import datetime, timezone
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load configuration
try:
    with open('/app/config/env.json', 'r') as f:
        config = json.load(f)
except FileNotFoundError:
    logger.warning("Config file not found, using defaults")
    config = {
        "device_layer": {
            "port": 5000,
            "sensors": {"accelerometer": True, "gyroscope": True, "eye_tracking": True}
        },
        "simulation": {"data_generation_interval": 1.0}
    }

app = Flask(__name__)

class VRSensorSimulator:
    """Simulates VR/AR device sensors with realistic data patterns"""
    
    def __init__(self):
        self.device_id = f"vr_device_{random.randint(1000, 9999)}"
        self.user_profile = self._generate_user_profile()
        self.baseline_behavior = self._establish_baseline()
        self.current_session = None
        self.sensor_data_buffer = []
        self.is_running = False
        
    def _generate_user_profile(self):
        """Generate a realistic user behavioral profile"""
        return {
            "user_id": f"user_{random.randint(10000, 99999)}",
            "head_movement_pattern": random.choice(["smooth", "jerky", "moderate"]),
            "eye_movement_speed": random.uniform(0.5, 2.0),
            "hand_dominance": random.choice(["left", "right"]),
            "play_style": random.choice(["aggressive", "passive", "explorer"]),
            "experience_level": random.choice(["beginner", "intermediate", "expert"])
        }
    
    def _establish_baseline(self):
        """Establish normal behavioral patterns"""
        return {
            "avg_head_rotation": {"x": 0, "y": 0, "z": 0},
            "typical_gaze_pattern": random.uniform(0.3, 0.8),
            "normal_hand_movement_range": random.uniform(0.5, 1.5),
            "session_duration_avg": random.randint(1800, 3600)  # 30-60 minutes
        }
    
    def generate_accelerometer_data(self, timestamp):
        """Generate realistic accelerometer data"""
        # Base movement with user pattern variations
        base_movement = 0.1 if self.user_profile["head_movement_pattern"] == "smooth" else 0.3
        
        return {
            "timestamp": timestamp,
            "sensor_type": "accelerometer",
            "device_id": self.device_id,
            "data": {
                "x": round(random.gauss(0, base_movement), 4),
                "y": round(random.gauss(0, base_movement), 4),
                "z": round(random.gauss(9.81, base_movement), 4),  # Gravity + movement
                "magnitude": 0
            }
        }
    
    def generate_gyroscope_data(self, timestamp):
        """Generate realistic gyroscope data"""
        # Simulate head rotation patterns
        rotation_intensity = 0.5 if self.user_profile["head_movement_pattern"] == "smooth" else 1.5
        
        return {
            "timestamp": timestamp,
            "sensor_type": "gyroscope",
            "device_id": self.device_id,
            "data": {
                "pitch": round(random.gauss(0, rotation_intensity), 4),
                "yaw": round(random.gauss(0, rotation_intensity), 4),
                "roll": round(random.gauss(0, rotation_intensity * 0.5), 4)  # Less roll movement
            }
        }
    
    def generate_eye_tracking_data(self, timestamp):
        """Generate realistic eye tracking data"""
        gaze_speed = self.user_profile["eye_movement_speed"]
        
        # Simulate realistic gaze patterns
        gaze_x = random.gauss(0.5, 0.2)  # Center-biased
        gaze_y = random.gauss(0.4, 0.15)  # Slightly upper-biased
        
        return {
            "timestamp": timestamp,
            "sensor_type": "eye_tracking",
            "device_id": self.device_id,
            "data": {
                "gaze_x": max(0, min(1, gaze_x)),
                "gaze_y": max(0, min(1, gaze_y)),
                "pupil_diameter_left": round(random.gauss(4.0, 0.5), 2),
                "pupil_diameter_right": round(random.gauss(4.0, 0.5), 2),
                "blink_rate": random.randint(15, 25),  # Blinks per minute
                "fixation_duration": random.randint(200, 800)  # Milliseconds
            }
        }
    
    def generate_head_tracking_data(self, timestamp):
        """Generate realistic head tracking data"""
        return {
            "timestamp": timestamp,
            "sensor_type": "head_tracking",
            "device_id": self.device_id,
            "data": {
                "position": {
                    "x": round(random.gauss(0, 0.1), 4),
                    "y": round(random.gauss(1.7, 0.05), 4),  # Average head height
                    "z": round(random.gauss(0, 0.1), 4)
                },
                "rotation": {
                    "pitch": round(random.gauss(0, 15), 2),
                    "yaw": round(random.gauss(0, 30), 2),
                    "roll": round(random.gauss(0, 5), 2)
                }
            }
        }
    
    def generate_haptic_data(self, timestamp):
        """Generate haptic feedback sensor data"""
        return {
            "timestamp": timestamp,
            "sensor_type": "haptic",
            "device_id": self.device_id,
            "data": {
                "force_feedback": {
                    "left_hand": round(random.uniform(0, 1), 3),
                    "right_hand": round(random.uniform(0, 1), 3)
                },
                "tactile_intensity": round(random.uniform(0, 1), 3),
                "vibration_pattern": random.choice(["pulse", "continuous", "wave"]),
                "temperature": round(random.gauss(22, 2), 1)  # Room temperature variation
            }
        }
    
    def generate_sensor_packet(self):
        """Generate a complete sensor data packet"""
        timestamp = datetime.now(timezone.utc).isoformat()
        sensors = config["device_layer"]["sensors"]
        
        packet = {
            "packet_id": f"pkt_{int(time.time() * 1000)}_{random.randint(1000, 9999)}",
            "timestamp": timestamp,
            "device_info": {
                "device_id": self.device_id,
                "device_type": "vr_headset",
                "firmware_version": "1.2.3",
                "battery_level": random.randint(20, 100)
            },
            "user_profile": self.user_profile,
            "sensors": []
        }
        
        # Add enabled sensors
        if sensors.get("accelerometer"):
            packet["sensors"].append(self.generate_accelerometer_data(timestamp))
        
        if sensors.get("gyroscope"):
            packet["sensors"].append(self.generate_gyroscope_data(timestamp))
            
        if sensors.get("eye_tracking"):
            packet["sensors"].append(self.generate_eye_tracking_data(timestamp))
            
        if sensors.get("head_tracking"):
            packet["sensors"].append(self.generate_head_tracking_data(timestamp))
            
        if sensors.get("haptic_feedback"):
            packet["sensors"].append(self.generate_haptic_data(timestamp))
        
        return packet
    
    def start_simulation(self):
        """Start continuous sensor data generation"""
        self.is_running = True
        self.current_session = {
            "session_id": f"session_{int(time.time())}",
            "start_time": datetime.now(timezone.utc).isoformat(),
            "packets_sent": 0
        }
        
        def sensor_loop():
            while self.is_running:
                try:
                    # Generate sensor packet
                    packet = self.generate_sensor_packet()
                    
                    # Send to ESA for processing
                    esa_agent.process_sensor_data(packet)
                    
                    # Buffer for external requests
                    self.sensor_data_buffer.append(packet)
                    if len(self.sensor_data_buffer) > 100:  # Keep last 100 packets
                        self.sensor_data_buffer.pop(0)
                    
                    self.current_session["packets_sent"] += 1
                    
                    # Send to fog layer
                    self._send_to_fog(packet)
                    
                    time.sleep(config["simulation"]["data_generation_interval"])
                    
                except Exception as e:
                    logger.error(f"Error in sensor loop: {e}")
                    time.sleep(1)
        
        self.sensor_thread = threading.Thread(target=sensor_loop, daemon=True)
        self.sensor_thread.start()
        logger.info(f"Sensor simulation started for device {self.device_id}")
    
    def _send_to_fog(self, packet):
        """Send sensor data to fog layer"""
        try:
            fog_url = os.getenv('FOG_URL', 'http://fog:6000')
            response = requests.post(
                f"{fog_url}/device_data",
                json=packet,
                timeout=5
            )
            if response.status_code != 200:
                logger.warning(f"Fog layer response: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not reach fog layer: {e}")
    
    def stop_simulation(self):
        """Stop sensor data generation"""
        self.is_running = False
        if hasattr(self, 'sensor_thread'):
            self.sensor_thread.join(timeout=2)
        logger.info(f"Sensor simulation stopped for device {self.device_id}")

# Initialize components
vr_simulator = VRSensorSimulator()

# Import ESA agent
from esa_agent import ESAAgent
esa_agent = ESAAgent(vr_simulator.device_id)

# Flask routes
@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "device_id": vr_simulator.device_id,
        "simulation_running": vr_simulator.is_running,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route('/sensor_data')
def get_sensor_data():
    """Get current sensor data"""
    if not vr_simulator.sensor_data_buffer:
        return jsonify({"error": "No sensor data available"}), 404
    
    return jsonify({
        "current_data": vr_simulator.sensor_data_buffer[-1],
        "buffer_size": len(vr_simulator.sensor_data_buffer),
        "session_info": vr_simulator.current_session
    })

@app.route('/sensor_history')
def get_sensor_history():
    """Get sensor data history"""
    limit = request.args.get('limit', 10, type=int)
    return jsonify({
        "history": vr_simulator.sensor_data_buffer[-limit:],
        "total_packets": len(vr_simulator.sensor_data_buffer)
    })

@app.route('/start_simulation', methods=['POST'])
def start_simulation():
    """Start sensor simulation"""
    if not vr_simulator.is_running:
        vr_simulator.start_simulation()
        return jsonify({"message": "Simulation started", "device_id": vr_simulator.device_id})
    return jsonify({"message": "Simulation already running"})

@app.route('/stop_simulation', methods=['POST'])
def stop_simulation():
    """Stop sensor simulation"""
    if vr_simulator.is_running:
        vr_simulator.stop_simulation()
        return jsonify({"message": "Simulation stopped"})
    return jsonify({"message": "Simulation not running"})

@app.route('/esa_status')
def esa_status():
    """Get ESA agent status"""
    return jsonify(esa_agent.get_status())

@app.route('/inject_anomaly', methods=['POST'])
def inject_anomaly():
    """Inject anomalous data for testing"""
    anomaly_type = request.json.get('type', 'movement')
    intensity = request.json.get('intensity', 'medium')
    
    # Generate anomalous packet
    packet = vr_simulator.generate_sensor_packet()
    
    if anomaly_type == 'movement':
        # Inject extreme movement values
        for sensor in packet['sensors']:
            if sensor['sensor_type'] == 'accelerometer':
                multiplier = 5 if intensity == 'high' else 3
                sensor['data']['x'] *= multiplier
                sensor['data']['y'] *= multiplier
    
    elif anomaly_type == 'behavioral':
        # Inject behavioral anomaly
        packet['user_profile']['head_movement_pattern'] = 'anomalous'
        
    # Process through ESA
    result = esa_agent.process_sensor_data(packet)
    
    return jsonify({
        "message": "Anomaly injected",
        "type": anomaly_type,
        "intensity": intensity,
        "detection_result": result
    })

if __name__ == '__main__':
    logger.info("Starting CE-CMS Device Layer Simulation")
    
    # Start sensor simulation automatically
    vr_simulator.start_simulation()
    
    # Start Flask server
    app.run(
        host='0.0.0.0',
        port=config["device_layer"]["port"],
        debug=False,
        threaded=True
    )