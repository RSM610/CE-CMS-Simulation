#!/usr/bin/env python3
"""
CE-CMS Fog Layer: Traffic Proxy
Network segmentation and traffic filtering for consumer electronics
"""

import json
import time
import threading
import requests
from flask import Flask, jsonify, request
from datetime import datetime, timezone
import logging
import os
from collections import defaultdict, deque
import hashlib

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
        "fog_layer": {
            "port": 6000,
            "rate_limits": {"packets_per_second": 1000}
        }
    }

app = Flask(__name__)

class NetworkSegmentationManager:
    """Manages network segmentation and VLAN isolation"""
    
    def __init__(self):
        self.vlans = {
            "metaverse": {"id": 100, "subnet": "192.168.100.0/24", "devices": []},
            "iot": {"id": 101, "subnet": "192.168.101.0/24", "devices": []},
            "guest": {"id": 102, "subnet": "192.168.102.0/24", "devices": []}
        }
        self.device_assignments = {}
        self.isolation_rules = []
        
    def assign_device_to_vlan(self, device_id, device_type):
        """Assign device to appropriate VLAN based on type"""
        if device_type in ["vr", "ar", "haptic"]:
            vlan = "metaverse"
        elif device_type in ["iot", "smart_speaker", "smart_tv"]:
            vlan = "iot"
        else:
            vlan = "guest"
            
        self.device_assignments[device_id] = vlan
        self.vlans[vlan]["devices"].append(device_id)
        
        logger.info(f"Assigned device {device_id} to VLAN {vlan}")
        return vlan
    
    def check_cross_vlan_access(self, source_device, target_device):
        """Check if cross-VLAN access is allowed"""
        source_vlan = self.device_assignments.get(source_device)
        target_vlan = self.device_assignments.get(target_device)
        
        if source_vlan == target_vlan:
            return True  # Same VLAN access allowed
            
        # Check isolation rules
        if source_vlan == "metaverse" and target_vlan == "iot":
            return False  # Metaverse devices isolated from IoT
            
        return True  # Default allow (can be configured)

class TrafficFilter:
    """Advanced traffic filtering and DDoS protection"""
    
    def __init__(self):
        self.rate_limits = config["fog_layer"]["rate_limits"]
        self.packet_counters = defaultdict(lambda: {"count": 0, "last_reset": time.time()})
        self.blocked_ips = set()
        self.suspicious_patterns = deque(maxlen=1000)
        self.whitelist = set()
        
    def check_rate_limit(self, source_ip):
        """Check if source IP exceeds rate limits"""
        current_time = time.time()
        counter = self.packet_counters[source_ip]
        
        # Reset counter every second
        if current_time - counter["last_reset"] >= 1.0:
            counter["count"] = 0
            counter["last_reset"] = current_time
        
        counter["count"] += 1
        
        # Check rate limit
        if counter["count"] > self.rate_limits["packets_per_second"]:
            self.blocked_ips.add(source_ip)
            logger.warning(f"Rate limit exceeded for {source_ip}")
            return False
            
        return True
    
    def analyze_traffic_pattern(self, packet_info):
        """Analyze traffic patterns for anomalies"""
        pattern = {
            "timestamp": time.time(),
            "source": packet_info.get("source_ip", "unknown"),
            "size": packet_info.get("size", 0),
            "protocol": packet_info.get("protocol", "unknown")
        }
        
        self.suspicious_patterns.append(pattern)
        
        # Simple anomaly detection
        recent_patterns = [p for p in self.suspicious_patterns 
                          if time.time() - p["timestamp"] < 60]
        
        if len(recent_patterns) > 100:  # High traffic volume
            sources = [p["source"] for p in recent_patterns]
            unique_sources = set(sources)
            
            if len(unique_sources) < 5:  # Few sources, high volume
                return {"anomaly": True, "type": "potential_ddos"}
        
        return {"anomaly": False}

class LateralThreatBlocker:
    """Prevents lateral movement of threats across network"""
    
    def __init__(self, network_manager):
        self.network_manager = network_manager
        self.threat_indicators = set()
        self.quarantined_devices = set()
        self.scanning_attempts = defaultdict(list)
        
    def detect_lateral_movement(self, source_device, target_device, packet_info):
        """Detect lateral movement attempts"""
        # Check for port scanning
        if packet_info.get("destination_port") in [22, 23, 80, 443, 8080]:
            self.scanning_attempts[source_device].append({
                "target": target_device,
                "port": packet_info.get("destination_port"),
                "timestamp": time.time()
            })
            
            # Check for scanning pattern
            recent_scans = [s for s in self.scanning_attempts[source_device]
                           if time.time() - s["timestamp"] < 300]  # 5 minutes
            
            if len(recent_scans) > 10:  # Multiple scanning attempts
                return {"threat": True, "type": "port_scanning"}
        
        # Check cross-VLAN access violations
        if not self.network_manager.check_cross_vlan_access(source_device, target_device):
            return {"threat": True, "type": "vlan_violation"}
        
        return {"threat": False}
    
    def quarantine_device(self, device_id, reason):
        """Quarantine suspicious device"""
        self.quarantined_devices.add(device_id)
        logger.warning(f"Device {device_id} quarantined: {reason}")
        
        # Log quarantine event
        self._log_security_event("device_quarantined", {
            "device_id": device_id,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    
    def _log_security_event(self, event_type, details):
        """Log security events"""
        try:
            with open('/app/results/logs/fog_security.json', 'a') as f:
                event = {
                    "event_type": event_type,
                    "details": details,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                f.write(json.dumps(event) + '\n')
        except Exception as e:
            logger.debug(f"Could not write security log: {e}")

class FogLayerProxy:
    """Main fog layer proxy coordinating all components"""
    
    def __init__(self):
        self.network_manager = NetworkSegmentationManager()
        self.traffic_filter = TrafficFilter()
        self.threat_blocker = LateralThreatBlocker(self.network_manager)
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "packets_blocked": 0,
            "threats_detected": 0,
            "devices_quarantined": 0,
            "start_time": datetime.now(timezone.utc).isoformat()
        }
        
    def process_device_data(self, data):
        """Process incoming data from device layer"""
        try:
            device_id = data.get("device_info", {}).get("device_id", "unknown")
            device_type = data.get("device_info", {}).get("device_type", "unknown")
            
            # Assign device to VLAN if not already assigned
            if device_id not in self.network_manager.device_assignments:
                self.network_manager.assign_device_to_vlan(device_id, device_type)
            
            # Extract packet information
            packet_info = {
                "source_ip": f"192.168.100.{hash(device_id) % 254 + 1}",  # Mock IP
                "size": len(json.dumps(data)),
                "protocol": "HTTPS",
                "timestamp": time.time()
            }
            
            # Check rate limits
            if not self.traffic_filter.check_rate_limit(packet_info["source_ip"]):
                self.stats["packets_blocked"] += 1
                return {"status": "blocked", "reason": "rate_limit_exceeded"}
            
            # Analyze traffic patterns
            anomaly_result = self.traffic_filter.analyze_traffic_pattern(packet_info)
            if anomaly_result["anomaly"]:
                self.stats["threats_detected"] += 1
                logger.warning(f"Traffic anomaly detected: {anomaly_result['type']}")
            
            # Forward to cloud layer
            result = self._forward_to_cloud(data)
            
            self.stats["packets_processed"] += 1
            
            return {
                "status": "processed",
                "device_id": device_id,
                "vlan": self.network_manager.device_assignments.get(device_id),
                "cloud_response": result,
                "anomaly_detected": anomaly_result["anomaly"]
            }
            
        except Exception as e:
            logger.error(f"Data processing error: {e}")
            return {"status": "error", "message": str(e)}
    
    def _forward_to_cloud(self, data):
        """Forward processed data to cloud layer"""
        try:
            cloud_url = os.getenv('CLOUD_URL', 'http://cloud:7000')
            response = requests.post(
                f"{cloud_url}/process_data",
                json=data,
                timeout=10
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning(f"Cloud layer response: {response.status_code}")
                return {"status": "cloud_error", "code": response.status_code}
                
        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not reach cloud layer: {e}")
            return {"status": "cloud_unavailable", "error": str(e)}
    
    def get_network_status(self):
        """Get current network status"""
        return {
            "vlans": self.network_manager.vlans,
            "device_assignments": self.network_manager.device_assignments,
            "blocked_ips": list(self.traffic_filter.blocked_ips),
            "quarantined_devices": list(self.threat_blocker.quarantined_devices),
            "statistics": self.stats
        }

# Initialize fog layer proxy
fog_proxy = FogLayerProxy()

# Flask routes
@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "layer": "fog",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": fog_proxy.stats
    })

@app.route('/device_data', methods=['POST'])
def receive_device_data():
    """Receive data from device layer"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        result = fog_proxy.process_device_data(data)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Device data processing error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/network_status')
def get_network_status():
    """Get network segmentation status"""
    return jsonify(fog_proxy.get_network_status())

@app.route('/block_device', methods=['POST'])
def block_device():
    """Manually block a device"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        reason = data.get('reason', 'manual_block')
        
        if not device_id:
            return jsonify({"error": "device_id required"}), 400
        
        fog_proxy.threat_blocker.quarantine_device(device_id, reason)
        return jsonify({"message": f"Device {device_id} blocked"})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/unblock_device', methods=['POST'])
def unblock_device():
    """Unblock a quarantined device"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        
        if device_id in fog_proxy.threat_blocker.quarantined_devices:
            fog_proxy.threat_blocker.quarantined_devices.remove(device_id)
            return jsonify({"message": f"Device {device_id} unblocked"})
        else:
            return jsonify({"error": "Device not quarantined"}), 404
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/traffic_stats')
def get_traffic_stats():
    """Get traffic filtering statistics"""
    return jsonify({
        "rate_limits": fog_proxy.traffic_filter.rate_limits,
        "blocked_ips": list(fog_proxy.traffic_filter.blocked_ips),
        "packet_counters": dict(fog_proxy.traffic_filter.packet_counters),
        "suspicious_patterns": len(fog_proxy.traffic_filter.suspicious_patterns)
    })

if __name__ == '__main__':
    logger.info("Starting CE-CMS Fog Layer Proxy")
    
    app.run(
        host='0.0.0.0',
        port=config["fog_layer"]["port"],
        debug=False,
        threaded=True
    )