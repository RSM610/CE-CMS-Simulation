#!/usr/bin/env python3
"""
CE-CMS Lateral Movement Blocker
Prevents lateral movement of threats across network segments
"""

import time
import json
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import threading

logger = logging.getLogger(__name__)

class LateralMovementDetector:
    """Detects lateral movement patterns in network traffic"""
    
    def __init__(self):
        # Detection parameters
        self.scan_threshold = 10  # Port scan threshold
        self.time_window = 300    # 5 minutes
        self.privilege_escalation_indicators = [
            "admin", "root", "sudo", "administrator"
        ]
        
        # Tracking structures
        self.connection_attempts = defaultdict(list)
        self.failed_authentications = defaultdict(list)
        self.privilege_escalations = defaultdict(list)
        self.suspicious_processes = defaultdict(list)
        
        # Network topology awareness
        self.network_segments = {
            "metaverse": {"subnet": "192.168.100.0/24", "security_level": "high"},
            "iot": {"subnet": "192.168.101.0/24", "security_level": "medium"},
            "guest": {"subnet": "192.168.102.0/24", "security_level": "low"}
        }
        
        # Device trust levels
        self.device_trust_scores = defaultdict(lambda: 1.0)  # 0.0 = untrusted, 1.0 = trusted
        
    def analyze_connection_pattern(self, source_device, target_device, connection_info):
        """Analyze connection patterns for lateral movement"""
        current_time = time.time()
        source_ip = connection_info.get("source_ip", "unknown")
        target_ip = connection_info.get("target_ip", "unknown")
        target_port = connection_info.get("target_port", 0)
        
        # Record connection attempt
        attempt = {
            "timestamp": current_time,
            "source_device": source_device,
            "target_device": target_device,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "target_port": target_port,
            "protocol": connection_info.get("protocol", "TCP"),
            "success": connection_info.get("success", False)
        }
        
        self.connection_attempts[source_device].append(attempt)
        
        # Clean old entries
        self._clean_old_entries(self.connection_attempts[source_device])
        
        # Detect various lateral movement patterns
        detection_results = []
        
        # 1. Port scanning detection
        port_scan_result = self._detect_port_scanning(source_device)
        if port_scan_result["detected"]:
            detection_results.append(port_scan_result)
        
        # 2. Cross-segment movement detection
        cross_segment_result = self._detect_cross_segment_movement(
            source_device, target_device, connection_info
        )
        if cross_segment_result["detected"]:
            detection_results.append(cross_segment_result)
        
        # 3. Privilege escalation detection
        privesc_result = self._detect_privilege_escalation(source_device, connection_info)
        if privesc_result["detected"]:
            detection_results.append(privesc_result)
        
        # 4. Beaconing detection
        beacon_result = self._detect_beaconing_behavior(source_device)
        if beacon_result["detected"]:
            detection_results.append(beacon_result)
        
        return {
            "source_device": source_device,
            "target_device": target_device,
            "detections": detection_results,
            "threat_score": self._calculate_threat_score(detection_results),
            "recommended_action": self._recommend_action(detection_results)
        }
    
    def _detect_port_scanning(self, source_device):
        """Detect port scanning behavior"""
        recent_attempts = [
            attempt for attempt in self.connection_attempts[source_device]
            if time.time() - attempt["timestamp"] < self.time_window
        ]
        
        # Count unique target ports
        target_ports = set(attempt["target_port"] for attempt in recent_attempts)
        
        if len(target_ports) > self.scan_threshold:
            # Check for common vulnerable ports
            vulnerable_ports = {22, 23, 80, 443, 3389, 5900, 1433, 3306}
            scanned_vulnerable = target_ports.intersection(vulnerable_ports)
            
            return {
                "detected": True,
                "type": "port_scanning",
                "severity": "high" if scanned_vulnerable else "medium",
                "details": {
                    "unique_ports": len(target_ports),
                    "vulnerable_ports_scanned": list(scanned_vulnerable),
                    "scan_duration": max(recent_attempts, key=lambda x: x["timestamp"])["timestamp"] - 
                                   min(recent_attempts, key=lambda x: x["timestamp"])["timestamp"]
                }
            }
        
        return {"detected": False}
    
    def _detect_cross_segment_movement(self, source_device, target_device, connection_info):
        """Detect unauthorized cross-segment movement"""
        source_segment = self._get_device_segment(source_device)
        target_segment = self._get_device_segment(target_device)
        
        if source_segment != target_segment:
            # Check if cross-segment access is authorized
            if not self._is_cross_segment_authorized(source_segment, target_segment):
                return {
                    "detected": True,
                    "type": "unauthorized_cross_segment",
                    "severity": "high",
                    "details": {
                        "source_segment": source_segment,
                        "target_segment": target_segment,
                        "source_security_level": self.network_segments[source_segment]["security_level"],
                        "target_security_level": self.network_segments[target_segment]["security_level"]
                    }
                }
        
        return {"detected": False}
    
    def _detect_privilege_escalation(self, source_device, connection_info):
        """Detect privilege escalation attempts"""
        # Look for privilege escalation indicators in connection data
        connection_data = connection_info.get("data", "").lower()
        
        escalation_detected = any(
            indicator in connection_data 
            for indicator in self.privilege_escalation_indicators
        )
        
        if escalation_detected:
            escalation_event = {
                "timestamp": time.time(),
                "device": source_device,
                "indicators_found": [
                    indicator for indicator in self.privilege_escalation_indicators
                    if indicator in connection_data
                ]
            }
            
            self.privilege_escalations[source_device].append(escalation_event)
            self._clean_old_entries(self.privilege_escalations[source_device])
            
            return {
                "detected": True,
                "type": "privilege_escalation",
                "severity": "critical",
                "details": escalation_event
            }
        
        return {"detected": False}
    
    def _detect_beaconing_behavior(self, source_device):
        """Detect C2 beaconing behavior"""
        recent_attempts = [
            attempt for attempt in self.connection_attempts[source_device]
            if time.time() - attempt["timestamp"] < self.time_window
        ]
        
        if len(recent_attempts) < 10:
            return {"detected": False}
        
        # Group by target
        targets = defaultdict(list)
        for attempt in recent_attempts:
            targets[attempt["target_ip"]].append(attempt["timestamp"])
        
        # Look for regular intervals (potential beaconing)
        for target_ip, timestamps in targets.items():
            if len(timestamps) >= 5:
                # Calculate intervals
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                avg_interval = sum(intervals) / len(intervals)
                interval_variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)
                
                # Regular intervals suggest beaconing
                if interval_variance < (avg_interval * 0.1)**2:  # Low variance
                    return {
                        "detected": True,
                        "type": "beaconing",
                        "severity": "high",
                        "details": {
                            "target_ip": target_ip,
                            "beacon_interval": avg_interval,
                            "beacon_count": len(timestamps),
                            "variance": interval_variance
                        }
                    }
        
        return {"detected": False}
    
    def _get_device_segment(self, device_id):
        """Determine which network segment a device belongs to"""
        # Simple mapping based on device ID pattern
        device_hash = int(hashlib.md5(device_id.encode()).hexdigest(), 16)
        
        if "vr" in device_id.lower() or "ar" in device_id.lower():
            return "metaverse"
        elif "iot" in device_id.lower() or "smart" in device_id.lower():
            return "iot"
        else:
            return "guest"
    
    def _is_cross_segment_authorized(self, source_segment, target_segment):
        """Check if cross-segment access is authorized"""
        # Define authorization matrix
        authorization_matrix = {
            "metaverse": {"metaverse": True, "iot": False, "guest": False},
            "iot": {"metaverse": False, "iot": True, "guest": False},
            "guest": {"metaverse": False, "iot": False, "guest": True}
        }
        
        return authorization_matrix.get(source_segment, {}).get(target_segment, False)
    
    def _calculate_threat_score(self, detections):
        """Calculate overall threat score based on detections"""
        if not detections:
            return 0.0
        
        severity_weights = {
            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1.0
        }
        
        total_score = sum(
            severity_weights.get(detection.get("severity", "low"), 0.2)
            for detection in detections
        )
        
        return min(1.0, total_score)
    
    def _recommend_action(self, detections):
        """Recommend action based on detections"""
        if not detections:
            return "allow"
        
        max_severity = max(
            detection.get("severity", "low") 
            for detection in detections
        )
        
        action_map = {
            "low": "monitor",
            "medium": "rate_limit",
            "high": "quarantine",
            "critical": "block"
        }
        
        return action_map.get(max_severity, "monitor")
    
    def _clean_old_entries(self, entry_list):
        """Clean old entries from tracking lists"""
        current_time = time.time()
        cutoff_time = current_time - self.time_window
        
        # Remove entries older than time window
        while entry_list and entry_list[0]["timestamp"] < cutoff_time:
            entry_list.pop(0)

class LateralMovementBlocker:
    """Implements blocking mechanisms for lateral movement"""
    
    def __init__(self):
        self.detector = LateralMovementDetector()
        self.blocked_devices = set()
        self.quarantined_devices = set()
        self.rate_limited_devices = defaultdict(int)
        
        # Blocking rules
        self.blocking_rules = []
        self.auto_block_enabled = True
        
        # Statistics
        self.stats = {
            "detections": 0,
            "blocks": 0,
            "quarantines": 0,
            "rate_limits": 0
        }
    
    def process_connection(self, source_device, target_device, connection_info):
        """Process connection and apply blocking if necessary"""
        # Check if source is already blocked
        if source_device in self.blocked_devices:
            return {
                "action": "blocked",
                "reason": "device_blocked",
                "allow_connection": False
            }
        
        # Analyze for lateral movement
        analysis = self.detector.analyze_connection_pattern(
            source_device, target_device, connection_info
        )
        
        if analysis["detections"]:
            self.stats["detections"] += 1
            
            # Apply recommended action
            action = analysis["recommended_action"]
            
            if action == "block" and self.auto_block_enabled:
                self._block_device(source_device, analysis)
                return {
                    "action": "blocked",
                    "reason": "lateral_movement_detected",
                    "allow_connection": False,
                    "analysis": analysis
                }
            
            elif action == "quarantine":
                self._quarantine_device(source_device, analysis)
                return {
                    "action": "quarantined",
                    "reason": "suspicious_behavior",
                    "allow_connection": False,
                    "analysis": analysis
                }
            
            elif action == "rate_limit":
                self._rate_limit_device(source_device, analysis)
                return {
                    "action": "rate_limited",
                    "reason": "potential_threat",
                    "allow_connection": True,
                    "analysis": analysis
                }
        
        return {
            "action": "allowed",
            "reason": "normal_behavior",
            "allow_connection": True,
            "analysis": analysis
        }
    
    def _block_device(self, device_id, analysis):
        """Block device completely"""
        self.blocked_devices.add(device_id)
        self.stats["blocks"] += 1
        
        self._log_action("device_blocked", device_id, analysis)
        logger.warning(f"Device {device_id} blocked due to lateral movement")
    
    def _quarantine_device(self, device_id, analysis):
        """Quarantine device with limited access"""
        self.quarantined_devices.add(device_id)
        self.stats["quarantines"] += 1
        
        self._log_action("device_quarantined", device_id, analysis)
        logger.warning(f"Device {device_id} quarantined due to suspicious behavior")
    
    def _rate_limit_device(self, device_id, analysis):
        """Apply rate limiting to device"""
        self.rate_limited_devices[device_id] += 1
        self.stats["rate_limits"] += 1
        
        self._log_action("device_rate_limited", device_id, analysis)
        logger.info(f"Device {device_id} rate limited")
    
    def _log_action(self, action, device_id, analysis):
        """Log blocking actions"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "device_id": device_id,
            "analysis": analysis
        }
        
        try:
            with open('/app/results/logs/lateral_movement.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.debug(f"Could not write lateral movement log: {e}")
    
    def unblock_device(self, device_id):
        """Unblock a device"""
        if device_id in self.blocked_devices:
            self.blocked_devices.remove(device_id)
            logger.info(f"Device {device_id} unblocked")
            return True
        return False
    
    def unquarantine_device(self, device_id):
        """Remove device from quarantine"""
        if device_id in self.quarantined_devices:
            self.quarantined_devices.remove(device_id)
            logger.info(f"Device {device_id} removed from quarantine")
            return True
        return False
    
    def get_status(self):
        """Get current blocker status"""
        return {
            "blocked_devices": len(self.blocked_devices),
            "quarantined_devices": len(self.quarantined_devices),
            "rate_limited_devices": len(self.rate_limited_devices),
            "auto_block_enabled": self.auto_block_enabled,
            "statistics": self.stats,
            "active_rules": len(self.blocking_rules)
        }

# Example usage for testing
if __name__ == "__main__":
    blocker = LateralMovementBlocker()
    
    # Simulate some connections
    test_connections = [
        {
            "source": "vr_device_1",
            "target": "iot_device_1",
            "info": {
                "source_ip": "192.168.100.10",
                "target_ip": "192.168.101.20",
                "target_port": 22,
                "protocol": "TCP",
                "success": False
            }
        },
        {
            "source": "vr_device_1",
            "target": "iot_device_2",
            "info": {
                "source_ip": "192.168.100.10",
                "target_ip": "192.168.101.21",
                "target_port": 23,
                "protocol": "TCP",
                "success": False
            }
        }
    ]
    
    # Process connections
    for conn in test_connections:
        result = blocker.process_connection(
            conn["source"], conn["target"], conn["info"]
        )
        print(f"Connection result: {result}")
    
    # Get status
    status = blocker.get_status()
    print(f"Blocker status: {status}")