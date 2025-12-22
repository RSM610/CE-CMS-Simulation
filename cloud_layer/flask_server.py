#!/usr/bin/env python3
"""
CE-CMS Cloud Layer: Flask Server
Central server for threat intelligence and identity management
"""

import json
import time
import threading
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
        "cloud_layer": {
            "port": 7000,
            "ai_threat_detection": True,
            "did_verification": True
        }
    }

app = Flask(__name__)

# Import cloud components
from threat_detector import ThreatIntelligenceEngine
from did_simulator import DIDVerificationService

class CloudSecurityOrchestrator:
    """Main orchestrator for cloud-layer security services"""
    
    def __init__(self):
        # Initialize components
        self.threat_engine = ThreatIntelligenceEngine()
        self.did_service = DIDVerificationService()
        
        # Data storage
        self.processed_data = deque(maxlen=10000)
        self.threat_reports = deque(maxlen=1000)
        self.identity_verifications = deque(maxlen=1000)
        
        # Statistics
        self.stats = {
            "data_packets_processed": 0,
            "threats_detected": 0,
            "identities_verified": 0,
            "false_positives": 0,
            "start_time": datetime.now(timezone.utc).isoformat()
        }
        
        # Cross-platform threat intelligence
        self.global_threat_patterns = defaultdict(list)
        self.platform_connections = {}
        
    def process_fog_data(self, fog_data):
        """Process data received from fog layer"""
        try:
            processing_start = time.time()
            
            # Extract device information
            device_info = fog_data.get("device_info", {})
            device_id = device_info.get("device_id", "unknown")
            
            # Verify device identity
            identity_result = self.did_service.verify_device_identity(device_id, device_info)
            
            # Analyze for threats
            threat_result = self.threat_engine.analyze_data(fog_data)
            
            # Store processed data
            processed_entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "device_id": device_id,
                "original_data": fog_data,
                "identity_verification": identity_result,
                "threat_analysis": threat_result,
                "processing_time_ms": round((time.time() - processing_start) * 1000, 2)
            }
            
            self.processed_data.append(processed_entry)
            
            # Update statistics
            self.stats["data_packets_processed"] += 1
            
            if threat_result.get("threat_detected", False):
                self.stats["threats_detected"] += 1
                self._handle_detected_threat(device_id, threat_result)
            
            if identity_result.get("verified", False):
                self.stats["identities_verified"] += 1
            
            # Prepare response
            response = {
                "status": "processed",
                "device_id": device_id,
                "identity_verified": identity_result.get("verified", False),
                "threat_level": threat_result.get("threat_level", "none"),
                "processing_time_ms": processed_entry["processing_time_ms"],
                "recommendations": self._generate_recommendations(identity_result, threat_result)
            }
            
            return response
            
        except Exception as e:
            logger.error(f"Cloud data processing error: {e}")
            return {"status": "error", "message": str(e)}
    
    def _handle_detected_threat(self, device_id, threat_result):
        """Handle detected threats with appropriate response"""
        threat_level = threat_result.get("threat_level", "low")
        threat_type = threat_result.get("threat_type", "unknown")
        
        # Create threat report
        threat_report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": device_id,
            "threat_level": threat_level,
            "threat_type": threat_type,
            "confidence": threat_result.get("confidence", 0.0),
            "indicators": threat_result.get("indicators", []),
            "recommended_actions": threat_result.get("recommendations", [])
        }
        
        self.threat_reports.append(threat_report)
        
        # Update global threat intelligence
        self.global_threat_patterns[threat_type].append({
            "timestamp": time.time(),
            "device_hash": hashlib.sha256(device_id.encode()).hexdigest()[:16],
            "threat_level": threat_level,
            "indicators": threat_result.get("indicators", [])
        })
        
        # Log threat
        self._log_threat_event(threat_report)
        
        # Send alerts if high severity
        if threat_level in ["high", "critical"]:
            self._send_threat_alert(threat_report)
    
    def _generate_recommendations(self, identity_result, threat_result):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Identity-based recommendations
        if not identity_result.get("verified", False):
            recommendations.append({
                "type": "identity",
                "action": "require_re_authentication",
                "priority": "high"
            })
        
        # Threat-based recommendations
        threat_level = threat_result.get("threat_level", "none")
        
        if threat_level == "high":
            recommendations.extend([
                {"type": "security", "action": "increase_monitoring", "priority": "high"},
                {"type": "network", "action": "restrict_network_access", "priority": "medium"}
            ])
        elif threat_level == "medium":
            recommendations.append({
                "type": "security", "action": "enhanced_logging", "priority": "medium"
            })
        
        return recommendations
    
    def _log_threat_event(self, threat_report):
        """Log threat events to file"""
        try:
            with open('/app/results/logs/cloud_threats.json', 'a') as f:
                f.write(json.dumps(threat_report) + '\n')
        except Exception as e:
            logger.debug(f"Could not write threat log: {e}")
    
    def _send_threat_alert(self, threat_report):
        """Send threat alerts to external systems"""
        # In a real implementation, this would send alerts to SIEM, SOC, etc.
        logger.critical(f"HIGH SEVERITY THREAT DETECTED: {threat_report}")
        
        # Could integrate with external alerting systems
        # - Email notifications
        # - Slack/Teams webhooks  
        # - SIEM integration
        # - Mobile push notifications
    
    def get_global_threat_intelligence(self):
        """Get aggregated threat intelligence"""
        current_time = time.time()
        recent_cutoff = current_time - 3600  # Last hour
        
        threat_summary = {}
        
        for threat_type, patterns in self.global_threat_patterns.items():
            recent_patterns = [
                p for p in patterns 
                if p["timestamp"] > recent_cutoff
            ]
            
            if recent_patterns:
                threat_summary[threat_type] = {
                    "recent_occurrences": len(recent_patterns),
                    "severity_distribution": self._calculate_severity_distribution(recent_patterns),
                    "trend": self._calculate_threat_trend(patterns)
                }
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_summary": threat_summary,
            "total_threats": sum(len(patterns) for patterns in self.global_threat_patterns.values()),
            "active_threats": len([t for threats in self.global_threat_patterns.values() 
                                 for t in threats if t["timestamp"] > recent_cutoff])
        }
    
    def _calculate_severity_distribution(self, patterns):
        """Calculate distribution of threat severities"""
        severities = [p["threat_level"] for p in patterns]
        distribution = defaultdict(int)
        
        for severity in severities:
            distribution[severity] += 1
            
        total = len(severities)
        return {severity: count/total for severity, count in distribution.items()}
    
    def _calculate_threat_trend(self, patterns):
        """Calculate threat trend over time"""
        if len(patterns) < 2:
            return "stable"
        
        # Simple trend calculation based on recent vs older patterns
        current_time = time.time()
        recent_cutoff = current_time - 1800  # Last 30 minutes
        older_cutoff = current_time - 3600   # 30-60 minutes ago
        
        recent_count = len([p for p in patterns if p["timestamp"] > recent_cutoff])
        older_count = len([p for p in patterns if older_cutoff < p["timestamp"] <= recent_cutoff])
        
        if older_count == 0:
            return "emerging"
        
        ratio = recent_count / older_count
        
        if ratio > 1.5:
            return "increasing"
        elif ratio < 0.5:
            return "decreasing"
        else:
            return "stable"
    
    def get_cloud_status(self):
        """Get comprehensive cloud layer status"""
        return {
            "services": {
                "threat_intelligence": self.threat_engine.get_status(),
                "identity_verification": self.did_service.get_status()
            },
            "statistics": self.stats,
            "data_storage": {
                "processed_data_count": len(self.processed_data),
                "threat_reports_count": len(self.threat_reports),
                "identity_verifications_count": len(self.identity_verifications)
            },
            "global_intelligence": self.get_global_threat_intelligence()
        }

# Initialize cloud orchestrator
cloud_orchestrator = CloudSecurityOrchestrator()

# Flask routes
@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "layer": "cloud",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services_active": True
    })

@app.route('/process_data', methods=['POST'])
def process_data():
    """Process data from fog layer"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        result = cloud_orchestrator.process_fog_data(data)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Data processing error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/threat_intelligence')
def get_threat_intelligence():
    """Get global threat intelligence"""
    return jsonify(cloud_orchestrator.get_global_threat_intelligence())

@app.route('/cloud_status')
def get_cloud_status():
    """Get comprehensive cloud status"""
    return jsonify(cloud_orchestrator.get_cloud_status())

@app.route('/recent_threats')
def get_recent_threats():
    """Get recent threat reports"""
    limit = request.args.get('limit', 10, type=int)
    recent_threats = list(cloud_orchestrator.threat_reports)[-limit:]
    
    return jsonify({
        "recent_threats": recent_threats,
        "total_threats": len(cloud_orchestrator.threat_reports)
    })

@app.route('/verify_identity', methods=['POST'])
def verify_identity():
    """Verify device identity"""
    try:
        data = request.get_json()
        device_id = data.get('device_id')
        device_info = data.get('device_info', {})
        
        if not device_id:
            return jsonify({"error": "device_id required"}), 400
        
        result = cloud_orchestrator.did_service.verify_device_identity(device_id, device_info)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analytics/threat_trends')
def get_threat_trends():
    """Get threat analytics and trends"""
    threat_intelligence = cloud_orchestrator.get_global_threat_intelligence()
    
    # Add additional analytics
    analytics = {
        "threat_intelligence": threat_intelligence,
        "processing_metrics": {
            "avg_processing_time": cloud_orchestrator.stats.get("avg_processing_time", 0),
            "throughput_per_minute": cloud_orchestrator.stats["data_packets_processed"] / max(1, 
                (time.time() - time.mktime(datetime.fromisoformat(
                    cloud_orchestrator.stats["start_time"].replace('Z', '+00:00')
                ).timetuple())) / 60
            )
        },
        "accuracy_metrics": {
            "threat_detection_rate": (
                cloud_orchestrator.stats["threats_detected"] / 
                max(1, cloud_orchestrator.stats["data_packets_processed"])
            ),
            "false_positive_rate": (
                cloud_orchestrator.stats["false_positives"] / 
                max(1, cloud_orchestrator.stats["threats_detected"])
            )
        }
    }
    
    return jsonify(analytics)

if __name__ == '__main__':
    logger.info("Starting CE-CMS Cloud Layer Server")
    
    app.run(
        host='0.0.0.0',
        port=config["cloud_layer"]["port"],
        debug=False,
        threaded=True
    )