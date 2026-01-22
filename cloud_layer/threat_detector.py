#!/usr/bin/env python3
"""
CE-CMS Threat Intelligence Engine - COMPLETE FIXED VERSION
AI-driven threat detection and classification for cloud layer
"""

import json
import time
import logging
import numpy as np
from datetime import datetime, timezone
from collections import defaultdict, deque
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import hashlib

logger = logging.getLogger(__name__)

class ThreatIntelligenceEngine:
    """AI-powered threat intelligence and detection engine"""
    
    def __init__(self):
        # ML models for threat detection
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        
        # Training data and model state
        self.is_trained = False
        self.training_data = []
        self.threat_signatures = {}
        
        # Threat intelligence database
        self.threat_indicators = {
            "known_malicious_ips": set(),
            "suspicious_patterns": [],
            "attack_signatures": {},
            "behavioral_anomalies": []
        }
        
        # Real-time threat tracking
        self.active_threats = defaultdict(list)
        self.threat_correlations = defaultdict(list)
        self.threat_timeline = deque(maxlen=10000)
        
        # Threat categories and scoring
        self.threat_categories = {
            "chaperone_attack": {"weight": 0.9, "indicators": ["boundary_manipulation", "spatial_disorientation"]},
            "identity_spoofing": {"weight": 0.8, "indicators": ["fake_credentials", "impersonation"]},
            "lateral_movement": {"weight": 0.7, "indicators": ["port_scanning", "privilege_escalation"]},
            "data_exfiltration": {"weight": 0.9, "indicators": ["unusual_data_access", "large_transfers"]},
            "ddos_attack": {"weight": 0.6, "indicators": ["traffic_flooding", "service_disruption"]},
            "malware_infection": {"weight": 0.8, "indicators": ["malicious_payload", "system_compromise"]}
        }
        
        # Initialize with baseline threat signatures
        self._initialize_threat_signatures()
        
    def _initialize_threat_signatures(self):
        """Initialize known threat signatures"""
        self.threat_signatures = {
            "chaperone_attack": {
                "features": ["boundary_deviation", "spatial_confusion", "collision_risk"],
                "thresholds": {"boundary_deviation": 2.0, "collision_risk": 0.8}
            },
            "identity_spoofing": {
                "features": ["credential_mismatch", "behavioral_inconsistency", "device_fingerprint"],
                "thresholds": {"credential_mismatch": 0.7, "behavioral_inconsistency": 0.6}
            },
            "behavioral_anomaly": {
                "features": ["usage_pattern", "interaction_frequency", "session_duration"],
                "thresholds": {"usage_pattern": 0.5, "interaction_frequency": 3.0}
            }
        }
    
    def analyze_data(self, data):
        """Main threat analysis function - FIXED"""
        try:
            analysis_start = time.time()
            
            # Validate input data
            if not data or not isinstance(data, dict):
                logger.warning(f"Invalid data received: {type(data)}")
                return {
                    "threat_detected": False,
                    "threat_level": "none",
                    "error": "invalid_data_format"
                }
            
            # Extract features for analysis with safe defaults
            features = self._extract_threat_features(data)
            
            if not features:
                return {
                    "threat_detected": False,
                    "threat_level": "none",
                    "reason": "no_features_extracted"
                }
            
            # Perform multiple detection methods
            anomaly_result = self._detect_anomalies(features, data)
            signature_result = self._match_threat_signatures(features, data)
            behavioral_result = self._analyze_behavioral_patterns(data)
            correlation_result = self._correlate_with_global_intelligence(data)
            
            # Combine results and calculate overall threat score
            combined_score = self._calculate_combined_threat_score([
                anomaly_result, signature_result, behavioral_result, correlation_result
            ])
            
            # Determine threat level and type
            threat_level, threat_type = self._classify_threat(combined_score, [
                anomaly_result, signature_result, behavioral_result, correlation_result
            ])
            
            # Generate recommendations
            recommendations = self._generate_threat_recommendations(
                threat_level, threat_type, combined_score
            )
            
            # Update threat timeline
            threat_entry = {
                "timestamp": time.time(),
                "device_id": data.get("device_info", {}).get("device_id", "unknown"),
                "threat_level": threat_level,
                "threat_type": threat_type,
                "confidence": combined_score.get("confidence", 0.0),
                "analysis_time_ms": round((time.time() - analysis_start) * 1000, 2)
            }
            
            self.threat_timeline.append(threat_entry)
            
            # Log significant threats
            if threat_level in ["medium", "high", "critical"]:
                self._log_threat_detection(threat_entry, data)
            
            return {
                "threat_detected": threat_level != "none",
                "threat_level": threat_level,
                "threat_type": threat_type,
                "confidence": combined_score.get("confidence", 0.0),
                "indicators": combined_score.get("indicators", []),
                "recommendations": recommendations,
                "analysis_details": {
                    "anomaly_score": anomaly_result.get("score", 0.0),
                    "signature_matches": len(signature_result.get("matches", [])),
                    "behavioral_deviation": behavioral_result.get("deviation", 0.0),
                    "global_correlation": correlation_result.get("correlation", 0.0)
                },
                "processing_time_ms": threat_entry["analysis_time_ms"]
            }
            
        except Exception as e:
            logger.error(f"Threat analysis error: {e}")
            return {
                "threat_detected": False,
                "threat_level": "none",
                "error": str(e)
            }
    
    def _extract_threat_features(self, data):
        """Extract features relevant for threat detection - FIXED"""
        try:
            features = {}
            
            # Safely extract device information
            device_info = data.get("device_info", {})
            if isinstance(device_info, dict):
                features["device_type"] = device_info.get("device_type", "unknown")
                features["battery_level"] = device_info.get("battery_level", 100)
                features["firmware_version"] = device_info.get("firmware_version", "1.0.0")
            
            # Check for malicious indicators in packet
            if data.get("malicious", False):
                features["malicious_packet"] = 1.0
            else:
                features["malicious_packet"] = 0.0
            
            # Extract attack type if present
            attack_type = data.get("attack_type", "none")
            if attack_type != "none":
                features["attack_indicator"] = 1.0
                features["attack_type"] = attack_type
            else:
                features["attack_indicator"] = 0.0
            
            # Sensor data features (if present)
            sensors = data.get("sensors", [])
            if isinstance(sensors, list):
                for sensor in sensors:
                    if not isinstance(sensor, dict):
                        continue
                        
                    sensor_type = sensor.get("sensor_type", "unknown")
                    sensor_data = sensor.get("data", {})
                    
                    if sensor_type == "accelerometer" and isinstance(sensor_data, dict):
                        x = sensor_data.get("x", 0)
                        y = sensor_data.get("y", 0)
                        z = sensor_data.get("z", 0)
                        magnitude = np.sqrt(x**2 + y**2 + z**2)
                        features[f"{sensor_type}_magnitude"] = magnitude
                        features[f"{sensor_type}_deviation"] = abs(magnitude - 9.81)
                        
                    elif sensor_type == "eye_tracking" and isinstance(sensor_data, dict):
                        gaze_x = sensor_data.get("gaze_x", 0.5)
                        gaze_y = sensor_data.get("gaze_y", 0.5)
                        features["gaze_velocity"] = np.sqrt((gaze_x - 0.5)**2 + (gaze_y - 0.5)**2)
                        features["pupil_variation"] = abs(
                            sensor_data.get("pupil_diameter_left", 4.0) - 
                            sensor_data.get("pupil_diameter_right", 4.0)
                        )
                        features["blink_rate"] = sensor_data.get("blink_rate", 20)
                        
                    elif sensor_type == "head_tracking" and isinstance(sensor_data, dict):
                        rotation = sensor_data.get("rotation", {})
                        if isinstance(rotation, dict):
                            features["head_rotation_intensity"] = np.sqrt(
                                rotation.get("pitch", 0)**2 + 
                                rotation.get("yaw", 0)**2 + 
                                rotation.get("roll", 0)**2
                            )
            
            # User behavior features (if present)
            user_profile = data.get("user_profile", {})
            if isinstance(user_profile, dict):
                features["user_experience"] = user_profile.get("experience_level", "beginner")
                features["play_style"] = user_profile.get("play_style", "passive")
            
            # Temporal features
            features["timestamp"] = time.time()
            features["packet_size"] = len(json.dumps(data))
            
            return features
            
        except Exception as e:
            logger.error(f"Feature extraction error: {e}")
            return {}
    
    def _detect_anomalies(self, features, data):
        """Detect anomalies using ML models"""
        try:
            numerical_features = []
            for key, value in features.items():
                if isinstance(value, (int, float)):
                    numerical_features.append(value)
                elif isinstance(value, str):
                    numerical_features.append(hash(value) % 1000 / 1000.0)
            
            if len(numerical_features) < 5:
                return {"anomaly": False, "score": 0.0, "reason": "insufficient_features"}
            
            feature_vector = np.array(numerical_features[:20])
            if len(feature_vector) < 20:
                feature_vector = np.pad(feature_vector, (0, 20 - len(feature_vector)))
            
            if not self.is_trained:
                anomaly_score = 0.0
                
                if features.get("malicious_packet", 0.0) > 0:
                    anomaly_score += 0.8
                
                if features.get("attack_indicator", 0.0) > 0:
                    anomaly_score += 0.7
                
                if "accelerometer_deviation" in features and features["accelerometer_deviation"] > 5.0:
                    anomaly_score += 0.3
                
                if "gaze_velocity" in features and features["gaze_velocity"] > 0.8:
                    anomaly_score += 0.2
                    
                if "head_rotation_intensity" in features and features["head_rotation_intensity"] > 45:
                    anomaly_score += 0.3
                
                return {
                    "anomaly": anomaly_score > 0.5,
                    "score": min(1.0, anomaly_score),
                    "method": "rule_based"
                }
            else:
                normalized_features = self.scaler.transform([feature_vector])
                anomaly_score = self.anomaly_detector.decision_function(normalized_features)[0]
                is_anomaly = self.anomaly_detector.predict(normalized_features)[0] == -1
                
                return {
                    "anomaly": is_anomaly,
                    "score": max(0, min(1, abs(anomaly_score))),
                    "method": "ml_based"
                }
                
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            return {"anomaly": False, "score": 0.0, "error": str(e)}
    
    def _match_threat_signatures(self, features, data):
        """Match against known threat signatures"""
        matches = []
        
        for threat_type, signature in self.threat_signatures.items():
            match_score = 0.0
            matched_features = []
            
            for feature_name in signature["features"]:
                if feature_name in features:
                    feature_value = features[feature_name]
                    threshold = signature["thresholds"].get(feature_name, 0.5)
                    
                    if isinstance(feature_value, (int, float)) and feature_value > threshold:
                        match_score += 1.0 / len(signature["features"])
                        matched_features.append(feature_name)
            
            if match_score > 0.3:
                matches.append({
                    "threat_type": threat_type,
                    "match_score": match_score,
                    "matched_features": matched_features
                })
        
        return {
            "matches": matches,
            "best_match": max(matches, key=lambda x: x["match_score"]) if matches else None
        }
    
    def _analyze_behavioral_patterns(self, data):
        """Analyze behavioral patterns for anomalies"""
        device_id = data.get("device_info", {}).get("device_id", "unknown") if isinstance(data.get("device_info"), dict) else "unknown"
        
        user_profile = data.get("user_profile", {})
        
        behavioral_score = 0.0
        deviations = []
        
        if isinstance(user_profile, dict):
            if user_profile.get("head_movement_pattern") == "anomalous":
                behavioral_score += 0.4
                deviations.append("unusual_head_movement")
        
        sensors = data.get("sensors", [])
        if isinstance(sensors, list):
            for sensor in sensors:
                if isinstance(sensor, dict) and sensor.get("sensor_type") == "eye_tracking":
                    sensor_data = sensor.get("data", {})
                    if isinstance(sensor_data, dict):
                        blink_rate = sensor_data.get("blink_rate", 20)
                        if blink_rate < 5 or blink_rate > 40:
                            behavioral_score += 0.2
                            deviations.append("unusual_blink_pattern")
        
        return {
            "deviation": behavioral_score,
            "deviations": deviations,
            "device_id": device_id
        }
    
    def _correlate_with_global_intelligence(self, data):
        """Correlate with global threat intelligence"""
        device_id = data.get("device_info", {}).get("device_id", "unknown") if isinstance(data.get("device_info"), dict) else "unknown"
        device_hash = hashlib.sha256(device_id.encode()).hexdigest()[:16]
        
        correlation_score = 0.0
        correlations = []
        
        current_time = time.time()
        
        recent_threats = [
            t for t in self.threat_timeline 
            if current_time - t["timestamp"] < 3600
        ]
        
        similar_threats = [
            t for t in recent_threats 
            if t["device_id"] != device_id and t["threat_level"] in ["medium", "high", "critical"]
        ]
        
        if len(similar_threats) > 3:
            correlation_score += 0.3
            correlations.append("coordinated_attack_pattern")
        
        device_threats = [
            t for t in recent_threats 
            if t["device_id"] == device_id
        ]
        
        if len(device_threats) > 1:
            threat_levels = [t["threat_level"] for t in device_threats]
            if "low" in threat_levels and ("medium" in threat_levels or "high" in threat_levels):
                correlation_score += 0.4
                correlations.append("threat_escalation")
        
        return {
            "correlation": correlation_score,
            "correlations": correlations,
            "similar_threats": len(similar_threats)
        }
    
    def _calculate_combined_threat_score(self, analysis_results):
        """Combine multiple analysis results into overall threat score"""
        total_score = 0.0
        confidence = 0.0
        indicators = []
        
        weights = {
            "anomaly": 0.3,
            "signature": 0.4,
            "behavioral": 0.2,
            "correlation": 0.1
        }
        
        anomaly_result = analysis_results[0]
        if anomaly_result.get("anomaly", False):
            total_score += weights["anomaly"] * anomaly_result.get("score", 0.0)
            indicators.append(f"anomaly_detected_{anomaly_result.get('method', 'unknown')}")
        
        signature_result = analysis_results[1]
        if signature_result.get("best_match"):
            match_score = signature_result["best_match"]["match_score"]
            total_score += weights["signature"] * match_score
            indicators.append(f"signature_match_{signature_result['best_match']['threat_type']}")
        
        behavioral_result = analysis_results[2]
        behavioral_score = behavioral_result.get("deviation", 0.0)
        total_score += weights["behavioral"] * behavioral_score
        if behavioral_score > 0.3:
            indicators.extend(behavioral_result.get("deviations", []))
        
        correlation_result = analysis_results[3]
        correlation_score = correlation_result.get("correlation", 0.0)
        total_score += weights["correlation"] * correlation_score
        if correlation_score > 0.2:
            indicators.extend(correlation_result.get("correlations", []))
        
        detection_count = sum([
            1 if anomaly_result.get("anomaly", False) else 0,
            1 if signature_result.get("best_match") else 0,
            1 if behavioral_score > 0.3 else 0,
            1 if correlation_score > 0.2 else 0
        ])
        
        confidence = min(1.0, total_score + (detection_count * 0.1))
        
        return {
            "total_score": min(1.0, total_score),
            "confidence": confidence,
            "indicators": list(set(indicators)),
            "method_scores": {
                "anomaly": anomaly_result.get("score", 0.0),
                "signature": signature_result.get("best_match", {}).get("match_score", 0.0),
                "behavioral": behavioral_score,
                "correlation": correlation_score
            }
        }
    
    def _classify_threat(self, combined_score, analysis_results):
        """Classify threat level and type based on analysis"""
        total_score = combined_score.get("total_score", 0.0)
        
        if total_score >= 0.8:
            threat_level = "critical"
        elif total_score >= 0.6:
            threat_level = "high"
        elif total_score >= 0.4:
            threat_level = "medium"
        elif total_score >= 0.2:
            threat_level = "low"
        else:
            threat_level = "none"
        
        threat_type = "unknown"
        
        signature_result = analysis_results[1]
        if signature_result.get("best_match"):
            threat_type = signature_result["best_match"]["threat_type"]
        
        indicators = combined_score.get("indicators", [])
        
        if any("boundary" in indicator or "spatial" in indicator for indicator in indicators):
            threat_type = "chaperone_attack"
        elif any("identity" in indicator or "credential" in indicator for indicator in indicators):
            threat_type = "identity_spoofing"
        elif any("movement" in indicator or "escalation" in indicator for indicator in indicators):
            threat_type = "lateral_movement"
        elif any("coordinated" in indicator for indicator in indicators):
            threat_type = "coordinated_attack"
        elif any("anomaly" in indicator for indicator in indicators):
            threat_type = "behavioral_anomaly"
        
        return threat_level, threat_type
    
    def _generate_threat_recommendations(self, threat_level, threat_type, combined_score):
        """Generate specific recommendations based on threat analysis"""
        recommendations = []
        
        if threat_level == "critical":
            recommendations.extend([
                {"action": "immediate_isolation", "priority": "critical"},
                {"action": "emergency_response", "priority": "critical"},
                {"action": "forensic_analysis", "priority": "high"}
            ])
        elif threat_level == "high":
            recommendations.extend([
                {"action": "enhanced_monitoring", "priority": "high"},
                {"action": "restrict_privileges", "priority": "high"},
                {"action": "security_audit", "priority": "medium"}
            ])
        elif threat_level == "medium":
            recommendations.extend([
                {"action": "increase_logging", "priority": "medium"},
                {"action": "user_notification", "priority": "medium"}
            ])
        elif threat_level == "low":
            recommendations.append(
                {"action": "continuous_monitoring", "priority": "low"}
            )
        
        if threat_type == "chaperone_attack":
            recommendations.extend([
                {"action": "recalibrate_boundaries", "priority": "high"},
                {"action": "emergency_stop", "priority": "critical"}
            ])
        elif threat_type == "identity_spoofing":
            recommendations.extend([
                {"action": "re_authenticate", "priority": "high"},
                {"action": "verify_credentials", "priority": "medium"}
            ])
        elif threat_type == "lateral_movement":
            recommendations.extend([
                {"action": "network_segmentation", "priority": "high"},
                {"action": "access_review", "priority": "medium"}
            ])
        
        return recommendations
    
    def _log_threat_detection(self, threat_entry, original_data):
        """Log threat detection events"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threat_info": threat_entry,
            "device_data_hash": hashlib.sha256(
                json.dumps(original_data, sort_keys=True).encode()
            ).hexdigest()[:32]
        }
        
        try:
            with open('/app/results/logs/threat_detections.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.debug(f"Could not write threat detection log: {e}")
    
    def update_threat_signatures(self, new_signatures):
        """Update threat signatures with new intelligence"""
        self.threat_signatures.update(new_signatures)
        logger.info(f"Updated threat signatures: {len(new_signatures)} new signatures")
    
    def train_models(self, training_data):
        """Train ML models with new data"""
        try:
            if len(training_data) < 100:
                logger.warning("Insufficient training data for ML models")
                return False
            
            feature_matrix = []
            labels = []
            
            for sample in training_data:
                features = self._extract_threat_features(sample["data"])
                numerical_features = []
                
                for key, value in features.items():
                    if isinstance(value, (int, float)):
                        numerical_features.append(value)
                    elif isinstance(value, str):
                        numerical_features.append(hash(value) % 1000 / 1000.0)
                
                if len(numerical_features) >= 5:
                    feature_vector = np.array(numerical_features[:20])
                    if len(feature_vector) < 20:
                        feature_vector = np.pad(feature_vector, (0, 20 - len(feature_vector)))
                    
                    feature_matrix.append(feature_vector)
                    labels.append(sample.get("label", 0))
            
            if len(feature_matrix) < 50:
                return False
            
            feature_matrix = np.array(feature_matrix)
            
            self.scaler.fit(feature_matrix)
            normalized_features = self.scaler.transform(feature_matrix)
            
            self.anomaly_detector.fit(normalized_features)
            
            if len(set(labels)) > 1:
                self.threat_classifier.fit(normalized_features, labels)
            
            self.is_trained = True
            logger.info(f"Models trained on {len(feature_matrix)} samples")
            return True
            
        except Exception as e:
            logger.error(f"Model training error: {e}")
            return False
    
    def get_status(self):
        """Get threat intelligence engine status"""
        return {
            "is_trained": self.is_trained,
            "threat_signatures": len(self.threat_signatures),
            "active_threats": len(self.active_threats),
            "threat_timeline_size": len(self.threat_timeline),
            "known_indicators": {
                "malicious_ips": len(self.threat_indicators["known_malicious_ips"]),
                "suspicious_patterns": len(self.threat_indicators["suspicious_patterns"]),
                "attack_signatures": len(self.threat_indicators["attack_signatures"])
            },
            "threat_categories": list(self.threat_categories.keys())
        }
    
    def get_threat_statistics(self):
        """Get comprehensive threat statistics"""
        current_time = time.time()
        recent_cutoff = current_time - 3600
        
        recent_threats = [
            t for t in self.threat_timeline 
            if t["timestamp"] > recent_cutoff
        ]
        
        threat_levels = [t["threat_level"] for t in recent_threats]
        threat_types = [t["threat_type"] for t in recent_threats]
        
        level_distribution = defaultdict(int)
        type_distribution = defaultdict(int)
        
        for level in threat_levels:
            level_distribution[level] += 1
            
        for threat_type in threat_types:
            type_distribution[threat_type] += 1
        
        return {
            "total_threats_analyzed": len(self.threat_timeline),
            "recent_threats": len(recent_threats),
            "threat_level_distribution": dict(level_distribution),
            "threat_type_distribution": dict(type_distribution),
            "average_confidence": (
                sum(t["confidence"] for t in recent_threats) / max(1, len(recent_threats))
            ),
            "detection_rate": len(recent_threats) / max(1, len(self.threat_timeline)) * 100
        }

if __name__ == "__main__":
    engine = ThreatIntelligenceEngine()
    
    test_data = {
        "device_info": {
            "device_id": "test_vr_001",
            "device_type": "vr_headset",
            "battery_level": 75
        },
        "sensors": [
            {
                "sensor_type": "accelerometer",
                "data": {"x": 0.1, "y": 0.2, "z": 9.8}
            },
            {
                "sensor_type": "eye_tracking", 
                "data": {"gaze_x": 0.5, "gaze_y": 0.4, "blink_rate": 22}
            }
        ],
        "user_profile": {
            "experience_level": "intermediate",
            "play_style": "aggressive"
        }
    }
    
    result = engine.analyze_data(test_data)
    print(f"Threat analysis result: {result}")
    
    status = engine.get_status()
    print(f"Engine status: {status}")