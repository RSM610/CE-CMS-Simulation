#!/usr/bin/env python3
"""
CE-CMS Fog Layer: DDoS Simulation and Protection
Simulates DDoS attacks and implements protection mechanisms
"""

import time
import threading
import random
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
import json

logger = logging.getLogger(__name__)

class DDoSSimulator:
    """Simulates various DDoS attack patterns"""
    
    def __init__(self):
        self.attack_patterns = {
            "volumetric": {"packet_rate": 5000, "duration": 30},
            "protocol": {"packet_rate": 1000, "duration": 60},
            "application": {"packet_rate": 500, "duration": 120}
        }
        self.is_attacking = False
        self.current_attack = None
        
    def generate_attack_traffic(self, attack_type="volumetric"):
        """Generate simulated attack traffic"""
        pattern = self.attack_patterns.get(attack_type, self.attack_patterns["volumetric"])
        
        attack_packets = []
        packet_rate = pattern["packet_rate"]
        
        # Generate source IPs (botnet simulation)
        source_ips = []
        for _ in range(random.randint(50, 200)):
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            source_ips.append(ip)
        
        # Generate attack packets
        for i in range(packet_rate):
            packet = {
                "id": f"attack_pkt_{i}",
                "source_ip": random.choice(source_ips),
                "destination_ip": "192.168.100.1",  # Target fog node
                "size": random.randint(64, 1500),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "timestamp": time.time() + (i / packet_rate),
                "attack_type": attack_type,
                "malicious": True
            }
            attack_packets.append(packet)
        
        return attack_packets
    
    def start_attack(self, attack_type="volumetric", target_ip="192.168.100.1"):
        """Start DDoS attack simulation"""
        if self.is_attacking:
            return {"status": "attack_already_active"}
        
        self.is_attacking = True
        self.current_attack = {
            "type": attack_type,
            "target": target_ip,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "packets_sent": 0
        }
        
        def attack_thread():
            pattern = self.attack_patterns[attack_type]
            end_time = time.time() + pattern["duration"]
            
            while time.time() < end_time and self.is_attacking:
                # Generate burst of packets
                packets = self.generate_attack_traffic(attack_type)
                self.current_attack["packets_sent"] += len(packets)
                
                # Simulate sending packets (in real scenario, would use network)
                logger.warning(f"DDoS attack burst: {len(packets)} packets to {target_ip}")
                
                # Wait before next burst
                time.sleep(1.0)
            
            self.is_attacking = False
            self.current_attack["end_time"] = datetime.now(timezone.utc).isoformat()
            logger.info(f"DDoS attack completed: {self.current_attack}")
        
        threading.Thread(target=attack_thread, daemon=True).start()
        return {"status": "attack_started", "attack_info": self.current_attack}
    
    def stop_attack(self):
        """Stop current DDoS attack"""
        if not self.is_attacking:
            return {"status": "no_active_attack"}
        
        self.is_attacking = False
        return {"status": "attack_stopped", "attack_info": self.current_attack}

class DDoSProtection:
    """DDoS protection mechanisms for fog layer"""
    
    def __init__(self):
        # Rate limiting
        self.rate_limits = {
            "packets_per_second": 1000,
            "connections_per_minute": 100,
            "bytes_per_second": 1000000  # 1MB/s
        }
        
        # Traffic tracking
        self.traffic_stats = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "connection_count": 0,
            "last_reset": time.time()
        })
        
        # Detection thresholds
        self.detection_thresholds = {
            "volumetric_pps": 2000,  # Packets per second
            "protocol_anomaly": 0.8,  # Anomaly score
            "application_latency": 5.0  # Seconds
        }
        
        # Mitigation strategies
        self.mitigation_active = False
        self.blocked_sources = set()
        self.rate_limited_sources = defaultdict(int)
        
        # Attack detection
        self.attack_indicators = deque(maxlen=1000)
        self.detection_window = 60  # seconds
        
    def analyze_traffic(self, packet_info):
        """Analyze incoming traffic for DDoS patterns"""
        source_ip = packet_info.get("source_ip", "unknown")
        current_time = time.time()
        
        # Update traffic statistics
        stats = self.traffic_stats[source_ip]
        
        # Reset counters if needed
        if current_time - stats["last_reset"] >= 1.0:
            stats["packet_count"] = 0
            stats["byte_count"] = 0
            stats["last_reset"] = current_time
        
        # Update counters
        stats["packet_count"] += 1
        stats["byte_count"] += packet_info.get("size", 0)
        
        # Detect volumetric attacks
        volumetric_score = self._detect_volumetric_attack(source_ip, stats)
        
        # Detect protocol anomalies
        protocol_score = self._detect_protocol_anomaly(packet_info)
        
        # Detect application layer attacks
        application_score = self._detect_application_attack(packet_info)
        
        # Combine scores
        total_score = max(volumetric_score, protocol_score, application_score)
        
        # Record detection result
        detection_result = {
            "timestamp": current_time,
            "source_ip": source_ip,
            "volumetric_score": volumetric_score,
            "protocol_score": protocol_score,
            "application_score": application_score,
            "total_score": total_score,
            "packet_info": packet_info
        }
        
        self.attack_indicators.append(detection_result)
        
        return detection_result
    
    def _detect_volumetric_attack(self, source_ip, stats):
        """Detect volumetric DDoS attacks"""
        pps = stats["packet_count"]  # Already per second due to reset
        
        if pps > self.detection_thresholds["volumetric_pps"]:
            return min(1.0, pps / (self.detection_thresholds["volumetric_pps"] * 2))
        
        return 0.0
    
    def _detect_protocol_anomaly(self, packet_info):
        """Detect protocol-based attacks"""
        protocol = packet_info.get("protocol", "TCP")
        packet_size = packet_info.get("size", 0)
        
        # Detect unusual protocol patterns
        if protocol == "UDP" and packet_size < 64:
            return 0.6  # UDP flood with small packets
        
        if protocol == "ICMP":
            return 0.5  # ICMP floods
        
        if packet_size > 1400:
            return 0.4  # Large packet attacks
        
        return 0.0
    
    def _detect_application_attack(self, packet_info):
        """Detect application layer attacks"""
        # Simulate application layer analysis
        if packet_info.get("malicious", False):
            return 0.9  # Known malicious packet
        
        # Check for application-specific patterns
        if "HTTP" in packet_info.get("protocol", ""):
            return 0.3  # HTTP-based attacks
        
        return 0.0
    
    def should_block_packet(self, packet_info):
        """Determine if packet should be blocked"""
        source_ip = packet_info.get("source_ip", "unknown")
        
        # Check if source is already blocked
        if source_ip in self.blocked_sources:
            return True, "source_blocked"
        
        # Analyze traffic
        analysis = self.analyze_traffic(packet_info)
        
        # Apply rate limiting
        if self._check_rate_limit(source_ip, packet_info):
            return True, "rate_limited"
        
        # Check attack score
        if analysis["total_score"] > 0.7:
            self._apply_mitigation(source_ip, analysis)
            return True, "attack_detected"
        
        return False, "allowed"
    
    def _check_rate_limit(self, source_ip, packet_info):
        """Check if source exceeds rate limits"""
        stats = self.traffic_stats[source_ip]
        
        # Check packet rate
        if stats["packet_count"] > self.rate_limits["packets_per_second"]:
            self.rate_limited_sources[source_ip] += 1
            return True
        
        # Check byte rate
        if stats["byte_count"] > self.rate_limits["bytes_per_second"]:
            self.rate_limited_sources[source_ip] += 1
            return True
        
        return False
    
    def _apply_mitigation(self, source_ip, analysis):
        """Apply DDoS mitigation strategies"""
        total_score = analysis["total_score"]
        
        if total_score > 0.9:
            # High threat - block source
            self.blocked_sources.add(source_ip)
            self._log_mitigation("source_blocked", source_ip, analysis)
            
        elif total_score > 0.7:
            # Medium threat - rate limit
            self.rate_limited_sources[source_ip] = int(total_score * 10)
            self._log_mitigation("rate_limited", source_ip, analysis)
        
        self.mitigation_active = True
    
    def _log_mitigation(self, action, source_ip, analysis):
        """Log mitigation actions"""
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "source_ip": source_ip,
            "analysis": analysis
        }
        
        try:
            with open('/app/results/logs/ddos_mitigation.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            logger.debug(f"Could not write mitigation log: {e}")
    
    def get_protection_status(self):
        """Get current protection status"""
        recent_attacks = [
            indicator for indicator in self.attack_indicators
            if time.time() - indicator["timestamp"] < self.detection_window
        ]
        
        return {
            "mitigation_active": self.mitigation_active,
            "blocked_sources": len(self.blocked_sources),
            "rate_limited_sources": len(self.rate_limited_sources),
            "recent_attacks": len(recent_attacks),
            "detection_thresholds": self.detection_thresholds,
            "rate_limits": self.rate_limits,
            "traffic_sources": len(self.traffic_stats)
        }
    
    def reset_mitigation(self):
        """Reset mitigation state"""
        self.blocked_sources.clear()
        self.rate_limited_sources.clear()
        self.mitigation_active = False
        logger.info("DDoS mitigation state reset")

class AdaptiveDDoSProtection(DDoSProtection):
    """Adaptive DDoS protection with machine learning"""
    
    def __init__(self):
        super().__init__()
        self.baseline_traffic = {}
        self.anomaly_detector = None
        self.learning_enabled = True
        
    def learn_baseline(self, packet_info):
        """Learn normal traffic patterns"""
        if not self.learning_enabled:
            return
        
        source_ip = packet_info.get("source_ip", "unknown")
        
        if source_ip not in self.baseline_traffic:
            self.baseline_traffic[source_ip] = {
                "packet_sizes": [],
                "inter_arrival_times": [],
                "protocols": defaultdict(int),
                "last_packet_time": time.time()
            }
        
        baseline = self.baseline_traffic[source_ip]
        current_time = time.time()
        
        # Record packet characteristics
        baseline["packet_sizes"].append(packet_info.get("size", 0))
        baseline["inter_arrival_times"].append(
            current_time - baseline["last_packet_time"]
        )
        baseline["protocols"][packet_info.get("protocol", "TCP")] += 1
        baseline["last_packet_time"] = current_time
        
        # Keep sliding window
        if len(baseline["packet_sizes"]) > 1000:
            baseline["packet_sizes"] = baseline["packet_sizes"][-500:]
            baseline["inter_arrival_times"] = baseline["inter_arrival_times"][-500:]
    
    def detect_baseline_deviation(self, packet_info):
        """Detect deviations from learned baseline"""
        source_ip = packet_info.get("source_ip", "unknown")
        
        if source_ip not in self.baseline_traffic:
            return 0.0  # No baseline yet
        
        baseline = self.baseline_traffic[source_ip]
        
        if len(baseline["packet_sizes"]) < 50:
            return 0.0  # Insufficient data
        
        # Calculate deviations
        packet_size = packet_info.get("size", 0)
        protocol = packet_info.get("protocol", "TCP")
        
        # Size deviation
        avg_size = sum(baseline["packet_sizes"]) / len(baseline["packet_sizes"])
        size_deviation = abs(packet_size - avg_size) / max(avg_size, 1)
        
        # Protocol deviation
        total_packets = sum(baseline["protocols"].values())
        expected_protocol_ratio = baseline["protocols"][protocol] / total_packets
        protocol_deviation = 1.0 - expected_protocol_ratio
        
        # Combine deviations
        total_deviation = min(1.0, (size_deviation + protocol_deviation) / 2)
        
        return total_deviation

# Example usage for testing
if __name__ == "__main__":
    # Create DDoS simulator and protection
    simulator = DDoSSimulator()
    protection = AdaptiveDDoSProtection()
    
    # Start attack simulation
    print("Starting DDoS attack simulation...")
    attack_result = simulator.start_attack("volumetric")
    print(f"Attack started: {attack_result}")
    
    # Simulate traffic analysis
    time.sleep(2)
    
    # Generate some test packets
    test_packets = simulator.generate_attack_traffic("volumetric")
    
    blocked_count = 0
    for packet in test_packets[:100]:  # Test first 100 packets
        should_block, reason = protection.should_block_packet(packet)
        if should_block:
            blocked_count += 1
    
    print(f"Blocked {blocked_count} out of 100 attack packets")
    
    # Get protection status
    status = protection.get_protection_status()
    print(f"Protection status: {status}")
    
    # Stop attack
    stop_result = simulator.stop_attack()
    print(f"Attack stopped: {stop_result}")