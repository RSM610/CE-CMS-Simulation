#!/usr/bin/env python3
"""
CE-CMS Chaperone Attack Simulation
Simulates VR boundary manipulation attacks that can cause physical harm
"""

import json
import time
import random
import requests
import threading
import logging
from datetime import datetime, timezone
import numpy as np

logger = logging.getLogger(__name__)

class ChaperoneAttacker:
    """Simulates chaperone boundary manipulation attacks"""
    
    def __init__(self, target_device_url):
        self.target_url = target_device_url
        self.attack_active = False
        self.attack_stats = {
            "attacks_launched": 0,
            "malicious_packets_sent": 0,
            "boundary_manipulations": 0,
            "collision_risks_created": 0
        }
        
        # Attack parameters
        self.attack_types = {
            "boundary_shrinking": {
                "description": "Shrink VR boundaries to cause collisions",
                "boundary_scale": 0.3,  # 30% of original size
                "danger_level": "high"
            },
            "boundary_shifting": {
                "description": "Shift boundaries to unsafe areas",
                "boundary_offset": 2.0,  # 2 meters offset
                "danger_level": "medium"
            },
            "boundary_removal": {
                "description": "Remove safety boundaries entirely",
                "boundary_scale": 0.0,  # No boundaries
                "danger_level": "critical"
            },
            "false_floor": {
                "description": "Create false floor height perception",
                "floor_offset": 0.5,  # 50cm height difference
                "danger_level": "high"
            }
        }
    
    def generate_malicious_boundary_data(self, attack_type="boundary_shrinking"):
        """Generate malicious boundary manipulation data"""
        attack_config = self.attack_types.get(attack_type, self.attack_types["boundary_shrinking"])
        
        # Base legitimate boundary data
        boundary_data = {
            "boundary_type": "rectangular",
            "corners": [
                {"x": -2.0, "y": 0.0, "z": -1.5},  # Normal 4x3 meter play area
                {"x": 2.0, "y": 0.0, "z": -1.5},
                {"x": 2.0, "y": 0.0, "z": 1.5},
                {"x": -2.0, "y": 0.0, "z": 1.5}
            ],
            "floor_height": 0.0,
            "ceiling_height": 3.0,
            "safety_margin": 0.5
        }
        
        # Apply malicious modifications
        if attack_type == "boundary_shrinking":
            scale = attack_config["boundary_scale"]
            for corner in boundary_data["corners"]:
                corner["x"] *= scale
                corner["z"] *= scale
                
        elif attack_type == "boundary_shifting":
            offset = attack_config["boundary_offset"]
            for corner in boundary_data["corners"]:
                corner["x"] += offset  # Shift towards wall/obstacle
                
        elif attack_type == "boundary_removal":
            boundary_data["corners"] = []  # Remove all boundaries
            boundary_data["safety_margin"] = 0.0
            
        elif attack_type == "false_floor":
            boundary_data["floor_height"] = attack_config["floor_offset"]
            
        return {
            "packet_id": f"chaperone_attack_{int(time.time() * 1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": attack_type,
            "malicious": True,
            "boundary_data": boundary_data,
            "device_info": {
                "device_id": "malicious_controller_001",
                "device_type": "boundary_controller",
                "spoofed_authority": True
            }
        }
    
    def inject_spatial_confusion(self):
        """Inject spatial disorientation data"""
        confusion_packet = {
            "packet_id": f"spatial_confusion_{int(time.time() * 1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "spatial_confusion",
            "malicious": True,
            "sensors": [{
                "sensor_type": "head_tracking",
                "data": {
                    "position": {
                        "x": random.uniform(-10, 10),  # Impossible position
                        "y": random.uniform(-5, 5),
                        "z": random.uniform(-10, 10)
                    },
                    "rotation": {
                        "pitch": random.uniform(-180, 180),  # Extreme rotation
                        "yaw": random.uniform(-360, 360),
                        "roll": random.uniform(-180, 180)
                    }
                }
            }],
            "device_info": {
                "device_id": "malicious_tracker_002",
                "device_type": "head_tracker",
                "spoofed_sensor": True
            }
        }
        
        return confusion_packet
    
    def create_collision_risk_scenario(self):
        """Create scenario that increases collision risk"""
        # Simulate moving the virtual world while user is moving
        collision_packet = {
            "packet_id": f"collision_risk_{int(time.time() * 1000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "attack_type": "collision_induction",
            "malicious": True,
            "world_state": {
                "world_offset": {
                    "x": random.uniform(-2, 2),  # Sudden world movement
                    "y": 0,
                    "z": random.uniform(-2, 2)
                },
                "world_rotation": random.uniform(-45, 45),  # Disorienting rotation
                "gravity_direction": {
                    "x": random.uniform(-1, 1),  # Wrong gravity direction
                    "y": random.uniform(-1, 1),
                    "z": random.uniform(-1, 1)
                }
            },
            "device_info": {
                "device_id": "malicious_world_controller_003",
                "device_type": "world_state_manager",
                "spoofed_authority": True
            }
        }
        
        return collision_packet
    
    def launch_chaperone_attack(self, attack_type="boundary_shrinking", duration=30):
        """Launch a chaperone attack"""
        if self.attack_active:
            return {"status": "attack_already_active"}
        
        self.attack_active = True
        self.attack_stats["attacks_launched"] += 1
        
        attack_config = self.attack_types[attack_type]
        
        logger.warning(f"Launching chaperone attack: {attack_type}")
        logger.warning(f"Description: {attack_config['description']}")
        logger.warning(f"Danger Level: {attack_config['danger_level']}")
        
        def attack_thread():
            start_time = time.time()
            
            while time.time() - start_time < duration and self.attack_active:
                try:
                    # Send malicious boundary data
                    boundary_packet = self.generate_malicious_boundary_data(attack_type)
                    self._send_attack_packet(boundary_packet)
                    self.attack_stats["boundary_manipulations"] += 1
                    
                    # Add spatial confusion
                    if random.random() < 0.3:  # 30% chance
                        confusion_packet = self.inject_spatial_confusion()
                        self._send_attack_packet(confusion_packet)
                    
                    # Create collision risks
                    if random.random() < 0.2:  # 20% chance
                        collision_packet = self.create_collision_risk_scenario()
                        self._send_attack_packet(collision_packet)
                        self.attack_stats["collision_risks_created"] += 1
                    
                    time.sleep(random.uniform(1, 3))  # Random intervals
                    
                except Exception as e:
                    logger.error(f"Attack packet send error: {e}")
                    time.sleep(1)
            
            self.attack_active = False
            logger.info(f"Chaperone attack {attack_type} completed")
        
        threading.Thread(target=attack_thread, daemon=True).start()
        
        return {
            "status": "attack_launched",
            "attack_type": attack_type,
            "duration": duration,
            "danger_level": attack_config["danger_level"]
        }
    
    def _send_attack_packet(self, packet):
        """Send malicious packet to target device"""
        try:
            # Try to send to device layer
            response = requests.post(
                f"{self.target_url}/inject_anomaly",
                json={
                    "type": "chaperone",
                    "intensity": "high",
                    "packet": packet
                },
                timeout=5
            )
            
            self.attack_stats["malicious_packets_sent"] += 1
            
            if response.status_code != 200:
                logger.debug(f"Attack packet rejected: {response.status_code}")
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Could not send attack packet: {e}")
    
    def stop_attack(self):
        """Stop current attack"""
        if not self.attack_active:
            return {"status": "no_active_attack"}
        
        self.attack_active = False
        return {"status": "attack_stopped"}
    
    def get_attack_stats(self):
        """Get attack statistics"""
        return {
            "attack_active": self.attack_active,
            "statistics": self.attack_stats,
            "available_attacks": list(self.attack_types.keys())
        }

class ChaperoneDefenseValidator:
    """Validates chaperone defense mechanisms"""
    
    def __init__(self, device_url):
        self.device_url = device_url
        self.test_results = []
    
    def test_boundary_validation(self):
        """Test if device validates boundary data"""
        # Test with obviously invalid boundaries
        invalid_boundaries = [
            {"corners": []},  # No boundaries
            {"corners": [{"x": 0, "y": 0, "z": 0}]},  # Single point
            {"corners": [{"x": 100, "y": 0, "z": 100}] * 4},  # Too large
            {"floor_height": -10},  # Underground
            {"ceiling_height": 0.5}  # Too low
        ]
        
        results = []
        
        for i, invalid_boundary in enumerate(invalid_boundaries):
            try:
                packet = {
                    "test_id": f"boundary_validation_{i}",
                    "boundary_data": invalid_boundary,
                    "expected_result": "rejection"
                }
                
                response = requests.post(
                    f"{self.device_url}/inject_anomaly",
                    json={"type": "boundary", "packet": packet},
                    timeout=5
                )
                
                results.append({
                    "test_case": f"invalid_boundary_{i}",
                    "packet_sent": True,
                    "response_code": response.status_code,
                    "defense_active": response.status_code != 200
                })
                
            except Exception as e:
                results.append({
                    "test_case": f"invalid_boundary_{i}",
                    "packet_sent": False,
                    "error": str(e)
                })
        
        return {
            "test_type": "boundary_validation",
            "total_tests": len(invalid_boundaries),
            "results": results,
            "defense_effectiveness": len([r for r in results if r.get("defense_active", False)]) / len(results)
        }
    
    def test_spatial_consistency(self):
        """Test spatial consistency validation"""
        # Test with spatially impossible data
        impossible_scenarios = [
            {"position": {"x": 1000, "y": 1000, "z": 1000}},  # Impossible position
            {"rotation": {"pitch": 720, "yaw": 720, "roll": 720}},  # Impossible rotation
            {"velocity": {"x": 100, "y": 100, "z": 100}},  # Impossible speed
        ]
        
        results = []
        
        for i, scenario in enumerate(impossible_scenarios):
            try:
                packet = {
                    "test_id": f"spatial_consistency_{i}",
                    "spatial_data": scenario,
                    "expected_result": "rejection"
                }
                
                response = requests.post(
                    f"{self.device_url}/inject_anomaly",
                    json={"type": "spatial", "packet": packet},
                    timeout=5
                )
                
                results.append({
                    "test_case": f"impossible_scenario_{i}",
                    "packet_sent": True,
                    "response_code": response.status_code,
                    "defense_active": response.status_code != 200
                })
                
            except Exception as e:
                results.append({
                    "test_case": f"impossible_scenario_{i}",
                    "packet_sent": False,
                    "error": str(e)
                })
        
        return {
            "test_type": "spatial_consistency",
            "total_tests": len(impossible_scenarios),
            "results": results,
            "defense_effectiveness": len([r for r in results if r.get("defense_active", False)]) / len(results)
        }

# Example usage for testing
if __name__ == "__main__":
    import os
    
    # Get target URLs from environment
    device_url = os.getenv('DEVICE_URL', 'http://localhost:5000')
    
    # Create attacker
    attacker = ChaperoneAttacker(device_url)
    
    print("Starting chaperone attack simulation...")
    
    # Launch different attack types
    attack_types = ["boundary_shrinking", "boundary_shifting", "false_floor"]
    
    for attack_type in attack_types:
        print(f"\nLaunching {attack_type} attack...")
        result = attacker.launch_chaperone_attack(attack_type, duration=10)
        print(f"Attack result: {result}")
        
        # Wait for attack to complete
        time.sleep(12)
        
        # Get stats
        stats = attacker.get_attack_stats()
        print(f"Attack stats: {stats}")
    
    # Test defenses
    print("\nTesting chaperone defenses...")
    validator = ChaperoneDefenseValidator(device_url)
    
    boundary_test = validator.test_boundary_validation()
    print(f"Boundary validation test: {boundary_test}")
    
    spatial_test = validator.test_spatial_consistency()
    print(f"Spatial consistency test: {spatial_test}")
    
    print("Chaperone attack simulation completed.")