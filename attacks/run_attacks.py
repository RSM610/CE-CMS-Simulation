#!/usr/bin/env python3
"""
CE-CMS Attack Orchestrator - FIXED VERSION
Coordinates all attack simulations for comprehensive testing
"""

import json
import time
import logging
import os
import threading
from datetime import datetime, timezone

# Import attack modules
from chaperone_attack import ChaperoneAttacker
from identity_spoof import IdentitySpoofingAttacker  
from ddos_flood import DDoSFlooder

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackOrchestrator:
    """Orchestrates coordinated attack simulations"""
    
    def __init__(self):
        # Get target URLs from environment
        self.target_urls = {
            'device': os.getenv('DEVICE_URL', 'http://device:5000'),
            'fog': os.getenv('FOG_URL', 'http://fog:6000'),
            'cloud': os.getenv('CLOUD_URL', 'http://cloud:7000')
        }
        
        # Initialize attackers
        self.chaperone_attacker = ChaperoneAttacker(self.target_urls['device'])
        self.identity_spoofer = IdentitySpoofingAttacker(self.target_urls)
        self.ddos_flooder = DDoSFlooder(self.target_urls)
        
        # Attack orchestration
        self.attack_scenarios = []
        self.attack_results = {}
        
        # Load attack configuration
        try:
            with open('/app/config/env.json', 'r') as f:
                self.config = json.load(f).get('attacks', {})
        except:
            self.config = {
                "chaperone": {"enabled": True, "intensity": "medium"},
                "ddos": {"enabled": True, "packet_rate": 5000},
                "identity_spoofing": {"enabled": True}
            }
    
    def run_baseline_collection(self, duration=30):
        """Collect baseline metrics before attacks"""
        logger.info(f"Collecting baseline metrics for {duration} seconds...")
        
        baseline_start = time.time()
        time.sleep(duration)
        
        baseline_metrics = {
            "duration": duration,
            "start_time": datetime.now(timezone.utc).isoformat(),
            "end_time": datetime.now(timezone.utc).isoformat(),
            "baseline_established": True
        }
        
        self.attack_results['baseline'] = baseline_metrics
        logger.info("Baseline metrics collection completed")
    
    def execute_chaperone_attacks(self):
        """Execute chaperone attack scenarios"""
        if not self.config.get('chaperone', {}).get('enabled', True):
            logger.info("Chaperone attacks disabled in configuration")
            return
        
        logger.info("Starting chaperone attack scenarios...")
        
        chaperone_results = []
        attack_types = ["boundary_shrinking", "boundary_shifting", "false_floor"]
        
        for attack_type in attack_types:
            logger.info(f"Executing {attack_type} attack...")
            
            start_time = time.time()
            result = self.chaperone_attacker.launch_chaperone_attack(
                attack_type=attack_type, 
                duration=20
            )
            
            time.sleep(25)
            stats = self.chaperone_attacker.get_attack_stats()
            
            attack_result = {
                "attack_type": attack_type,
                "launch_result": result,
                "final_stats": stats,
                "duration": time.time() - start_time
            }
            
            chaperone_results.append(attack_result)
            logger.info(f"Completed {attack_type} attack")
            time.sleep(10)
        
        self.attack_results['chaperone'] = chaperone_results
        logger.info("All chaperone attacks completed")
    
    def execute_ddos_attacks(self):
        """Execute DDoS attack scenarios"""
        if not self.config.get('ddos', {}).get('enabled', True):
            logger.info("DDoS attacks disabled in configuration")
            return
        
        logger.info("Starting DDoS attack scenarios...")
        
        ddos_results = []
        
        # Volumetric attack
        logger.info("Executing volumetric DDoS attack...")
        start_time = time.time()
        
        volumetric_result = self.ddos_flooder.launch_volumetric_attack(
            duration=30, 
            intensity="high"
        )
        
        time.sleep(35)
        volumetric_stats = self.ddos_flooder.get_attack_stats()
        
        ddos_results.append({
            "attack_type": "volumetric",
            "launch_result": volumetric_result,
            "final_stats": volumetric_stats,
            "duration": time.time() - start_time
        })
        
        time.sleep(15)
        
        # Application layer attack
        logger.info("Executing application layer DDoS attack...")
        start_time = time.time()
        
        app_layer_result = self.ddos_flooder.launch_application_layer_attack(duration=25)
        
        time.sleep(30)
        app_layer_stats = self.ddos_flooder.get_attack_stats()
        
        ddos_results.append({
            "attack_type": "application_layer",
            "launch_result": app_layer_result,
            "final_stats": app_layer_stats,
            "duration": time.time() - start_time
        })
        
        self.attack_results['ddos'] = ddos_results
        logger.info("All DDoS attacks completed")
    
    def execute_identity_spoofing_attacks(self):
        """Execute identity spoofing attack scenarios"""
        if not self.config.get('identity_spoofing', {}).get('enabled', True):
            logger.info("Identity spoofing attacks disabled in configuration")
            return
        
        logger.info("Starting identity spoofing attack scenarios...")
        
        start_time = time.time()
        spoof_result = self.identity_spoofer.launch_spoofing_attack(duration=40)
        
        time.sleep(45)
        spoof_stats = self.identity_spoofer.get_attack_stats()
        
        identity_results = {
            "attack_type": "identity_spoofing",
            "launch_result": spoof_result,
            "final_stats": spoof_stats,
            "duration": time.time() - start_time
        }
        
        self.attack_results['identity_spoofing'] = identity_results
        logger.info("Identity spoofing attacks completed")
    
    def execute_coordinated_attack(self):
        """Execute coordinated multi-vector attack"""
        logger.info("Starting coordinated multi-vector attack...")
        
        threads = []
        
        def chaperone_thread():
            self.chaperone_attacker.launch_chaperone_attack("boundary_removal", 30)
        
        def ddos_thread():
            self.ddos_flooder.launch_volumetric_attack(30, "extreme")
        
        def identity_thread():
            self.identity_spoofer.launch_spoofing_attack(30)
        
        threads.append(threading.Thread(target=chaperone_thread))
        threads.append(threading.Thread(target=ddos_thread))
        threads.append(threading.Thread(target=identity_thread))
        
        start_time = time.time()
        
        for thread in threads:
            thread.start()
        
        time.sleep(35)
        
        coordinated_results = {
            "attack_type": "coordinated_multi_vector",
            "chaperone_stats": self.chaperone_attacker.get_attack_stats(),
            "ddos_stats": self.ddos_flooder.get_attack_stats(),
            "identity_stats": self.identity_spoofer.get_attack_stats(),
            "duration": time.time() - start_time,
            "simultaneous_attacks": 3
        }
        
        self.attack_results['coordinated'] = coordinated_results
        logger.info("Coordinated attack completed")
    
    def generate_attack_summary(self):
        """Generate comprehensive attack summary"""
        summary = {
            "simulation_info": {
                "start_time": datetime.now(timezone.utc).isoformat(),
                "target_urls": self.target_urls,
                "configuration": self.config
            },
            "attack_results": self.attack_results,
            "overall_statistics": {
                "total_attack_scenarios": len(self.attack_results),
                "attacks_executed": [k for k in self.attack_results.keys() if k != 'baseline'],
                "total_simulation_time": sum(
                    result.get('duration', 0) 
                    for result in self.attack_results.values()
                    if isinstance(result, dict) and 'duration' in result
                )
            }
        }
        
        # Save to results file
        try:
            with open('/app/results/logs/attack_summary.json', 'w') as f:
                json.dump(summary, f, indent=2)
            logger.info("Attack summary saved to /app/results/logs/attack_summary.json")
        except Exception as e:
            logger.error(f"Could not save attack summary: {e}")
        
        return summary
    
    def run_full_attack_simulation(self):
        """Run complete attack simulation"""
        logger.info("="*60)
        logger.info("CE-CMS ATTACK SIMULATION STARTING")
        logger.info("="*60)
        
        simulation_start = time.time()
        
        try:
            # Phase 1: Baseline collection
            self.run_baseline_collection(30)
            
            # Phase 2: Individual attack scenarios
            self.execute_chaperone_attacks()
            
            logger.info("System recovery pause...")
            time.sleep(20)
            
            self.execute_ddos_attacks()
            
            logger.info("System recovery pause...")
            time.sleep(20)
            
            self.execute_identity_spoofing_attacks()
            
            # Phase 3: Coordinated attack
            logger.info("System recovery before coordinated attack...")
            time.sleep(30)
            
            self.execute_coordinated_attack()
            
            # Phase 4: Generate summary
            summary = self.generate_attack_summary()
            
            total_time = time.time() - simulation_start
            
            logger.info("="*60)
            logger.info("CE-CMS ATTACK SIMULATION COMPLETED")
            logger.info(f"Total simulation time: {total_time:.2f} seconds")
            logger.info(f"Attacks executed: {len(summary['attack_results'])}")
            logger.info("="*60)
            
            return summary
            
        except Exception as e:
            logger.error(f"Attack simulation error: {e}")
            return {"error": str(e), "partial_results": self.attack_results}

def main():
    """Main attack simulation entry point"""
    logger.info("Initializing CE-CMS Attack Simulation...")
    
    # Wait for system to be ready
    logger.info("Waiting for target systems to be ready...")
    time.sleep(30)
    
    # Create orchestrator and run simulation
    orchestrator = AttackOrchestrator()
    results = orchestrator.run_full_attack_simulation()
    
    # Print final summary
    print("\n" + "="*60)
    print("ATTACK SIMULATION SUMMARY")
    print("="*60)
    
    if 'error' not in results:
        for attack_type, result in results.get('attack_results', {}).items():
            if attack_type == 'baseline':
                print(f"✓ Baseline Collection: {result.get('duration', 0):.1f}s")
            elif isinstance(result, list):
                print(f"✓ {attack_type.title()} Attacks: {len(result)} scenarios")
            else:
                print(f"✓ {attack_type.title()} Attack: {result.get('duration', 0):.1f}s")
        
        total_time = results.get('overall_statistics', {}).get('total_simulation_time', 0)
        print(f"\nTotal Simulation Time: {total_time:.1f} seconds")
    else:
        print(f"✗ Simulation failed: {results['error']}")
    
    print("="*60)

if __name__ == "__main__":
    main()