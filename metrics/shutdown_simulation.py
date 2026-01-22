#!/usr/bin/env python3
"""
CE-CMS Simulation Shutdown Script - COMPLETE
Monitors attack completion and triggers graceful shutdown
"""

import time
import requests
import json
import os
import sys
import logging
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def check_attack_completion():
    """Check if attack simulation has completed"""
    try:
        if os.path.exists('/app/results/logs/attack_summary.json'):
            with open('/app/results/logs/attack_summary.json', 'r') as f:
                summary = json.load(f)
            
            results = summary.get('attack_results', {})
            
            required_phases = ['baseline', 'chaperone', 'ddos', 'identity_spoofing', 'coordinated']
            completed_phases = [phase for phase in required_phases if phase in results]
            
            completion_percentage = (len(completed_phases) / len(required_phases)) * 100
            
            logger.info(f"Attack simulation progress: {completion_percentage:.1f}% ({len(completed_phases)}/{len(required_phases)} phases)")
            
            if len(completed_phases) >= len(required_phases):
                logger.info("All attack phases completed!")
                return True, summary
        
        return False, None
        
    except Exception as e:
        logger.error(f"Error checking attack completion: {e}")
        return False, None

def stop_sensor_simulation():
    """Stop the sensor simulation on device layer"""
    try:
        device_url = os.getenv('DEVICE_URL', 'http://device:5000')
        response = requests.post(f"{device_url}/stop_simulation", timeout=5)
        if response.status_code == 200:
            logger.info("✓ Sensor simulation stopped")
            return True
    except Exception as e:
        logger.warning(f"Could not stop sensor simulation: {e}")
    return False

def export_final_metrics():
    """Export final metrics from metrics service"""
    try:
        metrics_url = os.getenv('METRICS_URL', 'http://metrics:8000')
        response = requests.post(f"{metrics_url}/export_metrics", timeout=10)
        if response.status_code == 200:
            logger.info("✓ Final metrics exported")
            return True
    except Exception as e:
        logger.warning(f"Could not export final metrics: {e}")
    return False

def generate_final_report():
    """Trigger final report generation"""
    try:
        logger.info("Generating final report...")
        result = subprocess.run(
            ['python', '/app/summary_report.py'],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            logger.info("✓ Final report generated successfully")
            if result.stdout:
                logger.info(result.stdout)
            return True
        else:
            logger.error(f"✗ Report generation failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("Report generation timed out")
        return False
    except Exception as e:
        logger.error(f"Error generating final report: {e}")
        return False

def main():
    """Main shutdown coordinator"""
    logger.info("="*60)
    logger.info("CE-CMS SHUTDOWN MONITOR STARTED")
    logger.info("="*60)
    logger.info("Waiting for attack simulation to complete...")
    
    max_wait_time = 600  # 10 minutes maximum
    check_interval = 10  # Check every 10 seconds
    elapsed_time = 0
    
    while elapsed_time < max_wait_time:
        completed, summary = check_attack_completion()
        
        if completed:
            logger.info("")
            logger.info("="*60)
            logger.info("ATTACK SIMULATION COMPLETED - INITIATING SHUTDOWN")
            logger.info("="*60)
            
            # Wait for final data collection
            logger.info("Waiting 30 seconds for final data collection...")
            time.sleep(30)
            
            # Stop sensor simulation
            logger.info("Stopping sensor simulation...")
            stop_sensor_simulation()
            
            # Export metrics
            logger.info("Exporting final metrics...")
            export_final_metrics()
            
            # Wait a bit more for logs to flush
            logger.info("Waiting for logs to flush...")
            time.sleep(5)
            
            # Generate final report
            logger.info("Generating final report...")
            report_success = generate_final_report()
            
            # Summary
            logger.info("")
            logger.info("="*60)
            logger.info("SIMULATION COMPLETE - SUMMARY")
            logger.info("="*60)
            
            if summary:
                stats = summary.get('overall_statistics', {})
                logger.info(f"Total attack scenarios: {stats.get('total_attack_scenarios', 0)}")
                logger.info(f"Attacks executed: {', '.join(stats.get('attacks_executed', []))}")
                logger.info(f"Total simulation time: {stats.get('total_simulation_time', 0):.1f}s")
            
            logger.info("")
            logger.info("Results available in:")
            logger.info("  - results/logs/attack_summary.json")
            logger.info("  - results/logs/attacks.log")
            logger.info("  - results/reports/executive_summary.txt")
            logger.info("  - results/reports/attack_mitigation_rates.png")
            logger.info("="*60)
            
            if report_success:
                logger.info("✓ All shutdown tasks completed successfully")
            else:
                logger.warning("✗ Some shutdown tasks had issues")
            
            # Signal completion
            try:
                with open('/app/results/.simulation_complete', 'w') as f:
                    f.write(f"Completed: {time.time()}\n")
                    f.write(f"Report Generated: {report_success}\n")
            except:
                pass
            
            logger.info("="*60)
            logger.info("You can now safely stop the containers")
            logger.info("="*60)
            
            return 0
        
        time.sleep(check_interval)
        elapsed_time += check_interval
        
        if elapsed_time % 60 == 0:
            logger.info(f"Still waiting... ({elapsed_time}s elapsed)")
    
    logger.warning("")
    logger.warning("="*60)
    logger.warning("MAXIMUM WAIT TIME EXCEEDED")
    logger.warning("="*60)
    logger.warning("Simulation may be incomplete - forcing shutdown")
    
    # Still try to generate report with partial data
    logger.info("Attempting to generate report with partial data...")
    generate_final_report()
    
    return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.info("Shutdown monitor interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error in shutdown monitor: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)