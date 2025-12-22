#!/usr/bin/env python3
"""
CE-CMS Metrics Logger
Centralized logging and metrics collection for the simulation
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
import pandas as pd

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

class MetricsCollector:
    """Collects and aggregates metrics from all system layers"""
    
    def __init__(self):
        # System URLs
        self.system_urls = {
            'device': os.getenv('DEVICE_URL', 'http://device:5000'),
            'fog': os.getenv('FOG_URL', 'http://fog:6000'),
            'cloud': os.getenv('CLOUD_URL', 'http://cloud:7000')
        }
        
        # Metrics storage
        self.metrics_history = defaultdict(deque)
        self.performance_data = []
        self.security_events = []
        self.attack_detections = []
        
        # Collection parameters
        self.collection_interval = 5.0  # seconds
        self.is_collecting = False
        
        # Statistics
        self.collection_stats = {
            "total_collections": 0,
            "successful_collections": 0,
            "failed_collections": 0,
            "start_time": datetime.now(timezone.utc).isoformat()
        }
    
    def collect_device_metrics(self):
        """Collect metrics from device layer"""
        try:
            # Get ESA status
            esa_response = requests.get(f"{self.system_urls['device']}/esa_status", timeout=5)
            if esa_response.status_code == 200:
                esa_data = esa_response.json()
                
                # Get sensor data
                sensor_response = requests.get(f"{self.system_urls['device']}/sensor_data", timeout=5)
                sensor_data = sensor_response.json() if sensor_response.status_code == 200 else {}
                
                device_metrics = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "layer": "device",
                    "esa_status": esa_data,
                    "sensor_info": sensor_data,
                    "collection_success": True
                }
                
                self.metrics_history['device'].append(device_metrics)
                return device_metrics
            
        except Exception as e:
            logger.debug(f"Device metrics collection error: {e}")
            return {"layer": "device", "collection_success": False, "error": str(e)}
    
    def collect_fog_metrics(self):
        """Collect metrics from fog layer"""
        try:
            # Get network status
            network_response = requests.get(f"{self.system_urls['fog']}/network_status", timeout=5)
            if network_response.status_code == 200:
                network_data = network_response.json()
                
                # Get traffic stats
                traffic_response = requests.get(f"{self.system_urls['fog']}/traffic_stats", timeout=5)
                traffic_data = traffic_response.json() if traffic_response.status_code == 200 else {}
                
                fog_metrics = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "layer": "fog",
                    "network_status": network_data,
                    "traffic_stats": traffic_data,
                    "collection_success": True
                }
                
                self.metrics_history['fog'].append(fog_metrics)
                return fog_metrics
            
        except Exception as e:
            logger.debug(f"Fog metrics collection error: {e}")
            return {"layer": "fog", "collection_success": False, "error": str(e)}
    
    def collect_cloud_metrics(self):
        """Collect metrics from cloud layer"""
        try:
            # Get cloud status
            status_response = requests.get(f"{self.system_urls['cloud']}/cloud_status", timeout=5)
            if status_response.status_code == 200:
                status_data = status_response.json()
                
                # Get threat intelligence
                threat_response = requests.get(f"{self.system_urls['cloud']}/threat_intelligence", timeout=5)
                threat_data = threat_response.json() if threat_response.status_code == 200 else {}
                
                cloud_metrics = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "layer": "cloud",
                    "status": status_data,
                    "threat_intelligence": threat_data,
                    "collection_success": True
                }
                
                self.metrics_history['cloud'].append(cloud_metrics)
                return cloud_metrics
            
        except Exception as e:
            logger.debug(f"Cloud metrics collection error: {e}")
            return {"layer": "cloud", "collection_success": False, "error": str(e)}
    
    def collect_all_metrics(self):
        """Collect metrics from all layers"""
        collection_start = time.time()
        
        # Collect from all layers
        device_metrics = self.collect_device_metrics()
        fog_metrics = self.collect_fog_metrics()
        cloud_metrics = self.collect_cloud_metrics()
        
        # Aggregate collection results
        collection_result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "collection_time_ms": round((time.time() - collection_start) * 1000, 2),
            "device_metrics": device_metrics,
            "fog_metrics": fog_metrics,
            "cloud_metrics": cloud_metrics
        }
        
        # Update statistics
        self.collection_stats["total_collections"] += 1
        successful = sum(1 for m in [device_metrics, fog_metrics, cloud_metrics] 
                        if m.get("collection_success", False))
        
        if successful == 3:
            self.collection_stats["successful_collections"] += 1
        else:
            self.collection_stats["failed_collections"] += 1
        
        # Store aggregated metrics
        self.performance_data.append(collection_result)
        
        # Keep memory usage reasonable
        if len(self.performance_data) > 1000:
            self.performance_data = self.performance_data[-500:]
        
        for layer_history in self.metrics_history.values():
            if len(layer_history) > 1000:
                # Keep only recent entries
                while len(layer_history) > 500:
                    layer_history.popleft()
        
        return collection_result
    
    def start_continuous_collection(self):
        """Start continuous metrics collection"""
        if self.is_collecting:
            return {"status": "already_collecting"}
        
        self.is_collecting = True
        logger.info("Starting continuous metrics collection")
        
        def collection_loop():
            while self.is_collecting:
                try:
                    self.collect_all_metrics()
                    time.sleep(self.collection_interval)
                except Exception as e:
                    logger.error(f"Metrics collection error: {e}")
                    time.sleep(self.collection_interval)
        
        self.collection_thread = threading.Thread(target=collection_loop, daemon=True)
        self.collection_thread.start()
        
        return {"status": "collection_started"}
    
    def stop_continuous_collection(self):
        """Stop continuous metrics collection"""
        if not self.is_collecting:
            return {"status": "not_collecting"}
        
        self.is_collecting = False
        logger.info("Stopped continuous metrics collection")
        return {"status": "collection_stopped"}
    
    def get_metrics_summary(self):
        """Get summary of collected metrics"""
        current_time = time.time()
        
        # Calculate collection statistics
        recent_collections = [
            p for p in self.performance_data
            if (current_time - time.mktime(
                datetime.fromisoformat(p["timestamp"].replace('Z', '+00:00')).timetuple()
            )) < 3600  # Last hour
        ]
        
        return {
            "collection_active": self.is_collecting,
            "collection_interval": self.collection_interval,
            "total_data_points": len(self.performance_data),
            "recent_collections": len(recent_collections),
            "layer_metrics": {
                layer: len(history) for layer, history in self.metrics_history.items()
            },
            "collection_statistics": self.collection_stats,
            "average_collection_time": (
                sum(p.get("collection_time_ms", 0) for p in recent_collections) / 
                max(1, len(recent_collections))
            )
        }
    
    def export_metrics_to_csv(self):
        """Export metrics to CSV files"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Export performance data
            if self.performance_data:
                df_performance = pd.DataFrame(self.performance_data)
                performance_file = f"/app/results/metrics/performance_{timestamp}.csv"
                df_performance.to_csv(performance_file, index=False)
                logger.info(f"Exported performance metrics to {performance_file}")
            
            # Export layer-specific metrics
            for layer, history in self.metrics_history.items():
                if history:
                    df_layer = pd.DataFrame(list(history))
                    layer_file = f"/app/results/metrics/{layer}_metrics_{timestamp}.csv"
                    df_layer.to_csv(layer_file, index=False)
                    logger.info(f"Exported {layer} metrics to {layer_file}")
            
            return {"status": "export_successful", "timestamp": timestamp}
            
        except Exception as e:
            logger.error(f"Metrics export error: {e}")
            return {"status": "export_failed", "error": str(e)}

# Initialize metrics collector
metrics_collector = MetricsCollector()

# Flask routes
@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "metrics_logger",
        "collecting": metrics_collector.is_collecting,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route('/start_collection', methods=['POST'])
def start_collection():
    """Start metrics collection"""
    result = metrics_collector.start_continuous_collection()
    return jsonify(result)

@app.route('/stop_collection', methods=['POST'])
def stop_collection():
    """Stop metrics collection"""
    result = metrics_collector.stop_continuous_collection()
    return jsonify(result)

@app.route('/metrics_summary')
def get_metrics_summary():
    """Get metrics collection summary"""
    summary = metrics_collector.get_metrics_summary()
    return jsonify(summary)

@app.route('/latest_metrics')
def get_latest_metrics():
    """Get latest collected metrics"""
    if metrics_collector.performance_data:
        return jsonify(metrics_collector.performance_data[-1])
    else:
        return jsonify({"message": "No metrics available"}), 404

@app.route('/export_metrics', methods=['POST'])
def export_metrics():
    """Export metrics to CSV"""
    result = metrics_collector.export_metrics_to_csv()
    return jsonify(result)

@app.route('/metrics_history')
def get_metrics_history():
    """Get metrics history"""
    limit = request.args.get('limit', 100, type=int)
    layer = request.args.get('layer', 'all')
    
    if layer == 'all':
        history = metrics_collector.performance_data[-limit:]
    else:
        history = list(metrics_collector.metrics_history.get(layer, []))[-limit:]
    
    return jsonify({
        "layer": layer,
        "limit": limit,
        "count": len(history),
        "history": history
    })

if __name__ == '__main__':
    logger.info("Starting CE-CMS Metrics Logger")
    
    # Start metrics collection automatically
    metrics_collector.start_continuous_collection()
    
    # Start Flask server
    app.run(
        host='0.0.0.0',
        port=8000,
        debug=False,
        threaded=True
    )