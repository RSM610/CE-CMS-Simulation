#!/usr/bin/env python3
"""
CE-CMS Log Monitor
Real-time monitoring and analysis of simulation logs
"""

import os
import time
import json
import threading
import logging
from datetime import datetime, timezone
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import re
import requests
from flask import Flask, jsonify, request, render_template_string
import sqlite3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

class LogMonitor:
    """Real-time log monitoring and analysis"""
    
    def __init__(self):
        self.logs_dir = '/app/results/logs'
        self.db_path = '/app/results/metrics/log_analysis.db'
        
        # Monitoring state
        self.is_monitoring = False
        self.observer = None
        
        # Log patterns for different event types
        self.patterns = {
            'esa_event': re.compile(r'ESA_EVENT.*?(?P<event_type>\w+).*?severity:(?P<severity>\w+)', re.IGNORECASE),
            'ddos_detected': re.compile(r'DDoS.*?detected.*?from\s+(?P<source_ip>[\d.]+)', re.IGNORECASE),
            'threat_blocked': re.compile(r'threat.*?blocked.*?(?P<threat_id>\w+)', re.IGNORECASE),
            'lateral_movement': re.compile(r'lateral.*?movement.*?(?P<action>blocked|detected)', re.IGNORECASE),
            'identity_verification': re.compile(r'DID.*?verification.*?(?P<status>success|failed)', re.IGNORECASE),
            'attack_attempt': re.compile(r'attack.*?(?P<attack_type>\w+).*?from\s+(?P<source>[\w.:]+)', re.IGNORECASE),
            'performance_metric': re.compile(r'(?P<metric>\w+):\s*(?P<value>[\d.]+)(?P<unit>ms|%|MB)?', re.IGNORECASE)
        }
        
        # Real-time metrics
        self.metrics = {
            'events_per_minute': deque(maxlen=60),
            'threat_count': 0,
            'attack_count': 0,
            'blocked_count': 0,
            'performance_issues': 0,
            'layer_activity': defaultdict(int),
            'event_timeline': deque(maxlen=1000)
        }
        
        # Initialize database
        self.init_database()
        
        # Alert thresholds
        self.alert_thresholds = {
            'high_attack_rate': 10,  # attacks per minute
            'high_threat_count': 50,  # total threats
            'performance_degradation': 5  # performance issues per minute
        }
        
        self.alerts = deque(maxlen=100)
    
    def init_database(self):
        """Initialize SQLite database for log storage"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS log_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT,
                    message TEXT,
                    source_file TEXT,
                    metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    layer TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL,
                    unit TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    source_ip TEXT,
                    target TEXT,
                    action TEXT,
                    severity INTEGER,
                    details TEXT
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_layer ON log_events(layer)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_perf_timestamp ON performance_metrics(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_timestamp ON security_events(timestamp)')
            
            conn.commit()
            conn.close()
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
    
    def store_log_event(self, event_data):
        """Store log event in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO log_events 
                (timestamp, layer, event_type, severity, message, source_file, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_data.get('timestamp'),
                event_data.get('layer'),
                event_data.get('event_type'),
                event_data.get('severity'),
                event_data.get('message'),
                event_data.get('source_file'),
                json.dumps(event_data.get('metadata', {}))
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.debug(f"Database storage error: {e}")
    
    def parse_log_line(self, line, source_file):
        """Parse individual log line and extract relevant information"""
        if not line.strip():
            return None
        
        # Determine layer from source file
        layer = 'unknown'
        if 'device' in source_file:
            layer = 'device'
        elif 'fog' in source_file:
            layer = 'fog'
        elif 'cloud' in source_file:
            layer = 'cloud'
        elif 'attack' in source_file:
            layer = 'attack'
        elif 'metrics' in source_file:
            layer = 'metrics'
        
        # Extract timestamp (assuming standard format)
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', line)
        timestamp = timestamp_match.group(1) if timestamp_match else datetime.now(timezone.utc).isoformat()
        
        # Try to match against known patterns
        event_data = {
            'timestamp': timestamp,
            'layer': layer,
            'source_file': source_file,
            'message': line.strip(),
            'event_type': 'unknown',
            'metadata': {}
        }
        
        # Check for specific event patterns
        for pattern_name, pattern in self.patterns.items():
            match = pattern.search(line)
            if match:
                event_data['event_type'] = pattern_name
                event_data['metadata'].update(match.groupdict())
                
                # Extract severity if present
                if 'severity' in match.groupdict():
                    event_data['severity'] = match.groupdict()['severity']
                
                break
        
        # Update real-time metrics
        self.update_metrics(event_data)
        
        # Store in database
        self.store_log_event(event_data)
        
        return event_data
    
    def update_metrics(self, event_data):
        """Update real-time metrics based on log event"""
        current_time = time.time()
        
        # Update event timeline
        self.metrics['event_timeline'].append({
            'timestamp': current_time,
            'event': event_data
        })
        
        # Update layer activity
        self.metrics['layer_activity'][event_data['layer']] += 1
        
        # Update specific counters
        event_type = event_data['event_type']
        
        if 'threat' in event_type or 'attack' in event_type:
            if 'blocked' in event_data['message'].lower():
                self.metrics['blocked_count'] += 1
            else:
                self.metrics['threat_count'] += 1
        
        if 'attack' in event_type:
            self.metrics['attack_count'] += 1
        
        if 'performance' in event_type or 'timeout' in event_data['message'].lower():
            self.metrics['performance_issues'] += 1
        
        # Check for alerts
        self.check_alerts()
    
    def check_alerts(self):
        """Check for alert conditions"""
        current_time = time.time()
        
        # Count recent events (last minute)
        recent_events = [
            e for e in self.metrics['event_timeline']
            if current_time - e['timestamp'] < 60
        ]
        
        recent_attacks = sum(1 for e in recent_events 
                           if 'attack' in e['event']['event_type'])
        
        recent_performance_issues = sum(1 for e in recent_events 
                                      if 'performance' in e['event']['event_type'])
        
        # Generate alerts
        if recent_attacks > self.alert_thresholds['high_attack_rate']:
            self.generate_alert('HIGH_ATTACK_RATE', 
                              f"High attack rate detected: {recent_attacks} attacks in last minute")
        
        if self.metrics['threat_count'] > self.alert_thresholds['high_threat_count']:
            self.generate_alert('HIGH_THREAT_COUNT', 
                              f"High threat count: {self.metrics['threat_count']} total threats")
        
        if recent_performance_issues > self.alert_thresholds['performance_degradation']:
            self.generate_alert('PERFORMANCE_DEGRADATION', 
                              f"Performance issues detected: {recent_performance_issues} in last minute")
    
    def generate_alert(self, alert_type, message):
        """Generate alert"""
        alert = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': alert_type,
            'message': message,
            'severity': 'high' if 'HIGH' in alert_type else 'medium'
        }
        
        self.alerts.append(alert)
        logger.warning(f"ALERT: {alert_type} - {message}")
    
    def get_metrics_summary(self):
        """Get current metrics summary"""
        current_time = time.time()
        
        # Recent activity (last 5 minutes)
        recent_events = [
            e for e in self.metrics['event_timeline']
            if current_time - e['timestamp'] < 300
        ]
        
        return {
            'monitoring_active': self.is_monitoring,
            'total_events': len(self.metrics['event_timeline']),
            'recent_events': len(recent_events),
            'threat_count': self.metrics['threat_count'],
            'attack_count': self.metrics['attack_count'],
            'blocked_count': self.metrics['blocked_count'],
            'performance_issues': self.metrics['performance_issues'],
            'layer_activity': dict(self.metrics['layer_activity']),
            'recent_alerts': list(self.alerts)[-10:],  # Last 10 alerts
            'events_per_minute': len(recent_events) / 5  # 5-minute average
        }
    
    def query_events(self, layer=None, event_type=None, hours=1, limit=100):
        """Query events from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query
            query = "SELECT * FROM log_events WHERE timestamp > datetime('now', '-{} hours')".format(hours)
            params = []
            
            if layer:
                query += " AND layer = ?"
                params.append(layer)
            
            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            # Convert to dictionaries
            columns = [desc[0] for desc in cursor.description]
            events = [dict(zip(columns, row)) for row in results]
            
            conn.close()
            return events
            
        except Exception as e:
            logger.error(f"Database query error: {e}")
            return []

class LogFileHandler(FileSystemEventHandler):
    """Handle file system events for log files"""
    
    def __init__(self, monitor):
        self.monitor = monitor
        self.file_positions = {}
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith('.log'):
            self.process_log_file(event.src_path)
    
    def on_created(self, event):
        if event.is_directory:
            return
        
        if event.src_path.endswith('.log'):
            self.file_positions[event.src_path] = 0
            self.process_log_file(event.src_path)
    
    def process_log_file(self, file_path):
        """Process new lines in log file"""
        try:
            with open(file_path, 'r') as f:
                # Seek to last known position
                last_pos = self.file_positions.get(file_path, 0)
                f.seek(last_pos)
                
                # Read new lines
                new_lines = f.readlines()
                
                # Update position
                self.file_positions[file_path] = f.tell()
                
                # Process each new line
                for line in new_lines:
                    event_data = self.monitor.parse_log_line(line, os.path.basename(file_path))
                    if event_data:
                        logger.debug(f"Processed log event: {event_data['event_type']} from {event_data['layer']}")
        
        except Exception as e:
            logger.debug(f"Error processing log file {file_path}: {e}")

# Initialize monitor
log_monitor = LogMonitor()

# Flask routes
@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "log_monitor",
        "monitoring": log_monitor.is_monitoring,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    """Start log monitoring"""
    if log_monitor.is_monitoring:
        return jsonify({"status": "already_monitoring"})
    
    try:
        # Create observer and handler
        log_monitor.observer = Observer()
        handler = LogFileHandler(log_monitor)
        log_monitor.observer.schedule(handler, log_monitor.logs_dir, recursive=True)
        
        # Start monitoring
        log_monitor.observer.start()
        log_monitor.is_monitoring = True
        
        logger.info(f"Started monitoring logs in {log_monitor.logs_dir}")
        return jsonify({"status": "monitoring_started"})
        
    except Exception as e:
        logger.error(f"Failed to start monitoring: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    """Stop log monitoring"""
    if not log_monitor.is_monitoring:
        return jsonify({"status": "not_monitoring"})
    
    try:
        log_monitor.observer.stop()
        log_monitor.observer.join(timeout=5)
        log_monitor.is_monitoring = False
        
        logger.info("Stopped log monitoring")
        return jsonify({"status": "monitoring_stopped"})
        
    except Exception as e:
        logger.error(f"Failed to stop monitoring: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/metrics')
def get_metrics():
    """Get current metrics"""
    return jsonify(log_monitor.get_metrics_summary())

@app.route('/events')
def get_events():
    """Get filtered events"""
    layer = request.args.get('layer')
    event_type = request.args.get('event_type')
    hours = request.args.get('hours', 1, type=int)
    limit = request.args.get('limit', 100, type=int)
    
    events = log_monitor.query_events(layer, event_type, hours, limit)
    return jsonify({
        "count": len(events),
        "events": events
    })

@app.route('/alerts')
def get_alerts():
    """Get recent alerts"""
    return jsonify({
        "count": len(log_monitor.alerts),
        "alerts": list(log_monitor.alerts)
    })

@app.route('/dashboard')
def dashboard():
    """Simple web dashboard"""
    dashboard_html = """
<!DOCTYPE html>
<html>
<head>
    <title>CE-CMS Log Monitor Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .metric { background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }
        .alert { background: #ffebee; padding: 10px; margin: 5px 0; border-left: 4px solid #f44336; }
        .high { border-left-color: #f44336; }
        .medium { border-left-color: #ff9800; }
        .low { border-left-color: #4caf50; }
    </style>
</head>
<body>
    <h1>CE-CMS Log Monitor Dashboard</h1>
    <div id="metrics"></div>
    <div id="alerts"></div>
    
    <script>
        function updateDashboard() {
            fetch('/metrics')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('metrics').innerHTML = `
                        <h2>Current Metrics</h2>
                        <div class="metric">Monitoring Active: ${data.monitoring_active}</div>
                        <div class="metric">Total Events: ${data.total_events}</div>
                        <div class="metric">Recent Events (5min): ${data.recent_events}</div>
                        <div class="metric">Threats: ${data.threat_count}</div>
                        <div class="metric">Attacks: ${data.attack_count}</div>
                        <div class="metric">Blocked: ${data.blocked_count}</div>
                        <div class="metric">Events/Min: ${data.events_per_minute.toFixed(2)}</div>
                    `;
                });
            
            fetch('/alerts')
                .then(response => response.json())
                .then(data => {
                    let alertsHtml = '<h2>Recent Alerts</h2>';
                    data.alerts.slice(-10).forEach(alert => {
                        alertsHtml += `<div class="alert ${alert.severity}">${alert.timestamp}: ${alert.message}</div>`;
                    });
                    document.getElementById('alerts').innerHTML = alertsHtml;
                });
        }
        
        // Update every 5 seconds
        setInterval(updateDashboard, 5000);
        updateDashboard();
    </script>
</body>
</html>
    """
    return dashboard_html

if __name__ == '__main__':
    logger.info("Starting CE-CMS Log Monitor")
    
    # Start monitoring automatically if logs directory exists
    if os.path.exists(log_monitor.logs_dir):
        try:
            log_monitor.observer = Observer()
            handler = LogFileHandler(log_monitor)
            log_monitor.observer.schedule(handler, log_monitor.logs_dir, recursive=True)
            log_monitor.observer.start()
            log_monitor.is_monitoring = True
            logger.info("Auto-started log monitoring")
        except Exception as e:
            logger.error(f"Failed to auto-start monitoring: {e}")
    
    # Start Flask server
    app.run(
        host='0.0.0.0',
        port=8001,
        debug=False,
        threaded=True
    )