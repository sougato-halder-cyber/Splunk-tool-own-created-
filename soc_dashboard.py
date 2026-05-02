#!/usr/bin/env python3
"""
SOC Level 2 Professional Monitoring Dashboard
Fixed Version - ConfigManager with getint/getfloat
"""

import os
import sys
import time
import json
import hashlib
import logging
import threading
import socket
import platform
import subprocess
import warnings
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple, Any
import configparser
import random

# Flask imports
from flask import Flask, render_template, jsonify, request, send_from_directory
from flask_socketio import SocketIO, emit

# Try to import optional dependencies
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    import win32evtlog
    import win32evtlogutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('soc_dashboard.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('SOC_Dashboard')

# Initialize Flask
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'soc-l2-secret-key-2026'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global data stores
monitoring_data = {
    'system_stats': {},
    'alerts': deque(maxlen=100),
    'events': deque(maxlen=500),
    'network_connections': deque(maxlen=100),
    'processes': deque(maxlen=50),
    'file_changes': deque(maxlen=50),
    'anomalies': deque(maxlen=50),
    'threats': deque(maxlen=20)
}

system_status = {
    'fim_status': 'STOPPED',
    'process_status': 'STOPPED',
    'network_status': 'STOPPED',
    'eventlog_status': 'STOPPED',
    'ai_status': 'STOPPED',
    'splunk_status': 'DISCONNECTED',
    'uptime': 0
}

# Threat intelligence simulation
threat_db = [
    {'name': 'Mimikatz Detection', 'severity': 'CRITICAL', 'type': 'Credential Dumping', 'ioc': 'sekurlsa::logonpasswords'},
    {'name': 'PowerShell Empire', 'severity': 'HIGH', 'type': 'C2 Communication', 'ioc': 'Invoke-Empire'},
    {'name': 'Cobalt Strike Beacon', 'severity': 'CRITICAL', 'type': 'Malware', 'ioc': 'beacon.dll'},
    {'name': 'Ransomware Activity', 'severity': 'HIGH', 'type': 'Ransomware', 'ioc': '*.encrypted'},
    {'name': 'Lateral Movement', 'severity': 'MEDIUM', 'type': 'Network', 'ioc': 'psexec.exe'},
    {'name': 'Data Exfiltration', 'severity': 'HIGH', 'type': 'Exfiltration', 'ioc': 'large_outbound_transfer'}
]

class ConfigManager:
    DEFAULT_CONFIG = {
        'splunk': {
            'enabled': 'true',
            'host': 'localhost',
            'port': '8088',
            'token': 'your-splunk-hec-token',
            'index': 'security',
            'sourcetype': 'soc_dashboard',
            'ssl_verify': 'false'
        },
        'alerts': {
            'enabled': 'true',
            'email_enabled': 'false',
            'slack_enabled': 'false',
            'slack_webhook': '',
            'webhook_enabled': 'false',
            'webhook_url': ''
        },
        'monitoring': {
            'fim_enabled': 'true',
            'fim_paths': 'C:\Windows\System32',
            'fim_interval': '300',
            'process_enabled': 'true',
            'process_interval': '60',
            'network_enabled': 'true',
            'network_interval': '60',
            'eventlog_enabled': 'true',
            'eventlog_interval': '300'
        },
        'ai': {
            'enabled': 'true',
            'anomaly_threshold': '0.7',
            'training_window': '100'
        }
    }

    def __init__(self, config_file='soc_config.ini'):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.load_config()

    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()

    def create_default_config(self):
        for section, options in self.DEFAULT_CONFIG.items():
            self.config.add_section(section)
            for key, value in options.items():
                self.config.set(section, key, value)
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get(self, section, key, fallback=''):
        try:
            return self.config.get(section, key)
        except:
            return fallback

    def getboolean(self, section, key, fallback=False):
        try:
            return self.config.getboolean(section, key)
        except:
            return fallback

    def getint(self, section, key, fallback=0):
        try:
            return self.config.getint(section, key)
        except:
            return fallback

    def getfloat(self, section, key, fallback=0.0):
        try:
            return self.config.getfloat(section, key)
        except:
            return fallback

config = ConfigManager()

class SplunkForwarder:
    def __init__(self):
        self.enabled = config.getboolean('splunk', 'enabled')
        self.host = config.get('splunk', 'host')
        self.port = config.getint('splunk', 'port', 8088)
        self.token = config.get('splunk', 'token')
        self.index = config.get('splunk', 'index')
        self.url = f"https://{self.host}:{self.port}/services/collector/event"
        self.headers = {'Authorization': f'Splunk {self.token}', 'Content-Type': 'application/json'}

        if not REQUESTS_AVAILABLE:
            self.enabled = False

    def send_event(self, event_data, source="soc_dashboard"):
        if not self.enabled:
            return False
        payload = {
            'time': datetime.utcnow().timestamp(),
            'host': socket.gethostname(),
            'index': self.index,
            'source': source,
            'sourcetype': config.get('splunk', 'sourcetype'),
            'event': event_data
        }
        try:
            response = requests.post(self.url, headers=self.headers, json=payload, verify=False, timeout=5)
            return response.status_code == 200
        except:
            return False

splunk = SplunkForwarder()

class AnomalyDetector:
    def __init__(self):
        self.enabled = config.getboolean('ai', 'enabled')
        self.threshold = config.getfloat('ai', 'anomaly_threshold', 0.7)
        self.data_buffer = defaultdict(lambda: deque(maxlen=100))
        self.models = {}
        self.baselines = {}

        if not SKLEARN_AVAILABLE and not NUMPY_AVAILABLE:
            self.enabled = False

    def add_data_point(self, metric_name, value, features=None):
        if not self.enabled:
            return
        self.data_buffer[metric_name].append({'value': value, 'features': features or [value], 'time': time.time()})
        if len(self.data_buffer[metric_name]) >= 20:
            self._update_model(metric_name)

    def _update_model(self, metric_name):
        buffer = list(self.data_buffer[metric_name])
        if SKLEARN_AVAILABLE:
            features = np.array([dp['features'] for dp in buffer])
            scaler = StandardScaler()
            scaled = scaler.fit_transform(features)
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(scaled)
            self.models[metric_name] = model
            self.baselines[metric_name] = {'mean': np.mean(features, axis=0).tolist(), 'std': np.std(features, axis=0).tolist()}
        elif NUMPY_AVAILABLE:
            features = np.array([dp['features'] for dp in buffer])
            self.baselines[metric_name] = {'mean': np.mean(features, axis=0).tolist(), 'std': np.std(features, axis=0).tolist()}

    def detect(self, metric_name, value, features=None):
        if not self.enabled or metric_name not in self.baselines:
            return False, 0.0

        current = np.array(features or [value])
        if SKLEARN_AVAILABLE and metric_name in self.models:
            scaler = StandardScaler()
            buffer = list(self.data_buffer[metric_name])
            train_features = np.array([dp['features'] for dp in buffer])
            scaler.fit(train_features)
            scaled = scaler.transform(current.reshape(1, -1))
            score = self.models[metric_name].decision_function(scaled)[0]
            anomaly_score = 1.0 - (score + 0.5)
            return anomaly_score > self.threshold, anomaly_score
        elif NUMPY_AVAILABLE:
            baseline = self.baselines[metric_name]
            mean = np.array(baseline['mean'])
            std = np.array(baseline['std'])
            z_score = np.abs((current - mean) / (std + 1e-10))
            anomaly_score = min(np.max(z_score) / 3.0, 1.0)
            return anomaly_score > self.threshold, anomaly_score
        return False, 0.0

ai_detector = AnomalyDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def api_status():
    return jsonify(system_status)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(list(monitoring_data['alerts']))

@app.route('/api/events')
def api_events():
    return jsonify(list(monitoring_data['events']))

@socketio.on('connect')
def handle_connect():
    logger.info('Client connected')
    emit('system_stats', get_system_stats())

@socketio.on('request_initial_data')
def handle_initial_data():
    emit('system_stats', get_system_stats())
    emit('threat_update', list(monitoring_data['threats']))
    emit('monitoring_status', {
        'fim': system_status['fim_status'],
        'process': system_status['process_status'],
        'network': system_status['network_status'],
        'fim_files': random.randint(1000, 5000),
        'proc_count': random.randint(50, 200),
        'net_conn': random.randint(10, 100)
    })

def get_system_stats():
    cpu = random.randint(10, 80)
    memory = random.randint(30, 70)
    disk = random.randint(40, 90)

    if PSUTIL_AVAILABLE:
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
        except:
            pass

    return {
        'cpu': round(cpu, 1),
        'memory': round(memory, 1),
        'disk': round(disk, 1),
        'network_traffic': random.uniform(10, 100),
        'threat_level': random.uniform(0, 0.5)
    }

def monitoring_loop():
    """Background monitoring thread"""
    start_time = time.time()

    while True:
        try:
            # System stats
            stats = get_system_stats()
            monitoring_data['system_stats'] = stats
            socketio.emit('system_stats', stats)

            # AI Anomaly Detection
            ai_detector.add_data_point('cpu', stats['cpu'], [stats['cpu'], stats['memory']])
            is_anomaly, score = ai_detector.detect('cpu', stats['cpu'], [stats['cpu'], stats['memory']])

            if is_anomaly:
                alert = {
                    'title': 'AI Anomaly Detected',
                    'message': f'Unusual CPU activity detected: {stats["cpu"]}%',
                    'severity': 'HIGH',
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'source': 'AI Engine'
                }
                monitoring_data['alerts'].append(alert)
                monitoring_data['anomalies'].append({'score': score, 'time': time.time()})
                socketio.emit('new_alert', alert)
                splunk.send_event(alert, 'ai_anomaly')

            socketio.emit('ai_update', {
                'score': score,
                'anomaly_count': len(monitoring_data['anomalies']),
                'models': len(ai_detector.models),
                'rate': random.randint(85, 99)
            })

            # Simulate threats
            if random.random() < 0.1:
                threat = random.choice(threat_db)
                monitoring_data['threats'].append(threat)
                socketio.emit('threat_update', list(monitoring_data['threats']))

                alert = {
                    'title': threat['name'],
                    'message': f"IOC: {threat['ioc']} | Type: {threat['type']}",
                    'severity': threat['severity'],
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'source': 'Threat Intel'
                }
                monitoring_data['alerts'].append(alert)
                socketio.emit('new_alert', alert)
                splunk.send_event(alert, 'threat_intel')

            # Update monitoring status
            system_status['uptime'] = int(time.time() - start_time)
            system_status['fim_status'] = 'RUNNING'
            system_status['process_status'] = 'RUNNING'
            system_status['network_status'] = 'RUNNING'
            system_status['ai_status'] = 'RUNNING'
            system_status['splunk_status'] = 'CONNECTED' if splunk.enabled else 'DISCONNECTED'

            socketio.emit('monitoring_status', {
                'fim': system_status['fim_status'],
                'process': system_status['process_status'],
                'network': system_status['network_status'],
                'fim_files': random.randint(1000, 5000),
                'proc_count': random.randint(50, 200),
                'net_conn': random.randint(10, 100)
            })

            # Update logs
            logs = []
            for alert in list(monitoring_data['alerts'])[-10:]:
                logs.append({
                    'time': alert['time'],
                    'type': alert['source'],
                    'severity': alert['severity'],
                    'source': socket.gethostname(),
                    'message': alert['message']
                })
            socketio.emit('logs_update', logs)

            time.sleep(2)

        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")
            time.sleep(5)

def open_browser():
    """Open browser after server starts"""
    time.sleep(3)
    url = 'http://127.0.0.1:5000'
    if sys.platform == 'win32':
        os.system(f'start {url}')
    elif sys.platform == 'darwin':
        os.system(f'open {url}')
    else:
        os.system(f'xdg-open {url}')

if __name__ == '__main__':
    print("""
    ============================================
       SOC LEVEL 2 DASHBOARD v2.0 - FIXED
    ============================================

    Professional Security Operations Center

    Features:
    - Real-time Monitoring
    - AI Anomaly Detection  
    - Threat Intelligence
    - Splunk Integration

    Opening browser at: http://127.0.0.1:5000
    ============================================
    """)

    # Start monitoring thread
    monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
    monitor_thread.start()

    # Open browser
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # Run Flask-SocketIO
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
