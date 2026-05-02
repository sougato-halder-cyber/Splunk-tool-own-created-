# SOC Level 2 Professional Dashboard

## 🎯 Overview
Professional Security Operations Center dashboard with Black Hat/Cisco SOC style interface.

## 🔥 Features

### Dashboard
- Real-time system metrics (CPU, Memory, Disk)
- Live network traffic visualization
- Security alert feed with severity levels
- Threat intelligence cards

### Monitoring Modules
- **File Integrity Monitoring (FIM)** - Track file changes
- **Process Monitor** - Detect suspicious processes
- **Network Monitor** - Monitor connections
- **Windows Event Log** - Security event analysis

### AI-Powered Detection
- Isolation Forest anomaly detection
- Statistical Z-score analysis
- Real-time threat scoring
- Behavioral analysis

### Integration
- **Splunk HEC** - Event forwarding
- **Email Alerts** - SMTP notifications
- **Slack Alerts** - Webhook notifications
- **Custom Webhooks** - API integration

## 📋 Prerequisites

```bash
# Install Python 3.8+
# Install dependencies
pip install -r requirements_dashboard.txt
```

## 🚀 Running the Dashboard

### Option 1: Direct Python
```bash
python soc_dashboard.py
```
Browser automatically open hobe: http://127.0.0.1:5000

### Option 2: Windows Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Create executable
pyinstaller --onefile --name SOC_Dashboard --hidden-import=flask --hidden-import=flask_socketio --hidden-import=requests --hidden-import=numpy --hidden-import=psutil --hidden-import=sklearn --hidden-import=sklearn.ensemble --hidden-import=sklearn.preprocessing --hidden-import=win32evtlog --hidden-import=win32evtlogutil --add-data "templates;templates" soc_dashboard.py
```

## ⚙️ Configuration

Edit `soc_config.ini`:

```ini
[splunk]
host = your-splunk-server.com
token = your-hec-token
index = security

[alerts]
slack_webhook = your-webhook-url
email_to = security@company.com
```

## 🖥️ Dashboard Sections

1. **Dashboard** - Main overview with metrics and alerts
2. **Live Monitoring** - Real-time process and file monitoring
3. **Threat Intel** - Active threat indicators
4. **Network Map** - Network topology visualization
5. **Event Logs** - Security event table
6. **AI Analysis** - Machine learning anomaly detection
7. **Configuration** - System settings

## 📊 Splunk Setup

1. Enable HTTP Event Collector (HEC)
2. Create HEC token
3. Configure in `soc_config.ini`
4. Events forward hobe automatically

### Splunk Search:
```spl
index=security sourcetype=soc_dashboard
| stats count by event_type
| timechart span=1m count by severity
```

## 🚨 Alert Severity Levels

- **CRITICAL** - Immediate action required (Red)
- **HIGH** - Urgent investigation needed (Orange)
- **MEDIUM** - Review required (Yellow)
- **LOW** - Informational (Green)
- **INFO** - General information (Blue)

## 🧠 AI Detection

The system uses:
1. **Isolation Forest** - Advanced ML anomaly detection
2. **Statistical Analysis** - Z-score baseline deviation
3. **Behavioral Learning** - Adaptive threshold adjustment

## 🔧 Troubleshooting

### Port 5000 already in use:
```bash
# Kill process using port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Missing templates:
Ensure `templates/index.html` exists in same directory.

### PyInstaller errors:
```bash
pyinstaller --clean --onefile soc_dashboard.py
```

## 👨‍💻 Author
SOC Level 2 Incident Response Team
